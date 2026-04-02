#!/usr/bin/env python3
"""
parser.py — Deterministic extraction layer for Agentic-BugBounty Explorer.

Receives via stdin a JSON task:
{
  "task": "html_links" | "js_endpoints" | "secrets" | "headers" | "deps" | "full_url",
  "content": "...",          # content to analyze (string)
  "url": "https://...",      # base URL for full_url task (optional)
  "filename": "...",         # filename hint for deps task (optional)
  "max_bytes": 100000        # bytes limit to process (default 100000)
}

Returns via stdout a JSON result:
{
  "task": "...",
  "results": { ... },        # task-specific results
  "stats": { "input_bytes": N, "elapsed_ms": N }
}

Exit code always 0 — errors are in "error" field of JSON output.
"""

import sys
import json
import re
import time
import math
from urllib.parse import urljoin, urlparse

# ── BeautifulSoup import with fallback ────────────────────────────────────────

try:
    from bs4 import BeautifulSoup, Comment
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ── Compiled patterns ─────────────────────────────────────────────────────────

# API endpoints from JS — captures path-like strings in fetch/axios/$.ajax/etc.
RE_API_FETCH = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|delete|patch|head|request)|'''
    r'''(?:\$|jQuery)\.(?:get|post|ajax|getJSON))\s*\(\s*[`"']([^`"'\s]{3,200})[`"']''',
    re.IGNORECASE
)

# URL in typical API variables
RE_API_VAR = re.compile(
    r'''(?:apiUrl|api_url|baseUrl|base_url|endpoint|API_BASE|BASE_URL|API_URL|'''
    r'''SERVER_URL|BACKEND_URL|SERVICE_URL)\s*[=:]\s*[`"']([^`"'\s]{3,200})[`"']''',
    re.IGNORECASE
)

# HTTP paths in template literals and strings
RE_PATH_STRING = re.compile(
    r'''[`"'](/(?:api|v\d|rest|graphql|auth|oauth|admin|internal|private|'''
    r'''users?|account|login|register|token|refresh|reset|verify|upload|'''
    r'''download|files?|config|settings?|profile|search|webhook)[^`"'\s]*)[`"']''',
    re.IGNORECASE
)

# Route definitions (Express, FastAPI, Flask, Rails, Laravel, Spring)
RE_ROUTE_DEF = re.compile(
    r'''(?:app|router|@app|Route)\s*\.(?:get|post|put|delete|patch|head|options|all|use)\s*'''
    r'''\(\s*[`"']([^`"'\s]{2,200})[`"']''',
    re.IGNORECASE
)

# High-entropy secret patterns
RE_SECRET_PATTERNS = [
    # JWT (3 base64 parts with dots)
    (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),
     "jwt_token"),
    # AWS Access Key
    (re.compile(r'\b(AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b'),
     "aws_access_key"),
    # AWS Secret
    (re.compile(r'''(?:aws.?secret|AWS_SECRET)[^=\n]*=\s*["']?([A-Za-z0-9/+]{40})["']?''',
                re.IGNORECASE),
     "aws_secret_key"),
    # Generic API key assignments
    (re.compile(
        r'''(?:api[_-]?key|apikey|api[_-]?token|auth[_-]?token|access[_-]?token|'''
        r'''secret[_-]?key|private[_-]?key|client[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{16,64})["']''',
        re.IGNORECASE),
     "api_key_assignment"),
    # Stripe keys
    (re.compile(r'\b(sk_live_|pk_live_|sk_test_|pk_test_)[A-Za-z0-9]{20,}\b'),
     "stripe_key"),
    # GitHub token
    (re.compile(r'\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b'),
     "github_token"),
    # Google API key
    (re.compile(r'\bAIza[A-Za-z0-9_\-]{35}\b'),
     "google_api_key"),
    # Slack token
    (re.compile(r'\bxox[baprs]-[A-Za-z0-9\-]{10,72}\b'),
     "slack_token"),
    # Hardcoded password
    (re.compile(
        r'''(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,64})["']''',
        re.IGNORECASE),
     "hardcoded_password"),
    # Internal hostname patterns
    (re.compile(
        r'''https?://([a-z0-9\-]+\.(?:internal|local|corp|intranet|svc|'''
        r'''cluster\.local|lan|home|localdomain)(?::\d+)?(?:/[^\s"'`>]*)?)''',
        re.IGNORECASE),
     "internal_url"),
    # Private IP addresses in strings
    (re.compile(
        r'''["'`]((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|'''
        r'''192\.168\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[^\s"'`>]*)?)["'`]'''),
     "private_ip"),
]

# Tech fingerprinting from HTTP headers
TECH_HEADER_MAP = {
    "x-powered-by": lambda v: [{"name": v.strip(), "category": "runtime", "source": "header", "confidence": "high"}],
    "server": lambda v: [{"name": v.strip(), "category": "server", "source": "header", "confidence": "high"}],
    "x-generator": lambda v: [{"name": v.strip(), "category": "cms", "source": "header", "confidence": "high"}],
    "x-drupal-cache": lambda v: [{"name": "Drupal", "category": "cms", "source": "header", "confidence": "high"}],
    "x-wordpress-auth": lambda v: [{"name": "WordPress", "category": "cms", "source": "header", "confidence": "high"}],
    "x-aspnet-version": lambda v: [{"name": f"ASP.NET {v.strip()}", "category": "framework", "source": "header", "confidence": "high"}],
    "x-aspnetmvc-version": lambda v: [{"name": f"ASP.NET MVC {v.strip()}", "category": "framework", "source": "header", "confidence": "high"}],
}

# Security header check
SECURITY_HEADERS_REQUIRED = {
    "content-security-policy": "CSP missing — XSS risk",
    "x-frame-options": "Clickjacking risk",
    "x-content-type-options": "MIME sniffing risk",
    "strict-transport-security": "HSTS missing",
    "permissions-policy": "Feature policy missing",
    "referrer-policy": "Referrer leakage risk",
}

# ── Shannon entropy ────────────────────────────────────────────────────────────

def shannon_entropy(s):
    """Calculate Shannon entropy of a string — high = likely secret."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def is_likely_secret(value):
    """Filter false positives: placeholders, common values, too short."""
    if len(value) < 8:
        return False
    lower = value.lower()
    placeholders = {
        "your_api_key", "your_secret", "changeme", "placeholder",
        "example", "test", "dummy", "xxxxxxxxxx", "0000000000",
        "your-secret-here", "insert_key_here", "api_key_here",
        "secret_key_here", "token_here", "password_here",
    }
    if lower in placeholders or any(p in lower for p in ["xxxx", "1234567", "abcdef"]):
        return False
    return shannon_entropy(value) > 3.5

# ── Task handlers ─────────────────────────────────────────────────────────────

def task_html_links(content, base_url=""):
    """Extract links, forms, hidden inputs, and comments from HTML using BeautifulSoup."""
    if not BS4_AVAILABLE:
        return {"error": "BeautifulSoup not available", "links": [], "forms": [], "comments": []}

    try:
        soup = BeautifulSoup(content[:200_000], "lxml")
    except Exception:
        soup = BeautifulSoup(content[:200_000], "html.parser")

    # Links (a, link, script, img, iframe)
    links = []
    seen_links = set()
    for tag in soup.find_all(["a", "link", "script", "iframe", "form"]):
        href = tag.get("href") or tag.get("src") or tag.get("action") or ""
        if not href or href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        full = urljoin(base_url, href) if base_url else href
        if full not in seen_links:
            seen_links.add(full)
            links.append({
                "url": full,
                "tag": tag.name,
                "rel": tag.get("rel", []),
                "text": (tag.get_text()[:50].strip() if tag.name == "a" else ""),
            })

    # Forms with method and action
    forms = []
    for form in soup.find_all("form"):
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            inp_type = inp.get("type", "text")
            inp_name = inp.get("name", "")
            if inp_name:
                inputs.append({
                    "name": inp_name,
                    "type": inp_type,
                    "hidden": inp_type == "hidden",
                    "value": inp.get("value", "") if inp_type == "hidden" else None,
                })
        forms.append({
            "action": urljoin(base_url, form.get("action", "")) if base_url else form.get("action", ""),
            "method": (form.get("method") or "get").upper(),
            "inputs": inputs,
            "has_csrf_token": any(
                i["name"].lower() in {"csrf_token", "_token", "authenticity_token",
                                      "__requestverificationtoken", "csrfmiddlewaretoken"}
                for i in inputs
            ),
        })

    # HTML comments (often contain debug info, TODO, versions)
    comments = []
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        text = str(comment).strip()
        if len(text) > 10:
            comments.append(text[:200])

    # Informative meta tags
    meta_info = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name", meta.get("property", "")).lower()
        if name in {"generator", "framework", "author", "version"}:
            meta_info[name] = meta.get("content", "")

    return {
        "links": links[:100],
        "forms": forms[:20],
        "comments": comments[:20],
        "meta_info": meta_info,
    }


def task_js_endpoints(content):
    """Extract API endpoints, route definitions, and auth patterns from JS/TS."""
    endpoints = {}  # deduplicated by path

    for match in RE_API_FETCH.finditer(content):
        p = match.group(1)
        if p not in endpoints:
            endpoints[p] = {"path": p, "method": "unknown", "source": "fetch_call"}

    for match in RE_API_VAR.finditer(content):
        p = match.group(1)
        if p not in endpoints and (p.startswith("/") or p.startswith("http")):
            endpoints[p] = {"path": p, "method": "unknown", "source": "api_var"}

    for match in RE_PATH_STRING.finditer(content):
        p = match.group(1)
        if p not in endpoints:
            endpoints[p] = {"path": p, "method": "unknown", "source": "path_string"}

    for match in RE_ROUTE_DEF.finditer(content):
        p = match.group(1)
        preceding = content[max(0, match.start()-10):match.start()]
        method_match = re.search(r'\.(get|post|put|delete|patch|head|all)\s*$', preceding, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "unknown"
        endpoints[p] = {"path": p, "method": method, "source": "route_def"}

    auth_patterns = []
    auth_indicators = {
        "jwt": re.compile(r'\b(?:jwt|jsonwebtoken|verify|sign|decode)\b', re.IGNORECASE),
        "oauth": re.compile(r'\b(?:oauth|authorization_code|client_id|client_secret|redirect_uri)\b', re.IGNORECASE),
        "api_key": re.compile(r'\b(?:api[_-]?key|x-api-key|apikey)\b', re.IGNORECASE),
        "session": re.compile(r'\b(?:session|cookie|express-session|connect\.sid)\b', re.IGNORECASE),
        "basic_auth": re.compile(r'\bBasic\s+[A-Za-z0-9+/]{10,}', re.IGNORECASE),
    }
    for auth_type, pattern in auth_indicators.items():
        m = pattern.search(content)
        if m:
            ctx = content[max(0, m.start()-20):m.end()+50].strip().replace("\n", " ")[:100]
            auth_patterns.append({"type": auth_type, "context": ctx})

    storage_patterns = re.findall(
        r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["\']([^"\']+)["\']',
        content, re.IGNORECASE
    )
    storage_keys = list(set(storage_patterns))[:10]

    return {
        "endpoints": list(endpoints.values())[:80],
        "auth_patterns": auth_patterns[:10],
        "storage_keys": storage_keys,
    }


def task_secrets(content):
    """Search for secrets, credentials, high-entropy tokens in content."""
    found = []
    seen_values = set()

    for pattern, secret_type in RE_SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()

            if not value or value in seen_values:
                continue

            if not is_likely_secret(value):
                continue

            seen_values.add(value)

            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            ctx = content[start:end].replace("\n", " ").strip()

            masked = value[:4] + "*" * min(len(value) - 4, 8)
            entropy = round(shannon_entropy(value), 2)

            found.append({
                "type": secret_type,
                "masked_value": masked,
                "entropy": entropy,
                "length": len(value),
                "context": ctx[:100],
                "line": content[:match.start()].count("\n") + 1,
            })

    return {"secrets": found[:30]}


def task_headers(headers_text):
    """Analyze HTTP headers: tech fingerprinting, missing security headers, info leak."""
    technologies = []
    missing_security = []
    information_leakage = []
    present_headers = {}

    for line in headers_text.split("\n"):
        line = line.strip()
        if not line or ": " not in line:
            continue
        key, _, value = line.partition(": ")
        key_lower = key.lower().strip()
        value = value.strip()
        present_headers[key_lower] = value

    for header_name, extractor in TECH_HEADER_MAP.items():
        if header_name in present_headers:
            technologies.extend(extractor(present_headers[header_name]))

    for required_header, risk_note in SECURITY_HEADERS_REQUIRED.items():
        if required_header not in present_headers:
            missing_security.append({
                "header": required_header,
                "risk": risk_note,
            })

    leaky_headers = [
        "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
        "x-generator", "x-runtime", "x-version", "x-debug", "via",
        "x-backend-server", "x-forwarded-server", "x-served-by",
    ]
    for h in leaky_headers:
        if h in present_headers:
            information_leakage.append({
                "header": h,
                "value": present_headers[h],
                "risk": f"Reveals {h.replace('x-', '').replace('-', ' ')} information",
            })

    if "access-control-allow-origin" in present_headers:
        acao = present_headers["access-control-allow-origin"]
        if acao == "*":
            information_leakage.append({
                "header": "access-control-allow-origin",
                "value": acao,
                "risk": "Wildcard CORS — may allow cross-origin credential access if combined with ACAO credentials header",
            })

    set_cookie = present_headers.get("set-cookie", "")
    if set_cookie:
        cookie_issues = []
        if "httponly" not in set_cookie.lower():
            cookie_issues.append("HttpOnly missing")
        if "secure" not in set_cookie.lower():
            cookie_issues.append("Secure flag missing")
        if "samesite" not in set_cookie.lower():
            cookie_issues.append("SameSite missing")
        if cookie_issues:
            information_leakage.append({
                "header": "set-cookie",
                "value": set_cookie[:100],
                "risk": f"Cookie flags: {', '.join(cookie_issues)}",
            })

    return {
        "technologies": technologies,
        "missing_security_headers": missing_security,
        "information_leakage": information_leakage,
    }


def task_deps(content, filename=""):
    """Analyze dependency manifest (package.json, requirements.txt, pom.xml, etc.)."""
    deps = []
    filename_lower = filename.lower()

    # package.json
    if "package.json" in filename_lower or (content.strip().startswith("{") and '"dependencies"' in content):
        try:
            data = json.loads(content)
            all_deps = {}
            all_deps.update(data.get("dependencies", {}))
            all_deps.update(data.get("devDependencies", {}))
            for name, version in all_deps.items():
                deps.append({"package": name, "version": str(version), "ecosystem": "npm"})
        except json.JSONDecodeError:
            pass

    # requirements.txt
    elif "requirements" in filename_lower or (not content.strip().startswith("{") and "==" in content):
        for line in content.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^([A-Za-z0-9_\-\.]+)\s*(?:==|>=|<=|~=|!=)\s*([^\s;]+)', line)
            if match:
                deps.append({
                    "package": match.group(1),
                    "version": match.group(2),
                    "ecosystem": "pypi"
                })

    # pom.xml (Maven)
    elif "pom.xml" in filename_lower or "<dependency>" in content:
        for match in re.finditer(
            r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>'
            r'(?:\s*<version>([^<]*)</version>)?',
            content, re.DOTALL
        ):
            deps.append({
                "package": f"{match.group(1).strip()}:{match.group(2).strip()}",
                "version": match.group(3).strip() if match.group(3) else "unknown",
                "ecosystem": "maven"
            })

    # Gemfile
    elif "gemfile" in filename_lower or "gem '" in content.lower():
        for match in re.finditer(r'''gem\s+['"]([^'"]+)['"](?:,\s*['"]([^'"]+)['"])?''', content):
            deps.append({
                "package": match.group(1),
                "version": match.group(2) or "any",
                "ecosystem": "rubygems"
            })

    # composer.json
    elif "composer.json" in filename_lower:
        try:
            data = json.loads(content)
            for name, version in {**data.get("require", {}), **data.get("require-dev", {})}.items():
                deps.append({"package": name, "version": str(version), "ecosystem": "packagist"})
        except json.JSONDecodeError:
            pass

    # go.mod
    elif "go.mod" in filename_lower:
        for match in re.finditer(r'^require\s+([^\s]+)\s+([^\s]+)', content, re.MULTILINE):
            deps.append({"package": match.group(1), "version": match.group(2), "ecosystem": "go"})
        for match in re.finditer(r'^\s+([^\s]+)\s+(v[^\s]+)', content, re.MULTILINE):
            deps.append({"package": match.group(1), "version": match.group(2), "ecosystem": "go"})

    # Flag known vulnerable packages
    vulnerable_patterns = [
        "lodash", "moment", "jquery", "log4j", "struts", "jackson",
        "fastjson", "xstream", "groovy", "ognl", "commons-collections",
        "spring-core", "spring-web", "netty", "shiro", "dubbo",
    ]
    flagged = []
    for dep in deps:
        pkg_lower = dep["package"].lower()
        for vp in vulnerable_patterns:
            if vp in pkg_lower:
                flagged.append({
                    **dep,
                    "flag": f"Known vulnerability-prone package: {vp}",
                })
                break

    return {
        "dependencies": deps[:100],
        "flagged_packages": flagged[:20],
        "total_count": len(deps),
    }


def task_full_url(url, timeout=10):
    """
    Light fetch of a URL: HEAD for headers, GET for content.
    Returns headers + initial body snippet (no LLM).
    """
    try:
        import urllib.request
        import urllib.error
        import ssl

        headers_sent = {
            "User-Agent": "Mozilla/5.0 (compatible; security-researcher/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(url, headers=headers_sent, method="GET")
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            head_headers = dict(resp.headers)
            body_bytes = resp.read(100_000)
            body = body_bytes.decode("utf-8", errors="replace")
            return {
                "status_code": resp.status,
                "final_url": resp.url,
                "headers": {k.lower(): v for k, v in head_headers.items()},
                "body_snippet": body[:500],
                "content_type": head_headers.get("Content-Type", ""),
                "content_length": head_headers.get("Content-Length", ""),
            }
    except Exception as e:
        return {"error": str(e)}


# ── Dispatcher ────────────────────────────────────────────────────────────────

def main():
    t0 = time.time()

    try:
        raw = sys.stdin.read()
        task_input = json.loads(raw)
    except Exception as e:
        print(json.dumps({"error": f"Invalid JSON input: {e}"}))
        sys.exit(0)

    task = task_input.get("task", "")
    content = task_input.get("content", "")
    url = task_input.get("url", "")
    filename = task_input.get("filename", "")
    max_bytes = task_input.get("max_bytes", 100_000)

    # Truncate content to limit
    if content and len(content) > max_bytes:
        content = content[:max_bytes]

    try:
        if task == "html_links":
            results = task_html_links(content, url)
        elif task == "js_endpoints":
            results = task_js_endpoints(content)
        elif task == "secrets":
            results = task_secrets(content)
        elif task == "headers":
            results = task_headers(content)
        elif task == "deps":
            results = task_deps(content, filename)
        elif task == "full_url":
            results = task_full_url(url)
        else:
            results = {"error": f"Unknown task: {task}"}
    except Exception as e:
        results = {"error": str(e)}

    elapsed_ms = round((time.time() - t0) * 1000)
    output = {
        "task": task,
        "results": results,
        "stats": {
            "input_bytes": len(content) + len(url),
            "elapsed_ms": elapsed_ms,
        }
    }

    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
