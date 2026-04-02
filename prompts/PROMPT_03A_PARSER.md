# PROMPT 06 — Parser Deterministico (Explorer Refactor)
# Esegui dopo il PROMPT 03 (Explorer Agent).
# Sostituisce il layer LLM nell'Explorer con parser deterministici.
# Crea scripts/lib/parser.py e scripts/lib/parser-bridge.js
# Modifica scripts/lib/explorer.js

---

Sei un ingegnere che sta ottimizzando il framework Agentic-BugBounty.

Il problema attuale: `scripts/lib/explorer.js` passa HTML grezzo, JS bundle,
e header HTTP a un LLM per estrarne endpoint, segreti, tecnologie.
Questo è inefficiente: il 90% dei token sono markup e rumore,
la latenza è 5-30 secondi per chiamata, e la precision su pattern
strutturati è inferiore a quella di un parser deterministico.

**Principio da implementare:**

```
PRIMA (tutto via LLM):
  HTML/JS grezzo (50KB) → LLM → { endpoints, secrets, tech }

DOPO (parsing prima, LLM solo su dati già strutturati):
  HTML/JS grezzo → parser deterministico → dati puliti (< 2KB)
                                               ↓
                                    LLM solo se serve reasoning
                                    (classificazione ambigua, contesto)
```

Il parser deterministico gestisce:
- Link e form HTML (BeautifulSoup)
- Endpoint API da JS (regex specializzate)
- Segreti e token (pattern entropy-based)
- Header HTTP (parser strutturato)
- Dependency manifest (JSON/TOML/XML parse nativo)
- Commenti con informazioni sensibili

Il LLM interviene solo per:
- Classificare se un endpoint trovato dal parser è "interessante" (batch piccolo)
- Valutare se un pattern sembra un segreto reale vs. un placeholder
- Fingerprinting stack quando gli header sono ambigui

---

## FILE DA CREARE

### `scripts/lib/parser.py`

Script Python autonomo che riceve un task JSON via stdin
e restituisce risultati JSON via stdout.
Nessuna dipendenza esterna oltre BeautifulSoup4, lxml, requests
(già installati nell'ambiente).

```python
#!/usr/bin/env python3
"""
parser.py — Deterministic extraction layer per Agentic-BugBounty Explorer.

Riceve via stdin un JSON task:
{
  "task": "html_links" | "js_endpoints" | "secrets" | "headers" | "deps" | "full_url",
  "content": "...",          # contenuto da analizzare (stringa)
  "url": "https://...",      # URL base per full_url task (opzionale)
  "max_bytes": 100000        # limite bytes da processare (default 100000)
}

Restituisce via stdout un JSON result:
{
  "task": "...",
  "results": { ... },        # risultati specifici per task
  "stats": { "input_bytes": N, "elapsed_ms": N }
}

Exit code 0 sempre — gli errori sono nel campo "error" del JSON output.
"""

import sys
import json
import re
import time
import hashlib
import math
from urllib.parse import urljoin, urlparse

# ── BeautifulSoup import con fallback ─────────────────────────────────────────

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ── Pattern compilati ─────────────────────────────────────────────────────────

# Endpoint API da JS — cattura path-like strings in fetch/axios/$.ajax/etc.
RE_API_FETCH = re.compile(
    r'''(?:fetch|axios\.(?:get|post|put|delete|patch|head|request)|'''
    r'''(?:\$|jQuery)\.(?:get|post|ajax|getJSON))\s*\(\s*[`"']([^`"'\s]{3,200})[`"']''',
    re.IGNORECASE
)

# URL in variabili tipiche API
RE_API_VAR = re.compile(
    r'''(?:apiUrl|api_url|baseUrl|base_url|endpoint|API_BASE|BASE_URL|API_URL|'''
    r'''SERVER_URL|BACKEND_URL|SERVICE_URL)\s*[=:]\s*[`"']([^`"'\s]{3,200})[`"']''',
    re.IGNORECASE
)

# Path HTTP nei template literal e stringhe
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

# Segreti ad alta entropia — pattern base
RE_SECRET_PATTERNS = [
    # JWT (3 parti base64 con punti)
    (re.compile(r'\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b'),
     "jwt_token"),
    # AWS Access Key
    (re.compile(r'\b(AKIA|ASIA|AROA|AIDA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b'),
     "aws_access_key"),
    # AWS Secret (40 char alfanumerico + simboli dopo "=")
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
    # Hardcoded password in common config patterns
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

# Tech fingerprinting da header HTTP
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

# ── Shannon entropy ───────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calcola la Shannon entropy di una stringa — alto = probabile segreto."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())

def is_likely_secret(value: str) -> bool:
    """Filtra falsi positivi: placeholder, valori comuni, troppo brevi."""
    if len(value) < 8:
        return False
    lower = value.lower()
    # Placeholder comuni
    placeholders = {
        "your_api_key", "your_secret", "changeme", "placeholder",
        "example", "test", "dummy", "xxxxxxxxxx", "0000000000",
        "your-secret-here", "insert_key_here", "api_key_here",
        "secret_key_here", "token_here", "password_here",
    }
    if lower in placeholders or any(p in lower for p in ["xxxx", "1234567", "abcdef"]):
        return False
    # Entropia minima per essere un segreto reale
    return shannon_entropy(value) > 3.5

# ── Task handlers ─────────────────────────────────────────────────────────────

def task_html_links(content: str, base_url: str = "") -> dict:
    """Estrae link, form, input nascosti, e commenti da HTML con BeautifulSoup."""
    if not BS4_AVAILABLE:
        return {"error": "BeautifulSoup not available", "links": [], "forms": [], "comments": []}

    try:
        soup = BeautifulSoup(content[:200_000], "lxml")
    except Exception:
        soup = BeautifulSoup(content[:200_000], "html.parser")

    # Link (a, link, script, img, iframe)
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

    # Form con metodo e action
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

    # Commenti HTML (spesso contengono debug info, TODO, versioni)
    comments = []
    for comment in soup.find_all(string=lambda text: isinstance(text, type(soup.new_string("")))):
        pass  # BeautifulSoup Comment type
    from bs4 import Comment
    for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
        text = str(comment).strip()
        if len(text) > 10:
            comments.append(text[:200])

    # Meta tag informativi
    meta_info = {}
    for meta in soup.find_all("meta"):
        name = meta.get("name", meta.get("property", "")).lower()
        if name in {"generator", "framework", "author", "version"}:
            meta_info[name] = meta.get("content", "")

    return {
        "links": links[:100],  # max 100 link
        "forms": forms[:20],
        "comments": comments[:20],
        "meta_info": meta_info,
    }


def task_js_endpoints(content: str) -> dict:
    """Estrae endpoint API, route definitions, e auth patterns da JS/TS."""
    endpoints = {}  # deduplicato per path

    # Fetch / axios calls
    for match in RE_API_FETCH.finditer(content):
        path = match.group(1)
        if path not in endpoints:
            endpoints[path] = {"path": path, "method": "unknown", "source": "fetch_call"}

    # API variable assignments
    for match in RE_API_VAR.finditer(content):
        path = match.group(1)
        if path not in endpoints and (path.startswith("/") or path.startswith("http")):
            endpoints[path] = {"path": path, "method": "unknown", "source": "api_var"}

    # Path strings in common patterns
    for match in RE_PATH_STRING.finditer(content):
        path = match.group(1)
        if path not in endpoints:
            endpoints[path] = {"path": path, "method": "unknown", "source": "path_string"}

    # Route definitions
    for match in RE_ROUTE_DEF.finditer(content):
        path = match.group(1)
        # Estrai il method dal testo che precede
        preceding = content[max(0, match.start()-10):match.start()]
        method_match = re.search(r'\.(get|post|put|delete|patch|head|all)\s*$', preceding, re.IGNORECASE)
        method = method_match.group(1).upper() if method_match else "unknown"
        endpoints[path] = {"path": path, "method": method, "source": "route_def"}

    # Auth patterns
    auth_patterns = []
    auth_indicators = {
        "jwt": re.compile(r'\b(?:jwt|jsonwebtoken|verify|sign|decode)\b', re.IGNORECASE),
        "oauth": re.compile(r'\b(?:oauth|authorization_code|client_id|client_secret|redirect_uri)\b', re.IGNORECASE),
        "api_key": re.compile(r'\b(?:api[_-]?key|x-api-key|apikey)\b', re.IGNORECASE),
        "session": re.compile(r'\b(?:session|cookie|express-session|connect\.sid)\b', re.IGNORECASE),
        "basic_auth": re.compile(r'\bBasic\s+[A-Za-z0-9+/]{10,}', re.IGNORECASE),
    }
    for auth_type, pattern in auth_indicators.items():
        if pattern.search(content):
            # Cerca il contesto (30 char intorno al match)
            m = pattern.search(content)
            ctx = content[max(0, m.start()-20):m.end()+50].strip().replace("\n", " ")[:100]
            auth_patterns.append({"type": auth_type, "context": ctx})

    # localStorage / sessionStorage usage (XSS target)
    storage_patterns = re.findall(
        r'(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*["\']([^"\']+)["\']',
        content, re.IGNORECASE
    )
    storage_keys = list(set(storage_patterns))[:10]

    return {
        "endpoints": list(endpoints.values())[:80],
        "auth_patterns": auth_patterns[:10],
        "storage_keys": storage_keys,  # chiavi in localStorage — potenziale XSS
    }


def task_secrets(content: str) -> dict:
    """Cerca segreti, credenziali, token ad alta entropia nel contenuto."""
    found = []
    seen_values = set()

    for pattern, secret_type in RE_SECRET_PATTERNS:
        for match in pattern.finditer(content):
            # Alcuni pattern hanno gruppo 1, altri matchano l'intero
            value = match.group(1) if match.lastindex else match.group(0)
            value = value.strip()

            if not value or value in seen_values:
                continue

            # Filtra placeholder e valori non-secret
            if not is_likely_secret(value):
                continue

            seen_values.add(value)

            # Contesto (tronca per non esporre troppo)
            start = max(0, match.start() - 30)
            end = min(len(content), match.end() + 30)
            ctx = content[start:end].replace("\n", " ").strip()

            # Oscura il valore nell'output (mostra solo i primi 4 char + entropy)
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


def task_headers(headers_text: str) -> dict:
    """Analizza header HTTP: tech fingerprinting, security headers mancanti, info leak."""
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

    # Tech fingerprinting
    for header_name, extractor in TECH_HEADER_MAP.items():
        if header_name in present_headers:
            technologies.extend(extractor(present_headers[header_name]))

    # Security header check
    for required_header, risk_note in SECURITY_HEADERS_REQUIRED.items():
        if required_header not in present_headers:
            missing_security.append({
                "header": required_header,
                "risk": risk_note,
            })

    # Information leakage
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

    # CORS check
    if "access-control-allow-origin" in present_headers:
        acao = present_headers["access-control-allow-origin"]
        if acao == "*":
            information_leakage.append({
                "header": "access-control-allow-origin",
                "value": acao,
                "risk": "Wildcard CORS — may allow cross-origin credential access if combined with ACAO credentials header",
            })

    # Cookie flags
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


def task_deps(content: str, filename: str = "") -> dict:
    """Analizza dependency manifest (package.json, requirements.txt, pom.xml, etc.)."""
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

    # pom.xml (Maven) — estrazione semplice
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

    # Cerca dipendenze con naming pattern noto-vulnerabili
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


def task_full_url(url: str, timeout: int = 10) -> dict:
    """
    Fetch leggero di un URL: HEAD per header, GET per contenuto.
    Ritorna header + snippet iniziale del body (no LLM).
    """
    try:
        import requests as req
        headers_sent = {
            "User-Agent": "Mozilla/5.0 (compatible; security-researcher/1.0)",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

        # Prima HEAD per header senza scaricare il body
        head_resp = req.head(url, headers=headers_sent, timeout=timeout,
                             allow_redirects=True, verify=False)
        head_headers = dict(head_resp.headers)

        # GET per il body (solo i primi 100KB)
        get_resp = req.get(url, headers=headers_sent, timeout=timeout,
                           allow_redirects=True, verify=False, stream=True)
        body_bytes = b""
        for chunk in get_resp.iter_content(chunk_size=8192):
            body_bytes += chunk
            if len(body_bytes) >= 100_000:
                break
        body = body_bytes.decode("utf-8", errors="replace")

        return {
            "status_code": get_resp.status_code,
            "final_url": get_resp.url,
            "headers": {k.lower(): v for k, v in head_headers.items()},
            "body_snippet": body[:500],  # Solo i primi 500 char per context
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

    # Tronca il contenuto al limite
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
```

---

### `scripts/lib/parser-bridge.js`

Bridge Node.js → Python parser. Chiama `parser.py` via spawn,
gestisce timeout e fallback, restituisce il risultato parsed.

```javascript
"use strict";

/**
 * parser-bridge.js — Bridge Node.js → Python deterministic parser.
 *
 * Lancia scripts/lib/parser.py via spawn e comunica via JSON su stdin/stdout.
 * Nessuna chiamata LLM — tutto deterministico e veloce.
 *
 * API:
 *   const { parse } = require("./parser-bridge");
 *   const result = await parse("js_endpoints", { content: "..." });
 *   const result = await parse("html_links",   { content: "...", url: "https://..." });
 *   const result = await parse("secrets",      { content: "..." });
 *   const result = await parse("headers",      { content: "Server: nginx\n..." });
 *   const result = await parse("deps",         { content: "...", filename: "package.json" });
 *   const result = await parse("full_url",     { url: "https://target.com" });
 */

const { spawnSync } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");

const PARSER_SCRIPT = path.resolve(__dirname, "parser.py");
const DEFAULT_TIMEOUT_MS = 15_000;

/**
 * Esegui il parser Python per un task specifico.
 *
 * @param {string} task — "html_links" | "js_endpoints" | "secrets" | "headers" | "deps" | "full_url"
 * @param {object} opts — { content?, url?, filename?, max_bytes?, timeoutMs? }
 * @returns {{ results: object, stats: object } | null} — null su errore
 */
function parse(task, opts = {}) {
  if (!fs.existsSync(PARSER_SCRIPT)) {
    return null; // parser.py non trovato — graceful degradation
  }

  const input = JSON.stringify({
    task,
    content:   opts.content   || "",
    url:       opts.url       || "",
    filename:  opts.filename  || "",
    max_bytes: opts.max_bytes || 100_000,
  });

  const result = spawnSync("python3", [PARSER_SCRIPT], {
    input,
    encoding:    "utf8",
    timeout:     opts.timeoutMs || DEFAULT_TIMEOUT_MS,
    windowsHide: true,
    maxBuffer:   10 * 1024 * 1024, // 10MB max output
  });

  if (result.error || result.status !== 0) {
    return null; // Fallback silenzioso
  }

  try {
    const parsed = JSON.parse(result.stdout.trim());
    if (parsed.error) return null;
    return parsed;
  } catch {
    return null;
  }
}

/**
 * Versione batch: esegue più task in parallelo via Promise.allSettled.
 * Ognuno ha il suo processo Python separato (nessuno stato condiviso).
 *
 * @param {Array<{task: string, opts: object}>} tasks
 * @returns {Promise<Array<object|null>>}
 */
async function parseBatch(tasks) {
  return Promise.allSettled(
    tasks.map(({ task, opts }) =>
      new Promise((resolve) => resolve(parse(task, opts)))
    )
  ).then((results) =>
    results.map((r) => (r.status === "fulfilled" ? r.value : null))
  );
}

module.exports = { parse, parseBatch };
```

---

## MODIFICA — `scripts/lib/explorer.js`

Riscrivi completamente il file per usare il parser deterministico.
Il LLM viene chiamato **solo** per classificare i risultati del parser
(non per estrarre dati grezzi).

Sostituisci l'intero contenuto di `scripts/lib/explorer.js` con:

```javascript
"use strict";

/**
 * explorer.js — Surface mapping agent (refactored con parser deterministico).
 *
 * Architettura:
 *   1. Parser deterministico (parser.py via parser-bridge.js)
 *      → estrae link, endpoint, segreti, tech, deps in millisecondi, zero token
 *   2. LLM (opzionale, solo se OPENROUTER_API_KEY presente)
 *      → classifica endpoint "interessanti" da un batch compatto di dati già strutturati
 *      → valuta se un pattern è un segreto reale vs. placeholder (su batch piccolo)
 *
 * Failure contract: ogni errore è isolato. L'Explorer non blocca mai il pipeline.
 */

const fs   = require("node:fs");
const path = require("node:path");
const { spawnSync } = require("node:child_process");
const { parse, parseBatch } = require("./parser-bridge");
const { callLLMJson } = require("./llm");

// ─── Helpers ──────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`  \x1b[2m[explorer] ${msg}\x1b[0m\n`);
}

function findFiles(dir, extensions, maxFiles = 30) {
  if (!dir || !fs.existsSync(dir)) return [];
  try {
    const result = spawnSync(
      "find",
      [dir, "-type", "f",
       "-not", "-path", "*/node_modules/*",
       "-not", "-path", "*/.git/*",
       "-not", "-path", "*/dist/*",
       "-not", "-path", "*/build/*",
       ...extensions.flatMap((e) => ["-o", "-name", `*.${e}`]).slice(1)],
      { encoding: "utf8", timeout: 10_000 }
    );
    return (result.stdout || "").split("\n").filter(Boolean).slice(0, maxFiles);
  } catch {
    return [];
  }
}

function safeReadFile(filePath, maxBytes = 200_000) {
  try {
    const stat = fs.statSync(filePath);
    if (stat.size > maxBytes) {
      const buf = Buffer.alloc(maxBytes);
      const fd = fs.openSync(filePath, "r");
      fs.readSync(fd, buf, 0, maxBytes, 0);
      fs.closeSync(fd);
      return buf.toString("utf8");
    }
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

// ─── Step 1: Parser deterministico ───────────────────────────────────────────

async function runDeterministicParsing(assetContext) {
  const results = {
    endpoints:    [],
    secrets:      [],
    technologies: [],
    deps:         [],
    links:        [],
    auth_patterns:[],
    storage_keys: [],
    missing_security_headers: [],
    information_leakage: [],
  };

  const tasks = [];

  // ── Dependency manifests (qualsiasi asset type) ───────────────────────────
  const depFiles = [
    "package.json", "requirements.txt", "pom.xml",
    "build.gradle", "Gemfile", "composer.json", "go.mod",
  ];
  const targetDir = assetContext.target;

  if (targetDir && fs.existsSync(targetDir)) {
    for (const depFile of depFiles) {
      const fullPath = path.join(targetDir, depFile);
      const content = safeReadFile(fullPath, 100_000);
      if (content) {
        const parsed = parse("deps", { content, filename: depFile });
        if (parsed?.results) {
          results.deps.push(...(parsed.results.flagged_packages || []));
        }
      }
    }
  }

  // ── JS/TS endpoint extraction (whitebox) ─────────────────────────────────
  if (assetContext.mode === "whitebox" && targetDir && fs.existsSync(targetDir)) {
    const jsFiles = findFiles(targetDir, ["js", "ts", "jsx", "tsx", "mjs"], 25);
    for (const jsFile of jsFiles) {
      const content = safeReadFile(jsFile, 150_000);
      if (!content) continue;

      // Endpoint
      const epResult = parse("js_endpoints", { content });
      if (epResult?.results) {
        results.endpoints.push(...(epResult.results.endpoints || []));
        results.auth_patterns.push(...(epResult.results.auth_patterns || []));
        results.storage_keys.push(...(epResult.results.storage_keys || []));
      }

      // Segreti
      const secResult = parse("secrets", { content });
      if (secResult?.results?.secrets?.length > 0) {
        results.secrets.push(
          ...secResult.results.secrets.map((s) => ({ ...s, file: path.relative(targetDir, jsFile) }))
        );
      }
    }

    // PHP, Python, Ruby, Java source
    const sourceFiles = findFiles(targetDir, ["php", "py", "rb", "java", "go"], 20);
    for (const srcFile of sourceFiles) {
      const content = safeReadFile(srcFile, 100_000);
      if (!content) continue;
      const secResult = parse("secrets", { content });
      if (secResult?.results?.secrets?.length > 0) {
        results.secrets.push(
          ...secResult.results.secrets.map((s) => ({ ...s, file: path.relative(targetDir, srcFile) }))
        );
      }
    }

    // HTML files — link e form
    const htmlFiles = findFiles(targetDir, ["html", "htm"], 10);
    for (const htmlFile of htmlFiles) {
      const content = safeReadFile(htmlFile, 200_000);
      if (!content) continue;
      const htmlResult = parse("html_links", { content });
      if (htmlResult?.results) {
        results.links.push(...(htmlResult.results.links || []));
      }
    }
  }

  // ── Blackbox: fetch URL e parsing ────────────────────────────────────────
  const targetUrl = assetContext.target && assetContext.target.startsWith("http")
    ? assetContext.target
    : null;

  if (targetUrl) {
    const fetchResult = parse("full_url", { url: targetUrl });
    if (fetchResult?.results && !fetchResult.results.error) {
      const fr = fetchResult.results;

      // Analizza header
      const headerText = Object.entries(fr.headers || {})
        .map(([k, v]) => `${k}: ${v}`)
        .join("\n");
      const headerResult = parse("headers", { content: headerText });
      if (headerResult?.results) {
        results.technologies.push(...(headerResult.results.technologies || []));
        results.missing_security_headers.push(
          ...(headerResult.results.missing_security_headers || [])
        );
        results.information_leakage.push(
          ...(headerResult.results.information_leakage || [])
        );
      }

      // Analizza il body HTML
      if (fr.body_snippet && fr.content_type?.includes("html")) {
        // Fetch body completo per link extraction
        const htmlResult = parse("html_links", {
          content: fr.body_snippet,
          url: targetUrl,
        });
        if (htmlResult?.results) {
          results.links.push(...(htmlResult.results.links || []).slice(0, 30));
        }
      }

      // Segreti nel body (es. API key esposta nella pagina)
      if (fr.body_snippet) {
        const secResult = parse("secrets", { content: fr.body_snippet });
        if (secResult?.results?.secrets?.length > 0) {
          results.secrets.push(...secResult.results.secrets);
        }
      }
    }
  }

  // Deduplicazione
  results.endpoints = deduplicateBy(results.endpoints, "path");
  results.secrets   = deduplicateBy(results.secrets, "masked_value");
  results.technologies = deduplicateBy(results.technologies, "name");

  return results;
}

function deduplicateBy(arr, key) {
  const seen = new Set();
  return arr.filter((item) => {
    const val = item[key];
    if (seen.has(val)) return false;
    seen.add(val);
    return true;
  });
}

// ─── Step 2: LLM classification (solo su dati già strutturati) ───────────────

/**
 * Chiama il LLM SOLO per classificare endpoint come "interessanti" per la security.
 * Input: lista compatta di path già estratti dal parser (~500 token max).
 * Output: subset degli endpoint con note di security.
 */
async function classifyEndpointsWithLLM(endpoints) {
  if (!endpoints || endpoints.length === 0) return [];
  if (!process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY_1) {
    return endpoints.slice(0, 10); // Senza LLM, restituisce i primi 10
  }

  // Batch compatto — solo path e method, max 40 endpoint
  const batch = endpoints.slice(0, 40).map((ep) => ({
    path:   ep.path,
    method: ep.method || "unknown",
  }));

  const prompt = `You are a security researcher. Given these API endpoints extracted from a web application,
identify which ones are most interesting for security testing (auth bypass, IDOR, injection, sensitive data).

Endpoints:
${JSON.stringify(batch, null, 2)}

Respond with JSON only:
{
  "interesting": [
    { "path": "/api/...", "reason": "one sentence", "vuln_class": "IDOR|injection|auth|info_disclosure|other" }
  ]
}

Include at most 15 endpoints. Only include genuinely interesting ones, not static assets or public pages.`;

  try {
    const result = await callLLMJson(prompt, { timeoutMs: 30_000 });
    return result?.interesting || [];
  } catch {
    return [];
  }
}

// ─── Formatter output ─────────────────────────────────────────────────────────

function formatExplorerContextForPrompt(parsed, classified) {
  const parts = [];

  if (parsed.secrets?.length > 0) {
    parts.push("⚠️  SECRETS / CREDENTIALS DETECTED:");
    for (const s of parsed.secrets.slice(0, 10)) {
      parts.push(`  • [${s.type}] entropy=${s.entropy} len=${s.length}${s.file ? ` in ${s.file}` : ""}`);
      parts.push(`    Context: ${s.context}`);
    }
  }

  if (classified?.length > 0) {
    parts.push("\nINTERESTING API ENDPOINTS (classified):");
    for (const ep of classified) {
      parts.push(`  • ${ep.path} [${ep.vuln_class}] — ${ep.reason}`);
    }
  } else if (parsed.endpoints?.length > 0) {
    parts.push(`\nAPI ENDPOINTS (${parsed.endpoints.length} found, top 15):`);
    for (const ep of parsed.endpoints.slice(0, 15)) {
      parts.push(`  • ${ep.method || "?"} ${ep.path} [${ep.source}]`);
    }
  }

  if (parsed.auth_patterns?.length > 0) {
    parts.push("\nAUTH PATTERNS:");
    for (const ap of parsed.auth_patterns.slice(0, 5)) {
      parts.push(`  • ${ap.type}: ${ap.context}`);
    }
  }

  if (parsed.storage_keys?.length > 0) {
    parts.push(`\nlocalStorage/sessionStorage KEYS (XSS targets): ${parsed.storage_keys.join(", ")}`);
  }

  if (parsed.technologies?.length > 0) {
    parts.push(`\nDETECTED STACK: ${parsed.technologies.map((t) => t.name).join(", ")}`);
  }

  if (parsed.missing_security_headers?.length > 0) {
    parts.push(`\nMISSING SECURITY HEADERS: ${parsed.missing_security_headers.map((h) => h.header).join(", ")}`);
  }

  if (parsed.information_leakage?.length > 0) {
    parts.push("\nINFORMATION LEAKAGE:");
    for (const leak of parsed.information_leakage.slice(0, 5)) {
      parts.push(`  • ${leak.header}: ${leak.risk}`);
    }
  }

  if (parsed.deps?.length > 0) {
    parts.push("\nFLAGGED DEPENDENCIES:");
    for (const dep of parsed.deps.slice(0, 8)) {
      parts.push(`  • ${dep.package}@${dep.version} — ${dep.flag}`);
    }
  }

  if (parsed.links?.length > 0) {
    const interesting = parsed.links.filter((l) =>
      /admin|api|internal|debug|config|login|auth|upload|download/.test(l.url)
    );
    if (interesting.length > 0) {
      parts.push(`\nINTERESTING LINKS (${interesting.length}):`);
      for (const l of interesting.slice(0, 10)) {
        parts.push(`  • [${l.tag}] ${l.url}`);
      }
    }
  }

  if (parts.length === 0) return "";

  return `\n\nEXPLORER AGENT PRE-ANALYSIS (deterministic parser)\n${"─".repeat(50)}\n${parts.join("\n")}\n${"─".repeat(50)}\nUse the above to prioritize your analysis. Do not re-verify what Explorer already confirmed.\n`;
}

// ─── Entry point ──────────────────────────────────────────────────────────────

async function runExplorer(assetContext, projectRoot) {
  log("starting deterministic surface analysis...");
  const t0 = Date.now();

  let parsed = {};
  let classified = [];

  try {
    parsed = await runDeterministicParsing(assetContext);
    const elapsed1 = Date.now() - t0;
    log(`parser done in ${elapsed1}ms — endpoints:${parsed.endpoints?.length || 0} secrets:${parsed.secrets?.length || 0} tech:${parsed.technologies?.length || 0}`);
  } catch (e) {
    log(`parser error: ${e.message}`);
    return "";
  }

  // LLM classification solo se ci sono endpoint e OpenRouter è configurato
  if ((parsed.endpoints?.length || 0) > 5 &&
      (process.env.OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY_1)) {
    try {
      classified = await classifyEndpointsWithLLM(parsed.endpoints);
      const elapsed2 = Date.now() - t0;
      log(`LLM classification done in ${elapsed2}ms — ${classified.length} interesting endpoints`);
    } catch (e) {
      log(`LLM classification skipped: ${e.message}`);
    }
  }

  const hint = formatExplorerContextForPrompt(parsed, classified);
  const elapsed = Date.now() - t0;
  log(`total elapsed: ${elapsed}ms`);

  return hint;
}

module.exports = { runExplorer };
```

---

## VERIFICA FINALE

```bash
# Syntax check
node --check scripts/lib/parser-bridge.js && echo "parser-bridge OK"
node --check scripts/lib/explorer.js      && echo "explorer OK"
python3 -c "import ast; ast.parse(open('scripts/lib/parser.py').read()); print('parser.py syntax OK')"

# Test parser diretto
echo '{"task":"headers","content":"Server: nginx/1.18\nX-Powered-By: PHP/7.4\n"}' \
  | python3 scripts/lib/parser.py | python3 -m json.tool

echo '{"task":"secrets","content":"const apiKey = \"FAKE_STRIPE_KEY_FOR_TESTING_ONLY_NOT_REAL\";"}' \
  | python3 scripts/lib/parser.py | python3 -m json.tool

echo '{"task":"js_endpoints","content":"fetch(\"/api/v1/users\"); axios.post(\"/api/auth/login\");"}' \
  | python3 scripts/lib/parser.py | python3 -m json.tool

echo '{"task":"deps","content":"{\"dependencies\":{\"lodash\":\"4.17.15\",\"express\":\"4.18.0\"}}","filename":"package.json"}' \
  | python3 scripts/lib/parser.py | python3 -m json.tool

# Test bridge Node.js
node -e "
  const { parse } = require('./scripts/lib/parser-bridge');
  const r = parse('headers', { content: 'Server: Apache/2.4\nX-Frame-Options: DENY\n' });
  console.log('Bridge test:', JSON.stringify(r?.results?.technologies, null, 2));
"

# Test Explorer completo
node -e "
  const { runExplorer } = require('./scripts/lib/explorer');
  runExplorer({ asset: 'webapp', mode: 'blackbox', target: 'https://example.com' }, '.')
    .then((hint) => console.log('Explorer hint length:', hint.length))
    .catch(console.error);
"
```

Nessun file esistente deve essere stato modificato tranne `scripts/lib/explorer.js`.
I file creati sono:
- `scripts/lib/parser.py` (nuovo)
- `scripts/lib/parser-bridge.js` (nuovo)
