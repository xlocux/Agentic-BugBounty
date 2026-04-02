# CHAIN COORDINATOR — Stage 2.5
# Runs after all 6 specialist agents have completed their shards.
# Input:  findings/confirmed/report_bundle.json  (confirmed findings)
#         findings/unconfirmed/candidates.json    (needs_evidence + chain_candidates)
# Output: findings/confirmed/report_bundle.json  (augmented with chain findings)
#         findings/unconfirmed/candidates.json    (chain_id updated on members)

---

## OBJECTIVE

Your job is one thing: find multi-step vulnerability chains across the 6 specialist
agent reports, assign Chain IDs, and add them as first-class findings.

You do NOT re-analyze individual vulnerabilities. You do NOT run new grep patterns.
You reason across what the specialist agents already found.

---

## STEP 1 — Load Input Artifacts

```bash
cat [findings_dir]/confirmed/report_bundle.json
cat [findings_dir]/unconfirmed/candidates.json
```

Also read any shard files that exist (for chain_candidate state entries):
```bash
ls [findings_dir]/candidates_pool_*.json 2>/dev/null && \
  for f in [findings_dir]/candidates_pool_*.json; do cat "$f"; done
```

Build a working list of ALL candidates across all states:
  - `confirmed`         from report_bundle.json findings
  - `chain_candidate`   from candidates.json (these require an upstream link)
  - `needs_evidence`    from candidates.json (may complete a chain even without full confirmation)

---

## STEP 2 — Identify Chain Candidates

A chain exists when two or more findings combine to produce an impact greater than
either finding alone.

**Mandatory search:** For every `chain_candidate` entry, you MUST actively search the
confirmed and needs_evidence lists for the upstream link it requires.

**Proactive search:** For every confirmed finding, check the Chain Reference Library
below to identify what follow-on capabilities it enables.

Priority order (highest chain value first):
  1. chain_candidate entries — these explicitly require a chain link
  2. confirmed findings of type: SSRF, XSS-stored, auth_bypass, JWT, open_redirect,
     prototype_pollution, file_upload, SQLi, IDOR, mass_assignment
  3. needs_evidence entries that, when chained, yield a confirmed impact

---

## STEP 3 — Chain Reference Library

For each first-link type, actively search for these continuations in the candidate pool:

```
OPEN REDIRECT
  → OAuth token theft: search for OAuth candidates where redirect_uri is attacker-controlled
  → Phishing with trusted domain: any XSS or credential-harvest candidate

SSRF
  → Cloud metadata (AWS/GCP/Azure): any cloud_misconfig or credential exposure candidate
  → Internal Redis: any NoSQLi or session-related candidate on internal hosts
  → Internal admin panel: any access_control candidate restricted to internal network
  → DNS rebinding: any dns_rebinding candidate that unlocks the SSRF scope

XXE
  → SSRF via external entity: search for any URL-fetch or outbound-request candidate
  → LFI: search for path traversal or file read candidates
  → Internal port scan: any SSRF or network scan candidate

STORED XSS
  → CSRF admin action: search for CSRF candidates on admin-only endpoints
  → Session hijack: any session fixation or cookie theft candidate
  → CSP bypass via JSONP/script gadget: any open_redirect or JSONP endpoint candidate

DOM XSS / postMessage
  → Account takeover: any finding where the page has access to auth tokens
  → CSRF bypass: any CSRF candidate where a trusted postMessage origin is involved

IDOR
  → Admin object access: any access_control finding on privileged resources
  → Account takeover: any credential or token accessible via IDOR
  → Mass exfil: any IDOR on an enumerable ID range

AUTH BYPASS / JWT WEAK SECRET
  → Admin function access: any admin-only endpoint (RCE, data exfil, config change)
  → Impersonate arbitrary user: combine with any user-scoped finding for escalated impact

MASS ASSIGNMENT
  → Role elevation: any finding where isAdmin / role field is writable
  → Email/password override: any account update endpoint with insufficient field filtering

PROTOTYPE POLLUTION (server-side)
  → RCE via template engine: search for Handlebars/Pug/EJS template rendering candidates
  → Auth bypass: any auth check that reads from prototype (__proto__.isAdmin)
  → DOM XSS: if polluted value reaches client-side rendering

FILE UPLOAD BYPASS
  → Web shell → RCE: any candidate where uploaded file is served + executed
  → Path traversal via filename: any path traversal candidate in upload handler
  → XXE via SVG/Office: any XXE candidate triggered from file parsing
  → ImageMagick (SVG text://): any image processing candidate using ImageMagick
  → ImageMagick (EPSI/EPT): GhostScript RCE via magic bytes — check image processor
  → FFmpeg M3U8: any video processing candidate using FFmpeg
  → LibreOffice external ref: any document conversion candidate using LibreOffice

SSTI
  → RCE: almost always chains to RCE — confirm template engine and gadget path

SQLI
  → Credential dump → auth bypass: any authentication candidate using the same DB
  → File write (INTO OUTFILE) → RCE: any file write or webroot path candidate
  → Blind → sensitive data exfil: any candidate involving PII or credentials in DB

PATH TRAVERSAL / LFI
  → Source code read → secrets: search for any secret_scan candidate in same codebase
  → Config file → DB credentials → SQLi/auth bypass: combine with any DB candidate
  → Log poisoning → RCE: if log file is included via LFI, search for log injection candidate

RACE CONDITION
  → Double spend / duplicate coupon: any business logic candidate on the same resource
  → Privilege escalation: any role assignment or permission grant candidate (non-atomic check)
  → Token reuse: any one-time token (email verify, password reset) candidate

HTTP REQUEST SMUGGLING
  → Cache poisoning → Stored XSS: any cache or CDN candidate
  → Auth middleware bypass: any auth candidate where prefix injection skips auth check
  → Session hijack: any session candidate where smuggled prefix reads victim's request

WEB CACHE POISONING
  → Stored XSS at CDN scale: any XSS candidate delivered via cached response
  → Credential theft: any sensitive data in cached response

INFO DISCLOSURE (stack trace, debug endpoint, source map)
  → Path traversal: internal path leaked → use in traversal candidate
  → DB credentials: DB type/version + SQLi candidate for payload tuning
  → Swagger/OpenAPI: hidden endpoints → new attack surface (cross-reference with surface map)

OAUTH STATE MISSING / WEAK
  → CSRF → account linking: CSRF + OAuth callback candidate for account takeover

SAML BYPASS
  → Auth as arbitrary user: combine with any admin-only endpoint for full privilege

INSECURE DESERIALIZATION
  → RCE via gadget chain: any Java/PHP/Python deserialization candidate with known gadget
  → Privilege escalation: deserialized object with elevated role field

BROKEN LINK HIJACKING
  → Persistent XSS: expired external script + domain registration → malicious JS
  → OAuth/SSO provider link expired: intercept auth flow → mass account takeover

SECOND-ORDER INJECTION
  → Elevated execution: payload stored benign, executed later in admin/reporting context
  → Applies to: SQLi, XSS, SSTI, LDAP in any stored field

2FA/MFA BYPASS
  → Account takeover via OTP reuse: check if OTP is single-use at code level
  → Brute force: rate limit check on OTP endpoint

API VERSIONING
  → /api/v1/admin accessible while /api/v2/admin is protected → full admin access

HPP (HTTP Parameter Pollution)
  → WAF/filter bypass: first link bypasses security filter, second link exploits underlying vuln
  → Business logic: combined with price/quantity/flag tampering candidate

PROTOTYPE POLLUTION (client-side)
  → XSS via polluted innerHTML: combine with any DOM XSS candidate
  → Auth bypass: isAdmin/role check on prototype

CSS INJECTION / FONTLEAK (css_font_exfiltration)
  → Auth token exfiltration: if the page renders auth tokens/cookies in DOM text adjacent
    to attacker-controlled HTML (chat, comment, bio field), FontLeak can exfiltrate them
    using only CSS — no JS required. Chain severity = severity of the stolen credential.
  → PII leak at scale: stored CSS injection in a field visible to many users → mass exfil
    of all rendered personal data (names, emails, session IDs) for every page load
  → Session takeover: exfiltrated session token → replay attack → full account takeover
  Linkage condition: requires (a) stored/reflected CSS injection candidate AND (b) sensitive
  data rendered in the same DOM context. Confirm CSP allows font loading (data: or external).
```

---

## STEP 4 — Chain Assembly Rules

A chain is valid if ALL of the following are true:

1. **Linkage is explicit** — you can name the exact HTTP request or code path that
   connects the first finding to the second. "SSRF → metadata" requires you to have
   identified an SSRF candidate pointing at a metadata URL or reachable by it.
   Do not chain on general capability ("SSRF could hit Redis") — cite the actual candidate.

2. **Attacker can initiate the full chain** — the first step must be attacker-reachable
   (passes skepticism gate CHECK 2). If step 2 requires a privileged account, step 1
   must produce that account access.

3. **Chain severity ≥ max(individual severities)** — a chain that combines two mediums
   into a critical is valid. A chain that combines two criticals into another critical is
   still a chain finding (it documents the amplified impact path).

4. **No hypothetical links** — every link must correspond to an actual candidate in the pool.
   If the second link is "in theory, an attacker could..." → not a valid chain.

---

## STEP 5 — Chain ID Assignment

For each valid chain:

1. Assign: `CHAIN-01`, `CHAIN-02`, ... (sequential, sorted by chain severity desc)
2. Update every involved finding's `chain_id` field to the assigned Chain ID
3. Create a new chain finding entry (see schema below)

---

## STEP 6 — Write Output

### 6.1 Update report_bundle.json

For each chain identified:
  - Add a new finding to `findings[]` in `report_bundle.json`
  - The chain finding uses the Chain Finding Schema below
  - Also update `chain_id` on all existing findings that are part of this chain

For existing confirmed findings that are now part of a chain:
  - Set `chain_id: "CHAIN-NN"` in the finding JSON

### Chain Finding Schema

```json
{
  "report_id":            "WEB-NNN",
  "title":                "Chain CHAIN-NN: [First link] → [Final impact]",
  "vulnerability_class":  "vulnerability_chain",
  "severity":             "critical|high",
  "chain_id":             "CHAIN-NN",
  "chain_members": [
    {
      "step":       1,
      "report_id":  "[existing finding ID or candidate ID]",
      "agent":      "auth|inject|client|access|media|infra|git_intel",
      "vuln_class": "...",
      "title":      "...",
      "link_to_next": "how this step enables the next step — specific HTTP path or code reference"
    }
  ],
  "chain_narrative": "One paragraph: attacker starts at step 1, does X, which gives capability Y, then uses Y to reach Z, resulting in [final impact].",
  "final_impact":    "RCE|account_takeover|data_exfil|privilege_escalation|...",
  "cvss_vector":     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "poc": {
    "type":           "multi_step",
    "steps":          ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
    "preconditions":  ["..."],
    "expected_result": "..."
  },
  "affected_component": "[primary component of first link]",
  "source_model":       "chain-coordinator"
}
```

### 6.2 Update candidates.json

For any `chain_candidate` or `needs_evidence` entry that is now part of a chain:
  - Set `chain_id: "CHAIN-NN"`
  - Keep existing state (do not promote to confirmed — the chain finding is the confirmed entry)

### 6.3 Print summary

```
═══════════════════════════════════════════════════════
 CHAIN COORDINATOR — Stage 2.5 COMPLETE
═══════════════════════════════════════════════════════
 Target: [target]

 Candidates analyzed:      [N] confirmed + [M] chain_candidate + [K] needs_evidence
 Chains identified:        [J]
   [CHAIN-01] [severity]  [title]   (N steps)
   [CHAIN-02] [severity]  [title]   (N steps)
   ...

 Chain findings added to report_bundle.json: [J]
 Existing findings updated with chain_id:    [X]

 No chains found for: [list first-link types with no valid continuation]
═══════════════════════════════════════════════════════
```

---

## STEP 7 — Validate Output

```bash
node scripts/validate-bundle.js [findings_dir]/confirmed/report_bundle.json
```

If validation fails, fix the chain findings to conform to the schema before finishing.
