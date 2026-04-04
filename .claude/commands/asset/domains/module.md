# ASSET MODULE — Domains & Infrastructure Reconnaissance
# Covers: subdomain enumeration, DNS misconfiguration, cloud asset discovery,
#         certificate transparency, takeover, dangling records, exposed services
# Report ID prefix: DOM
# Note: "domains" is the --asset flag; always blackbox (no source applicable)

## THREAT MODEL

The domain/infrastructure surface is the outermost layer of a target's attack surface.
Misconfigurations here expose internal services, enable account takeover via DNS,
leak internal topology, and create pivot points before touching any application layer.

Primary attack classes:
  - Subdomain takeover: dangling CNAME/A records pointing to deprovisioned cloud resources
  - DNS zone misconfiguration: AXFR, wildcard, dangling NS delegation
  - Cloud asset exposure: public S3/GCS/Azure Blob, open Elasticsearch, exposed APIs
  - Forgotten/shadow assets: dev, staging, internal subdomains exposed to internet
  - Certificate transparency leaks: internal hostnames disclosed in CT logs
  - Email security gaps: missing/weak SPF, DKIM, DMARC enabling spoofing
  - Service fingerprinting: version disclosure, admin panels, default credentials
  - Virtual host confusion: Host header attacks on shared-IP infrastructure

The researcher's job at this layer is to **enumerate first, attack second**.
Every subdomain is a potential pivot. Every dangling record is a potential takeover.
Every open port on a discovered IP is a potential entry point for a deeper assessment.

## VULNERABILITY CLASSES (priority order)

1.  Subdomain Takeover               CWE-923  — dangling CNAME/A to deprovisioned cloud resource
2.  DNS Zone Transfer (AXFR)         CWE-200  — full zone data exposed via misconfigured NS
3.  Cloud Storage Exposure           CWE-284  — public S3/GCS/Azure Blob with sensitive data
4.  Exposed Admin / Internal Panel   CWE-284  — admin interfaces reachable from internet
5.  Email Spoofing (SPF/DKIM/DMARC)  CWE-290  — domain spoofable for phishing
6.  Dangling NS Delegation           CWE-923  — NS record points to unregistered domain → full zone control
7.  Open Redirect via CNAME          CWE-601  — CNAME chain exploitable for redirect
8.  Sensitive Subdomain Exposure     CWE-200  — dev/staging/internal exposed without auth
9.  Virtual Host Injection           CWE-116  — Host header manipulation on shared infrastructure
10. Default Credentials on Services  CWE-1392 — exposed services with vendor defaults

## RECONNAISSANCE PHASES

### Phase 0 — Scope Definition

Before any enumeration, read:
  - targets/<name>/intelligence/h1_scope_snapshot.json
  - targets/<name>/target.json

Extract:
  - In-scope root domains (e.g. example.com, *.example.com)
  - Explicitly out-of-scope domains
  - Asset types allowed (web, API, cloud)

**Never probe out-of-scope domains.** Build an explicit allowlist before starting.

---

### Phase 1 — Passive Subdomain Enumeration

Goal: enumerate subdomains without sending any packets to target infrastructure.

```bash
# Certificate Transparency (highest yield, zero noise)
curl -s "https://crt.sh/?q=%.TARGET.com&output=json" | \
  jq -r '.[].name_value' | sort -u | grep -v '^\*' > ct_subdomains.txt

# Alternative: subfinder passive sources
subfinder -d TARGET.com -silent -o subfinder_passive.txt

# Amass passive mode (DNS datasets, certificates, APIs)
amass enum -passive -d TARGET.com -o amass_passive.txt

# Merge and deduplicate
cat ct_subdomains.txt subfinder_passive.txt amass_passive.txt 2>/dev/null | \
  sort -u > all_passive.txt
wc -l all_passive.txt
```

---

### Phase 2 — Active DNS Enumeration

```bash
# DNS brute force with wordlist
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -u "https://FUZZ.TARGET.com" -H "Host: FUZZ.TARGET.com" \
  -mc 200,301,302,403 -t 50 -o ffuf_dns.json 2>/dev/null || \
gobuster dns -d TARGET.com \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt \
  -t 50 -o gobuster_dns.txt

# DNS zone transfer attempt (AXFR)
dig axfr TARGET.com @ns1.TARGET.com
dig axfr TARGET.com @ns2.TARGET.com
# If AXFR succeeds → Critical finding, dump full output

# Wildcard detection
dig A "$(openssl rand -hex 8).TARGET.com" +short
# If returns IP → wildcard DNS configured, filter results accordingly

# Merge active results
cat gobuster_dns.txt ffuf_dns.json 2>/dev/null >> all_active.txt
```

---

### Phase 3 — DNS Record Analysis

For every discovered subdomain, resolve and classify:

```bash
# Resolve all subdomains
cat all_passive.txt all_active.txt 2>/dev/null | sort -u > all_subdomains.txt

# Mass resolve
cat all_subdomains.txt | while read sub; do
  ip=$(dig +short A "$sub" | tail -1)
  cname=$(dig +short CNAME "$sub" | tail -1)
  echo "$sub | A: $ip | CNAME: $cname"
done > resolved.txt

# Find CNAMEs pointing to cloud providers
grep -E "\.amazonaws\.com|\.azurewebsites\.net|\.cloudapp\.azure\.com|\.github\.io|\
\.herokuapp\.com|\.netlify\.app|\.vercel\.app|\.pages\.dev|\.fastly\.net|\
\.wpengine\.com|\.ghost\.io|\.webflow\.io|\.surge\.sh" resolved.txt > cloud_cnames.txt

# Find unresolved A records (potential dangling)
grep "A: $" resolved.txt | grep -v "CNAME:" > unresolved.txt

echo "=== Cloud CNAMEs found ===" && wc -l cloud_cnames.txt
echo "=== Unresolved (potential dangling) ===" && wc -l unresolved.txt
```

---

### Phase 4 — Subdomain Takeover Detection

For each CNAME in cloud_cnames.txt, check if the target resource exists:

```bash
# Automated takeover check
nuclei -l all_subdomains.txt \
  -t /usr/share/nuclei-templates/takeovers/ \
  -o nuclei_takeovers.txt -silent

# Manual verification matrix by service:
# GitHub Pages: 404 "There isn't a GitHub Pages site here"
# AWS S3:       NoSuchBucket or 403 on bucket + bucket name = subdomain
# Heroku:       "No such app" response
# Netlify:      "Not Found" on *.netlify.app CNAME
# Azure:        NXDOMAIN or "Web App - Unavailable"
# Fastly:       "Fastly error: unknown domain"
# Ghost.io:     "Failed to load resource" for ghost.io CNAME
# Surge.sh:     "project not found"
# Vercel:       "The deployment could not be found"

# For each flagged subdomain, verify:
# 1. CNAME resolves to cloud provider namespace
# 2. HTTP response matches known "unclaimed" fingerprint
# 3. Attempt to claim the resource (document only, do NOT actually claim without auth)
```

**Confirmation requirement:** A subdomain takeover is only confirmed when:
- The CNAME target resolves to a provider that allows claiming
- The HTTP response matches the provider's "unclaimed" fingerprint
- You have documented the CNAME chain (subdomain → provider → unregistered resource)

---

### Phase 5 — Cloud Storage Enumeration

```bash
# S3 bucket discovery from subdomains
cat all_subdomains.txt | while read sub; do
  # Check if subdomain maps to S3
  curl -s -o /dev/null -w "%{http_code}" "http://$sub.s3.amazonaws.com/" | \
    grep -E "200|403" && echo "S3 found: $sub"
done

# Nuclei cloud misconfig templates
nuclei -l all_subdomains.txt \
  -t /usr/share/nuclei-templates/cloud/ \
  -t /usr/share/nuclei-templates/exposed-panels/ \
  -o nuclei_cloud.txt -silent

# Check for open S3 (list permission)
aws s3 ls s3://TARGET-BUCKET --no-sign-request 2>/dev/null && echo "OPEN BUCKET"

# Google Cloud Storage
curl -s "https://storage.googleapis.com/TARGET-BUCKET/" | grep -i "listbucketresult"
```

---

### Phase 6 — Email Security Analysis

```bash
# SPF record
dig TXT TARGET.com | grep "v=spf"
# WEAK: includes +all or ~all without hard fail (-all)
# MISSING: no SPF record → domain spoofable

# DMARC record
dig TXT _dmarc.TARGET.com | grep "v=DMARC"
# WEAK: p=none (monitor only, no enforcement)
# MISSING: no DMARC → spoofing possible

# DKIM (check common selectors)
for sel in default google mail k1 dkim smtp; do
  result=$(dig TXT "${sel}._domainkey.TARGET.com" +short 2>/dev/null)
  [ -n "$result" ] && echo "DKIM selector found: $sel"
done

# MX records
dig MX TARGET.com

# SPF spoofing test — ONLY in authorized scope:
# swaks --to victim@example.com --from admin@TARGET.com \
#   --server mx1.TARGET.com --header "Subject: SPF test"
```

**Severity matrix:**
- No SPF + no DMARC: High (domain fully spoofable)
- SPF exists but DMARC p=none: Medium (spoofing possible, not blocked)
- DMARC p=quarantine/reject: Low (mitigated, but document for completeness)

---

### Phase 7 — Live Service Fingerprinting

```bash
# HTTP probe all resolved subdomains
cat resolved.txt | awk -F'|' '{print $1}' | while read sub; do
  status=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "https://$sub" 2>/dev/null)
  [ "$status" != "000" ] && echo "$status $sub"
done | sort > http_status.txt

# WhatWeb fingerprint on live hosts
cat http_status.txt | awk '{print $2}' | head -50 | \
  whatweb --input-file=- --log-brief=whatweb.txt 2>/dev/null

# Nuclei broad scan on live hosts
cat http_status.txt | awk '{print $2}' > live_hosts.txt
nuclei -l live_hosts.txt \
  -t /usr/share/nuclei-templates/exposures/ \
  -t /usr/share/nuclei-templates/default-logins/ \
  -t /usr/share/nuclei-templates/vulnerabilities/ \
  -severity medium,high,critical \
  -o nuclei_services.txt -silent

# Port scan top services on resolved IPs
cat resolved.txt | awk -F'A: ' '{print $2}' | awk '{print $1}' | \
  grep -E '^[0-9]+\.' | sort -u > ips.txt
nmap -iL ips.txt --top-ports 100 -T4 --open -oN nmap_services.txt 2>/dev/null
```

---

### Phase 8 — Dangling NS Delegation

```bash
# Find delegated nameservers for subdomains
cat all_subdomains.txt | while read sub; do
  ns=$(dig NS "$sub" +short 2>/dev/null)
  if [ -n "$ns" ]; then
    # Check if NS domain is still registered
    echo "$sub NS: $ns"
    whois "$ns" 2>/dev/null | grep -i "no match\|not found\|free\|available" && \
      echo "⚠️  DANGLING NS: $ns may be unregistered"
  fi
done > ns_delegation.txt
```

A dangling NS means an attacker can register the NS domain and take over the entire
subdomain zone — **Critical severity**.

---

### Phase 9 — Virtual Host Discovery

```bash
# Collect unique IPs from resolved subdomains
cat ips.txt | sort -u | while read ip; do
  # Try to discover vhosts behind this IP
  ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
    -u "https://$ip/" \
    -H "Host: FUZZ.TARGET.com" \
    -mc 200,301,302,403 \
    -fs 0 \
    -t 30 -o "vhost_${ip}.json" 2>/dev/null
done
```

---

## CONFIRMATION REQUIREMENTS

Every finding must be confirmed before entering REPORT_BUNDLE:

| Finding | Confirmation method |
|---|---|
| Subdomain takeover | HTTP response matches unclaimed fingerprint + CNAME chain documented |
| DNS AXFR | Full zone dump saved as artifact |
| Open cloud storage | `aws s3 ls` or curl shows listing or sensitive files |
| Email spoofing | SPF/DMARC records documented, tool output attached |
| Dangling NS | whois confirms NS domain unregistered |
| Exposed admin panel | Screenshot + response body + no auth required confirmed |
| Default credentials | Successful login documented (do NOT change state) |

---

## COMPLETE VULN MODULE INDEX

| Module file | --vuln flag | Auto-load trigger |
|---|---|---|
| vuln/takeover.md | takeover | cloud CNAME found in Phase 3 |
| vuln/email_spoofing.md | email | missing SPF or DMARC in Phase 6 |
| vuln/cloud_storage.md | cloudstorage | S3/GCS/Azure CNAME found |
| vuln/axfr.md | axfr | NS servers discovered |

---

## KEY DISTINCTIONS

- **Subdomain takeover vs redirect:** A redirect to a provider's default page is NOT a
  takeover unless you can claim the resource. Document the CNAME chain precisely.

- **SPF softfail (~all) vs hardfail (-all):** ~all means spoofed mail goes to spam,
  not blocked. Still a finding if DMARC p=none allows delivery. Severity: Medium.

- **Cloud bucket 403 vs 200:** A 403 on a bucket means it exists but is private.
  A 200 with ListBucketResult means open listing. Only 200 listing is a finding.
  A 403 with readable error disclosing bucket name may be Informative.

- **Out-of-scope subdomain found:** Document it. Do not probe it. Flag for researcher note.

- **Internal hostname in CT logs:** Informative unless the host is live and externally
  reachable — then escalate to the appropriate vuln class.

---

## TOOLS SUMMARY

| Tool | Purpose |
|---|---|
| subfinder | Passive subdomain enumeration (CT, DNS datasets) |
| amass | Comprehensive passive + active enum |
| crt.sh | Certificate transparency subdomain discovery |
| nuclei | Automated takeover, cloud, exposure detection |
| ffuf / gobuster | DNS brute force, vhost discovery |
| whatweb | HTTP service fingerprinting |
| nmap | Port scan on discovered IPs |
| dig / host | DNS record queries (AXFR, MX, TXT, NS) |
| aws cli | S3 bucket access verification |
| whois | NS domain registration check |
