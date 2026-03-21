# VULN MODULE — Business Logic Flaws
# Asset: webapp
# CWE-840 | Report prefix: WEB-BIZ

## THREAT MODEL

Business logic flaws are not detectable by scanners — they require understanding
the application's intended workflow and finding ways to subvert it.
They exploit the gap between how developers assumed the app would be used
and how it can actually be used.

## VULNERABILITY CLASSES

1. Workflow bypass (skip steps in a multi-step process)
2. Negative value manipulation (negative prices, quantities)
3. Limit bypass (apply same discount multiple times, bypass purchase limits)
4. State manipulation (modify hidden fields, replay old state)
5. Price tampering (change price in client-side parameters)
6. Coupon/promo stacking (combine non-stackable discounts)
7. Refund abuse (refund without returning item, partial refund loops)
8. Account enumeration via non-auth features
9. Free trial abuse (re-register, different payment method bypass)
10. Order of operations abuse (pay less by manipulating timing)

## WHITEBOX PATTERNS

```bash
# State machine gaps — steps that can be skipped
grep -rn "step\|stage\|state\|phase\|wizard" \
  --include="*.php" --include="*.py" --include="*.js" -i

# Price/amount handling
grep -rn "price\|amount\|total\|discount\|quantity" \
  --include="*.php" --include="*.py" -i | \
  grep "\$_\(GET\|POST\|REQUEST\)\|request\.\|params\["
# User-controlled price = critical business logic flaw

# Validation only on frontend
grep -rn "min.*=.*0\|min.*=.*1\|max.*=" --include="*.html" --include="*.js"
# HTML-only validation: min/max on input fields — no server-side check

# Integer overflow in monetary calculations
grep -rn "int(\|Integer\.parseInt\|parseInt(" --include="*.py" --include="*.java" \
  --include="*.js" | grep -i "amount\|price\|quantity"
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
