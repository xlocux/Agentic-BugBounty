# TRIAGER CALIBRATION — Race Conditions

VALID if:
- Success rate demonstrates the race: N/M concurrent requests succeeded where expected ≤1
- Application state confirms: balance negative, coupon applied multiple times, duplicate order

NOT VALID:
- "This endpoint might be vulnerable to race conditions" without demonstrated outcome
- Single successful duplicate in isolation without statistical evidence

SEVERITY:
  Financial impact (double spend, negative balance) = Critical/High
  Coupon/promo multi-use = Medium/High
  Rate limit bypass for brute force = Medium
  Non-financial limit bypass = Low/Medium
