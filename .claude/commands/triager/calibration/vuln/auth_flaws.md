# TRIAGER CALIBRATION — Authentication Flaws

Username enumeration:
  VALID if: different response (time, message, status) for valid vs invalid users
  Informative if: only via registration endpoint with no login path

Brute force / no rate limiting:
  VALID if: demonstrate successful credential stuffing with actual account access
  Informative alone if: just "no rate limit" without successful login

Default credentials:
  VALID if: credential pair actually grants access (show authenticated response)

Password reset:
  Host header injection: VALID if reset URL contains attacker domain (check email)
  Token reuse: VALID if same token works twice
  Token predictability: VALID if token pattern allows predicting other tokens

2FA bypass:
  Direct step skip: VALID if authenticated dashboard accessed without 2FA step
  Code brute force: VALID only if demonstrated successful (not just "no lockout")

SEVERITY:
  Account takeover = Critical
  Auth bypass (any user) = High
  Username enumeration alone = Low
  No rate limit on login without ATO demo = Informative/Low
