# TRIAGER CALIBRATION — Business Logic

VALID if:
- Concrete financial or privilege impact demonstrated
- Workflow bypass reaches a state the app explicitly prevents

NOT VALID:
- "Users could theoretically abuse this" without a specific demonstrated path
- Price manipulation where server re-validates from DB (client-side only = not valid)
- Negative quantity that returns error (server already validates)

SEVERITY:
  Financial loss for company or user = Critical/High
  Free premium features = Medium
  Workflow step skip without financial impact = Low/Medium

OVERCLAIM WATCH:
"This allows unlimited discount stacking" → show the actual total discount achievable
"Users can transfer negative amounts" → show the actual balance change in response
