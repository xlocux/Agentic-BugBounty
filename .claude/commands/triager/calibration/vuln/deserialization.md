# TRIAGER CALIBRATION — Insecure Deserialization

VALID if:
- DNS callback confirmed (ysoserial URLDNS payload triggered DNS lookup)
- Code execution demonstrated (file written, command output returned)
- Known gadget chain exists in dependency tree (partial PoC acceptable for Critical)

NOT VALID:
- "unserialize() is called" without confirming user data reaches it
- Vulnerable library present but no reachable gadget chain

SEVERITY:
  DNS callback confirmed + known gadget chain = Critical
  DNS callback only (RCE not yet demonstrated) = High
  Deserialization confirmed, no gadget chain found = Medium
