# TRIAGER CALIBRATION — Executable / Binary
# Asset-specific bug vs feature rules for Check 3

## VALIDITY RULES BY VULNERABILITY CLASS

### Memory Corruption (BOF, Heap, UAF)
VALID if:
  - Crash demonstrated with controlled instruction pointer (RIP/EIP)
  - OR: crash with controlled memory write (write-what-where)
  - Partial PoC (crash only) acceptable for Critical/High — full RCE PoC not required
    if gadget chain exists in binary/dependencies
NOT VALID:
  - Crash in non-security-relevant context (debug build, test harness)
  - Crash requires privileges already at target privilege level

### Format String
VALID if:
  - %x/%p leaks stack/heap addresses (ASLR bypass)
  - %n demonstrates arbitrary write (even if not full RCE)
NOT VALID:
  - User-controlled format string in debug-only code path
  - Requires compile-time flag to enable vulnerable path

### Command Injection
VALID if:
  - system()/popen() called with user-controlled argument
  - PoC shows command execution (create a file, read /etc/passwd)
NOT VALID:
  - User input sanitized through shell escaping (verify bypass attempts)
  - Injected into argument position where shell metacharacters are stripped

### Severity modifiers for binary context
SUID/SGID binary → escalates any High to Critical
Network daemon (listens on socket) → remote exploitable → Critical if RCE
File parser (PDF, image, document) → triggered by malicious file → High
CLI tool, user permissions only → local impact → Medium
Sandbox / container context → escape required for full impact → note in summary

## MITIGATIONS IMPACT ON SEVERITY

Full mitigations (RELRO+Canary+NX+PIE):
  → Downgrade by 1 level (exploitation significantly harder)
  → Requires: info leak + ROP chain + heap grooming
  → Still report — sophisticated attackers overcome all mitigations

No mitigations:
  → Upgrade by 1 level (trivially exploitable)
  → Shellcode injection possible, hardcoded addresses usable

Partial mitigations:
  → No adjustment — note specifically which mitigations are missing
