# ASSET MODULE — Executable / Binary
# Covers: ELF (Linux), PE (Windows), Mach-O (macOS)
# Report ID prefix: EXE

## THREAT MODEL

Binary vulnerabilities allow attackers to:
  - Corrupt memory to redirect execution (buffer overflow, heap overflow)
  - Leak memory to bypass ASLR/stack canaries (info leak)
  - Achieve arbitrary code execution via ROP chains
  - Escalate privileges if the binary runs as SUID or service
  - Abuse logic flaws without memory corruption (command injection, path traversal)

Most critical context: is this binary SUID, a network daemon, or processing untrusted files?
If yes, memory corruption is immediately Critical.

## VULNERABILITY CLASSES (priority order)

1.  Stack Buffer Overflow               CWE-121  — classic smashing the stack
2.  Heap Buffer Overflow                CWE-122  — heap corruption
3.  Use-After-Free                      CWE-416  — dangling pointer dereference
4.  Format String Vulnerability         CWE-134  — printf(user_input)
5.  Integer Overflow / Underflow        CWE-190  — arithmetic leading to memory bugs
6.  Command / Argument Injection        CWE-78   — system() with user data
7.  Path Traversal                      CWE-22   — file path with user data
8.  Insecure Deserialization            CWE-502  — binary format parsing
9.  Race Condition (TOCTOU)             CWE-367  — time-of-check to time-of-use
10. Hardcoded Credentials               CWE-798  — secrets in binary strings

## WHITEBOX STATIC ANALYSIS

### Step 1 — Binary reconnaissance
```bash
# File type and architecture
file target_binary
checksec --file=target_binary
# Expected output: RELRO, Stack Canary, NX, PIE, RPATH, RUNPATH

# String extraction
strings target_binary | grep -iE "password|secret|token|api.?key|flag|admin"
strings target_binary | grep -E "http://|https://|ftp://"

# Symbols (if not stripped)
nm target_binary 2>/dev/null | grep -E " T | U "
objdump -d target_binary | grep "call.*system\|call.*exec\|call.*popen"

# Dynamic dependencies
ldd target_binary
readelf -d target_binary | grep NEEDED
```

### Step 2 — Decompile with Ghidra / Radare2
```bash
# Ghidra headless analysis
analyzeHeadless /tmp/ghidra-project TestProject \
  -import target_binary \
  -postScript PrintFunctionNames.java

# Radare2 quick analysis
r2 -A target_binary
# In r2: afl (list functions), pdf @ main (disassemble main), /c system (find calls)

# Look for dangerous function calls:
# strcpy, strcat, sprintf, gets, scanf, read without bounds
# system, popen, execve, execl with user-controlled args
# printf, fprintf, syslog with user-controlled format string
# malloc/free patterns for heap analysis
```

### Step 3 — Source code patterns (if available)
```bash
# Stack overflow candidates
grep -rn "strcpy(\|strcat(\|sprintf(\|gets(\b" --include="*.c" --include="*.cpp"
grep -rn "scanf(\"%s" --include="*.c" --include="*.cpp"
grep -rn "read(\|recv(\|fgets(" --include="*.c" --include="*.cpp"
# Verify: is the buffer size checked against input length?

# Format string
grep -rn "printf(\s*[a-zA-Z]\|fprintf(\s*\w\+,\s*[a-zA-Z]\|syslog(" --include="*.c" --include="*.cpp"
# Verify: is format string a literal or user-controlled?

# Command injection
grep -rn "system(\|popen(\|execve(\|execl(\|execlp(" --include="*.c" --include="*.cpp"
grep -rn "ShellExecute\|CreateProcess" --include="*.cpp"
# Verify: is user input sanitized before reaching these calls?

# Integer overflow leading to malloc size
grep -rn "malloc(\|calloc(\|realloc(" --include="*.c" --include="*.cpp"
# Look for: malloc(user_len * sizeof(type)) without overflow check

# Use-after-free
grep -rn "free(\b" --include="*.c" --include="*.cpp"
# Check: is the pointer nulled after free? Is it used again?
```

## DYNAMIC TESTING

### Fuzzing setup
```bash
# AFL++ fuzzing
afl-fuzz -i ./corpus -o ./findings -- ./target_binary @@

# LibFuzzer (if target has fuzzing harness)
clang -fsanitize=fuzzer,address -o target_fuzz target_fuzz.c

# Address Sanitizer build (if source available)
gcc -fsanitize=address,undefined -g -o target_asan target.c
echo "ASAN_OPTIONS=detect_leaks=1" && ./target_asan [input]
```

### GDB exploitation workflow
```bash
# Pattern generation for offset finding
python3 -c "import pwn; print(pwn.cyclic(200))" > pattern.txt
gdb ./target_binary
run < pattern.txt
# On crash: info registers, examine RSP/RIP
python3 -c "import pwn; print(pwn.cyclic_find(0x61616161))"

# Basic pwntools template
from pwn import *
p = process('./target_binary')
# or: p = remote('target.host', 1337)
offset = 72  # from cyclic analysis
payload = b'A' * offset + p64(win_function_address)
p.sendline(payload)
p.interactive()
```

### Security mitigations check
```
checksec output interpretation:
  RELRO Full    → GOT overwrite not possible
  Stack Canary  → stack overflow harder (need leak first)
  NX Enabled    → shellcode injection not possible (need ROP)
  PIE Enabled   → need info leak to defeat ASLR
  No RELRO      → GOT overwrite possible → easy code execution
  No Canary     → direct stack overflow to RIP
  NX Disabled   → shellcode injection possible
  No PIE        → hardcoded addresses usable in ROP
```

## IMPACT ESCALATION CONTEXT

Report severity depends heavily on execution context:
  SUID binary running as root  → exploit = local privilege escalation → High/Critical
  Network daemon / service     → remote exploit = RCE → Critical
  File parser (PDF, image)     → exploit via malicious file → High
  CLI tool, no special perms   → exploit requires local access → Medium
  CTF / sandboxed environment  → lower real-world impact → adjust accordingly
