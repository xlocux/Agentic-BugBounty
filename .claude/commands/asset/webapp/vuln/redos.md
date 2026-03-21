# VULN MODULE — ReDoS (Regular Expression Denial of Service)
# Asset: webapp (Node.js especially, also Python, Java, PHP)
# CWE-1333 | Report prefix: WEB-REDOS

## THREAT MODEL

Catastrophic backtracking in regex engines causes exponential evaluation time
for certain malicious inputs. A single request can tie up a server thread for
seconds or minutes. Most dangerous in single-threaded Node.js (blocks event loop).

## WHITEBOX PATTERNS

```bash
# Find regex patterns in code
grep -rn "new RegExp\|\.match(\|\.test(\|\.search(\|\.replace(" \
  --include="*.js" --include="*.ts" --include="*.py" --include="*.php" --include="*.java"

# Dangerous regex patterns (vulnerable to backtracking):
# (a+)+ or (a|aa)+ or (a*)*  — nested quantifiers on same chars
# Common vulnerable patterns:
grep -rn '".*\(.*\+\).*\+\|.*\(.*\*\).*\*.*"' --include="*.js"

# User input flowing into regex
grep -rn "new RegExp(\s*req\.\|new RegExp(\s*params\.\|new RegExp(\s*query\." \
  --include="*.js" --include="*.ts"
# User-controlled regex = arbitrary regex injection → ReDoS + potential bypass
```

## VULNERABLE REGEX PATTERNS

```javascript
// These patterns are vulnerable to ReDoS with crafted input:
/^(a+)+$/                    // input: "aaa...a!"
/^([a-zA-Z0-9])(([a-zA-Z0-9])*\2)+$/  // email-like
/^(([a-z])+.)+[A-Z]([a-z])+$/ // name validation
/(\w+\s?)*$/                  // word matching

// Email validation regexes are historically very vulnerable:
// Payload: "a@" + "a"*50 + "!"
// Or: "aaaaaaa@aaaaaaaaaaaaaaaaaaaaaaaaaaaa."
```

## TESTING

```bash
# Test timing with crafted input
time curl -s -X POST https://target.com/validate-email \
  -d "email=$(python3 -c "print('a'*50 + '@a' + 'a'*50 + '!')")"

# Node.js event loop block detection:
# If response takes >2s for the crafted input vs <10ms for valid input → ReDoS

# Tools:
# vuln-regex-detector
pip install redos-checker
redos-checker '(a+)+'

# safe-regex (npm)
npm install safe-regex
node -e "var s=require('safe-regex'); console.log(s(/(a+)+/))"
```

## SEVERITY NOTE

ReDoS severity depends on:
- Thread model: single-threaded (Node.js) = Critical (full server block)
- Multi-threaded (Java/Python) = Medium (one thread blocked)
- Requires authentication? → reduce severity if auth required
- Is the regex user-controlled (injection) or fixed pattern? 
  → User-controlled: Critical (arbitrary regex + ReDoS)
  → Fixed vulnerable pattern: Medium/Low
