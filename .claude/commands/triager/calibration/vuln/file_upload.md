# TRIAGER CALIBRATION — File Upload

VALID if:
- Webshell executes (show cmd=id output in response)
- SVG XSS: alert(document.domain) confirmed in victim's browser context
- Path traversal places file outside upload directory (show file path in response)

NOT VALID:
- File uploads but is not served or executed
- Extension bypassed but server returns 404 for the uploaded file path
- Content-type bypass: file stored but application never renders/executes it

SEVERITY:
  Webshell + code execution = Critical
  Stored XSS via SVG/HTML = High
  Path traversal (file write outside dir) = High
  XXE via DOCX/SVG = High
  File stored in wrong directory without execution = Low
