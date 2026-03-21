# shared/bypass — Bypass & Filter Evasion Modules

These modules are TRANSVERSAL — they apply across all asset types and vuln classes.
Load them when a payload is blocked or a filter needs to be circumvented.

## Module Index

| File | When to load |
|---|---|
| `encoding.md` | Any payload is blocked — start here. Covers URL/HTML/JS/base64/hex encoding chains |
| `xss_filter_evasion.md` | XSS payload blocked — tag variants, event handlers, CSP bypass, WAF evasion |
| `sqli_filter_evasion.md` | SQLi blocked — whitespace substitutes, keyword splitting, quote bypass, DB-specific tricks |
| `ssrf_filter_evasion.md` | SSRF blocked — localhost variants, cloud metadata, DNS rebinding, redirect chains |
| `auth_bypass.md` | Auth in place — JWT attacks, OAuth bypass, password reset, IDOR, mass assignment |
| `waf_evasion.md` | WAF confirmed — HTTP-level evasion, chunked encoding, parameter pollution, obfuscation |

## Load Order

When a payload is blocked, load in this order:
1. `encoding.md` — try encoding variants first (fastest, least intrusive)
2. Asset-specific bypass (e.g. `xss_filter_evasion.md` for XSS)
3. `waf_evasion.md` — if encoding fails and WAF is confirmed

## Integration with researcher agent

The researcher agent auto-loads bypass modules when:
- A candidate is found but dynamic confirmation fails with a 403/406
- Output is reflected but escaped (try alternative sinks)
- Auth check blocks access to vulnerable endpoint

## Invocation via --bypass flag

```
/researcher --asset webapp --mode blackbox --bypass xss ./src
/researcher --asset webapp --mode whitebox --bypass sqli,waf ./src
```

Available --bypass values:
  encoding, xss, sqli, ssrf, auth, waf, all
