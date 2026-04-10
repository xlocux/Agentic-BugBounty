/**
 * api.js — fetch wrapper and SSE client helper.
 * All fetch calls go through here so error handling is consistent.
 */

export async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
    body: options.body
      ? (typeof options.body === "string" ? options.body : JSON.stringify(options.body))
      : undefined
  });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${text}`);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) return res.json();
  return res.text();
}

/** Strip ANSI escape sequences from a log line before displaying in browser. */
// eslint-disable-next-line no-control-regex
export function stripAnsi(str) {
  return String(str).replace(/\x1b\[[0-9;]*[A-Za-z]/g, "").replace(/\x1b\][^\x07]*\x07/g, "");
}

/** Convert ANSI color codes to HTML spans. Safe — all non-escape text is HTML-escaped. */
export function ansiToHtml(str) {
  /* eslint-disable no-control-regex */
  const FG = {
    30:"#666",   31:"#e06c75", 32:"#98c379", 33:"#e5c07b",
    34:"#61afef", 35:"#c678dd", 36:"#56b6c2", 37:"#abb2bf",
    90:"#5c6370", 91:"#ff6b6b", 92:"#b5e890", 93:"#ffd580",
    94:"#84c3ff", 95:"#e0a0ff", 96:"#88dde8", 97:"#ffffff",
  };
  const esc = (s) => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;");
  // strip OSC sequences (window title, etc.)
  str = String(str).replace(/\x1b\][^\x07]*\x07/g, "");
  let html = "", open = false;
  for (const part of str.split(/(\x1b\[[0-9;]*m)/)) {
    if (!part.startsWith("\x1b[")) { html += esc(part); continue; }
    if (open) { html += "</span>"; open = false; }
    const codes = part.slice(2, -1).split(";").map(Number);
    if (codes.includes(0) || codes[0] === 0 || part === "\x1b[m") continue; // reset
    const fg   = codes.find(c => (c >= 30 && c <= 37) || (c >= 90 && c <= 97));
    const bold = codes.includes(1);
    const dim  = codes.includes(2);
    const style = [
      fg !== undefined ? `color:${FG[fg] || "inherit"}` : null,
      bold ? "font-weight:600" : null,
      dim  ? "opacity:0.55"   : null,
    ].filter(Boolean).join(";");
    if (style) { html += `<span style="${style}">`; open = true; }
  }
  if (open) html += "</span>";
  return html;
}

/**
 * Open an SSE connection. Returns an object with a close() method.
 * onMessage is called with parsed data objects.
 * onError is called on connection errors (default: console.error).
 */
export function openSSE(path, onMessage, onError = console.error) {
  const source = new EventSource(path);
  source.onmessage = (ev) => {
    try { onMessage(JSON.parse(ev.data)); } catch { /* ignore malformed events */ }
  };
  source.onerror = onError;
  return { close: () => source.close() };
}
