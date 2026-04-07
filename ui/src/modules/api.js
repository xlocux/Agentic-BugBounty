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
