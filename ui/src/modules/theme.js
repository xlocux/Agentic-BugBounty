/**
 * theme.js — dark/light toggle with localStorage persistence.
 */

const STORAGE_KEY = "abb-theme";

export function initTheme() {
  const saved = localStorage.getItem(STORAGE_KEY) || "dark";
  applyTheme(saved);

  document.getElementById("theme-toggle").addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    applyTheme(current === "dark" ? "light" : "dark");
  });
}

export function applyTheme(name) {
  document.documentElement.setAttribute("data-theme", name);
  localStorage.setItem(STORAGE_KEY, name);
}
