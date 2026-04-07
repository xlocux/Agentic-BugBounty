/**
 * modal.js — showAlert / showConfirm / showPrompt.
 * Replaces all browser alert/confirm/prompt calls with themed modal dialogs.
 */

const overlay   = () => document.getElementById("modal-overlay");
const msgEl     = () => document.getElementById("modal-message");
const inputRow  = () => document.getElementById("modal-input-row");
const inputEl   = () => document.getElementById("modal-input");
const okBtn     = () => document.getElementById("modal-ok");
const cancelBtn = () => document.getElementById("modal-cancel");

function open(msg, showInput, showCancel) {
  msgEl().textContent = msg;
  inputRow().classList.toggle("hidden", !showInput);
  cancelBtn().classList.toggle("hidden", !showCancel);
  if (showInput) {
    inputEl().value = "";
    setTimeout(() => inputEl().focus(), 50);
  }
  overlay().classList.remove("hidden");
}

function close() {
  overlay().classList.add("hidden");
}

let _resolve = null;

function setup() {
  okBtn().addEventListener("click", () => {
    if (_resolve) { _resolve({ ok: true, value: inputEl().value }); _resolve = null; }
    close();
  });

  cancelBtn().addEventListener("click", () => {
    if (_resolve) { _resolve({ ok: false, value: null }); _resolve = null; }
    close();
  });

  overlay().addEventListener("click", (e) => {
    if (e.target === overlay()) {
      if (_resolve) { _resolve({ ok: false, value: null }); _resolve = null; }
      close();
    }
  });

  document.addEventListener("keydown", (e) => {
    if (overlay().classList.contains("hidden")) return;
    if (e.key === "Escape") {
      if (_resolve) { _resolve({ ok: false, value: null }); _resolve = null; }
      close();
    }
    if (e.key === "Enter") {
      okBtn().click();
    }
  });
}

export function showAlert(msg) {
  return new Promise((resolve) => {
    _resolve = () => resolve();
    open(msg, false, false);
  });
}

export function showConfirm(msg) {
  return new Promise((resolve) => {
    _resolve = ({ ok }) => resolve(ok);
    open(msg, false, true);
  });
}

export function showPrompt(msg, defaultVal = "") {
  return new Promise((resolve) => {
    _resolve = ({ ok, value }) => resolve(ok ? value : null);
    open(msg, true, true);
    inputEl().value = defaultVal;
  });
}

export function initModal() {
  setup();
}
