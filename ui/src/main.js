import { initModal }      from "./modules/modal.js";
import { initTheme }      from "./modules/theme.js";
import { initTargets }    from "./panels/targets.js";
import { initRunControl } from "./panels/run-control.js";
import { initDashboard }  from "./panels/dashboard.js";
import { initSettings }   from "./panels/settings.js";

const PANELS = [
  { id: "targets",     init: initTargets },
  { id: "run-control", init: initRunControl },
  { id: "dashboard",   init: initDashboard },
  { id: "settings",    init: initSettings }
];

function mount() {
  initModal();
  initTheme();

  const container = document.getElementById("panel-container");

  // Create and initialize each panel div
  for (const p of PANELS) {
    const div = document.createElement("div");
    div.id        = `panel-${p.id}`;
    div.className = "panel";
    container.appendChild(div);
    p.init(div);
  }

  // Wire nav buttons
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => showPanel(btn.dataset.panel));
  });

  // Show initial panel from URL hash or default to targets
  const initial = location.hash.replace("#", "") || "targets";
  showPanel(initial);
}

function showPanel(id) {
  document.querySelectorAll(".panel").forEach((p)    => p.classList.remove("active"));
  document.querySelectorAll(".nav-btn").forEach((b)  => b.classList.remove("active"));

  const panelEl = document.getElementById(`panel-${id}`);
  if (panelEl) panelEl.classList.add("active");

  const btn = document.querySelector(`.nav-btn[data-panel="${id}"]`);
  if (btn) btn.classList.add("active");

  location.hash = id;
}

mount();
