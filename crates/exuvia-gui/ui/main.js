const invoke = window.__TAURI__?.core?.invoke;
const byId = (id) => document.getElementById(id);

const CATEGORY_ORDER = [
  "Application",
  "Preferences",
  "Caches",
  "Logs",
  "Services",
  "Registry",
];

const state = {
  apps: [],
  filtered: [],
  selectedId: null,
  scan: null,
  complete: false,
  permanent: false,
  checked: new Set(),
  history: [],
  view: "apps",
};

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();

  if (!invoke) {
    setStatus("Tauri bridge unavailable", "error");
    byId("detail").innerHTML = `
      <div class="empty-state">
        <div class="empty-mark">!</div>
        <h2>Could not connect to the Exuvia core</h2>
        <p>Run the desktop app with <span class="mono">cargo run -p exuvia-gui</span>.</p>
      </div>`;
    return;
  }

  loadApps();
});

function bindEvents() {
  byId("search").addEventListener("input", applyFilter);

  byId("app-list").addEventListener("click", (event) => {
    const row = event.target.closest(".app-row");
    if (!row) return;
    selectApp(row.dataset.id);
  });

  byId("detail").addEventListener("change", (event) => {
    const target = event.target;
    if (target.matches("input[data-item-key]")) {
      if (target.checked) {
        state.checked.add(target.dataset.itemKey);
      } else {
        state.checked.delete(target.dataset.itemKey);
      }
      updateSelectionSummary();
    }
    if (target.id === "permanent") {
      state.permanent = target.checked;
      updateSelectionSummary();
    }
  });

  byId("detail").addEventListener("click", (event) => {
    const mode = event.target.closest('[data-role="mode"]');
    if (mode) {
      const complete = mode.dataset.mode === "complete";
      if (complete !== state.complete) {
        state.complete = complete;
        rescan();
      }
      return;
    }

    const selectAll = event.target.closest('[data-role="select-all"]');
    if (selectAll) {
      state.checked = new Set(
        state.scan.items.filter((item) => item.removable).map((item) => item.key),
      );
      renderDetail();
      return;
    }

    const selectNone = event.target.closest('[data-role="select-none"]');
    if (selectNone) {
      state.checked = new Set();
      renderDetail();
      return;
    }

    const rescanButton = event.target.closest('[data-role="rescan"]');
    if (rescanButton) {
      rescan();
      return;
    }

    const quarantineButton = event.target.closest('[data-role="quarantine"]');
    if (quarantineButton) {
      quarantineSelected();
    }
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => switchView(tab.dataset.view));
  });

  byId("refresh-history").addEventListener("click", loadHistory);
  byId("history-list").addEventListener("click", (event) => {
    const button = event.target.closest("[data-restore]");
    if (button) {
      restoreManifest(button.dataset.restore);
    }
  });

  byId("modal-cancel").addEventListener("click", () => closeModal(false));
  byId("modal-confirm").addEventListener("click", () => closeModal(true));
  byId("modal").addEventListener("click", (event) => {
    if (event.target === byId("modal")) closeModal(false);
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !byId("modal").classList.contains("hidden")) {
      closeModal(false);
    }
  });
}

/* ---------------- data loading ---------------- */

async function loadApps() {
  setStatus("Reading installed applications...", "busy");
  try {
    const apps = await invoke("list_apps");
    state.apps = apps.sort(
      (left, right) => left.name.localeCompare(right.name, undefined, { sensitivity: "base" }),
    );
    applyFilter();
    setStatus(`${state.apps.length} application(s) found`);
  } catch (error) {
    setStatus("Could not read installed applications", "error");
    toast(String(error), "error");
    byId("app-list").innerHTML =
      '<div class="list-empty">Could not read the uninstall registry keys.</div>';
  }
}

function applyFilter() {
  const query = byId("search").value.trim().toLowerCase();
  state.filtered = query
    ? state.apps.filter((app) => {
        const haystack = [app.name, app.publisher, app.id, app.source]
          .filter(Boolean)
          .join(" ")
          .toLowerCase();
        return haystack.includes(query);
      })
    : state.apps;
  renderAppList();
}

function renderAppList() {
  const list = byId("app-list");
  const count = byId("app-count");
  count.textContent = `${state.filtered.length}`;

  if (!state.filtered.length) {
    list.innerHTML = `<div class="list-empty">No applications match this search.</div>`;
    return;
  }

  list.innerHTML = state.filtered
    .map((app) => {
      const active = app.id === state.selectedId ? " active" : "";
      const size = app.size_bytes ? formatBytes(app.size_bytes) : "";
      const meta = [app.publisher, app.source, app.version ? `v${app.version}` : null]
        .filter(Boolean)
        .map(escapeHtml)
        .join(" · ");
      return `
        <button class="app-row${active}" data-id="${escapeAttr(app.id)}" role="option" aria-selected="${active ? "true" : "false"}">
          <span class="app-row-main">
            <span class="app-name">${escapeHtml(app.name)}</span>
            <span class="app-meta">${meta}</span>
          </span>
          <span class="app-size">${size}</span>
        </button>`;
    })
    .join("");
}

async function selectApp(id) {
  const app = state.apps.find((candidate) => candidate.id === id);
  if (!app) return;

  state.selectedId = id;
  state.scan = null;
  state.permanent = false;
  state.checked = new Set();
  renderAppList();
  renderLoading(app);
  setStatus(`Scanning ${app.name}...`, "busy");

  try {
    const scan = await invoke("scan_app", { query: app.id, complete: state.complete });
    if (state.selectedId !== id) return;
    state.scan = scan;
    state.checked = new Set(
      scan.items.filter((item) => item.selected && item.removable).map((item) => item.key),
    );
    renderDetail();
    setStatus(
      scan.items.length
        ? `${scan.items.length} leftover item(s) found for ${scan.app.name}`
        : `No leftovers found for ${scan.app.name}`,
    );
  } catch (error) {
    if (state.selectedId !== id) return;
    setStatus("Scan failed", "error");
    renderError(String(error));
  }
}

async function rescan() {
  if (!state.scan) return;
  const id = state.scan.app.id;
  const app = state.apps.find((candidate) => candidate.id === id) || state.scan.app;
  state.checked = new Set();
  renderLoading(app);
  setStatus(`Scanning ${app.name}...`, "busy");
  try {
    const scan = await invoke("scan_app", { query: id, complete: state.complete });
    if (state.selectedId !== id) return;
    state.scan = scan;
    state.checked = new Set(
      scan.items.filter((item) => item.selected && item.removable).map((item) => item.key),
    );
    renderDetail();
    setStatus(`${scan.items.length} leftover item(s) found for ${scan.app.name}`);
  } catch (error) {
    setStatus("Scan failed", "error");
    renderError(String(error));
  }
}

/* ---------------- detail rendering ---------------- */

function renderLoading(app) {
  byId("detail").innerHTML = `
    <div class="empty-state">
      <div class="empty-mark">◌</div>
      <h2>Scanning ${escapeHtml(app.name)}</h2>
      <p>Looking through AppData, ProgramData, the registry, services and startup items.</p>
    </div>`;
}

function renderError(message) {
  byId("detail").innerHTML = `
    <div class="empty-state">
      <div class="empty-mark">!</div>
      <h2>Something went wrong</h2>
      <p>${escapeHtml(message)}</p>
    </div>`;
}

function renderDetail() {
  const scan = state.scan;
  if (!scan) return;

  const app = scan.app;
  const items = scan.items;
  const groups = CATEGORY_ORDER.map((category) => [
    category,
    items.filter((item) => item.category === category),
  ]).filter(([, group]) => group.length);

  const header = `
    <div class="detail-head">
      <div class="detail-icon">${escapeHtml(initials(app.name))}</div>
      <div class="detail-title">
        <h2>${escapeHtml(app.name)}</h2>
        <div class="detail-sub">
          <span class="chip">${escapeHtml(app.source)}</span>
          ${app.version ? `<span>v${escapeHtml(app.version)}</span>` : ""}
          ${app.publisher ? `<span>${escapeHtml(app.publisher)}</span>` : ""}
          <span class="mono">${escapeHtml(
            app.uninstall?.install_location || "install path unknown",
          )}</span>
        </div>
        <div class="detail-actions">
          <div class="segmented" role="group" aria-label="Cleanup mode">
            <button data-role="mode" data-mode="standard" class="${state.complete ? "" : "active"}">Standard</button>
            <button data-role="mode" data-mode="complete" class="${state.complete ? "active" : ""}">Complete</button>
          </div>
          <button class="button ghost small" data-role="select-all">Select all</button>
          <button class="button ghost small" data-role="select-none">Clear</button>
          <button class="button ghost small" data-role="rescan">Rescan</button>
        </div>
      </div>
    </div>`;

  const selectedItems = items.filter((item) => state.checked.has(item.key));
  const selectedBytes = selectedItems.reduce((total, item) => total + item.size_bytes, 0);

  const summary = `
    <div class="summary-strip">
      <div class="summary-stat">
        <span>Detected</span>
        <strong>${items.length}</strong>
      </div>
      <div class="summary-stat">
        <span>On disk</span>
        <strong>${scan.total_label}</strong>
      </div>
      <div class="summary-stat">
        <span>Selected</span>
        <strong id="selected-count">${selectedItems.length}</strong>
      </div>
      <div class="summary-stat">
        <span>To reclaim</span>
        <strong id="selected-size">${formatBytes(selectedBytes)}</strong>
      </div>
      <div class="spacer"></div>
      <span class="muted">${state.complete ? "Complete" : "Standard"} mode</span>
    </div>`;

  const warnings = scan.warnings?.length
    ? `<div class="warning-box"><strong>${scan.warnings.length} note(s) from the scanner</strong>${scan.warnings
        .map((warning) => escapeHtml(warning))
        .join("<br>")}</div>`
    : "";

  const content = groups.length
    ? groups
        .map(([category, group]) => {
          const bytes = group.reduce((total, item) => total + item.size_bytes, 0);
          return `
            <section class="category">
              <div class="category-head">
                <h3>${escapeHtml(category)}</h3>
                <span>${group.length} item(s) · ${formatBytes(bytes)}</span>
              </div>
              <div class="items">
                ${group.map(renderItem).join("")}
              </div>
            </section>`;
        })
        .join("")
    : `
      <div class="empty-state" style="height:auto;padding:64px 0 30px">
        <div class="empty-mark">✓</div>
        <h2>No leftovers detected</h2>
        <p>Exuvia found nothing that belongs to this application. The native uninstaller is still available from the CLI.</p>
      </div>`;

  const footer = items.length
    ? `
      <div class="footer-actions">
        <label class="permanent-toggle">
          <input type="checkbox" id="permanent" ${state.permanent ? "checked" : ""}>
          Permanently delete (cannot be restored)
        </label>
        <span class="spacer"></span>
        <span class="muted" id="selection-summary"></span>
        <button class="button ${state.permanent ? "danger" : "primary"}" data-role="quarantine">Quarantine selected</button>
      </div>`
    : "";

  byId("detail").innerHTML = header + summary + warnings + content + footer;
  updateSelectionSummary();
}

function renderItem(item) {
  const checked = state.checked.has(item.key) ? "checked" : "";
  const disabled = item.removable ? "" : "disabled";
  const reportOnly = item.removable ? "" : '<span class="pill report">report only</span>';
  return `
    <label class="item">
      <input type="checkbox" data-item-key="${escapeAttr(item.key)}" ${checked} ${disabled}>
      <span class="item-body">
        <span class="item-path">${escapeHtml(item.display_path)}</span>
        <span class="item-reason">
          <span class="pill ${escapeAttr(item.confidence)}">${escapeHtml(item.confidence)}</span>
          ${reportOnly}
          <span>${escapeHtml(item.reason)}</span>
        </span>
        ${item.detail ? `<span class="item-detail">${escapeHtml(item.detail)}</span>` : ""}
      </span>
      <span class="item-size">${escapeHtml(item.size_label)}</span>
    </label>`;
}

function updateSelectionSummary() {
  if (!state.scan) return;
  const selected = state.scan.items.filter((item) => state.checked.has(item.key));
  const bytes = selected.reduce((total, item) => total + item.size_bytes, 0);

  const count = byId("selected-count");
  const size = byId("selected-size");
  if (count) count.textContent = `${selected.length}`;
  if (size) size.textContent = formatBytes(bytes);

  const summary = byId("selection-summary");
  if (summary) {
    summary.textContent = `${selected.length} selected · ${formatBytes(bytes)}`;
  }

  const button = document.querySelector('[data-role="quarantine"]');
  if (button) {
    button.disabled = selected.length === 0;
    const verb = state.permanent ? "Delete" : "Quarantine";
    button.textContent = `${verb} ${selected.length} item${selected.length === 1 ? "" : "s"}`;
  }
}

/* ---------------- actions ---------------- */

async function quarantineSelected() {
  if (!state.scan) return;
  const keys = [...state.checked].filter((key) => {
    const item = state.scan.items.find((candidate) => candidate.key === key);
    return item?.removable;
  });

  if (!keys.length) {
    toast("Select at least one removable item first.", "error");
    return;
  }

  const selected = state.scan.items.filter((item) => keys.includes(item.key));
  const bytes = selected.reduce((total, item) => total + item.size_bytes, 0);
  const permanent = state.permanent;

  const confirmed = await confirmDialog({
    title: permanent ? "Permanently delete leftovers?" : "Quarantine leftovers?",
    body: `${selected.length} item(s) · ${formatBytes(bytes)} for ${state.scan.app.name}.\n\n${
      permanent
        ? "Permanent deletion cannot be undone."
        : "Items are moved into the Exuvia quarantine and can be restored from History."
    }`,
    confirmLabel: permanent ? "Delete permanently" : "Quarantine now",
    danger: permanent,
  });
  if (!confirmed) return;

  setStatus("Removing selected items...", "busy");
  try {
    const result = await invoke("quarantine", {
      query: state.scan.app.id,
      keys,
      permanent,
    });
    state.permanent = false;
    setStatus("Cleanup complete");
    toast(
      result.failed
        ? `Removed ${result.removed} item(s), ${result.failed} failed. Reclaimed ${result.reclaimed_label}.`
        : `Removed ${result.removed} item(s) and reclaimed ${result.reclaimed_label}.`,
      result.failed ? "error" : "ok",
    );
    await selectApp(state.scan.app.id);
  } catch (error) {
    setStatus("Cleanup failed", "error");
    toast(String(error), "error");
  }
}

/* ---------------- history ---------------- */

function switchView(view) {
  state.view = view;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", tab.dataset.view === view);
  });
  byId("apps-view").classList.toggle("hidden", view !== "apps");
  byId("history-view").classList.toggle("hidden", view !== "history");
  if (view === "history") loadHistory();
}

async function loadHistory() {
  setStatus("Loading history...", "busy");
  try {
    state.history = await invoke("history");
    renderHistory();
    setStatus(`${state.history.length} manifest(s)`);
  } catch (error) {
    setStatus("Could not load history", "error");
    toast(String(error), "error");
  }
}

function renderHistory() {
  const container = byId("history-list");
  if (!state.history.length) {
    container.innerHTML = `
      <div class="history-empty">
        No operations yet. Quarantine some leftovers and they will appear here with a restore action.
      </div>`;
    return;
  }

  container.innerHTML = state.history
    .map((manifest) => {
      const stateClass = String(manifest.state).replace("_", " ");
      const badgeClass = String(manifest.state).split("_")[0];
      const canRestore = ["completed", "partial", "partial_restore"].includes(manifest.state);
      const date = formatDate(manifest.created_at);
      return `
        <div class="history-card">
          <div>
            <div class="history-name">${escapeHtml(manifest.app_name)}</div>
            <div class="history-meta mono">${escapeHtml(manifest.id)} · ${escapeHtml(date)}</div>
          </div>
          <div class="history-stat"><span>Items</span><strong>${manifest.item_count}</strong></div>
          <div class="history-stat"><span>Reclaimed</span><strong>${escapeHtml(manifest.reclaimed_label)}</strong></div>
          <div style="display:flex;align-items:center;gap:10px">
            <span class="state-badge ${escapeAttr(badgeClass)}">${escapeHtml(stateClass)}</span>
            ${
              canRestore
                ? `<button class="button ghost small" data-restore="${escapeAttr(manifest.id)}">Restore</button>`
                : ""
            }
          </div>
        </div>`;
    })
    .join("");
}

async function restoreManifest(id) {
  const confirmed = await confirmDialog({
    title: "Restore this operation?",
    body: `Quarantined items from manifest ${id} will be moved back to their original locations. Existing files are never overwritten.`,
    confirmLabel: "Restore",
  });
  if (!confirmed) return;

  setStatus("Restoring...", "busy");
  try {
    const result = await invoke("restore_manifest", { id });
    setStatus("Restore complete");
    toast(
      result.failed
        ? `Restored ${result.restored} item(s); ${result.failed} could not be restored.`
        : `Restored ${result.restored} item(s).`,
      result.failed ? "error" : "ok",
    );
    loadHistory();
  } catch (error) {
    setStatus("Restore failed", "error");
    toast(String(error), "error");
  }
}

/* ---------------- ui helpers ---------------- */

let modalResolver = null;

function confirmDialog({ title, body, confirmLabel, danger = false }) {
  return new Promise((resolve) => {
    modalResolver = resolve;
    byId("modal-title").textContent = title;
    byId("modal-body").textContent = body;
    const confirm = byId("modal-confirm");
    confirm.textContent = confirmLabel;
    confirm.className = `button ${danger ? "danger" : "primary"}`;
    byId("modal").classList.remove("hidden");
    confirm.focus();
  });
}

function closeModal(value) {
  byId("modal").classList.add("hidden");
  const resolver = modalResolver;
  modalResolver = null;
  if (resolver) resolver(value);
}

let toastTimer = null;

function toast(message, kind = "ok") {
  const element = byId("toast");
  element.textContent = message;
  element.className = `toast ${kind}`;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => element.classList.add("hidden"), 6500);
}

function setStatus(text, kind = "idle") {
  byId("status-text").textContent = text;
  byId("status").dataset.kind = kind;
}

function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value >= 10 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

function formatDate(value) {
  if (!value) return "";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

function initials(name) {
  return String(name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((word) => word[0])
    .join("")
    .toUpperCase();
}

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => {
    switch (character) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/"/g, "&quot;");
}
