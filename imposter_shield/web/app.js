"use strict";
// ImposterShield SPA. No external deps (CSP: script-src 'self').

const API = "/api";
let token = sessionStorage.getItem("ishld_token") || null;
let currentFilter = "";
let selectedId = null;
let currentUser = null;
let editingUserId = null;     // null = create mode, number = edit mode

// ---------------------------------------------------------------- helpers
function authHeaders(extra = {}) {
  return token ? { Authorization: `Bearer ${token}`, ...extra } : extra;
}

async function api(path, { method = "GET", body, form } = {}) {
  const opts = { method, headers: authHeaders() };
  if (form) {
    opts.body = new URLSearchParams(form);
    opts.headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (body !== undefined) {
    opts.body = JSON.stringify(body);
    opts.headers["Content-Type"] = "application/json";
  }
  const res = await fetch(API + path, opts);
  if (res.status === 401) { logout(); throw new Error("Session expired"); }
  if (res.status === 204) return null;
  if (!res.ok) {
    let detail = res.statusText;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  const ct = res.headers.get("content-type") || "";
  return ct.includes("application/json") ? res.json() : res;
}

function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, c =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

function toast(msg, isErr = false) {
  const t = document.getElementById("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(t._tid);
  t._tid = setTimeout(() => (t.hidden = true), 3400);
}

function priClass(p) { return ["critical", "high", "medium"].includes(p) ? p : "medium"; }
function isAdmin() { return currentUser?.role === "admin"; }

// ---------------------------------------------------------------- tabs
function showTab(name) {
  document.getElementById("tab-cases").hidden = name !== "cases";
  document.getElementById("tab-admin").hidden = name !== "admin";
  document.getElementById("status-filters").hidden = name !== "cases";
  document.querySelectorAll(".tab-btn").forEach(b =>
    b.classList.toggle("active", b.dataset.tab === name));
  if (name === "admin") { loadUsers(); checkWorkerHealth(); }
}

// ---------------------------------------------------------------- auth
async function doLogin(e) {
  e.preventDefault();
  const errEl = document.getElementById("login-error");
  errEl.hidden = true;
  try {
    const data = await api("/auth/token", {
      form: {
        username: document.getElementById("email").value,
        password: document.getElementById("password").value,
      },
    });
    token = data.access_token;
    sessionStorage.setItem("ishld_token", token);
    await enterApp();
  } catch (err) {
    errEl.textContent = err.message;
    errEl.hidden = false;
  }
}

function logout() {
  token = null; currentUser = null;
  sessionStorage.removeItem("ishld_token");
  document.getElementById("app-view").hidden = true;
  document.getElementById("login-view").hidden = false;
}

async function enterApp() {
  currentUser = await api("/me");
  document.getElementById("user-label").textContent =
    `${esc(currentUser.email)} (${currentUser.role})`;
  // Show Admin tab only for admins
  document.querySelectorAll(".admin-only").forEach(el =>
    el.hidden = !isAdmin());
  document.getElementById("login-view").hidden = true;
  document.getElementById("app-view").hidden = false;
  showTab("cases");
  await loadCases();
  pollWorkerBadge();
}

// ---------------------------------------------------------------- worker badge
async function pollWorkerBadge() {
  try {
    const h = await api("/worker/health");
    const badge = document.getElementById("worker-badge");
    badge.className = "worker-badge " + (h.status === "ok" ? "ok" : "err");
    badge.querySelector(".label").textContent =
      h.status === "ok" ? "worker online" : "worker offline";
  } catch (_) {}
  setTimeout(pollWorkerBadge, 30_000);
}

// ---------------------------------------------------------------- cases
async function loadCases() {
  const q = currentFilter ? `?status_filter=${currentFilter}` : "";
  const cases = await api("/cases" + q);
  const list = document.getElementById("case-list");
  if (!cases.length) {
    list.innerHTML = `<div class="empty">No cases.</div>`;
    return;
  }
  list.innerHTML = cases.map(c => `
    <div class="case-card${c.id === selectedId ? " selected" : ""}" data-id="${c.id}">
      <div class="handle">@${esc(c.handle)}</div>
      <div class="meta">
        <span>${esc(c.platform)}</span>
        <span class="badge ${c.status}">${c.status.replace("_", " ")}</span>
      </div>
    </div>`).join("");
  list.querySelectorAll(".case-card").forEach(el =>
    el.addEventListener("click", () => openCase(Number(el.dataset.id))));
}

async function openCase(id) {
  selectedId = id;
  document.querySelectorAll(".case-card").forEach(el =>
    el.classList.toggle("selected", Number(el.dataset.id) === id));
  const c = await api(`/cases/${id}`);
  renderDetail(c);
}

function renderDetail(c) {
  const score = c.latest_score;
  const pct = score ? Math.round(score.confidence * 100) : 0;
  const bd = score ? score.breakdown : {};

  const recsHtml = (c.recommendations || []).map(r => `
    <div class="rec">
      <span class="badge ${priClass(r.priority)}">${r.priority}</span>
      <div class="body">
        <div class="chan">${esc(channelLabel(r.channel))}</div>
        <div class="why">${esc(r.rationale)}</div>
        ${r.requires_human
          ? `<div class="handoff-note">&#9888; Draft prepared — a human reviews &amp; submits.</div>`
          : ""}
      </div>
    </div>`).join("") || `<div class="empty">Score the case to get routing.</div>`;

  const harmHtml = (c.harm || []).map(h => {
    const flags = h.classifier_labels?.matched
      ? Object.entries(h.classifier_labels.matched)
          .map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")
      : "";
    return `<div class="harm-item">
      <span class="badge ${h.kind === "defamation" ? "high" : "critical"}">
        ${h.kind.replace("_", " ")}</span>
      ${esc(h.description)}
      ${h.evidence_url
        ? ` — <a href="${esc(h.evidence_url)}" target="_blank" rel="noopener noreferrer">evidence</a>`
        : ""}
      ${flags ? `<div class="flags">flagged: ${esc(flags)}</div>` : ""}
    </div>`;
  }).join("") || `<div class="empty">No harm evidence yet.</div>`;

  const breakdownRows = Object.entries(bd)
    .filter(([k]) => !["inputs", "weights"].includes(k))
    .map(([k, v]) =>
      `<div class="k">${esc(k)}</div><div>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`)
    .join("");

  document.getElementById("detail-panel").innerHTML = `
    <h1>@${esc(c.handle)}
      <span class="badge ${c.status}">${c.status.replace("_", " ")}</span></h1>
    <div class="sub">${esc(c.platform)} ·
      <a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">${esc(c.url)}</a></div>

    <div class="card">
      <h3>Confidence</h3>
      <div class="score-row">
        <span class="score-big">${pct}%</span>
        <span>${score?.enters_review ? "enters review queue" : "below threshold"}</span>
      </div>
      <div class="bar"><span style="width:${pct}%"></span></div>
      <div class="kv">${breakdownRows || "<div>Not scored yet.</div>"}</div>
      <div class="actions">
        <button class="btn small" id="btn-score">Run / re-score</button>
      </div>
    </div>

    <div class="card">
      <h3>Recommended channels</h3>${recsHtml}
    </div>

    <div class="card">
      <h3>Harm evidence</h3>
      ${harmHtml}
      <div class="field" style="margin-top:14px;">
        <div class="row">
          <select id="harm-kind" style="max-width:180px;">
            <option value="financial_scam">Financial scam</option>
            <option value="phishing">Phishing link</option>
            <option value="defamation">Defamation</option>
            <option value="malware">Malware</option>
            <option value="other">Other</option>
          </select>
          <input id="harm-desc" placeholder="Short description" />
        </div>
        <textarea id="harm-text" rows="2"
          placeholder="Captured text (e.g. the scam DM) — auto-classified"></textarea>
        <div class="row">
          <input id="harm-url" placeholder="Evidence URL (post / screenshot)" />
          <input id="harm-contact" placeholder="Reporter contact (optional)" />
        </div>
        <div>
          <button class="btn small primary" id="btn-add-harm">Add evidence</button>
        </div>
      </div>
    </div>

    <div class="card">
      <h3>Actions</h3>
      <div class="actions">
        <button class="btn small" id="btn-dossier">Download dossier PDF</button>
        <button class="btn small" id="btn-submitted">Mark submitted (by me)</button>
        <button class="btn small" id="btn-dismiss">Dismiss</button>
      </div>
      <div class="handoff-note">
        Submission is a manual human action and is recorded against your account.</div>
    </div>`;

  document.getElementById("btn-score").addEventListener("click", () => scoreCase(c.id));
  document.getElementById("btn-add-harm").addEventListener("click", () => addHarm(c.id));
  document.getElementById("btn-dossier").addEventListener("click", () => downloadDossier(c.id));
  document.getElementById("btn-submitted").addEventListener("click",
    () => setStatus(c.id, "submitted"));
  document.getElementById("btn-dismiss").addEventListener("click",
    () => setStatus(c.id, "dismissed"));
}

function channelLabel(ch) {
  return {
    dmca: "DMCA takedown (copyright)",
    fraud_report: "Fraud / scam report (critical)",
    defamation_notice: "Defamation notice (legal review)",
    impersonation_report: "Impersonation report (baseline)",
  }[ch] || ch;
}

// ---------------------------------------------------------------- case actions
async function scoreCase(id) {
  try {
    await api(`/suspects/${id}/score`, { method: "POST" });
    toast("Re-scored");
    await openCase(id); await loadCases();
  } catch (e) { toast(e.message, true); }
}

async function addHarm(id) {
  const body = {
    kind: document.getElementById("harm-kind").value,
    description: document.getElementById("harm-desc").value,
    captured_text: document.getElementById("harm-text").value,
    evidence_url: document.getElementById("harm-url").value,
    reporter_contact: document.getElementById("harm-contact").value,
  };
  if (!body.description) { toast("Description required", true); return; }
  try {
    await api(`/cases/${id}/harm`, { method: "POST", body });
    toast("Evidence added & classified");
    await openCase(id);
  } catch (e) { toast(e.message, true); }
}

async function setStatus(id, status) {
  try {
    await api(`/cases/${id}/status`, { method: "PATCH", body: { status, note: "" } });
    toast(`Marked ${status}`);
    await openCase(id); await loadCases();
  } catch (e) { toast(e.message, true); }
}

async function downloadDossier(id) {
  try {
    const res = await fetch(`${API}/cases/${id}/dossier`,
      { method: "POST", headers: authHeaders() });
    if (!res.ok) throw new Error("Dossier generation failed");
    const blob = await res.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `dossier-${id}.pdf`;
    a.click();
    URL.revokeObjectURL(a.href);
    toast("Dossier downloaded");
  } catch (e) { toast(e.message, true); }
}

// ================================================================ ADMIN PANEL

async function loadUsers() {
  try {
    const users = await api("/users");
    renderUserTable(users);
  } catch (e) { toast(e.message, true); }
}

function renderUserTable(users) {
  const wrap = document.getElementById("user-table-wrap");
  if (!users.length) { wrap.innerHTML = `<div class="empty">No users.</div>`; return; }
  wrap.innerHTML = `
    <table class="user-table">
      <thead><tr>
        <th>Name</th><th>Email</th><th>Role</th><th>Status</th><th>Actions</th>
      </tr></thead>
      <tbody>
        ${users.map(u => `
          <tr data-uid="${u.id}">
            <td>${esc(u.full_name || "—")}</td>
            <td>${esc(u.email)}</td>
            <td><span class="badge ${u.role}">${u.role}</span></td>
            <td><span class="badge ${u.is_active ? "active" : "inactive"}">
              ${u.is_active ? "active" : "disabled"}</span></td>
            <td><div class="actions">
              <button class="btn small btn-edit-user" data-uid="${u.id}"
                data-name="${esc(u.full_name)}" data-email="${esc(u.email)}"
                data-role="${u.role}">Edit</button>
              ${u.id !== currentUser.id
                ? `<button class="btn small btn-toggle-user" data-uid="${u.id}"
                     data-active="${u.is_active}">
                     ${u.is_active ? "Disable" : "Enable"}</button>
                   <button class="btn small btn-del-user" data-uid="${u.id}"
                     style="color:var(--crit)">Delete</button>`
                : `<span class="muted">(you)</span>`}
            </div></td>
          </tr>`).join("")}
      </tbody>
    </table>`;

  wrap.querySelectorAll(".btn-edit-user").forEach(btn =>
    btn.addEventListener("click", () => openUserForm(btn.dataset)));
  wrap.querySelectorAll(".btn-toggle-user").forEach(btn =>
    btn.addEventListener("click", () => toggleUser(Number(btn.dataset.uid),
      btn.dataset.active === "true")));
  wrap.querySelectorAll(".btn-del-user").forEach(btn =>
    btn.addEventListener("click", () => deleteUser(Number(btn.dataset.uid))));
}

function openUserForm(data = {}) {
  editingUserId = data.uid ? Number(data.uid) : null;
  const isEdit = editingUserId !== null;
  document.getElementById("user-form-title").textContent =
    isEdit ? "Edit account" : "New reviewer";
  document.getElementById("uf-name").value  = data.name  || "";
  document.getElementById("uf-email").value = data.email || "";
  document.getElementById("uf-role").value  = data.role  || "reviewer";
  document.getElementById("uf-password").value = "";
  document.getElementById("uf-email").disabled = isEdit; // email is immutable once set
  document.getElementById("user-form-error").hidden = true;
  document.getElementById("user-form-wrap").hidden = false;
  document.getElementById("uf-name").focus();
}

function closeUserForm() {
  editingUserId = null;
  document.getElementById("user-form-wrap").hidden = true;
}

async function saveUser() {
  const errEl = document.getElementById("user-form-error");
  errEl.hidden = true;
  const name     = document.getElementById("uf-name").value.trim();
  const email    = document.getElementById("uf-email").value.trim();
  const password = document.getElementById("uf-password").value;
  const role     = document.getElementById("uf-role").value;

  try {
    if (editingUserId === null) {
      // CREATE
      if (!email)         throw new Error("Email required");
      if (password.length < 12) throw new Error("Password must be at least 12 characters");
      await api("/users", {
        method: "POST",
        body: { email, full_name: name, password, role },
      });
      toast(`Reviewer ${email} created`);
    } else {
      // UPDATE
      const patch = { full_name: name || undefined, role };
      if (password) {
        if (password.length < 12) throw new Error("Password must be at least 12 characters");
        patch.password = password;
      }
      await api(`/users/${editingUserId}`, { method: "PATCH", body: patch });
      toast("Account updated");
    }
    closeUserForm();
    await loadUsers();
  } catch (e) {
    errEl.textContent = e.message;
    errEl.hidden = false;
  }
}

async function toggleUser(uid, currentlyActive) {
  try {
    await api(`/users/${uid}`, {
      method: "PATCH",
      body: { is_active: !currentlyActive },
    });
    toast(currentlyActive ? "Account disabled" : "Account enabled");
    await loadUsers();
  } catch (e) { toast(e.message, true); }
}

async function deleteUser(uid) {
  if (!confirm("Permanently delete this account? This cannot be undone.")) return;
  try {
    await api(`/users/${uid}`, { method: "DELETE" });
    toast("Account deleted");
    await loadUsers();
  } catch (e) { toast(e.message, true); }
}

async function checkWorkerHealth() {
  const el = document.getElementById("worker-health-detail");
  try {
    const h = await api("/worker/health");
    el.innerHTML = `<span style="color:${h.status === "ok" ? "var(--ok)" : "var(--crit)"}">
      ${h.status}</span>${h.reason ? ` — ${esc(h.reason)}` : ""}`;
  } catch (e) {
    el.textContent = `Error: ${e.message}`;
  }
}

// ---------------------------------------------------------------- wiring
document.getElementById("login-form").addEventListener("submit", doLogin);
document.getElementById("logout").addEventListener("click", logout);

document.getElementById("tab-nav").addEventListener("click", e => {
  if (e.target.tagName !== "BUTTON" || !e.target.dataset.tab) return;
  showTab(e.target.dataset.tab);
});

document.getElementById("status-filters").addEventListener("click", e => {
  if (e.target.tagName !== "BUTTON") return;
  currentFilter = e.target.dataset.status;
  document.querySelectorAll("#status-filters .chip").forEach(c =>
    c.classList.remove("active"));
  e.target.classList.add("active");
  loadCases();
});

document.getElementById("btn-new-user").addEventListener("click", () => openUserForm());
document.getElementById("btn-save-user").addEventListener("click", saveUser);
document.getElementById("btn-cancel-user").addEventListener("click", closeUserForm);

// boot
if (token) { enterApp().catch(() => logout()); }
