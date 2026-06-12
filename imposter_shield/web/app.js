"use strict";
// ImposterShield SPA. No external deps (CSP: script-src 'self'). All event
// handlers attached via addEventListener — no inline handlers.

const API = "/api";
let token = sessionStorage.getItem("ishld_token") || null;
let currentFilter = "";
let selectedId = null;

// ---------------------------------------------------------------- helpers
function authHeaders(extra = {}) {
  return token ? { Authorization: `Bearer ${token}`, ...extra } : extra;
}

async function api(path, { method = "GET", body, form } = {}) {
  const opts = { method, headers: authHeaders() };
  if (form) {
    opts.body = new URLSearchParams(form);
    opts.headers["Content-Type"] = "application/x-www-form-urlencoded";
  } else if (body) {
    opts.body = JSON.stringify(body);
    opts.headers["Content-Type"] = "application/json";
  }
  const res = await fetch(API + path, opts);
  if (res.status === 401) { logout(); throw new Error("Session expired"); }
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
  setTimeout(() => (t.hidden = true), 3200);
}

function priClass(p) { return ["critical", "high", "medium"].includes(p) ? p : "medium"; }

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
  token = null;
  sessionStorage.removeItem("ishld_token");
  document.getElementById("app-view").hidden = true;
  document.getElementById("login-view").hidden = false;
}

async function enterApp() {
  const me = await api("/me");
  document.getElementById("user-label").textContent = `${me.email} (${me.role})`;
  document.getElementById("login-view").hidden = true;
  document.getElementById("app-view").hidden = false;
  await loadCases();
}

// ---------------------------------------------------------------- cases
async function loadCases() {
  const q = currentFilter ? `?status_filter=${currentFilter}` : "";
  const cases = await api("/cases" + q);
  const list = document.getElementById("case-list");
  if (!cases.length) { list.innerHTML = `<div class="empty">No cases.</div>`; return; }
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
        ${r.requires_human ? `<div class="handoff-note">&#9888; Draft prepared — a human reviews &amp; submits.</div>` : ""}
      </div>
    </div>`).join("") || `<div class="empty">Score the case to get routing.</div>`;

  const harmHtml = (c.harm || []).map(h => {
    const flags = h.classifier_labels && h.classifier_labels.matched
      ? Object.entries(h.classifier_labels.matched).map(([k, v]) => `${k}: ${v.join(", ")}`).join(" · ")
      : "";
    return `<div class="harm-item">
      <span class="badge ${h.kind === "defamation" ? "high" : "critical"}">${h.kind.replace("_", " ")}</span>
      ${esc(h.description)}
      ${h.evidence_url ? ` — <a href="${esc(h.evidence_url)}" target="_blank" rel="noopener noreferrer">evidence</a>` : ""}
      ${flags ? `<div class="flags">flagged: ${esc(flags)}</div>` : ""}
    </div>`;
  }).join("") || `<div class="empty">No harm evidence yet.</div>`;

  const breakdownRows = Object.entries(bd)
    .filter(([k]) => !["inputs", "weights"].includes(k))
    .map(([k, v]) => `<div class="k">${esc(k)}</div><div>${esc(typeof v === "object" ? JSON.stringify(v) : v)}</div>`)
    .join("");

  document.getElementById("detail-panel").innerHTML = `
    <h1>@${esc(c.handle)} <span class="badge ${c.status}">${c.status.replace("_", " ")}</span></h1>
    <div class="sub">${esc(c.platform)} · <a href="${esc(c.url)}" target="_blank" rel="noopener noreferrer">${esc(c.url)}</a></div>

    <div class="card">
      <h3>Confidence</h3>
      <div class="score-row"><span class="score-big">${pct}%</span>
        <span>${score && score.enters_review ? "enters review queue" : "below threshold"}</span></div>
      <div class="bar"><span style="width:${pct}%"></span></div>
      <div class="kv">${breakdownRows || "<div>Not scored yet.</div>"}</div>
      <div class="actions"><button class="btn small" id="btn-score">Run / re-score</button></div>
    </div>

    <div class="card">
      <h3>Recommended channels</h3>
      ${recsHtml}
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
        <textarea id="harm-text" rows="2" placeholder="Captured text (e.g. the scam DM) — auto-classified"></textarea>
        <div class="row">
          <input id="harm-url" placeholder="Evidence URL (post / screenshot)" />
          <input id="harm-contact" placeholder="Reporter contact (optional)" />
        </div>
        <div><button class="btn small primary" id="btn-add-harm">Add evidence</button></div>
      </div>
    </div>

    <div class="card">
      <h3>Actions</h3>
      <div class="actions">
        <button class="btn small" id="btn-dossier">Download dossier PDF</button>
        <button class="btn small" id="btn-submitted">Mark submitted (by me)</button>
        <button class="btn small" id="btn-dismiss">Dismiss</button>
      </div>
      <div class="handoff-note">Submission is a manual human action and is recorded against your account.</div>
    </div>`;

  document.getElementById("btn-score").addEventListener("click", () => scoreCase(c.id));
  document.getElementById("btn-add-harm").addEventListener("click", () => addHarm(c.id));
  document.getElementById("btn-dossier").addEventListener("click", () => downloadDossier(c.id));
  document.getElementById("btn-submitted").addEventListener("click", () => setStatus(c.id, "submitted"));
  document.getElementById("btn-dismiss").addEventListener("click", () => setStatus(c.id, "dismissed"));
}

function channelLabel(ch) {
  return {
    dmca: "DMCA takedown (copyright)",
    fraud_report: "Fraud / scam report (critical)",
    defamation_notice: "Defamation notice (legal review)",
    impersonation_report: "Impersonation report (baseline)",
  }[ch] || ch;
}

// ---------------------------------------------------------------- actions
async function scoreCase(id) {
  try { await api(`/suspects/${id}/score`, { method: "POST" }); toast("Re-scored");
    await openCase(id); await loadCases(); }
  catch (e) { toast(e.message, true); }
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
  try { await api(`/cases/${id}/harm`, { method: "POST", body });
    toast("Evidence added & classified"); await openCase(id); }
  catch (e) { toast(e.message, true); }
}

async function setStatus(id, status) {
  try { await api(`/cases/${id}/status`, { method: "PATCH", body: { status, note: "" } });
    toast(`Marked ${status}`); await openCase(id); await loadCases(); }
  catch (e) { toast(e.message, true); }
}

async function downloadDossier(id) {
  try {
    const res = await fetch(`${API}/cases/${id}/dossier`, { method: "POST", headers: authHeaders() });
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

// ---------------------------------------------------------------- wiring
document.getElementById("login-form").addEventListener("submit", doLogin);
document.getElementById("logout").addEventListener("click", logout);
document.getElementById("status-filters").addEventListener("click", e => {
  if (e.target.tagName !== "BUTTON") return;
  currentFilter = e.target.dataset.status;
  document.querySelectorAll("#status-filters .chip").forEach(c => c.classList.remove("active"));
  e.target.classList.add("active");
  loadCases();
});

// boot
if (token) { enterApp().catch(() => logout()); }
