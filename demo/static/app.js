/**
 * SICA Dashboard — app.js
 *
 * Handles:
 *   - Tab navigation
 *   - Loading /api/config on startup
 *   - Dataset analysis (POST /api/datasets)
 *   - Test cases (POST /api/tests)
 *   - Attack demonstration (POST /api/session)
 *
 * All detection logic runs on the Python backend (run.py).
 * This file only handles UI rendering.
 */

/* ============================================================
   Tab navigation
============================================================ */
document.querySelectorAll(".nav-tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".nav-tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
  });
});


/* ============================================================
   Utility helpers
============================================================ */
function fmt(n) {
  // Format number to 4 decimal places
  return parseFloat(n).toFixed(4);
}

function resultBadge(result) {
  const cls = result === "ALLOW" ? "badge-allow" : "badge-alert";
  return `<span class="${cls}">${result}</span>`;
}

function statusBadge(status) {
  const cls = status === "PASS" ? "badge-pass" : "badge-fail";
  return `<span class="${cls}">${status}</span>`;
}

function hijackBadge(val) {
  const isYes = val === "yes";
  return `<span class="${isYes ? "badge-yes" : "badge-no"}">${val}</span>`;
}

function showError(el, msg) {
  el.innerHTML = `<div class="error-msg">${msg}</div>`;
}

function clearError(el) {
  el.innerHTML = "";
}


/* ============================================================
   Load configuration from SICA engine on page start
============================================================ */
async function loadConfig() {
  try {
    const res  = await fetch("/api/config");
    const cfg  = await res.json();

    document.getElementById("cfg-threshold").textContent = fmt(cfg.THRESHOLD);
    document.getElementById("cfg-wagent").textContent    = fmt(cfg.W_AGENT);
    document.getElementById("cfg-wnetwork").textContent  = fmt(cfg.W_NETWORK);
    document.getElementById("cfg-wfork").textContent     = fmt(cfg.W_FORK);

    document.getElementById("v-only").textContent  = cfg.VERSION_ONLY;
    document.getElementById("same16").textContent  = cfg.SAME_16;
    document.getElementById("same24").textContent  = cfg.SAME_24;

    document.getElementById("formula-display").innerHTML =
      `Risk = <em>${cfg.W_AGENT}</em> × user_agent_change\n` +
      `     + <em>${cfg.W_NETWORK}</em> × network_change\n` +
      `     + <em>${cfg.W_FORK}</em> × old_client_back`;

    document.getElementById("risk-threshold").textContent = fmt(cfg.THRESHOLD);

    // Store threshold for demo use
    window.SICA_THRESHOLD = cfg.THRESHOLD;

  } catch (e) {
    console.error("Failed to load SICA config:", e);
  }
}

loadConfig();


/* ============================================================
   Dataset Analysis
============================================================ */
document.getElementById("btn-run-datasets").addEventListener("click", async () => {
  const btn   = document.getElementById("btn-run-datasets");
  const errEl = document.getElementById("datasets-error");

  btn.disabled = true;
  btn.innerHTML = `<span class="loading"></span>Running…`;
  clearError(errEl);

  try {
    const res  = await fetch("/api/datasets", { method: "POST" });
    const data = await res.json();

    if (data.error) { showError(errEl, data.error); return; }

    // Render summary cards
    const summaryEl = document.getElementById("datasets-summary");
    summaryEl.style.display = "";
    summaryEl.innerHTML = Object.entries(data.summary).map(([ds, s]) => {
      const detRate = s.hijacked > 0 ? ((s.caught / s.hijacked) * 100).toFixed(1) : "N/A";
      const faRate  = s.normal   > 0 ? ((s.alerts - s.caught) / s.normal * 100).toFixed(1) : "N/A";
      return `
        <div class="dataset-card">
          <h4>Dataset ${ds}</h4>
          <div class="ds-stat"><span class="ds-label">Sessions</span>  <span class="ds-val">${s.sessions}</span></div>
          <div class="ds-stat"><span class="ds-label">Normal</span>    <span class="ds-val">${s.normal}</span></div>
          <div class="ds-stat"><span class="ds-label">Hijacked</span>  <span class="ds-val">${s.hijacked}</span></div>
          <div class="ds-stat"><span class="ds-label">Alerts</span>    <span class="ds-val">${s.alerts}</span></div>
          <div class="ds-stat"><span class="ds-label">Detected</span>  <span class="ds-val">${s.caught} / ${s.hijacked}</span></div>
          <div class="ds-stat"><span class="ds-label">Detection Rate</span><span class="ds-val">${detRate}%</span></div>
        </div>`;
    }).join("");

    // Render per-session table
    const tbody = document.getElementById("datasets-tbody");
    tbody.innerHTML = data.rows.map(r => `
      <tr>
        <td><strong>${r.dataset}</strong></td>
        <td class="mono">${r.session_id}</td>
        <td class="mono">${r.requests}</td>
        <td>${hijackBadge(r.simulated_hijack)}</td>
        <td class="mono">${r.peak_risk}</td>
        <td>${resultBadge(r.result)}</td>
      </tr>`).join("");

    document.getElementById("datasets-table-wrap").style.display = "";

  } catch (e) {
    showError(errEl, "Request failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "Run Analysis";
  }
});


/* ============================================================
   Test Cases
============================================================ */
document.getElementById("btn-run-tests").addEventListener("click", async () => {
  const btn   = document.getElementById("btn-run-tests");
  const errEl = document.getElementById("tests-error");

  btn.disabled = true;
  btn.innerHTML = `<span class="loading"></span>Running…`;
  clearError(errEl);

  try {
    const res  = await fetch("/api/tests", { method: "POST" });
    const data = await res.json();

    if (data.error) { showError(errEl, data.error); return; }

    // Summary bar
    const sumEl = document.getElementById("tests-summary");
    sumEl.style.display = "";
    document.getElementById("tst-total").textContent  = data.total;
    document.getElementById("tst-passed").textContent = data.passed;
    document.getElementById("tst-failed").textContent = data.failed;
    const rate = data.total > 0 ? ((data.passed / data.total) * 100).toFixed(1) + "%" : "—";
    document.getElementById("tst-rate").textContent = rate;

    // Table
    const tbody = document.getElementById("tests-tbody");
    tbody.innerHTML = data.rows.map(r => `
      <tr>
        <td class="mono">${r.test_id}</td>
        <td>${r.name}</td>
        <td>${resultBadge(r.expected)}</td>
        <td>${resultBadge(r.got)}</td>
        <td class="mono">${r.risk}</td>
        <td>${statusBadge(r.status)}</td>
      </tr>`).join("");

    document.getElementById("tests-table-wrap").style.display = "";

  } catch (e) {
    showError(errEl, "Request failed: " + e.message);
  } finally {
    btn.disabled = false;
    btn.innerHTML = "Run Tests";
  }
});


/* ============================================================
   Attack Demonstration
============================================================ */
let sessionHistory = [];   // [{ip, ua}, ...]
let requestCounter = 0;
let sessionFrozen  = false; // true once SICA raises ALERT: no more requests
let requestBusy    = false; // a request is in flight

/*
 * Session flow (UI only, scoring stays in run.py):
 *   no baseline -> Normal User READY, Attacker FROZEN
 *   active      -> both READY
 *   ALERT       -> session FROZEN, both blocked until New Session
 */
function setPanel(panel, prefix, ready, hint) {
  const panelEl = document.getElementById(panel);
  const stateEl = document.getElementById(prefix + "-state");
  panelEl.classList.toggle("is-frozen", !ready);
  panelEl.querySelectorAll("input, select, button").forEach(el => { el.disabled = !ready || requestBusy; });
  stateEl.textContent = ready ? "READY" : "FROZEN";
  stateEl.className   = "panel-state " + (ready ? "state-ready" : "state-frozen");
  document.getElementById(prefix + "-hint").textContent = hint;
}

function renderSessionState() {
  const started = requestCounter > 0;
  const stateEl = document.getElementById("session-state");

  if (sessionFrozen) {
    setPanel("normal-panel",   "normal",   false, "Session frozen by SICA. Start a new session.");
    setPanel("attacker-panel", "attacker", false, "Session frozen by SICA. Start a new session.");
    stateEl.textContent = "FROZEN";
    stateEl.className   = "session-state state-frozen";
  } else if (started) {
    setPanel("normal-panel",   "normal",   true, "Baseline established. Keep browsing as the owner.");
    setPanel("attacker-panel", "attacker", true, "Replay the stolen session ID from another client.");
    stateEl.textContent = "ACTIVE";
    stateEl.className   = "session-state state-active";
  } else {
    setPanel("normal-panel",   "normal",   true, "Send the first request to establish the session baseline.");
    setPanel("attacker-panel", "attacker", false, "Locked until the normal user establishes the session.");
    stateEl.textContent = "NOT STARTED";
    stateEl.className   = "session-state";
  }
  // the session ID can only be changed before the first request
  document.getElementById("inp-session-id").disabled = started;
}

function showFrozenBanner(data) {
  const banner = document.getElementById("frozen-banner");
  banner.innerHTML = `<strong>ALERT: session frozen at request ${data.alert_request}</strong>
    ${data.alert_reason || "Client-binding change exceeded the risk threshold"}.
    No further requests are accepted. Click <em>New Session</em> to start again.`;
  banner.style.display = "";
}

function updateRiskCard(decision, risk, threshold) {
  const card    = document.getElementById("risk-card");
  const verdict = document.getElementById("risk-verdict");
  const scoreEl = document.getElementById("risk-score");
  const thrEl   = document.getElementById("risk-threshold");

  card.classList.remove("state-allow", "state-alert");
  if (decision === "ALLOW") {
    card.classList.add("state-allow");
    verdict.textContent = "SESSION ALLOWED";
  } else {
    card.classList.add("state-alert");
    verdict.textContent = "SESSION HIJACKING DETECTED";
  }
  scoreEl.textContent = fmt(risk);
  thrEl.textContent   = fmt(threshold);
}

function updateBindingCard(data) {
  const card = document.getElementById("binding-card");
  card.style.display = "";
  document.getElementById("binding-rows").innerHTML = `
    <div class="binding-row">
      <span class="binding-key">Session</span>
      <span class="binding-val">${document.getElementById("inp-session-id").value || "SID-DEMO-001"}</span>
    </div>
    <div class="binding-row">
      <span class="binding-key">IP</span>
      <span class="binding-val">${data.ip}</span>
    </div>
    <div class="binding-row">
      <span class="binding-key">Browser</span>
      <span class="binding-val">${data.browser}${data.version ? " " + data.version : ""}</span>
    </div>
    <div class="binding-row">
      <span class="binding-key">OS</span>
      <span class="binding-val">${data.os}</span>
    </div>
    <div class="binding-row">
      <span class="binding-key">Device</span>
      <span class="binding-val">${data.device}</span>
    </div>`;
}

function addTimelineEntry(n, data, sender) {
  const timeline = document.getElementById("timeline");
  // Remove empty-state placeholder on first entry
  const empty = timeline.querySelector(".empty-state");
  if (empty) empty.remove();

  const isAlert = data.decision === "ALERT";
  const cls     = isAlert ? "tl-alert" : "tl-allow";
  const bdgCls  = isAlert ? "tl-alert-badge" : "tl-allow-badge";

  const item = document.createElement("div");
  item.className = `tl-item ${cls}`;
  item.innerHTML = `
    <div class="tl-header">
      <span class="tl-req-num">Request ${n} — ${sender}</span>
      <span class="tl-decision-badge ${bdgCls}">${data.decision}</span>
    </div>
    <div class="tl-client">${data.ip} · ${data.browser}${data.version ? " " + data.version : ""}</div>
    <div class="tl-details">
      <div class="tl-detail">OS: <span>${data.os}</span></div>
      <div class="tl-detail">Device: <span>${data.device}</span></div>
      <div class="tl-detail">Network: <span>${data.net_label}</span></div>
      <div class="tl-detail">User-Agent: <span>${data.agent_label}</span></div>
      <div class="tl-detail">Fork: <span>${data.fork_label}</span></div>
    </div>
    <div class="tl-risk-line">
      Risk: <span class="tl-risk-num">${fmt(data.risk)}</span>
      &nbsp;·&nbsp; Threshold: ${fmt(data.threshold)}
    </div>`;

  // Prepend so newest is at top
  timeline.insertBefore(item, timeline.firstChild);
}

async function sendRequest(ip, ua, sender) {
  // Guard the flow even if a disabled button is triggered somehow
  if (sessionFrozen || requestBusy) return;
  if (sender !== "Normal User" && requestCounter === 0) return;

  const payload = {
    history: sessionHistory.map(h => ({ ip: h.ip, ua: h.ua })),
    ip,
    ua,
  };

  requestBusy = true;
  renderSessionState();
  try {
    const res  = await fetch("/api/session", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify(payload),
    });
    if (!res.ok) throw new Error("server returned " + res.status);
    const data = await res.json();

    // Record in history (store resolved UA shortcut so subsequent calls remain consistent)
    sessionHistory.push({ ip, ua });
    requestCounter++;

    updateRiskCard(data.decision, data.risk, data.threshold);
    updateBindingCard(data);
    addTimelineEntry(requestCounter, data, sender);

    if (data.decision === "ALERT") {
      sessionFrozen = true;
      showFrozenBanner(data);
    }
  } finally {
    requestBusy = false;
    renderSessionState();
  }
}

document.getElementById("btn-send-normal").addEventListener("click", async () => {
  const ip = document.getElementById("inp-normal-ip").value.trim();
  const ua = document.getElementById("inp-normal-ua").value;
  if (!ip) { alert("Please enter an IP address for the normal user."); return; }
  try {
    await sendRequest(ip, ua, "Normal User");
  } catch (e) {
    alert("Error: " + e.message);
  }
});

document.getElementById("btn-send-attacker").addEventListener("click", async () => {
  const ip = document.getElementById("inp-attacker-ip").value.trim();
  const ua = document.getElementById("inp-attacker-ua").value;
  if (!ip) { alert("Please enter an IP address for the attacker."); return; }
  try {
    await sendRequest(ip, ua, "Simulated Attacker");
  } catch (e) {
    alert("Error: " + e.message);
  }
});

/* Reset — clears only the demo session, never touches result files */
document.getElementById("btn-reset").addEventListener("click", () => {
  sessionHistory = [];
  requestCounter = 0;
  sessionFrozen  = false;
  document.getElementById("frozen-banner").style.display = "none";

  const card    = document.getElementById("risk-card");
  const verdict = document.getElementById("risk-verdict");
  const scoreEl = document.getElementById("risk-score");

  card.classList.remove("state-allow", "state-alert");
  verdict.textContent = "Waiting for activity";
  scoreEl.textContent = "—";

  document.getElementById("binding-card").style.display = "none";

  const timeline = document.getElementById("timeline");
  timeline.innerHTML = '<div class="empty-state">No requests yet. Use the panels above to simulate session activity.</div>';

  renderSessionState();
});

renderSessionState();
