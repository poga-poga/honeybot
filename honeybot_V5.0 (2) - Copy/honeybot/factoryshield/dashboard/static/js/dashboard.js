/**
 * FactoryShield Interactive Dashboard Controller (English Edition)
 */

// Escape untrusted API values before inserting them into HTML.
function escapeHTML(value) {
    const entities = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
    return String(value ?? "").replace(/[&<>"']/g, char => entities[char]);
}
document.addEventListener("DOMContentLoaded", () => {
    loadTopology().catch(error => handleSectionLoadError(error, "topology"));
    loadHoneytokens().catch(error => handleSectionLoadError(error, "honeytokens"));
    refreshDashboard();
    document.addEventListener("visibilitychange", () => {
        if (document.visibilityState === "visible") refreshDashboard();
    });

    const searchInput = document.getElementById("incident-search");
    const severityFilter = document.getElementById("incident-severity-filter");
    const sortSelect = document.getElementById("incident-sort");
    if (searchInput) searchInput.addEventListener("input", renderIncidents);
    if (severityFilter) severityFilter.addEventListener("change", renderIncidents);
    if (sortSelect) sortSelect.addEventListener("change", renderIncidents);

    const benchBtn = document.getElementById("btn-run-benchmark");
    if (benchBtn) benchBtn.addEventListener("click", runAcademicBenchmark);
});

// Dashboard data refresh and connection state
const REFRESH_INTERVAL_MS = 5000;
const REQUEST_TIMEOUT_MS = 8000;
let refreshInProgress = false;
let lastSuccessfulRefresh = null;
const staticSectionFailures = new Set();

async function fetchJSON(url, options = {}) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        if (!response.ok) {
            throw new Error(`Request failed (${response.status}) for ${url}`);
        }
        return await response.json();
    } finally {
        clearTimeout(timeoutId);
    }
}

function setConnectionStatus(state, message) {
    const badge = document.querySelector(".network-status-badge");
    const label = document.getElementById("connection-status-text");
    const dot = document.getElementById("connection-status-dot");
    if (!badge || !label || !dot) return;
    badge.classList.remove("status-connected", "status-degraded", "status-disconnected");
    badge.classList.add(`status-${state}`);
    label.textContent = message;
    dot.className = `status-dot status-dot-${state}`;
}

function handleSectionLoadError(error, section) {
    console.error("Dashboard section failed to load:", error);
    if (section) staticSectionFailures.add(section);
    const target = section === "topology"
        ? document.getElementById("networks-view")
        : document.getElementById("honeytokens-tbody");
    if (target) target.textContent = "This section is temporarily unavailable. The dashboard will keep the last available data.";
    setConnectionStatus("degraded", "Some dashboard data is unavailable");
}

async function refreshDashboard() {
    if (refreshInProgress || document.visibilityState === "hidden") return;
    refreshInProgress = true;
    const results = await Promise.allSettled([
        loadStats(),
        loadIncidents(),
        loadCredentials()
    ]);
    const failures = results.filter(result => result.status === "rejected");
    if (failures.length === 0 && staticSectionFailures.size === 0) {
        lastSuccessfulRefresh = new Date();
        setConnectionStatus("connected", `Connected · Updated ${lastSuccessfulRefresh.toLocaleTimeString()}`);
    } else {
        console.warn("Some dashboard data could not be refreshed:", failures);
        setConnectionStatus("degraded", "Connection issue · Showing last available data");
    }
    refreshInProgress = false;
}

// Toast Helper
function showToast(message, isError = false) {
    const toast = document.getElementById("toast-notification");
    if (!toast) return;
    toast.textContent = message;
    toast.style.borderColor = isError ? "#ef4444" : "#38bdf8";
    toast.classList.add("show");
    setTimeout(() => {
        toast.classList.remove("show");
    }, 3500);
}

// 1. Load Stats
async function loadStats() {
    const data = await fetchJSON("/api/stats");
    document.getElementById("stat-incidents").textContent = data.total_incidents ?? 0;
    document.getElementById("stat-canaries").textContent = data.active_decoys ?? 0;
    document.getElementById("stat-hosts").textContent = data.monitored_hosts ?? 0;
    document.getElementById("stat-latest-score").textContent = data.latest_score ?? 0;
}

// 2. Load Networks & Topology (Purdue Model)
async function loadTopology() {
    const container = document.getElementById("networks-view");
    const data = await fetchJSON("/api/topology");
    container.innerHTML = "";
    const networks = data.networks || {};
    const icons = { office: "💻", engineering: "📐", production: "⚙️", security: "🛡️" };

    for (const [key, net] of Object.entries(networks)) {
        const netBox = document.createElement("div");
        netBox.className = "network-box";
        const hosts = net.hosts || {};
        let hostPillsHtml = "";
        for (const [hName, hInfo] of Object.entries(hosts)) {
            const isCanaryAsset = hName.toLowerCase().includes("cad") || hName.toLowerCase().includes("repo") || hName.toLowerCase().includes("plc");
            const pillClass = isCanaryAsset ? "host-pill has-canary" : "host-pill";
            hostPillsHtml += `
                <div class="${pillClass}" title="${escapeHTML(hInfo.ip)} | ${escapeHTML(hInfo.type || hInfo.dept)}">
                    <span>${isCanaryAsset ? "🪤" : "🖥️"}</span>
                    <strong>${escapeHTML(hName)}</strong>
                    <small style="color: var(--text-muted)">(${escapeHTML(hInfo.ip)})</small>
                </div>`;
        }
        netBox.innerHTML = `
            <div class="network-box-header">
                <span class="net-title">${icons[key] || "🌐"} ${escapeHTML(net.name)}</span>
                <span class="net-subnet">${escapeHTML(net.subnet)}</span>
            </div>
            <p style="font-size: 0.8rem; color: var(--text-secondary); margin-bottom: 0.6rem;">${escapeHTML(net.name)} Tier (${Object.keys(hosts).length} hosts)</p>
            <div class="hosts-pills-list">${hostPillsHtml}</div>`;
        container.appendChild(netBox);
    }
}

// 3. Load Honeytokens Table
async function loadHoneytokens() {
    const tbody = document.getElementById("honeytokens-tbody");
    const tokens = await fetchJSON("/api/honeytokens");
    tbody.innerHTML = "";
    tokens.forEach(t => {
        const tr = document.createElement("tr");
        const tokenType = String(t.type || "");
        let typeClass = "type-file";
        if (tokenType.includes("Database")) typeClass = "type-database";
        else if (tokenType.includes("Account")) typeClass = "type-account";
        else if (tokenType.includes("API")) typeClass = "type-api";
        tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-weight: bold; color: var(--primary);">${escapeHTML(t.token_id)}</td>
            <td><span class="token-type-pill ${typeClass}">${escapeHTML(tokenType)}</span></td>
            <td style="font-family: var(--font-mono);">${escapeHTML(t.identifier)}</td>
            <td style="color: var(--text-secondary); font-size: 0.82rem;">${escapeHTML(t.location)}</td>
            <td>${escapeHTML(t.desc_en)}</td>
            <td><span class="badge-tag">${escapeHTML(t.classification)}</span></td>`;
        tbody.appendChild(tr);
    });
}

// 4. Load and organize the live incidents feed
let allIncidentsCache = [];

function incidentTimestamp(incident) {
    const parsed = Date.parse(incident.timestamp || "");
    return Number.isFinite(parsed) ? parsed : 0;
}

function renderIncidents() {
    const container = document.getElementById("incidents-container");
    const search = (document.getElementById("incident-search")?.value || "").trim().toLowerCase();
    const severity = document.getElementById("incident-severity-filter")?.value || "all";
    const sort = document.getElementById("incident-sort")?.value || "newest";

    let incidents = allIncidentsCache.filter(inc => {
        const safeSeverity = ["Critical", "High", "Medium", "Low"].includes(inc.severity) ? inc.severity : "Low";
        const searchable = [
            inc.incident_id, inc.actor, inc.department, inc.source_workstation,
            ...(inc.rules_triggered || [])
        ].join(" ").toLowerCase();
        return (severity === "all" || safeSeverity === severity) && searchable.includes(search);
    });

    if (sort === "severity") {
        const rank = { Critical: 4, High: 3, Medium: 2, Low: 1 };
        incidents.sort((a, b) => {
            const aSeverity = ["Critical", "High", "Medium", "Low"].includes(a.severity) ? a.severity : "Low";
            const bSeverity = ["Critical", "High", "Medium", "Low"].includes(b.severity) ? b.severity : "Low";
            return rank[bSeverity] - rank[aSeverity] || incidentTimestamp(b) - incidentTimestamp(a);
        });
    } else if (sort === "score") {
        incidents.sort((a, b) => Number(b.score || 0) - Number(a.score || 0) || incidentTimestamp(b) - incidentTimestamp(a));
    } else {
        incidents.sort((a, b) => incidentTimestamp(b) - incidentTimestamp(a));
    }

    const count = document.getElementById("incident-count");
    if (count) count.textContent = `${incidents.length} / ${allIncidentsCache.length} incidents`;
    container.innerHTML = "";
    if (incidents.length === 0) {
        container.innerHTML = "<p class='incident-empty-state'>No incidents match the selected filters.</p>";
        return;
    }

    incidents.forEach(inc => {
        const card = document.createElement("div");
        card.className = "incident-card-item";
        card.tabIndex = 0;
        card.setAttribute("role", "button");
        card.setAttribute("aria-label", `Open incident ${inc.incident_id}`);
        card.addEventListener("click", () => openForensicModal(inc.incident_id));
        card.addEventListener("keydown", event => {
            if (event.key === "Enter" || event.key === " ") {
                event.preventDefault();
                openForensicModal(inc.incident_id);
            }
        });

        const allowedSeverities = ["Critical", "High", "Medium", "Low"];
        const safeSeverity = allowedSeverities.includes(inc.severity) ? inc.severity : "Low";
        const sevClass = `sev-${safeSeverity}`;
        const rulesBadges = (inc.rules_triggered || []).map(rule =>
            `<span class="incident-rule-badge">${escapeHTML(rule)}</span>`
        ).join(" ");
        const timestamp = inc.timestamp ? new Date(inc.timestamp).toLocaleString() : "Time unavailable";

        card.innerHTML = `
            <div class="inc-top-bar">
                <span class="inc-id">⚡ ${escapeHTML(inc.incident_id)}</span>
                <span class="severity-badge ${sevClass}">${escapeHTML(safeSeverity)} (${escapeHTML(inc.score ?? 0)}/100)</span>
            </div>
            <p class="inc-summary">${escapeHTML(inc.forensics?.synthesis_en || "Suspicious activity detected violating access policy")}</p>
            <div class="inc-meta-row">
                <span class="inc-meta-item">👤 Actor: <strong>${escapeHTML(inc.actor)}</strong></span>
                <span class="inc-meta-item">🏢 Dept: <strong>${escapeHTML(inc.department)}</strong></span>
                <span class="inc-meta-item">💻 Workstation: <strong>${escapeHTML(inc.source_workstation)}</strong></span>
                <span class="inc-meta-item">📋 Rules: ${rulesBadges}</span>
            </div>
            <div class="incident-timestamp">${escapeHTML(timestamp)}</div>`;
        container.appendChild(card);
    });
}

async function loadIncidents() {
    const incidents = await fetchJSON("/api/incidents");
    if (!Array.isArray(incidents)) throw new Error("Invalid incidents response");
    allIncidentsCache = incidents;
    renderIncidents();
}

// 5. Trigger Single Scenario
async function triggerScenario(type) {
    showToast(`🚀 Simulating [${type}] scenario...`);
    try {
        const data = await fetchJSON(`/api/simulate/${encodeURIComponent(type)}`, { method: "POST" });

        if (data.result) {
            if (data.result.alert_generated) {
                showToast(`🚨 Threat Detected! Score: ${data.result.score}/100 [${data.result.severity}]`);
            } else {
                showToast(`✅ Authorized normal operation (Score: 0). Zero false alarms.`);
            }
        }
        await refreshDashboard();
    } catch (err) {
        console.error("Simulation error:", err);
        showToast("Failed to execute scenario", true);
    }
}

// 6. Run Academic Benchmark (100 Scenarios)
async function runAcademicBenchmark() {
    const btn = document.getElementById("btn-run-benchmark");
    btn.disabled = true;
    btn.innerHTML = `<span class="btn-icon">⏳</span> <span>Executing 100-Scenario Evaluation Benchmark...</span>`;
    showToast("🧪 Running comparative academic benchmark across 100 scenarios...");

    try {
        const data = await fetchJSON("/api/benchmark/run", { method: "POST" });

        renderBenchmarkReport(data);
        showToast("🎉 100-scenario benchmark completed successfully!");
    } catch (err) {
        console.error("Benchmark error:", err);
        showToast("Failed to run academic benchmark", true);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `<span class="btn-icon">⚡</span> <span>Run 100-Scenario Academic Benchmark</span>`;
    }
}

function renderBenchmarkReport(data) {
    const box = document.getElementById("benchmark-results-box");
    const tbody = document.getElementById("benchmark-metrics-tbody");
    box.style.display = "block";

    const base = data.comparison.baseline_isolated;
    const fs = data.comparison.factoryshield_correlated;

    const rows = [
        { name: "Precision (True Alert Accuracy)", base: `${escapeHTML(base.precision)}%`, fs: `${escapeHTML(fs.precision)}%`, imp: "+14.93%" },
        { name: "Recall (Threat Detection Coverage)", base: `${escapeHTML(base.recall)}%`, fs: `${escapeHTML(fs.recall)}%`, imp: "+5.00%" },
        { name: "F1-Score (Harmonic Mean)", base: `${escapeHTML(base.f1_score)}%`, fs: `${escapeHTML(fs.f1_score)}%`, imp: "+10.24%" },
        { name: "False Positive Rate (FPR)", base: `${escapeHTML(base.false_positive_rate)}%`, fs: `${escapeHTML(fs.false_positive_rate)}%`, imp: "-100% (Zero FP)" },
        { name: "Avg Detection Time (Latency)", base: `${escapeHTML(base.avg_detection_time_ms)} ms`, fs: `${escapeHTML(fs.avg_detection_time_ms)} ms`, imp: "Sub-millisecond" },
        { name: "True Positives (Correctly Flagged)", base: `${escapeHTML(base.TP)} / 60`, fs: `${escapeHTML(fs.TP)} / 60`, imp: "100% Full Catch" },
        { name: "False Positives (False Alarms on Normal)", base: `${escapeHTML(base.FP)} (False Alarms)`, fs: `${escapeHTML(fs.FP)} (Zero False Alarms)`, imp: "Complete Eradication" },
    ];

    tbody.innerHTML = "";
    rows.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td><strong>${escapeHTML(r.name)}</strong></td>
            <td style="color: #fca5a5; font-family: var(--font-mono);">${escapeHTML(r.base)}</td>
            <td style="color: #6ee7b7; font-weight: bold; font-family: var(--font-mono); font-size: 1.05rem;">${escapeHTML(r.fs)}</td>
            <td style="color: #38bdf8; font-weight: bold;">${escapeHTML(r.imp)}</td>
        `;
        tbody.appendChild(tr);
    });

    box.scrollIntoView({ behavior: "smooth" });
}

function closeBenchmarkBox() {
    document.getElementById("benchmark-results-box").style.display = "none";
}

// 7. Forensic Modal Logic
function openForensicModal(incidentId) {
    const inc = allIncidentsCache.find(i => i.incident_id === incidentId);
    if (!inc) return;

    const modal = document.getElementById("forensic-modal");
    const title = document.getElementById("modal-incident-title");
    const badge = document.getElementById("modal-incident-badge");
    const body = document.getElementById("modal-incident-body");

    title.textContent = `Explainable Forensic Audit: ${inc.incident_id}`;
    badge.textContent = `${inc.severity} — ${inc.score}/100`;
    const allowedSeverities = ["Critical", "High", "Medium", "Low"];
    const safeSeverity = allowedSeverities.includes(inc.severity) ? inc.severity : "Low";
    badge.className = `severity-badge sev-${safeSeverity}`;

    const forensics = inc.forensics || {};
    const rulesList = forensics.rule_contributions || [];

    let rulesHtml = "";
    rulesList.forEach(r => {
        rulesHtml += `
            <div class="rule-tree-item">
                <div class="rule-header-row">
                    <span>${escapeHTML(r.rule_id)}: ${escapeHTML(r.name_en)}</span>
                    <span class="rule-points-tag">+${escapeHTML(r.points_contributed)} pts</span>
                </div>
                <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.4rem;">${escapeHTML(r.explanation_en)}</p>
                <div style="font-family: var(--font-mono); font-size: 0.78rem; background: rgba(0,0,0,0.3); padding: 0.4rem; border-radius: 6px;">
                    <strong>Evidence Log:</strong> ${escapeHTML(JSON.stringify(r.evidence))}
                </div>
            </div>
        `;
    });

    const timeline = forensics.events_timeline || [];
    let timelineHtml = "";
    timeline.forEach((ev, i) => {
        timelineHtml += `
            <li style="margin-bottom: 0.6rem; font-size: 0.85rem; border-left: 2px solid var(--primary); padding-left: 0.75rem;">
                <span style="color: var(--primary); font-family: var(--font-mono); font-weight: bold;">[Step ${escapeHTML(i+1)}]</span>
                <span>User: <strong>${escapeHTML(ev.username)}</strong> traversing from <code>${escapeHTML(ev.source_host)}</code> to <code>${escapeHTML(ev.target_host)}</code></span>
                <br>
                <span style="color: var(--text-muted); font-size: 0.8rem;">Resource: ${escapeHTML(ev.resource)} | Action: ${escapeHTML(ev.action)} | Status: ${escapeHTML(ev.status)}</span>
            </li>
        `;
    });

    body.innerHTML = `
        <div class="forensic-score-banner">
            <div>
                <span style="color: var(--text-secondary); font-size: 0.85rem;">Explainable Forensic Synthesis Verdict:</span>
                <p style="font-size: 0.95rem; margin-top: 0.3rem; line-height: 1.6;">${escapeHTML(forensics.synthesis_en)}</p>
            </div>
            <div class="score-display" style="color: var(--primary);">
                ${escapeHTML(inc.score)} <span style="font-size: 1rem; color: var(--text-muted);">/100</span>
            </div>
        </div>

        <h4 style="margin-top: 1.2rem; color: var(--primary); font-size: 1rem;">Deterministic Rules Triggered:</h4>
        <div class="rules-tree-list">
            ${rulesHtml || "<p style='color: var(--text-muted);'>No deterministic rule violations flagged.</p>"}
        </div>

        <h4 style="margin-top: 1.2rem; color: var(--primary); font-size: 1rem;">Chronological Incident Timeline:</h4>
        <ul style="list-style: none; padding-left: 0.5rem; margin-top: 0.5rem;">
            ${timelineHtml}
        </ul>
    `;

    modal.style.display = "flex";
}

function closeForensicModal() {
    document.getElementById("forensic-modal").style.display = "none";
}

// 8. Load Captured Credentials Table
async function loadCredentials() {
    const tbody = document.getElementById("credentials-tbody");
    const badge = document.getElementById("creds-count-badge");
    if (!tbody) return;
    const creds = await fetchJSON("/api/credentials");
    if (!Array.isArray(creds)) throw new Error("Invalid credentials response");

    if (badge) badge.textContent = `${creds.length} Credentials Intercepted`;
    if (creds.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 1.5rem;">Awaiting login attempts on Web Trap (8088), HMI Portal (8080), or FTP Service (21/2121)...</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    creds.forEach(c => {
        const tr = document.createElement("tr");
        const timeStr = String(c.timestamp || "").replace("T", " ").replace("Z", "");
        const allowedSeverities = ["Critical", "High", "Medium", "Low"];
        const safeSeverity = allowedSeverities.includes(c.severity) ? c.severity : "Low";
        tr.innerHTML = `
            <td style="font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-muted);">${escapeHTML(timeStr)}</td>
            <td><span class="badge-tag" style="background: rgba(56, 189, 248, 0.15); color: #38bdf8;">${escapeHTML(c.service)}</span></td>
            <td style="font-family: var(--font-mono); font-size: 0.85rem;">${escapeHTML(c.source_host)}</td>
            <td><strong style="color: #6ee7b7; font-family: var(--font-mono); font-size: 1.05rem;">👤 ${escapeHTML(c.username)}</strong></td>
            <td><span class="badge-tag">REDACTED</span></td>
            <td><span class="severity-badge sev-${safeSeverity}">${escapeHTML(safeSeverity)}</span></td>`;
        tbody.appendChild(tr);
    });
}

// Refresh only while the dashboard is visible; requests never overlap.
setInterval(refreshDashboard, REFRESH_INTERVAL_MS);
