// ─────────────────────────────────────────────
// dashboard.js  —  WAF Live Dashboard
// Schema ref (DynamoDB fields used):
//   status      → Number  (403, 200, …)
//   url         → String  (/testattack)
//   method      → String  (GET, POST, …)
//   ip          → String
//   rule_id     → String | NULL
//   severity    → String | NULL
//   datetime    → String  (ISO-8601)
//   source      → String  (nginx / modsecurity)
// ─────────────────────────────────────────────

const REFRESH_INTERVAL = 5000;

let currentLimit  = 10;
let currentStatus = "";

// Chart instances (kept so we can destroy before re-draw)
let _statusChart = null;
let _ruleChart   = null;

// ── Palette ──────────────────────────────────
const STATUS_COLORS = {
    "200": { bg: "rgba(15,157,88,0.72)",  border: "#0f9d58" },
    "403": { bg: "rgba(245,124,0,0.72)",  border: "#f57c00" },
    "5xx": { bg: "rgba(217,48,37,0.72)",  border: "#d93025" },
    "other": { bg: "rgba(160,174,192,0.6)", border: "#a0aec0" },
};

const RULE_COLORS = [
    "#667eea","#f6ad55","#fc8181","#68d391","#76e4f7",
    "#b794f4","#fbd38d","#f687b3","#81e6d9","#a0aec0",
];

// ── Helpers ───────────────────────────────────
function getStatus(log) {
    // DynamoDB Number type comes back as a JS number or string from boto3
    return String(log.status ?? "0");
}

function getRuleId(log) {
    // rule_id is NULL or a string
    if (!log.rule_id || log.rule_id === true) return null;   // NULL marker from boto3
    return String(log.rule_id);
}

function getDatetime(log) {
    return log.datetime || log.time_local || "-";
}

function statusBucket(s) {
    if (s === "200" || s === "201" || s === "204") return "200";
    if (s === "403") return "403";
    if (s.startsWith("5"))  return "5xx";
    return "other";
}

// ── Init ─────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("limit-select").addEventListener("change", e => {
        currentLimit = e.target.value;
        loadLogs();
    });
    document.getElementById("status-filter").addEventListener("change", e => {
        currentStatus = e.target.value;
        loadLogs();
    });

    loadLogs();
    setInterval(loadLogs, REFRESH_INTERVAL);
});

// ── Fetch ─────────────────────────────────────
async function loadLogs() {
    const res = await Auth.apiFetch(`/api/logs/recent?limit=${currentLimit}`);
    if (!res) return;

    const data = await res.json();
    if (!data.logs) return;

    const allLogs = data.logs;

    // Filter for table only
    let filtered = allLogs;
    if (currentStatus) {
        filtered = allLogs.filter(l => {
            const s = getStatus(l);
            if (currentStatus === "500") return s.startsWith("5");
            return s === currentStatus;
        });
    }

    renderStats(allLogs);          // always use full set for stats
    renderStatusChart(allLogs);    // full set
    renderRuleChart(allLogs);      // full set (filter 403 inside)
    renderTable(filtered);

    const now = new Date();
    const el = document.getElementById("last-updated");
    if (el) el.textContent = `Updated ${now.toLocaleTimeString()}`;
}

// ── Stats ─────────────────────────────────────
function renderStats(logs) {
    const total   = logs.length;
    const blocked = logs.filter(l => getStatus(l) === "403").length;
    document.getElementById("total-events").textContent  = total;
    document.getElementById("blocked-count").textContent = blocked;
    document.getElementById("allowed-count").textContent = total - blocked;
}

// ── Bar chart: status codes ───────────────────
function renderStatusChart(logs) {
    const counts = {};
    logs.forEach(l => {
        const b = statusBucket(getStatus(l));
        counts[b] = (counts[b] || 0) + 1;
    });

    const order    = ["200","403","5xx","other"];
    const labelMap = { "200":"2xx Allow","403":"403 Block","5xx":"5xx Error","other":"Other" };

    const labels  = [];
    const values  = [];
    const bgs     = [];
    const borders = [];

    order.forEach(k => {
        if (counts[k]) {
            labels.push(labelMap[k]);
            values.push(counts[k]);
            bgs.push(STATUS_COLORS[k].bg);
            borders.push(STATUS_COLORS[k].border);
        }
    });

    const canvas = document.getElementById("statusChart");
    const empty  = document.getElementById("statusEmpty");

    if (values.length === 0) {
        canvas.style.display = "none";
        empty.style.display  = "flex";
        if (_statusChart) { _statusChart.destroy(); _statusChart = null; }
        return;
    }

    canvas.style.display = "block";
    empty.style.display  = "none";

    if (_statusChart) _statusChart.destroy();
    _statusChart = new Chart(canvas.getContext("2d"), {
        type: "bar",
        data: {
            labels,
            datasets: [{
                label: "Requests",
                data: values,
                backgroundColor: bgs,
                borderColor: borders,
                borderWidth: 1.5,
                borderRadius: 6,
                borderSkipped: false,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { callbacks: { label: c => ` ${c.parsed.y} requests` } }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { font: { size: 12, family: "'DM Sans',sans-serif" }, color: "#718096" }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: "rgba(0,0,0,0.045)" },
                    ticks: {
                        stepSize: 1,
                        font: { size: 11, family: "'DM Sans',sans-serif" },
                        color: "#a0aec0"
                    }
                }
            }
        }
    });
}

// ── Doughnut: rule_id breakdown ───────────────
function renderRuleChart(logs) {
    // Only look at 403 blocks; group by rule_id
    const blocked = logs.filter(l => getStatus(l) === "403");

    const counts = {};
    blocked.forEach(l => {
        const rid = getRuleId(l) || "Unknown / NULL";
        counts[rid] = (counts[rid] || 0) + 1;
    });

    // Sort desc, top 9
    const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 9);
    const labels = sorted.map(e => e[0]);
    const values = sorted.map(e => e[1]);

    const canvas = document.getElementById("ruleChart");
    const empty  = document.getElementById("ruleEmpty");

    if (values.length === 0) {
        canvas.style.display = "none";
        empty.style.display  = "flex";
        if (_ruleChart) { _ruleChart.destroy(); _ruleChart = null; }
        return;
    }

    canvas.style.display = "block";
    empty.style.display  = "none";

    if (_ruleChart) _ruleChart.destroy();
    _ruleChart = new Chart(canvas.getContext("2d"), {
        type: "doughnut",
        data: {
            labels,
            datasets: [{
                data: values,
                backgroundColor: RULE_COLORS.slice(0, labels.length).map(c => c + "cc"),
                borderColor:     RULE_COLORS.slice(0, labels.length),
                borderWidth: 1.5,
                hoverOffset: 8,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: "60%",
            plugins: {
                legend: {
                    position: "right",
                    labels: {
                        font: { size: 11, family: "'DM Sans',sans-serif" },
                        color: "#4a5568",
                        boxWidth: 12,
                        padding: 10,
                        usePointStyle: true,
                    }
                },
                tooltip: { callbacks: { label: c => ` ${c.label}: ${c.parsed} hits` } }
            }
        }
    });
}

// ── Table ─────────────────────────────────────
function renderTable(logs) {
    const tbody = document.getElementById("live-logs-body");
    tbody.innerHTML = "";

    if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" style="text-align:center;padding:40px;color:#a0aec0;">
            No logs matching filter</td></tr>`;
        return;
    }

    logs.forEach(log => {
        const status   = getStatus(log);
        const method   = log.method  || "-";
        const url      = log.url     || "-";
        const ip       = log.ip      || "-";
        const ruleId   = getRuleId(log) || "-";
        const severity = log.severity || "-";
        const dt       = getDatetime(log);

        // Format datetime nicely
        let timeDisplay = dt;
        try {
            if (dt && dt !== "-") {
                timeDisplay = new Date(dt).toLocaleTimeString("th-TH", {
                    hour: "2-digit", minute: "2-digit", second: "2-digit"
                });
            }
        } catch { /* keep raw */ }

        // Badge class
        let badgeClass = "badge-def";
        if (status === "200") badgeClass = "badge-200";
        else if (status === "403") badgeClass = "badge-403";
        else if (status.startsWith("5")) badgeClass = "badge-5xx";

        const tr = document.createElement("tr");
        if (status === "403") tr.style.backgroundColor = "#fff9f0";

        tr.innerHTML = `
            <td style="font-size:12px;color:#718096;white-space:nowrap;">${timeDisplay}</td>
            <td style="font-family:monospace;font-size:12px;">${ip}</td>
            <td><span class="badge bg-light text-dark border" style="font-size:11px;">${method}</span></td>
            <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px;"
                title="${url}">${url}</td>
            <td><span class="badge ${badgeClass}" style="font-size:11.5px;padding:3px 10px;border-radius:12px;font-weight:600;">${status}</span></td>
            <td style="font-family:monospace;font-size:12px;color:#667eea;">${ruleId}</td>
            <td style="font-size:12px;color:#718096;">${severity}</td>
        `;
        tbody.appendChild(tr);
    });
}