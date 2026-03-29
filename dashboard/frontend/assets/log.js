// ═══════════════════════════════════════════
// State
// ═══════════════════════════════════════════
let _allLogs    = [];
let _filtered   = [];
let _displayed  = [];

let _sortKey    = "datetime";
let _sortDir    = -1;

let _page       = 1;
const PAGE_SIZE = 25;

let _autoTimer  = null;
const REFRESH_MS = 8000;

// ═══════════════════════════════════════════
// Init
// ═══════════════════════════════════════════
document.addEventListener("DOMContentLoaded", () => {
    Auth.renderShell("logs");
    loadLogs();

    document.getElementById("auto-refresh-toggle").addEventListener("change", e => {
        if (e.target.checked) startAutoRefresh();
        else stopAutoRefresh();
    });

    document.getElementById("f-search").addEventListener("keydown", e => {
        if (e.key === "Enter") applyFilters();
    });

    startAutoRefresh();
});

// ═══════════════════════════════════════════
// Auto refresh
// ═══════════════════════════════════════════
function startAutoRefresh() {
    stopAutoRefresh();
    _autoTimer = setInterval(loadLogs, REFRESH_MS);
    document.getElementById("auto-refresh-badge").style.display = "";
}

function stopAutoRefresh() {
    if (_autoTimer) { clearInterval(_autoTimer); _autoTimer = null; }
    document.getElementById("auto-refresh-badge").style.display = "none";
}

// ═══════════════════════════════════════════
// Fetch Logs
// ═══════════════════════════════════════════
async function loadLogs() {
    const limit = document.getElementById("f-limit").value;
    const res = await Auth.apiFetch(`/api/logs/recent?limit=${limit}`);
    if (!res) return;

    const data = await res.json();
    _allLogs = data.logs || [];

    updateSummary(_allLogs);
    applyFilters();

    const now = new Date();
    document.getElementById("last-upd").textContent =
        `— ${now.toLocaleTimeString("th-TH")}`;
}

// ═══════════════════════════════════════════
// Summary
// ═══════════════════════════════════════════
function updateSummary(logs) {
    document.getElementById("s-total").textContent = logs.length;
    document.getElementById("s-403").textContent   = logs.filter(l => String(l.status) === "403").length;
    document.getElementById("s-200").textContent   = logs.filter(l => ["200","201","204"].includes(String(l.status))).length;
    document.getElementById("s-5xx").textContent   = logs.filter(l => String(l.status).startsWith("5")).length;
    document.getElementById("s-susp").textContent  = logs.filter(l => l.is_suspicious_path === true).length;
    document.getElementById("s-ips").textContent   = new Set(logs.map(l => l.ip)).size;
}

// ═══════════════════════════════════════════
// Filter + Sort
// ═══════════════════════════════════════════
function applyFilters() {
    const search   = document.getElementById("f-search").value.toLowerCase();
    const fStatus  = document.getElementById("f-status").value;
    const fMethod  = document.getElementById("f-method").value;
    const fSev     = document.getElementById("f-severity").value;
    const fSource  = document.getElementById("f-source").value;
    const fSusp    = document.getElementById("f-susp").value;

    _filtered = _allLogs.filter(log => {
        const s = String(log.status ?? "");

        if (fStatus === "200" && !["200","201","204"].includes(s)) return false;
        if (fStatus === "403" && s !== "403") return false;
        if (fStatus === "5xx" && !s.startsWith("5")) return false;

        if (fMethod && (log.method || "").toUpperCase() !== fMethod) return false;

        if (fSev === "null") { if (log.severity && log.severity !== "null") return false; }
        else if (fSev && (log.severity || "").toUpperCase() !== fSev) return false;

        if (fSource && (log.source || "").toLowerCase() !== fSource) return false;

        if (fSusp === "true"  && !log.is_suspicious_path) return false;
        if (fSusp === "false" && log.is_suspicious_path) return false;

        if (search) {
            const haystack = Object.values(log).join(" ").toLowerCase();
            if (!haystack.includes(search)) return false;
        }

        return true;
    });

    _filtered.sort((a, b) => {
        let av = a[_sortKey] ?? "";
        let bv = b[_sortKey] ?? "";
        return String(av).localeCompare(String(bv)) * _sortDir;
    });

    _page = 1;
    renderTable();
    renderPagination();
}

// ═══════════════════════════════════════════
// Table Render
// ═══════════════════════════════════════════
function renderTable() {
    const tbody = document.getElementById("logs-body");

    const start = (_page - 1) * PAGE_SIZE;
    _displayed  = _filtered.slice(start, start + PAGE_SIZE);

    if (_displayed.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9">No logs</td></tr>`;
        return;
    }

    tbody.innerHTML = _displayed.map((log, i) => `
        <tr onclick="openDrawer(${start + i})">
            <td>${log.datetime || "-"}</td>
            <td>${log.ip || "-"}</td>
            <td>${log.method || "-"}</td>
            <td>${log.url || "-"}</td>
            <td>${log.status || "-"}</td>
            <td>${log.rule_id || "-"}</td>
            <td>${log.severity || "-"}</td>
            <td>${log.source || "-"}</td>
            <td>${log.is_suspicious_path ? "⚠" : "-"}</td>
        </tr>
    `).join("");
}

// ═══════════════════════════════════════════
// Pagination
// ═══════════════════════════════════════════
function renderPagination() {
    const total = _filtered.length;
    const pages = Math.ceil(total / PAGE_SIZE);

    const btns = document.getElementById("page-btns");
    if (pages <= 1) { btns.innerHTML = ""; return; }

    let html = "";
    for (let p = 1; p <= pages; p++) {
        html += `<button onclick="goPage(${p})">${p}</button>`;
    }
    btns.innerHTML = html;
}

function goPage(p) {
    _page = p;
    renderTable();
}

// ═══════════════════════════════════════════
// Drawer
// ═══════════════════════════════════════════
function openDrawer(idx) {
    const log = _filtered[idx];
    document.getElementById("drawer-body").innerText =
        JSON.stringify(log, null, 2);

    document.getElementById("overlay").classList.add("open");
    document.getElementById("drawer").classList.add("open");
}

function closeDrawer() {
    document.getElementById("overlay").classList.remove("open");
    document.getElementById("drawer").classList.remove("open");
}