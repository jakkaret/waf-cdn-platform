const REFRESH_INTERVAL = 5000;

let currentLimit  = 10;
let currentStatus = "";

function getHttpStatus(log) {
    return log.transaction?.response?.http_code || log.status || 0;
}

document.addEventListener("DOMContentLoaded", () => {
    document.getElementById("limit-select").addEventListener("change", (e) => {
        currentLimit = e.target.value;
        loadLogs();
    });

    document.getElementById("status-filter").addEventListener("change", (e) => {
        currentStatus = e.target.value;
        loadLogs();
    });

    loadLogs();
    setInterval(loadLogs, REFRESH_INTERVAL);
});

async function loadLogs() {
    const res = await Auth.apiFetch(`/api/logs/recent?limit=${currentLimit}`);
    if (!res) return;

    const data = await res.json();
    if (!data.logs) return;

    let logs = data.logs;

    if (currentStatus) {
        logs = logs.filter(l =>
            String(l.transaction?.response?.http_code) === currentStatus
        );
    }

    renderStats(logs);
    renderLogs(logs);
}

function renderStats(logs) {
    const total   = logs.length;
    const blocked = logs.filter(l => Number(getHttpStatus(l)) === 403).length;
    const allowed = total - blocked;

    document.getElementById("total-events").textContent  = total;
    document.getElementById("blocked-count").textContent = blocked;
    document.getElementById("allowed-count").textContent = allowed;
}

function renderLogs(logs) {
    const tableBody = document.getElementById("live-logs-body");
    tableBody.innerHTML = "";

    logs.forEach(log => {
        const status = Number(getHttpStatus(log));
        const method = log.transaction?.request?.method || "-";
        const uri    = log.transaction?.request?.uri    || "-";
        const ip     = log.transaction?.client_ip       || "-";
        const time   = log.transaction?.time_local || log.time_local || "-";

        const row = document.createElement("tr");
        if (status === 403) row.style.backgroundColor = "#ffe5e5";

        row.innerHTML = `
            <td>${time}</td>
            <td>${ip}</td>
            <td>${method}</td>
            <td>${uri}</td>
            <td>${status}</td>
        `;

        tableBody.appendChild(row);
    });
}
