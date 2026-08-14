// Sentinel EDR Dashboard Real-Time WebSocket Client
const ws_protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
const ws_url = `${ws_protocol}//${window.location.host}/ws/telemetry/`;
let socket = null;

function connectWebSocket() {
    console.log("EDR SOC Console: Initiating handshake at " + ws_url);
    socket = new WebSocket(ws_url);

    socket.onopen = function() {
        console.log("EDR SOC Console: Live connection established.");
        showNotification("Security connection online.", "success");
    };

    socket.onmessage = function(e) {
        try {
            const data = JSON.parse(e.data);
            handleRealTimeEvent(data);
        } catch (err) {
            console.error("EDR SOC Console: Parse error:", err);
        }
    };

    socket.onclose = function() {
        console.warn("EDR SOC Console: Disconnected. Attempting reconnection in 3s...");
        setTimeout(connectWebSocket, 3000);
    };

    socket.onerror = function(err) {
        console.error("EDR SOC Console: Connection error:", err);
        socket.close();
    };
}

function showNotification(message, type) {
    // Show toast alerts dynamically
    const container = document.querySelector("main div.fixed");
    if (!container) return;
    
    const count = Math.floor(Math.random() * 1000);
    const toast = document.createElement("div");
    toast.id = `toast-ws-${count}`;
    toast.className = `px-md py-sm rounded border ${
        type === 'success' ? 'bg-surface-container-high border-secondary-container text-secondary-container glow-active' : 'bg-error-container/20 border-error text-error glow-critical'
    } flex items-center gap-md transition-all duration-300 transform translate-x-0`;
    
    toast.innerHTML = `
        <span class="material-symbols-outlined text-md">
            ${type === 'success' ? 'check_circle' : 'warning'}
        </span>
        <span class="font-label-mono text-xs">${message}</span>
        <button onclick="document.getElementById('toast-ws-${count}').remove()" class="text-on-surface-variant hover:text-on-surface">
            <span class="material-symbols-outlined text-sm">close</span>
        </button>
    `;
    
    container.appendChild(toast);
    setTimeout(() => {
        const t = document.getElementById(`toast-ws-${count}`);
        if (t) {
            t.classList.add('opacity-0', 'translate-x-full');
            setTimeout(() => t.remove(), 300);
        }
    }, 4000);
}

function handleRealTimeEvent(payload) {
    const eventType = payload.event_type;
    const content = payload.content;

    // Trigger stats updates on all pages containing summary cards
    if (eventType === 'alert') {
        showNotification(`ALERT TRIGGERED: ${content.type} on ${content.hostname}`, "error");
        fetchStatsAndRefreshCards();
        addAlertToDashboardFeed(content);
        addAlertToGeneralFeed(content);
    }

    if (eventType === 'process') {
        addProcessToPageTable(content);
    }

    if (eventType === 'service') {
        updateServiceRow(content);
    }

    if (eventType === 'health') {
        updateLiveCharts(content);
    }
}

function fetchStatsAndRefreshCards() {
    // Pull the statistics from Django endpoint
    fetch('/api/dashboard/stats/')
        .then(res => res.json())
        .then(data => {
            // Update counts on page
            const criticalAlerts = document.querySelector("#critical-alerts-val");
            const highAlerts = document.querySelector("#high-alerts-val");
            const mediumAlerts = document.querySelector("#medium-alerts-val");
            const lowAlerts = document.querySelector("#low-alerts-val");

            if (criticalAlerts) criticalAlerts.innerText = data.critical_alerts;
            if (highAlerts) highAlerts.innerText = data.high_alerts;
            if (mediumAlerts) mediumAlerts.innerText = data.medium_alerts;
            if (lowAlerts) lowAlerts.innerText = data.low_alerts;
        })
        .catch(err => console.error("Error updating stats cards:", err));
}

function addAlertToDashboardFeed(alert) {
    const feedBody = document.querySelector("#recent-alerts-table-body");
    if (!feedBody) return;

    // Remove empty row if present
    const emptyRow = feedBody.querySelector("tr td.text-center");
    if (emptyRow) {
        feedBody.innerHTML = "";
    }

    const tr = document.createElement("tr");
    tr.className = "hover:bg-surface-container-high/40 transition-colors animate-pulse";
    
    let severityClass = "bg-blue-950/40 text-blue-400 border border-blue-500/30";
    if (alert.severity === 'critical') severityClass = "bg-red-950/40 text-red-400 border border-red-500/30";
    else if (alert.severity === 'high') severityClass = "bg-orange-950/40 text-orange-400 border border-orange-500/30";
    else if (alert.severity === 'medium') severityClass = "bg-yellow-950/40 text-yellow-400 border border-yellow-500/30";

    const timestampStr = new Date(alert.timestamp).toISOString().replace('T', ' ').substring(0, 19);

    tr.innerHTML = `
        <td class="py-md px-xs">
            <span class="px-sm py-0.5 rounded text-[10px] font-bold uppercase ${severityClass}">
                ${alert.severity}
            </span>
        </td>
        <td class="py-md font-bold text-secondary-container">${alert.type}</td>
        <td class="py-md">${alert.hostname}</td>
        <td class="py-md">${alert.username}</td>
        <td class="py-md text-on-surface-variant max-w-xs truncate" title="${alert.description}">${alert.description}</td>
        <td class="py-md text-right text-on-surface-variant">${timestampStr}</td>
    `;

    feedBody.insertBefore(tr, feedBody.firstChild);
    
    // Cap table size to 10 rows
    if (feedBody.children.length > 10) {
        feedBody.removeChild(feedBody.lastChild);
    }
}

function addAlertToGeneralFeed(alert) {
    const alertsFeed = document.querySelector("#alerts-list-container");
    if (!alertsFeed) return;

    const noAlerts = alertsFeed.querySelector("div.text-center");
    if (noAlerts) {
        alertsFeed.innerHTML = "";
    }

    let borderClass = "border-blue-500/30 border-l-4 border-l-blue-500";
    let badgeClass = "bg-blue-950/40 text-blue-400 border border-blue-500/30";
    if (alert.severity === 'critical') {
        borderClass = "border-red-500/30 border-l-4 border-l-red-500";
        badgeClass = "bg-red-950/40 text-red-400 border border-red-500/30";
    } else if (alert.severity === 'high') {
        borderClass = "border-orange-500/30 border-l-4 border-l-orange-500";
        badgeClass = "bg-orange-950/40 text-orange-400 border border-orange-500/30";
    } else if (alert.severity === 'medium') {
        borderClass = "border-yellow-500/30 border-l-4 border-l-yellow-500";
        badgeClass = "bg-yellow-950/40 text-yellow-400 border border-yellow-500/30";
    }

    const timestampStr = new Date(alert.timestamp).toISOString().replace('T', ' ').substring(0, 19);

    const div = document.createElement("div");
    div.className = `border rounded-lg bg-surface-container-high/40 p-md flex flex-col gap-sm relative transition-all duration-200 hover:bg-surface-container-high/70 ${borderClass} animate-pulse`;
    
    div.innerHTML = `
        <div class="flex flex-wrap justify-between items-start gap-sm">
            <div class="flex items-center gap-sm">
                <span class="px-sm py-0.5 rounded text-[10px] font-bold uppercase ${badgeClass}">
                    ${alert.severity}
                </span>
                <h4 class="font-bold text-sm text-secondary-container uppercase">${alert.type}</h4>
            </div>
            <div class="flex items-center gap-md">
                <span class="font-label-mono text-[10px] text-on-surface-variant">${timestampStr}</span>
                <span class="text-yellow-400 font-label-mono text-[10px] font-bold uppercase">⚡ NEW RECEIVED</span>
            </div>
        </div>

        <p class="text-xs text-on-surface">${alert.description}</p>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-sm border-t border-outline-variant/30 pt-sm mt-xs font-label-mono text-[10px] text-on-surface-variant">
            <div>
                <span class="font-bold text-on-surface uppercase">Endpoint:</span> ${alert.hostname}
            </div>
            <div>
                <span class="font-bold text-on-surface uppercase">Username:</span> ${alert.username}
            </div>
            <div>
                <span class="font-bold text-on-surface uppercase">MITRE ATT&CK:</span> ${alert.mitre_technique}
            </div>
        </div>

        ${alert.recommendation ? `
        <div class="mt-xs bg-[#070b14] border border-outline-variant/50 rounded p-xs text-[10px]">
            <span class="font-bold text-secondary-container uppercase">Analyst Recommendation:</span>
            <p class="text-on-surface-variant mt-0.5">${alert.recommendation}</p>
        </div>
        ` : ''}
    `;

    alertsFeed.insertBefore(div, alertsFeed.firstChild);
}

function addProcessToPageTable(proc) {
    const procBody = document.querySelector("#processes-table-body");
    if (!procBody) return;

    const empty = procBody.querySelector("tr td.text-center");
    if (empty) {
        procBody.innerHTML = "";
    }

    const tr = document.createElement("tr");
    tr.className = `hover:bg-surface-container-high/40 transition-colors animate-pulse ${
        proc.is_suspicious ? 'bg-error-container/5 border-l-2 border-l-error' : ''
    }`;

    tr.innerHTML = `
        <td class="py-md px-xs font-bold">${proc.hostname}</td>
        <td class="py-md text-secondary-container">${proc.pid}</td>
        <td class="py-md text-on-surface-variant">${proc.ppid}</td>
        <td class="py-md font-bold text-on-surface max-w-xs truncate" title="${proc.name}">${proc.name}</td>
        <td class="py-md">${proc.username}</td>
        <td class="py-md">${proc.cpu_percent}%</td>
        <td class="py-md">${parseFloat(proc.memory_percent).toFixed(2)}%</td>
        <td class="py-md text-[10px] text-on-surface-variant font-mono select-all truncate max-w-[120px]" title="${proc.sha256}">${proc.sha256 || 'N/A'}</td>
        <td class="py-md">
            ${proc.is_suspicious ? `
            <span class="text-error font-bold" title="${proc.suspicious_reason}">&#9888; SUSPICIOUS</span>
            <span class="block text-[10px] text-on-error-container/85 max-w-xs truncate" title="${proc.suspicious_reason}">${proc.suspicious_reason}</span>
            ` : '<span class="text-green-400 font-bold">CLEAN</span>'}
        </td>
    `;

    procBody.insertBefore(tr, procBody.firstChild);

    // Limit processes table to 50 items
    if (procBody.children.length > 50) {
        procBody.removeChild(procBody.lastChild);
    }
}

function updateServiceRow(svc) {
    const serviceTableBody = document.querySelector("#services-table-body");
    if (!serviceTableBody) return;

    // Search for existing row matching Host + Name
    let matchedRow = null;
    for (let row of serviceTableBody.rows) {
        const hostCell = row.cells[0]?.innerText.trim();
        const nameCell = row.cells[1]?.innerText.trim();
        if (hostCell === svc.hostname && nameCell === svc.name) {
            matchedRow = row;
            break;
        }
    }

    let statusBadge = "bg-yellow-950/40 text-yellow-400 border border-yellow-500/30";
    if (svc.status === 'Running') statusBadge = "bg-green-950/40 text-green-400 border border-green-500/30";
    else if (svc.status === 'Stopped') statusBadge = "bg-red-950/40 text-red-400 border border-red-500/30";

    if (matchedRow) {
        // Highlight updating row
        matchedRow.classList.add("animate-pulse");
        matchedRow.cells[2].innerText = svc.display_name;
        matchedRow.cells[3].innerHTML = `<span class="px-sm py-0.5 rounded text-[10px] font-bold uppercase ${statusBadge}">${svc.status}</span>`;
        matchedRow.cells[4].innerText = svc.start_type;
        setTimeout(() => matchedRow.classList.remove("animate-pulse"), 1500);
    } else {
        // Create new row
        const tr = document.createElement("tr");
        tr.className = "hover:bg-surface-container-high/40 transition-colors animate-pulse";
        tr.innerHTML = `
            <td class="py-md px-xs font-bold">${svc.hostname}</td>
            <td class="py-md font-bold text-secondary-container">${svc.name}</td>
            <td class="py-md text-on-surface-variant">${svc.display_name}</td>
            <td class="py-md">
                <span class="px-sm py-0.5 rounded text-[10px] font-bold uppercase ${statusBadge}">${svc.status}</span>
            </td>
            <td class="py-md text-on-surface-variant">${svc.start_type}</td>
        `;
        serviceTableBody.insertBefore(tr, serviceTableBody.firstChild);
    }
}

function updateLiveCharts(health) {
    // Only update if we are looking at the selected host
    const selectedHostDropdown = document.querySelector("#hostSelectorForm select");
    if (!selectedHostDropdown || selectedHostDropdown.value !== health.hostname) return;

    // Retrieve active Chart.js instances if rendered
    const charts = Chart.instances;
    const resourceChart = Object.values(charts).find(c => c.canvas.id === 'resourceUsageChart');
    const netChart = Object.values(charts).find(c => c.canvas.id === 'networkUsageChart');

    const nowStr = new Date().toLocaleTimeString();

    if (resourceChart) {
        resourceChart.data.labels.push(nowStr);
        resourceChart.data.datasets[0].data.push(health.cpu_percent);
        resourceChart.data.datasets[1].data.push(health.memory_percent);

        if (resourceChart.data.labels.length > 20) {
            resourceChart.data.labels.shift();
            resourceChart.data.datasets[0].data.shift();
            resourceChart.data.datasets[1].data.shift();
        }
        resourceChart.update();
    }

    if (netChart) {
        netChart.data.labels.push(nowStr);
        netChart.data.datasets[0].data.push((health.network_upload_bytes / 1024).toFixed(2));
        netChart.data.datasets[1].data.push((health.network_download_bytes / 1024).toFixed(2));

        if (netChart.data.labels.length > 20) {
            netChart.data.labels.shift();
            netChart.data.datasets[0].data.shift();
            netChart.data.datasets[1].data.shift();
        }
        netChart.update();
    }
}

// Bootstrap connections
document.addEventListener("DOMContentLoaded", function() {
    connectWebSocket();
});
