/**
 * G66 Network Forensic SOC Dashboard Application
 * Group G66 | RIG Exploit Kit & KPOT Stealer Network Analysis
 */

// Application State
let currentMode = 'demo';
let packetsData = [];
let iocsData = [];
let timelineData = [];
let statsData = {};
let charts = {};

// DOM Loaded Initialization
document.addEventListener('DOMContentLoaded', () => {
    initNavigation();
    initCharts();
    initUploadZone();
    initChecklist();
    initEventListeners();
    fetchSystemStatus();
    loadDashboardData();
    drawNetworkGraph();
});

// --- NAVIGATION & TABS ---
function initNavigation() {
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', () => {
            const tab = item.getAttribute('data-tab');
            switchTab(tab);
        });
    });

    const mobileMenuBtn = document.getElementById('mobile-menu-btn');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', () => {
            document.querySelector('.sidebar').classList.toggle('open');
        });
    }
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-item').forEach(btn => {
        btn.classList.toggle('active', btn.getAttribute('data-tab') === tabId);
    });

    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.toggle('active', pane.id === `pane-${tabId}`);
    });

    const headingMap = {
        'dashboard': 'Network Forensic SOC Dashboard',
        'pcap': 'Packet Ingestion & Deep Inspection',
        'iocs': 'Threat Intelligence & Corroborated IOCs',
        'timeline': 'Attack Reconstruction & Network Topology',
        'investigation': 'Forensic Investigation & MITRE ATT&CK',
        'ir': 'Incident Response Checklist & Playbook',
        'report': 'Executive Network Forensics Report'
    };
    if (headingMap[tabId]) {
        document.getElementById('page-heading').innerText = headingMap[tabId];
    }

    if (tabId === 'timeline') {
        setTimeout(drawNetworkGraph, 100);
    }
}

// --- DATA FETCHING & UI UPDATES ---
async function fetchSystemStatus() {
    try {
        const res = await fetch('/api/status');
        const data = await res.json();
        currentMode = data.mode;

        // Update Evidence Bar
        document.getElementById('bar-filename').innerText = data.file_name;
        document.getElementById('bar-filehash').innerText = data.file_hash.substring(0, 32) + '...';
        document.getElementById('bar-filehash').title = data.file_hash;
        document.getElementById('bar-filesize').innerText = data.file_size;
        document.getElementById('bar-timestamp').innerText = data.upload_timestamp;

        // Mode Badge
        const modeBadge = document.getElementById('mode-badge');
        const modeText = document.getElementById('mode-text');
        const bannerNotice = document.getElementById('banner-notice-text');

        if (data.mode === 'demo') {
            modeBadge.className = 'mode-pill mode-demo';
            modeBadge.innerHTML = '<i class="fa-solid fa-flask"></i> <span>DEMO DATA (SYNTHETIC)</span>';
            if (bannerNotice) {
                bannerNotice.innerText = "Currently analyzing synthetic educational dataset simulating host 10.0.76.109 compromise via RIG Exploit Kit. Reference indicators are displayed for correlation.";
            }
        } else if (data.mode === 'pcap') {
            modeBadge.className = 'mode-pill mode-pcap';
            modeBadge.innerHTML = '<i class="fa-solid fa-satellite-dish"></i> <span>PCAP ANALYSIS (DIRECT EVIDENCE)</span>';
            if (bannerNotice) {
                bannerNotice.innerText = `Ingested real capture evidence: ${data.file_name}. Packet timings, headers, and protocol streams are parsed from physical wire data.`;
            }
        } else {
            modeBadge.className = 'mode-pill';
            modeBadge.innerHTML = '<i class="fa-solid fa-circle-pause"></i> <span>AWAITING INGESTION</span>';
        }

        // Analyst Notes
        if (data.analyst_notes) {
            document.getElementById('analyst-notes-input').value = data.analyst_notes;
        }

        // Update Report Meta
        document.getElementById('rep-filename').innerText = data.file_name;
        document.getElementById('rep-mode').innerText = data.mode === 'demo' ? 'SYNTHETIC DEMO' : 'LIVE PCAP EVIDENCE';
        document.getElementById('rep-filehash').innerText = data.file_hash;

    } catch (err) {
        console.error('Error fetching system status:', err);
    }
}

async function loadDashboardData() {
    try {
        // Load Stats
        const statsRes = await fetch('/api/stats');
        statsData = await statsRes.json();
        updateKPICards(statsData);
        updateCharts(statsData);

        // Load Packets
        fetchPackets();

        // Load IOCs
        fetchIOCs();

        // Load Timeline
        fetchTimeline();

        // Load MITRE
        fetchMitre();

    } catch (err) {
        console.error('Error loading dashboard data:', err);
        showToast('Error loading dataset', 'error');
    }
}

function updateKPICards(stats) {
    document.getElementById('kpi-packets').innerText = stats.total_packets || 0;
    document.getElementById('kpi-src-ips').innerText = stats.unique_src_ips || 0;
    document.getElementById('kpi-dst-ips').innerText = stats.unique_dst_ips || 0;
    document.getElementById('kpi-http').innerText = stats.http_requests || 0;
    document.getElementById('kpi-suspicious').innerText = stats.suspicious_events || 0;

    document.getElementById('nav-packet-count').innerText = stats.total_packets || 0;

    // Report stats
    document.getElementById('rep-packets').innerText = stats.total_packets || 0;
    document.getElementById('rep-suspicious').innerText = stats.suspicious_events || 0;
}

// --- PACKETS INSPECTOR ---
async function fetchPackets() {
    const proto = document.getElementById('filter-protocol').value;
    const src = document.getElementById('filter-src').value.trim();
    const dst = document.getElementById('filter-dst').value.trim();
    const search = document.getElementById('filter-search').value.trim();
    const suspiciousOnly = document.getElementById('filter-suspicious-only').checked;

    const params = new URLSearchParams({
        protocol: proto,
        src_ip: src,
        dst_ip: dst,
        search: search,
        suspicious_only: suspiciousOnly,
        limit: 200
    });

    try {
        const res = await fetch(`/api/packets?${params}`);
        const data = await res.json();
        packetsData = data.packets || [];

        renderPacketsTable(packetsData);
        renderRecentEventsTable(packetsData);
        document.getElementById('packets-count-label').innerText = `Showing ${packetsData.length} matching packets (Total: ${data.total_matching})`;
    } catch (err) {
        console.error('Error fetching packets:', err);
    }
}

function renderPacketsTable(packets) {
    const tbody = document.getElementById('tbody-packets');
    tbody.innerHTML = '';

    if (packets.length === 0) {
        tbody.innerHTML = `<tr><td colspan="9" class="text-center text-muted" style="padding: 28px;">No packets match current filter parameters.</td></tr>`;
        return;
    }

    packets.forEach(p => {
        const tr = document.createElement('tr');
        tr.className = p.is_suspicious ? 'table-row-alert' : '';
        tr.style.cursor = 'pointer';

        let badgeHtml = '<span class="badge badge-info">Normal</span>';
        if (p.is_suspicious) {
            badgeHtml = '<span class="badge badge-critical">Flagged</span>';
        }

        tr.innerHTML = `
            <td>#${p.packet_no}</td>
            <td class="text-dim">${p.timestamp}</td>
            <td class="${p.src_ip === '10.0.76.109' ? 'text-cyan' : ''}">${p.src_ip}${p.src_port ? ':' + p.src_port : ''}</td>
            <td class="${p.dst_ip === '37.46.135.170' || p.dst_ip === '8.209.83.76' ? 'text-red' : ''}">${p.dst_ip}${p.dst_port ? ':' + p.dst_port : ''}</td>
            <td><span class="badge ${getProtocolBadgeClass(p.protocol)}">${p.protocol}</span></td>
            <td>${p.length} B</td>
            <td class="text-truncate" style="max-width: 320px;" title="${escapeHtml(p.info)}">${escapeHtml(p.info)}</td>
            <td>${badgeHtml}</td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation(); openPacketModal(${p.packet_no})">
                    <i class="fa-solid fa-eye"></i>
                </button>
            </td>
        `;

        tr.addEventListener('click', () => openPacketModal(p.packet_no));
        tbody.appendChild(tr);
    });
}

function renderRecentEventsTable(packets) {
    const tbody = document.getElementById('tbody-recent-events');
    tbody.innerHTML = '';

    const suspicious = packets.filter(p => p.is_suspicious).slice(0, 6);
    if (suspicious.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center text-muted" style="padding: 20px;">No suspicious security events detected in current capture.</td></tr>`;
        return;
    }

    suspicious.forEach(p => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>#${p.packet_no}</td>
            <td class="font-mono text-dim">${p.timestamp}</td>
            <td class="text-cyan font-mono">${p.src_ip}</td>
            <td class="text-red font-mono">${p.dst_ip}</td>
            <td><span class="badge badge-info">${p.protocol}</span></td>
            <td><span class="text-red font-weight-500">${escapeHtml(p.suspicious_reason || 'Anomalous traffic signature')}</span></td>
            <td>
                <button class="btn btn-secondary btn-sm" onclick="openPacketModal(${p.packet_no})">Inspect</button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function getProtocolBadgeClass(proto) {
    switch (proto) {
        case 'HTTP': return 'badge-high';
        case 'DNS': return 'badge-medium';
        case 'TCP': return 'badge-info';
        case 'TLS/HTTPS': return 'badge-success';
        case 'ARP': return 'badge-soft';
        default: return 'badge-info';
    }
}

// --- PACKET DEEP MODAL ---
function openPacketModal(packetNo) {
    const pkt = packetsData.find(p => p.packet_no === packetNo);
    if (!pkt) return;

    document.getElementById('modal-pkt-title').innerText = `Packet #${pkt.packet_no} Deep Inspection`;
    const badge = document.getElementById('modal-pkt-badge');
    badge.innerText = pkt.protocol;
    badge.className = `badge ${getProtocolBadgeClass(pkt.protocol)}`;

    const metaGrid = document.getElementById('modal-pkt-meta');
    metaGrid.innerHTML = `
        <div><strong>Timestamp:</strong> <span class="font-mono">${pkt.timestamp}</span></div>
        <div><strong>Frame Length:</strong> <span class="font-mono">${pkt.length} Bytes</span></div>
        <div><strong>Source IP & Port:</strong> <span class="font-mono text-cyan">${pkt.src_ip}:${pkt.src_port || 'N/A'}</span></div>
        <div><strong>Dest IP & Port:</strong> <span class="font-mono text-red">${pkt.dst_ip}:${pkt.dst_port || 'N/A'}</span></div>
        <div><strong>Ethernet Source MAC:</strong> <span class="font-mono">${pkt.mac_src || 'Unspecified'}</span></div>
        <div><strong>Ethernet Dest MAC:</strong> <span class="font-mono">${pkt.mac_dst || 'Unspecified'}</span></div>
        <div><strong>Evidence Class:</strong> <span>${pkt.evidence_type}</span></div>
        <div><strong>Security Status:</strong> <span class="${pkt.is_suspicious ? 'text-red' : 'text-green'} font-weight-bold">${pkt.is_suspicious ? 'SUSPICIOUS / FLAG' : 'NORMAL TRAFFIC'}</span></div>
    `;

    if (pkt.suspicious_reason) {
        metaGrid.innerHTML += `<div style="grid-column: span 2;" class="text-red"><strong>Detection Reason:</strong> ${escapeHtml(pkt.suspicious_reason)}</div>`;
    }

    if (pkt.dns_query) {
        metaGrid.innerHTML += `<div style="grid-column: span 2;" class="text-cyan"><strong>DNS Query Domain:</strong> ${escapeHtml(pkt.dns_query)}</div>`;
    }

    if (pkt.http_meta && pkt.http_meta.method) {
        metaGrid.innerHTML += `
            <div style="grid-column: span 2;">
                <strong>HTTP Request:</strong> <span class="text-cyan">${pkt.http_meta.method} ${escapeHtml(pkt.http_meta.path || '/')}</span> (Host: ${escapeHtml(pkt.http_meta.host || 'N/A')})
            </div>
        `;
    }

    const payloadEl = document.getElementById('modal-pkt-payload');
    if (pkt.payload_snippet) {
        payloadEl.innerText = pkt.payload_snippet;
    } else {
        payloadEl.innerText = "[No raw application payload present in transport frame]";
    }

    document.getElementById('packet-detail-modal').classList.add('show');
}

function closeModal() {
    document.getElementById('packet-detail-modal').classList.remove('show');
}

// Close modal on click outside
window.addEventListener('click', (e) => {
    const modal = document.getElementById('packet-detail-modal');
    if (e.target === modal) {
        closeModal();
    }
});

// --- IOCs THREAT INTEL ---
async function fetchIOCs() {
    try {
        const res = await fetch('/api/iocs');
        const data = await res.json();
        iocsData = data.iocs || [];
        renderIOCTables(iocsData);
    } catch (err) {
        console.error('Error fetching IOCs:', err);
    }
}

function renderIOCTables(iocs) {
    const tbody = document.getElementById('tbody-iocs');
    const repTbody = document.getElementById('rep-ioc-tbody');
    tbody.innerHTML = '';
    repTbody.innerHTML = '';

    iocs.forEach(ioc => {
        let sevClass = 'badge-info';
        if (ioc.severity === 'Critical') sevClass = 'badge-critical';
        else if (ioc.severity === 'High') sevClass = 'badge-high';
        else if (ioc.severity === 'Medium') sevClass = 'badge-medium';

        let statusClass = ioc.match_count > 0 ? 'text-green font-weight-bold' : 'text-muted';

        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td class="font-mono text-cyan">${ioc.id}</td>
            <td><strong>${ioc.type}</strong></td>
            <td class="font-mono ${ioc.severity === 'Critical' ? 'text-red' : 'text-cyan'}">${ioc.value}</td>
            <td>${ioc.category}</td>
            <td class="text-dim">${ioc.evidence_source}</td>
            <td><span class="badge ${sevClass}">${ioc.severity}</span></td>
            <td class="text-center font-mono"><strong>${ioc.match_count}</strong></td>
            <td class="${statusClass}"><i class="fa-solid ${ioc.match_count > 0 ? 'fa-circle-check' : 'fa-circle-question'}"></i> ${ioc.validation_status}</td>
        `;
        tbody.appendChild(tr);

        // Report row
        const repTr = document.createElement('tr');
        repTr.innerHTML = `
            <td class="font-mono">${ioc.value}</td>
            <td>${ioc.type}</td>
            <td>${ioc.category}</td>
            <td><span class="badge ${sevClass}">${ioc.severity}</span></td>
            <td>${ioc.match_count > 0 ? ioc.match_count + ' packets' : 'Reference Only'}</td>
        `;
        repTbody.appendChild(repTr);
    });
}

// --- ATTACK TIMELINE ---
async function fetchTimeline() {
    try {
        const res = await fetch('/api/timeline');
        const data = await res.json();
        timelineData = data.timeline || [];
        renderTimeline(timelineData);
    } catch (err) {
        console.error('Error fetching timeline:', err);
    }
}

function renderTimeline(timeline) {
    const container = document.getElementById('timeline-flow');
    const repContainer = document.getElementById('rep-timeline-summary');
    container.innerHTML = '';
    repContainer.innerHTML = '';

    timeline.forEach(t => {
        const isInterp = t.type.includes('Interpretation');
        const div = document.createElement('div');
        div.className = `timeline-node ${isInterp ? 'interpretation' : ''}`;

        div.innerHTML = `
            <div class="timeline-header">
                <span class="timeline-ts">${t.timestamp}</span>
                <span class="timeline-type">${t.type}</span>
                <span class="badge badge-info">${t.stage}</span>
            </div>
            <div class="timeline-card">
                <h4>${escapeHtml(t.headline)}</h4>
                <p>${escapeHtml(t.details)}</p>
                <div class="timeline-meta-tags">
                    <span><i class="fa-solid fa-arrows-split-up-and-left"></i> ${t.source_ip} &rarr; ${t.dest_ip}</span>
                    <span><i class="fa-solid fa-shield-virus"></i> ${t.mitre}</span>
                    <span><i class="fa-solid fa-magnifying-glass"></i> ${t.evidence_status}</span>
                </div>
            </div>
        `;
        container.appendChild(div);

        // Report summary
        const repItem = document.createElement('div');
        repItem.className = 'rep-tl-item';
        repItem.innerHTML = `
            <span class="font-mono text-dim" style="min-width: 170px;">${t.timestamp}</span>
            <div>
                <strong>${escapeHtml(t.stage)}:</strong> ${escapeHtml(t.headline)} 
                <span class="text-dim">(${t.source_ip} &rarr; ${t.dest_ip})</span>
            </div>
        `;
        repContainer.appendChild(repItem);
    });
}

// --- MITRE ATT&CK ---
async function fetchMitre() {
    try {
        const res = await fetch('/api/mitre');
        const data = await res.json();
        const tbody = document.getElementById('tbody-mitre');
        tbody.innerHTML = '';

        data.framework.forEach(m => {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td><strong>${m.tactic}</strong></td>
                <td class="font-mono text-cyan">${m.id}</td>
                <td><strong>${m.name}</strong></td>
                <td>${m.description}</td>
                <td><span class="badge ${m.confidence === 'Confirmed' ? 'badge-critical' : 'badge-high'}">${m.confidence}</span></td>
            `;
            tbody.appendChild(tr);
        });
    } catch (err) {
        console.error('Error fetching MITRE:', err);
    }
}

// --- CHARTS (CHART.JS) ---
function initCharts() {
    const ctxProto = document.getElementById('chart-protocol').getContext('2d');
    charts.proto = new Chart(ctxProto, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'HTTP', 'DNS', 'UDP', 'Other'],
            datasets: [{
                data: [1, 1, 1, 1, 1],
                backgroundColor: ['#38bdf8', '#f59e0b', '#00f2fe', '#818cf8', '#64748b'],
                borderColor: '#0d131f',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'bottom', labels: { color: '#94a3b8', boxWidth: 12 } }
            }
        }
    });

    const ctxTime = document.getElementById('chart-timeline').getContext('2d');
    charts.time = new Chart(ctxTime, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Packets / Interval',
                data: [],
                borderColor: '#00f2fe',
                backgroundColor: 'rgba(0, 242, 254, 0.1)',
                fill: true,
                tension: 0.35,
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30, 45, 71, 0.4)' } },
                y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30, 45, 71, 0.4)' } }
            }
        }
    });

    const ctxTop = document.getElementById('chart-top-ips').getContext('2d');
    charts.top = new Chart(ctxTop, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Transmitted Packets',
                data: [],
                backgroundColor: '#38bdf8',
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: '#64748b' }, grid: { display: false } },
                y: { ticks: { color: '#64748b' }, grid: { color: 'rgba(30, 45, 71, 0.4)' } }
            }
        }
    });
}

function updateCharts(stats) {
    if (!stats || !charts.proto) return;

    // Protocol distribution
    if (stats.protocols) {
        charts.proto.data.labels = Object.keys(stats.protocols);
        charts.proto.data.datasets[0].data = Object.values(stats.protocols);
        charts.proto.update();
    }

    // Traffic time series
    if (stats.traffic_time_series) {
        charts.time.data.labels = stats.traffic_time_series.labels;
        charts.time.data.datasets[0].data = stats.traffic_time_series.counts;
        charts.time.update();
    }

    // Top talkers
    if (stats.top_talkers_src) {
        charts.top.data.labels = stats.top_talkers_src.map(t => t.ip);
        charts.top.data.datasets[0].data = stats.top_talkers_src.map(t => t.count);
        charts.top.update();
    }
}

// --- INTERACTIVE NETWORK TOPOLOGY CANVAS GRAPH ---
function drawNetworkGraph() {
    const canvas = document.getElementById('network-graph-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Nodes Coordinates
    const nodes = [
        { id: 'dns', label: 'Internal Gateway\n10.0.76.1', x: 160, y: 80, color: '#10b981', ring: '#059669' },
        { id: 'victim', label: 'Victim Host (BANGKOK-PC)\n10.0.76.109', x: 450, y: 170, color: '#00f2fe', ring: '#0284c7', pulse: true },
        { id: 'web', label: 'Compromised Referral\n185.190.140.22', x: 160, y: 260, color: '#f59e0b', ring: '#d97706' },
        { id: 'rig', label: 'RIG Exploit Delivery\n37.46.135.170', x: 740, y: 80, color: '#ef4444', ring: '#b91c1c' },
        { id: 'c2', label: 'KPOT Stealer C2\n8.209.83.76', x: 740, y: 260, color: '#a855f7', ring: '#7e22ce' }
    ];

    // Edges
    const edges = [
        { from: 'victim', to: 'dns', label: 'DNS Queries (Port 53)', color: 'rgba(16, 185, 129, 0.4)', dash: [4, 4] },
        { from: 'victim', to: 'web', label: 'HTTP GET (Iframe Redirection)', color: 'rgba(245, 158, 11, 0.5)' },
        { from: 'victim', to: 'rig', label: 'RIG EK Landing & /payload.bin', color: 'rgba(239, 68, 68, 0.7)' },
        { from: 'victim', to: 'c2', label: 'POST /gate.php (Exfiltration)', color: 'rgba(168, 85, 247, 0.7)' }
    ];

    // Draw Edges
    edges.forEach(e => {
        const n1 = nodes.find(n => n.id === e.from);
        const n2 = nodes.find(n => n.id === e.to);
        if (!n1 || !n2) return;

        ctx.beginPath();
        if (e.dash) ctx.setLineDash(e.dash);
        else ctx.setLineDash([]);
        ctx.strokeStyle = e.color;
        ctx.lineWidth = 2;
        ctx.moveTo(n1.x, n1.y);
        ctx.lineTo(n2.x, n2.y);
        ctx.stroke();
        ctx.setLineDash([]);

        // Midpoint Label
        const midX = (n1.x + n2.x) / 2;
        const midY = (n1.y + n2.y) / 2;
        ctx.font = '10px Inter';
        ctx.fillStyle = '#94a3b8';
        ctx.textAlign = 'center';
        ctx.fillText(e.label, midX, midY - 6);
    });

    // Draw Nodes
    nodes.forEach(n => {
        // Outer Glow
        ctx.beginPath();
        ctx.arc(n.x, n.y, 22, 0, Math.PI * 2);
        ctx.fillStyle = n.color;
        ctx.shadowColor = n.color;
        ctx.shadowBlur = 12;
        ctx.fill();
        ctx.shadowBlur = 0;

        // Inner Circle
        ctx.beginPath();
        ctx.arc(n.x, n.y, 14, 0, Math.PI * 2);
        ctx.fillStyle = '#0d131f';
        ctx.fill();

        // Label
        ctx.font = 'bold 11px Inter';
        ctx.fillStyle = '#f8fafc';
        ctx.textAlign = 'center';
        const lines = n.label.split('\n');
        ctx.fillText(lines[0], n.x, n.y + 36);
        ctx.font = '10px Fira Code';
        ctx.fillStyle = '#94a3b8';
        ctx.fillText(lines[1], n.x, n.y + 50);
    });
}

// --- FILE UPLOAD (DRAG & DROP) ---
function initUploadZone() {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('pcap-file-input');

    ['dragenter', 'dragover'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(event => {
        dropZone.addEventListener(event, (e) => {
            e.preventDefault();
            dropZone.classList.remove('drag-over');
        });
    });

    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileUpload(files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) {
            handleFileUpload(fileInput.files[0]);
        }
    });

    document.getElementById('btn-trigger-upload').addEventListener('click', () => {
        switchTab('pcap');
        setTimeout(() => fileInput.click(), 150);
    });
}

async function handleFileUpload(file) {
    const ext = file.name.split('.').pop().toLowerCase();
    if (ext !== 'pcap' && ext !== 'pcapng') {
        showToast('Invalid file format. Please upload .pcap or .pcapng.', 'error');
        return;
    }

    if (file.size > 50 * 1024 * 1024) {
        showToast('File size exceeds the 50MB safety limit.', 'error');
        return;
    }

    const formData = new FormData();
    formData.append('file', file);

    const progressBar = document.getElementById('upload-progress-bar');
    const progressFill = document.getElementById('upload-progress-fill');
    progressBar.style.display = 'block';
    progressFill.style.width = '35%';

    showToast(`Uploading and parsing ${file.name}...`, 'info');

    try {
        const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });

        progressFill.style.width = '90%';
        const result = await res.json();
        progressBar.style.display = 'none';

        if (result.success) {
            showToast(result.message, 'success');
            await fetchSystemStatus();
            await loadDashboardData();
        } else {
            showToast(result.error || 'Failed to parse PCAP file.', 'error');
        }
    } catch (err) {
        progressBar.style.display = 'none';
        showToast('Server connection error during upload.', 'error');
        console.error('Upload error:', err);
    }
}

// --- INCIDENT RESPONSE CHECKLIST ---
function initChecklist() {
    const checkboxes = document.querySelectorAll('.ir-checkbox');
    const saved = JSON.parse(localStorage.getItem('g66_ir_checklist') || '{}');

    checkboxes.forEach(cb => {
        if (saved[cb.id]) {
            cb.checked = true;
            cb.closest('.checklist-item').classList.add('checked');
        }

        cb.addEventListener('change', () => {
            const item = cb.closest('.checklist-item');
            if (cb.checked) {
                item.classList.add('checked');
            } else {
                item.classList.remove('checked');
            }
            updateChecklistProgress();
        });
    });

    updateChecklistProgress();
}

function updateChecklistProgress() {
    const checkboxes = document.querySelectorAll('.ir-checkbox');
    const checked = Array.from(checkboxes).filter(cb => cb.checked);
    const percent = Math.round((checked.length / checkboxes.length) * 100);

    document.getElementById('ir-percent').innerText = `${percent}%`;
    document.getElementById('ir-progress-fill').style.width = `${percent}%`;

    // Save to local storage
    const state = {};
    checkboxes.forEach(cb => { state[cb.id] = cb.checked; });
    localStorage.setItem('g66_ir_checklist', JSON.stringify(state));
}

// --- EVENT LISTENERS & BUTTON ACTIONS ---
function initEventListeners() {
    // Demo Mode Loader
    document.getElementById('btn-load-demo').addEventListener('click', async () => {
        try {
            const res = await fetch('/api/demo', { method: 'POST' });
            const data = await res.json();
            if (data.success) {
                showToast('Synthetic Case Study Demo Data loaded.', 'success');
                await fetchSystemStatus();
                await loadDashboardData();
            }
        } catch (err) {
            showToast('Failed to load demo data.', 'error');
        }
    });

    // Reset Analysis
    document.getElementById('btn-reset-data').addEventListener('click', async () => {
        if (confirm('Clear currently loaded forensic dataset buffer?')) {
            try {
                const res = await fetch('/api/reset', { method: 'POST' });
                const data = await res.json();
                if (data.success) {
                    showToast('Analysis state reset.', 'info');
                    await fetchSystemStatus();
                    await loadDashboardData();
                }
            } catch (err) {
                showToast('Failed to reset state.', 'error');
            }
        }
    });

    // Packet Table Filters
    ['filter-protocol', 'filter-suspicious-only'].forEach(id => {
        document.getElementById(id).addEventListener('change', fetchPackets);
    });

    ['filter-src', 'filter-dst', 'filter-search'].forEach(id => {
        document.getElementById(id).addEventListener('input', debounce(fetchPackets, 300));
    });

    // CSV Exports
    document.getElementById('btn-export-packets-csv').addEventListener('click', () => {
        window.location.href = '/api/export/csv';
    });

    document.getElementById('btn-export-iocs-csv').addEventListener('click', () => {
        window.location.href = '/api/export/iocs/csv';
    });

    // Save Analyst Notes
    document.getElementById('btn-save-notes').addEventListener('click', async () => {
        const notes = document.getElementById('analyst-notes-input').value;
        try {
            const res = await fetch('/api/notes', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ notes })
            });
            const data = await res.json();
            if (data.success) {
                showToast('Analyst notes saved to session.', 'success');
                document.getElementById('notes-status-text').innerText = 'Last saved: ' + new Date().toLocaleTimeString();
            }
        } catch (err) {
            showToast('Failed to save notes.', 'error');
        }
    });
}

// --- UTILITIES ---
function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    let icon = 'fa-info-circle';
    if (type === 'success') icon = 'fa-circle-check';
    if (type === 'error') icon = 'fa-circle-xmark';
    if (type === 'warning') icon = 'fa-triangle-exclamation';

    toast.innerHTML = `<i class="fa-solid ${icon}"></i> <span>${escapeHtml(message)}</span>`;
    container.appendChild(toast);

    setTimeout(() => {
        toast.style.opacity = '0';
        toast.style.transform = 'translateX(50px)';
        setTimeout(() => toast.remove(), 300);
    }, 3500);
}

function debounce(func, wait) {
    let timeout;
    return function (...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), wait);
    };
}

function escapeHtml(text) {
    if (!text) return '';
    return String(text)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}
