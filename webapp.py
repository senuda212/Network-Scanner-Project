"""webapp.py - Flask dashboard for scan history, statistics, and findings."""

from __future__ import annotations

import logging
import os
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import psycopg2
from flask import Flask, jsonify, request
from psycopg2.extras import RealDictCursor

from env_loader import load_dotenv

load_dotenv(Path(__file__).resolve().with_name(".env"), override=True)

logger = logging.getLogger(__name__)
app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
        logger.warning("DATABASE_URL not set; webapp will be read-only without DB")

RISKY_PORTS = {
        21,
        23,
        25,
        53,
        110,
        111,
        135,
        139,
        143,
        389,
        445,
        587,
        993,
        995,
        1433,
        1521,
        2049,
        2375,
        3306,
        3389,
        5432,
        5900,
        6379,
        7001,
        8000,
        8080,
        8443,
        9200,
        11211,
        27017,
}

PORT_REMEDIATION = {
        21: "Replace FTP with SFTP or restrict access behind a VPN and allowlist only trusted admin IPs.",
        23: "Disable Telnet and move management access to SSH with key-based authentication.",
        25: "Restrict SMTP to mail relays only and confirm the service is intended for this host.",
        53: "Keep DNS services on dedicated infrastructure and limit zone-transfer and recursion exposure.",
        135: "Limit RPC exposure to internal networks and apply the latest Microsoft security updates.",
        139: "Disable legacy NetBIOS where possible and block SMB from untrusted networks.",
        143: "Use encrypted mail access and restrict IMAP to authenticated clients only.",
        389: "Require LDAPS or TLS and restrict directory services to trusted management segments.",
        445: "Restrict SMB to internal ranges, disable SMBv1, and patch file-sharing hosts promptly.",
        3306: "Bind the database to internal interfaces only and enforce strong authentication and firewall allowlists.",
        3389: "Expose RDP only through VPN or bastion hosts, enable NLA, and enforce MFA where possible.",
        5432: "Keep PostgreSQL private, restrict to trusted application hosts, and avoid public exposure.",
        5900: "Limit VNC to secured admin networks and require encryption or a remote-access gateway.",
        6379: "Protect Redis with authentication, bind to localhost or private interfaces, and firewall the port.",
        9200: "Do not expose Elasticsearch publicly; require auth and keep it behind a private network segment.",
        27017: "Keep MongoDB private, enable authentication, and allow only trusted backend hosts.",
}

STATUS_ORDER = ["open", "closed", "filtered", "error"]
STATUS_LABELS = {
        "open": "Open",
        "closed": "Closed",
        "filtered": "Filtered",
        "error": "Error",
}

STATUS_COLORS = {
        "open": "#22c55e",
        "closed": "#94a3b8",
        "filtered": "#f59e0b",
        "error": "#f43f5e",
}

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Network Scanner Dashboard</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.3/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg: #07111f;
            --bg-alt: #0c1629;
            --panel: rgba(11, 19, 34, 0.86);
            --panel-strong: #101a31;
            --border: rgba(148, 163, 184, 0.16);
            --text: #e2e8f0;
            --muted: #94a3b8;
            --accent: #38bdf8;
            --accent-2: #8b5cf6;
            --good: #22c55e;
            --warn: #f59e0b;
            --bad: #f43f5e;
            --shadow: 0 24px 80px rgba(2, 6, 23, 0.44);
            --radius: 22px;
        }

        * { box-sizing: border-box; }
        html, body { min-height: 100%; }
        body {
            margin: 0;
            font-family: 'Inter', system-ui, sans-serif;
            color: var(--text);
            background:
                radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 30%),
                radial-gradient(circle at top right, rgba(139, 92, 246, 0.15), transparent 30%),
                linear-gradient(180deg, #07111f 0%, #091425 45%, #050a12 100%);
        }

        body::before {
            content: '';
            position: fixed;
            inset: 0;
            pointer-events: none;
            background-image: linear-gradient(rgba(148, 163, 184, 0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(148, 163, 184, 0.03) 1px, transparent 1px);
            background-size: 60px 60px;
            mask-image: linear-gradient(180deg, rgba(0,0,0,0.6), transparent 80%);
        }

        .shell {
            position: relative;
            max-width: 1500px;
            margin: 0 auto;
            padding: 32px 24px 40px;
        }

        .hero {
            display: flex;
            gap: 20px;
            justify-content: space-between;
            align-items: flex-start;
            padding: 28px;
            border: 1px solid var(--border);
            border-radius: calc(var(--radius) + 6px);
            background: linear-gradient(180deg, rgba(16, 26, 49, 0.96), rgba(8, 14, 26, 0.92));
            box-shadow: var(--shadow);
            backdrop-filter: blur(18px);
        }

        .eyebrow {
            display: inline-flex;
            gap: 8px;
            align-items: center;
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: #bae6fd;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.18);
        }

        h1 {
            margin: 16px 0 10px;
            font-size: clamp(2rem, 4vw, 3.4rem);
            line-height: 1.03;
            letter-spacing: -0.05em;
        }

        .lead {
            max-width: 760px;
            margin: 0;
            color: var(--muted);
            font-size: 15px;
            line-height: 1.7;
        }

        .hero-meta {
            display: grid;
            gap: 10px;
            min-width: 240px;
        }

        .pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 14px;
            border-radius: 999px;
            background: rgba(148, 163, 184, 0.08);
            border: 1px solid rgba(148, 163, 184, 0.12);
            color: var(--text);
            font-size: 13px;
            justify-content: center;
        }

        .pill strong { color: white; }

        .toolbar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 16px;
            margin: 22px 0 20px;
            flex-wrap: wrap;
        }

        .toolbar .controls {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
            align-items: center;
        }

        .select,
        .button {
            border: 1px solid var(--border);
            background: rgba(15, 23, 42, 0.82);
            color: var(--text);
            border-radius: 14px;
            padding: 12px 14px;
            font: inherit;
        }

        .button {
            cursor: pointer;
            background: linear-gradient(135deg, rgba(56, 189, 248, 0.16), rgba(139, 92, 246, 0.16));
        }

        .grid-metrics {
            display: grid;
            grid-template-columns: repeat(4, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }

        .metric {
            padding: 18px;
            border-radius: var(--radius);
            border: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(16, 26, 49, 0.88), rgba(8, 14, 26, 0.9));
            box-shadow: var(--shadow);
            min-height: 132px;
        }

        .metric .label {
            color: var(--muted);
            font-size: 12px;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }

        .metric .value {
            margin-top: 12px;
            font-size: clamp(1.7rem, 3vw, 2.5rem);
            font-weight: 800;
            letter-spacing: -0.05em;
        }

        .metric .note {
            margin-top: 12px;
            color: var(--muted);
            font-size: 13px;
            line-height: 1.5;
        }

        .layout {
            display: grid;
            grid-template-columns: minmax(0, 1.5fr) minmax(360px, 0.95fr);
            gap: 16px;
            align-items: start;
        }

        .panel {
            border: 1px solid var(--border);
            background: linear-gradient(180deg, rgba(16, 26, 49, 0.92), rgba(8, 14, 26, 0.92));
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            overflow: hidden;
        }

        .panel-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 12px;
            padding: 18px 18px 14px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.08);
        }

        .panel-header h2 {
            margin: 0;
            font-size: 18px;
            letter-spacing: -0.03em;
        }

        .panel-header p {
            margin: 6px 0 0;
            color: var(--muted);
            font-size: 13px;
        }

        .panel-body {
            padding: 18px;
        }

        .charts {
            display: grid;
            grid-template-columns: repeat(2, minmax(0, 1fr));
            gap: 16px;
            margin-bottom: 16px;
        }

        .chart-card {
            padding: 16px;
            border-radius: 18px;
            background: rgba(7, 11, 20, 0.5);
            border: 1px solid rgba(148, 163, 184, 0.08);
            min-height: 300px;
        }

        .chart-card canvas {
            width: 100% !important;
            height: 250px !important;
        }

        .history-table {
            width: 100%;
            border-collapse: collapse;
            border-spacing: 0;
            overflow: hidden;
        }

        .history-table th,
        .history-table td {
            padding: 14px 12px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.08);
            text-align: left;
            vertical-align: top;
            font-size: 13px;
        }

        .history-table th {
            color: #cbd5e1;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            background: rgba(148, 163, 184, 0.04);
        }

        .history-table tbody tr:hover {
            background: rgba(56, 189, 248, 0.05);
        }

        .status-chip,
        .severity-chip {
            display: inline-flex;
            align-items: center;
            gap: 7px;
            padding: 6px 10px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 700;
            white-space: nowrap;
        }

        .status-chip::before,
        .severity-chip::before {
            content: '';
            width: 8px;
            height: 8px;
            border-radius: 999px;
            background: currentColor;
        }

        .status-open { color: #86efac; background: rgba(34, 197, 94, 0.12); }
        .status-closed { color: #cbd5e1; background: rgba(148, 163, 184, 0.12); }
        .status-filtered { color: #fde68a; background: rgba(245, 158, 11, 0.12); }
        .status-error { color: #fecdd3; background: rgba(244, 63, 94, 0.12); }

        .severity-high { color: #fecaca; background: rgba(244, 63, 94, 0.14); }
        .severity-medium { color: #fde68a; background: rgba(245, 158, 11, 0.14); }
        .severity-low { color: #bbf7d0; background: rgba(34, 197, 94, 0.14); }

        .list {
            display: grid;
            gap: 12px;
        }

        .finding {
            padding: 14px;
            border-radius: 18px;
            border: 1px solid rgba(148, 163, 184, 0.1);
            background: rgba(7, 11, 20, 0.48);
        }

        .finding h3 {
            margin: 10px 0 8px;
            font-size: 15px;
        }

        .finding p,
        .finding li,
        .muted {
            color: var(--muted);
            font-size: 13px;
            line-height: 1.6;
        }

        .finding ul {
            margin: 10px 0 0 18px;
            padding: 0;
        }

        .subgrid {
            display: grid;
            gap: 16px;
            margin-top: 16px;
            grid-template-columns: repeat(2, minmax(0, 1fr));
        }

        .mini-list {
            display: grid;
            gap: 10px;
        }

        .mini-row {
            display: flex;
            justify-content: space-between;
            gap: 12px;
            padding: 12px 0;
            border-bottom: 1px solid rgba(148, 163, 184, 0.08);
            font-size: 13px;
        }

        .mini-row:last-child { border-bottom: 0; }

        .mini-row strong { display: block; font-size: 14px; }

        .footer-note {
            margin-top: 16px;
            color: var(--muted);
            font-size: 12px;
        }

        .error-box {
            padding: 14px 16px;
            border-radius: 14px;
            border: 1px solid rgba(244, 63, 94, 0.28);
            background: rgba(244, 63, 94, 0.08);
            color: #fecdd3;
            margin-top: 14px;
            display: none;
        }

        @media (max-width: 1120px) {
            .layout, .grid-metrics, .charts, .subgrid { grid-template-columns: 1fr; }
            .hero { flex-direction: column; }
            .hero-meta { width: 100%; }
        }

        @media (max-width: 720px) {
            .shell { padding: 18px 14px 26px; }
            .hero, .panel-body, .panel-header, .metric { padding-left: 16px; padding-right: 16px; }
            .toolbar { align-items: stretch; }
            .toolbar .controls { width: 100%; }
            .select, .button { flex: 1 1 auto; }
            .history-table th:nth-child(3), .history-table td:nth-child(3),
            .history-table th:nth-child(4), .history-table td:nth-child(4),
            .history-table th:nth-child(5), .history-table td:nth-child(5) { display: none; }
        }
    </style>
</head>
<body>
    <main class="shell">
        <section class="hero">
            <div>
                <div class="eyebrow">Network Scanner Intelligence</div>
                <h1>Scan history, exposure trends, and remediation in one view.</h1>
                <p class="lead">
                    A read-only dashboard for reviewing stored scan sessions, identifying high-risk exposure points,
                    and tracking repeat findings over time. It turns raw scan rows into reporting that is easier to
                    read, present, and act on.
                </p>
            </div>
            <div class="hero-meta">
                <div class="pill" id="db-pill">Loading database status...</div>
                <div class="pill"><strong id="last-refresh">--</strong>&nbsp;last refresh</div>
                <div class="pill"><strong id="window-label">30</strong>&nbsp;day window</div>
            </div>
        </section>

        <div class="toolbar">
            <div>
                <div class="eyebrow">Operational View</div>
                <p class="muted" style="margin:10px 0 0;">Filter the dashboard by time window. Sessions, charts, and findings refresh together.</p>
            </div>
            <div class="controls">
                <select id="days-select" class="select" aria-label="Select dashboard time window">
                    <option value="7">Last 7 days</option>
                    <option value="14">Last 14 days</option>
                    <option value="30" selected>Last 30 days</option>
                    <option value="90">Last 90 days</option>
                    <option value="180">Last 180 days</option>
                </select>
                <button id="refresh-button" class="button">Refresh</button>
            </div>
        </div>

        <section class="grid-metrics" id="metrics-grid"></section>

        <section class="layout">
            <div class="panel">
                <div class="panel-header">
                    <div>
                        <h2>Scan History</h2>
                        <p>Grouped by scan session so you can review one run at a time.</p>
                    </div>
                    <div class="muted" id="history-count">-- sessions</div>
                </div>
                <div class="panel-body">
                    <div class="charts">
                        <div class="chart-card"><canvas id="timeline-chart"></canvas></div>
                        <div class="chart-card"><canvas id="status-chart"></canvas></div>
                    </div>

                    <div class="subgrid">
                        <div class="panel" style="box-shadow:none; background:rgba(7,11,20,0.35);">
                            <div class="panel-header">
                                <div>
                                    <h2>Recent Sessions</h2>
                                    <p>Latest scan runs with open-port counts and risk level.</p>
                                </div>
                            </div>
                            <div class="panel-body" style="padding-top:0;">
                                <table class="history-table">
                                    <thead>
                                        <tr>
                                            <th>Session</th>
                                            <th>Targets</th>
                                            <th>Duration</th>
                                            <th>Open</th>
                                            <th>Risk</th>
                                        </tr>
                                    </thead>
                                    <tbody id="history-body">
                                        <tr><td colspan="5" class="muted">Loading scan history...</td></tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>

                        <div class="panel" style="box-shadow:none; background:rgba(7,11,20,0.35);">
                            <div class="panel-header">
                                <div>
                                    <h2>Exposure Mix</h2>
                                    <p>Top ports, services, and host concentration.</p>
                                </div>
                            </div>
                            <div class="panel-body">
                                <div class="mini-list" id="top-ports"></div>
                                <div style="height:14px"></div>
                                <div class="mini-list" id="top-hosts"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>

            <aside class="panel">
                <div class="panel-header">
                    <div>
                        <h2>Critical Findings</h2>
                        <p>Defensive exposure points and concise hardening advice.</p>
                    </div>
                    <div class="muted" id="finding-count">-- findings</div>
                </div>
                <div class="panel-body">
                    <div class="list" id="findings-list">
                        <div class="muted">Loading findings...</div>
                    </div>
                    <div class="footer-note">
                        The dashboard intentionally frames these as exposure and hardening items rather than exploit instructions.
                    </div>
                </div>
            </aside>
        </section>

        <div class="error-box" id="error-box"></div>
    </main>

    <script>
        const state = {
            dashboard: null,
            charts: { timeline: null, status: null },
        };

        const formatInt = (value) => new Intl.NumberFormat().format(Number(value || 0));

        const formatTimestamp = (value) => {
            if (!value) return '--';
            const date = new Date(value);
            if (Number.isNaN(date.getTime())) return String(value);
            return new Intl.DateTimeFormat(undefined, {
                month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
            }).format(date);
        };

        const statusClass = (status) => `status-${status || 'closed'}`;

        const severityClass = (severity) => `severity-${(severity || 'low').toLowerCase()}`;

        const escapeText = (value) => {
            const span = document.createElement('span');
            span.textContent = value ?? '';
            return span.innerHTML;
        };

        const showError = (message) => {
            const box = document.getElementById('error-box');
            box.style.display = 'block';
            box.textContent = message;
        };

        const hideError = () => {
            const box = document.getElementById('error-box');
            box.style.display = 'none';
            box.textContent = '';
        };

        const renderMetrics = (summary) => {
            const metrics = [
                {
                    label: 'Scan sessions',
                    value: summary.total_scans,
                    note: `${summary.total_checks} port checks across ${summary.total_hosts} hosts`,
                },
                {
                    label: 'Open ports',
                    value: summary.open_ports,
                    note: `${summary.risky_open_ports} high-risk exposures flagged by the dashboard`,
                },
                {
                    label: 'Filtered / error',
                    value: summary.filtered_ports + summary.error_ports,
                    note: 'Ports that were blocked, filtered, or failed to respond cleanly',
                },
                {
                    label: 'Critical findings',
                    value: summary.finding_count,
                    note: summary.latest_seen ? `Latest activity ${formatTimestamp(summary.latest_seen)}` : 'No scan activity yet',
                },
            ];

            document.getElementById('metrics-grid').innerHTML = metrics.map((metric) => `
                <article class="metric">
                    <div class="label">${escapeText(metric.label)}</div>
                    <div class="value">${formatInt(metric.value)}</div>
                    <div class="note">${escapeText(metric.note)}</div>
                </article>
            `).join('');
        };

        const renderHistory = (sessions) => {
            const body = document.getElementById('history-body');
            document.getElementById('history-count').textContent = `${formatInt(sessions.length)} sessions`;
            if (!sessions.length) {
                body.innerHTML = '<tr><td colspan="5" class="muted">No scan sessions found for this time window.</td></tr>';
                return;
            }

            body.innerHTML = sessions.map((session) => `
                <tr>
                    <td>
                        <strong>${escapeText(session.short_id)}</strong><br>
                        <span class="muted">${formatTimestamp(session.ended_at)}</span>
                    </td>
                    <td>
                        <div>${escapeText(session.targets_label)}</div>
                        <div class="muted">${formatInt(session.host_count)} host${session.host_count === 1 ? '' : 's'}</div>
                    </td>
                    <td>
                        <div>${escapeText(session.duration_label)}</div>
                        <div class="muted">${formatInt(session.checks)} checks</div>
                    </td>
                    <td>
                        <span class="status-chip ${statusClass('open')}">${formatInt(session.open_count)} open</span>
                    </td>
                    <td>
                        <span class="severity-chip ${severityClass(session.risk_severity)}">${escapeText(session.risk_label)}</span>
                    </td>
                </tr>
            `).join('');
        };

        const renderMiniList = (target, rows, emptyMessage, formatter) => {
            const node = document.getElementById(target);
            if (!rows.length) {
                node.innerHTML = `<div class="muted">${escapeText(emptyMessage)}</div>`;
                return;
            }

            node.innerHTML = rows.map(formatter).join('');
        };

        const renderFindings = (findings) => {
            document.getElementById('finding-count').textContent = `${formatInt(findings.length)} findings`;
            const target = document.getElementById('findings-list');

            if (!findings.length) {
                target.innerHTML = '<div class="finding"><div class="status-chip status-closed">No critical findings</div><h3>Nothing urgent detected</h3><p>The current scan window did not surface any high-risk exposure patterns.</p></div>';
                return;
            }

            target.innerHTML = findings.map((finding) => `
                <article class="finding">
                    <span class="severity-chip ${severityClass(finding.severity)}">${escapeText(finding.severity)}</span>
                    <h3>${escapeText(finding.title)}</h3>
                    <p>${escapeText(finding.summary)}</p>
                    <p><strong>Evidence:</strong> ${escapeText(finding.evidence)}</p>
                    <p><strong>Remediation:</strong> ${escapeText(finding.remediation)}</p>
                    ${finding.details?.length ? `<ul>${finding.details.map((line) => `<li>${escapeText(line)}</li>`).join('')}</ul>` : ''}
                </article>
            `).join('');
        };

        const renderCharts = (dashboard) => {
            const timelineCanvas = document.getElementById('timeline-chart');
            const statusCanvas = document.getElementById('status-chart');

            if (state.charts.timeline) state.charts.timeline.destroy();
            if (state.charts.status) state.charts.status.destroy();

            state.charts.timeline = new Chart(timelineCanvas, {
                type: 'line',
                data: {
                    labels: dashboard.timeline.map((item) => item.label),
                    datasets: [{
                        label: 'Open ports',
                        data: dashboard.timeline.map((item) => item.open_ports),
                        borderColor: '#38bdf8',
                        backgroundColor: 'rgba(56, 189, 248, 0.18)',
                        tension: 0.35,
                        fill: true,
                    }, {
                        label: 'Scans',
                        data: dashboard.timeline.map((item) => item.scans),
                        borderColor: '#8b5cf6',
                        backgroundColor: 'rgba(139, 92, 246, 0.12)',
                        tension: 0.35,
                        fill: false,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: { labels: { color: '#cbd5e1' } },
                    },
                    scales: {
                        x: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148, 163, 184, 0.08)' } },
                        y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(148, 163, 184, 0.08)' } },
                    },
                },
            });

            state.charts.status = new Chart(statusCanvas, {
                type: 'doughnut',
                data: {
                    labels: dashboard.status_breakdown.map((item) => item.label),
                    datasets: [{
                        data: dashboard.status_breakdown.map((item) => item.value),
                        backgroundColor: dashboard.status_breakdown.map((item) => item.color),
                        borderWidth: 0,
                    }],
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    cutout: '70%',
                    plugins: {
                        legend: {
                            position: 'bottom',
                            labels: { color: '#cbd5e1', usePointStyle: true, pointStyle: 'circle' },
                        },
                    },
                },
            });
        };

        const renderDashboard = (dashboard) => {
            state.dashboard = dashboard;
            document.getElementById('db-pill').innerHTML = dashboard.db_available
                ? '<strong>DB connected</strong> - data loaded from PostgreSQL'
                : '<strong>DB offline</strong> - dashboard running without data';
            document.getElementById('last-refresh').textContent = formatTimestamp(dashboard.generated_at);
            document.getElementById('window-label').textContent = String(dashboard.window_days);

            renderMetrics(dashboard.summary);
            renderHistory(dashboard.history);
            renderFindings(dashboard.findings);
            renderMiniList('top-ports', dashboard.top_ports, 'No port data available.', (row) => `
                <div class="mini-row">
                    <div>
                        <strong>Port ${escapeText(row.port)}</strong>
                        <div class="muted">${escapeText(row.service)} · ${formatInt(row.hosts)} hosts</div>
                    </div>
                    <div><strong>${formatInt(row.open_hits)}</strong><div class="muted">open</div></div>
                </div>
            `);

            renderMiniList('top-hosts', dashboard.top_hosts, 'No host data available.', (row) => `
                <div class="mini-row">
                    <div>
                        <strong>${escapeText(row.target_ip)}</strong>
                        <div class="muted">${formatInt(row.checks)} checks</div>
                    </div>
                    <div><strong>${formatInt(row.open_ports)}</strong><div class="muted">open ports</div></div>
                </div>
            `);

            renderCharts(dashboard);
        };

        const loadDashboard = async () => {
            const days = document.getElementById('days-select').value;
            document.getElementById('window-label').textContent = String(days);
            hideError();

            try {
                const response = await fetch(`/api/dashboard?days=${encodeURIComponent(days)}&limit=12`);
                const payload = await response.json();
                if (!response.ok || payload.error) {
                    throw new Error(payload.error || `Dashboard request failed with status ${response.status}`);
                }
                renderDashboard(payload);
            } catch (error) {
                showError(error.message || 'Unable to load dashboard data.');
                renderMetrics({ total_scans: 0, total_checks: 0, total_hosts: 0, open_ports: 0, risky_open_ports: 0, filtered_ports: 0, error_ports: 0, finding_count: 0, latest_seen: null });
                renderHistory([]);
                renderFindings([]);
                renderMiniList('top-ports', [], 'No port data available.', () => '');
                renderMiniList('top-hosts', [], 'No host data available.', () => '');
            }
        };

        document.getElementById('days-select').addEventListener('change', loadDashboard);
        document.getElementById('refresh-button').addEventListener('click', loadDashboard);

        loadDashboard();
    </script>
</body>
</html>
"""


def get_db_conn():
        if not DATABASE_URL:
                raise RuntimeError("DATABASE_URL not set")
        return psycopg2.connect(dsn=DATABASE_URL)


def _safe_int(value: Any, default: int = 0, minimum: int = 0, maximum: Optional[int] = None) -> int:
        try:
                parsed = int(value)
        except (TypeError, ValueError):
                return default
        if parsed < minimum:
                return minimum
        if maximum is not None and parsed > maximum:
                return maximum
        return parsed


def _format_duration(started_at: Any, ended_at: Any) -> str:
        if not started_at or not ended_at:
                return '--'
        delta = ended_at - started_at
        seconds = max(int(delta.total_seconds()), 0)
        minutes, secs = divmod(seconds, 60)
        hours, mins = divmod(minutes, 60)
        if hours:
                return f"{hours}h {mins}m"
        if minutes:
                return f"{minutes}m {secs}s"
        return f"{secs}s"


def _short_scan_id(scan_id: str) -> str:
        return scan_id[:8] if scan_id else '--'


def _session_targets(targets: Iterable[str]) -> str:
        targets = [target for target in targets if target]
        if not targets:
                return '--'
        if len(targets) <= 2:
                return ', '.join(targets)
        return f"{targets[0]}, {targets[1]} +{len(targets) - 2} more"


def _risk_from_counts(open_count: int, risky_count: int, unknown_count: int) -> Dict[str, str]:
        score = risky_count * 3 + unknown_count * 2 + max(open_count - 4, 0)
        if score >= 8:
                return {"label": "High exposure", "severity": "high"}
        if score >= 3:
                return {"label": "Review needed", "severity": "medium"}
        return {"label": "Low risk", "severity": "low"}


def _query_rows(query: str, params: Optional[Iterable[Any]] = None) -> List[Dict[str, Any]]:
        if not DATABASE_URL:
                return []
        conn = None
        try:
                conn = get_db_conn()
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute(query, tuple(params or ()))
                        rows = cur.fetchall()
                        return [dict(row) for row in rows]
        finally:
                if conn:
                        conn.close()


def _query_one(query: str, params: Optional[Iterable[Any]] = None) -> Optional[Dict[str, Any]]:
        rows = _query_rows(query, params)
        return rows[0] if rows else None


def _remediation_for_port(port: Optional[int], service: Optional[str] = None) -> str:
        if port in PORT_REMEDIATION:
                return PORT_REMEDIATION[port]
        if service:
                service_name = str(service).lower()
                if service_name in {"ssh", "sftp"}:
                        return "Restrict the service to trusted admin networks and enforce key-based authentication."
                if service_name in {"http", "https", "web"}:
                        return "Keep the web service patched, place it behind a reverse proxy or WAF, and limit admin access."
        return "Confirm the service is expected, restrict it to trusted networks, and close the port if it is not required."


def _build_finding(
        title: str,
        severity: str,
        summary: str,
        evidence: str,
        remediation: str,
        details: Optional[List[str]] = None,
) -> Dict[str, Any]:
        return {
                "title": title,
                "severity": severity,
                "summary": summary,
                "evidence": evidence,
                "remediation": remediation,
                "details": details or [],
        }


def _build_findings(days: int, limit: int = 250) -> List[Dict[str, Any]]:
        recent_rows = _query_rows(
                """
                SELECT scan_id, target_ip, port, status, service, timestamp
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                    AND status = 'open'
                ORDER BY timestamp DESC
                LIMIT %s
                """,
                (days, limit),
        )

        if not recent_rows:
                return []

        by_scan: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        port_counts: Counter[int] = Counter()
        open_targets_by_port: Dict[int, set] = defaultdict(set)

        for row in recent_rows:
                scan_id = row["scan_id"]
                port = int(row["port"])
                target_ip = row["target_ip"]
                by_scan[scan_id].append(row)
                port_counts[port] += 1
                open_targets_by_port[port].add(target_ip)

        findings: List[Dict[str, Any]] = []

        for scan_id, rows in by_scan.items():
                risky_rows = [row for row in rows if int(row["port"]) in RISKY_PORTS]
                unknown_rows = [row for row in rows if not row.get("service") or str(row.get("service")).lower() in {"unknown", "n/a", "none"}]
                if risky_rows:
                        ports = sorted({int(row["port"]) for row in risky_rows})
                        findings.append(
                                _build_finding(
                                        title="High-risk ports exposed",
                                        severity="High",
                                        summary=f"Session {_short_scan_id(scan_id)} exposed ports that commonly expand the attack surface.",
                                        evidence=f"Open ports: {', '.join(str(port) for port in ports[:6])}{'...' if len(ports) > 6 else ''}",
                                        remediation=_remediation_for_port(ports[0], risky_rows[0].get("service")),
                                        details=[f"{row['target_ip']}:{row['port']} ({row.get('service') or 'unknown'})" for row in risky_rows[:6]],
                                )
                        )
                if unknown_rows:
                        findings.append(
                                _build_finding(
                                        title="Unidentified services need verification",
                                        severity="Medium",
                                        summary="One or more open ports did not resolve to a known service name.",
                                        evidence=f"{len(unknown_rows)} open result(s) reported as unknown or blank service names.",
                                        remediation="Confirm whether the service is expected, then close the port or document it with an owner and purpose.",
                                        details=[f"{row['target_ip']}:{row['port']}" for row in unknown_rows[:6]],
                                )
                        )
                if len(rows) >= 5:
                        findings.append(
                                _build_finding(
                                        title="Broad exposure on a single scan session",
                                        severity="Medium",
                                        summary="The session shows several simultaneously open ports, which increases the reachable attack surface.",
                                        evidence=f"{len(rows)} open ports observed in session {_short_scan_id(scan_id)}.",
                                        remediation="Segment the host, narrow firewall rules, and verify that each open service is required for production use.",
                                        details=[f"{row['target_ip']}:{row['port']} ({row.get('service') or 'unknown'})" for row in rows[:6]],
                                )
                        )

        for port, count in port_counts.items():
                distinct_targets = len(open_targets_by_port[port])
                if distinct_targets >= 3:
                        findings.append(
                                _build_finding(
                                        title=f"Repeated exposure of port {port}",
                                        severity="High" if port in RISKY_PORTS else "Medium",
                                        summary="The same port is open across multiple targets in the selected window.",
                                        evidence=f"Port {port} is open on {distinct_targets} distinct host(s).",
                                        remediation=_remediation_for_port(port),
                                        details=[f"Observed {count} open result(s) on that port in the selected window."],
                                )
                        )

        unique: List[Dict[str, Any]] = []
        seen = set()
        for finding in findings:
                key = (finding["title"], finding["evidence"])
                if key in seen:
                        continue
                seen.add(key)
                unique.append(finding)

        severity_order = {"High": 0, "Medium": 1, "Low": 2}
        return sorted(unique, key=lambda item: (severity_order.get(item["severity"], 3), item["title"]))


def _build_history(days: int, limit: int, offset: int = 0) -> List[Dict[str, Any]]:
        rows = _query_rows(
                """
                SELECT
                        scan_id,
                        ARRAY_AGG(DISTINCT target_ip ORDER BY target_ip) AS targets,
                        MIN(timestamp) AS started_at,
                        MAX(timestamp) AS ended_at,
                        COUNT(*) AS checks,
                        COUNT(DISTINCT target_ip) AS host_count,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_count,
                        SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) AS closed_count,
                        SUM(CASE WHEN status = 'filtered' THEN 1 ELSE 0 END) AS filtered_count,
                        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_count,
                        SUM(CASE WHEN status = 'open' AND port = ANY(%s) THEN 1 ELSE 0 END) AS risky_open_count,
                        SUM(CASE WHEN status = 'open' AND (service IS NULL OR service = '' OR LOWER(service) IN ('unknown', 'n/a', 'none')) THEN 1 ELSE 0 END) AS unknown_service_count
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY scan_id
                ORDER BY MAX(timestamp) DESC
                LIMIT %s OFFSET %s
                """,
                (list(sorted(RISKY_PORTS)), days, limit, offset),
        )

        history: List[Dict[str, Any]] = []
        for row in rows:
                risk = _risk_from_counts(
                        int(row.get("open_count") or 0),
                        int(row.get("risky_open_count") or 0),
                        int(row.get("unknown_service_count") or 0),
                )
                history.append(
                        {
                                "scan_id": row["scan_id"],
                                "short_id": _short_scan_id(row["scan_id"]),
                                "targets": row.get("targets") or [],
                                "targets_label": _session_targets(row.get("targets") or []),
                                "started_at": row.get("started_at").isoformat() if row.get("started_at") else None,
                                "ended_at": row.get("ended_at").isoformat() if row.get("ended_at") else None,
                                "duration_label": _format_duration(row.get("started_at"), row.get("ended_at")),
                                "checks": int(row.get("checks") or 0),
                                "host_count": int(row.get("host_count") or 0),
                                "open_count": int(row.get("open_count") or 0),
                                "closed_count": int(row.get("closed_count") or 0),
                                "filtered_count": int(row.get("filtered_count") or 0),
                                "error_count": int(row.get("error_count") or 0),
                                "risk_label": risk["label"],
                                "risk_severity": risk["severity"],
                        }
                )
        return history


def _build_summary(days: int, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        row = _query_one(
                """
                SELECT
                        COUNT(*) AS total_checks,
                        COUNT(DISTINCT scan_id) AS total_scans,
                        COUNT(DISTINCT target_ip) AS total_hosts,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_ports,
                        SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) AS closed_ports,
                        SUM(CASE WHEN status = 'filtered' THEN 1 ELSE 0 END) AS filtered_ports,
                        SUM(CASE WHEN status = 'error' THEN 1 ELSE 0 END) AS error_ports,
                        SUM(CASE WHEN status = 'open' AND port = ANY(%s) THEN 1 ELSE 0 END) AS risky_open_ports,
                        COUNT(DISTINCT service) FILTER (WHERE service IS NOT NULL AND service <> '') AS distinct_services,
                        MAX(timestamp) AS latest_seen
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                """,
                (list(sorted(RISKY_PORTS)), days),
        ) or {}

        return {
                "total_checks": int(row.get("total_checks") or 0),
                "total_scans": int(row.get("total_scans") or 0),
                "total_hosts": int(row.get("total_hosts") or 0),
                "open_ports": int(row.get("open_ports") or 0),
                "closed_ports": int(row.get("closed_ports") or 0),
                "filtered_ports": int(row.get("filtered_ports") or 0),
                "error_ports": int(row.get("error_ports") or 0),
                "risky_open_ports": int(row.get("risky_open_ports") or 0),
                "distinct_services": int(row.get("distinct_services") or 0),
                "finding_count": len(findings),
                "latest_seen": row.get("latest_seen").isoformat() if row.get("latest_seen") else None,
        }


def _build_timeline(days: int) -> List[Dict[str, Any]]:
        rows = _query_rows(
                """
                SELECT
                        DATE_TRUNC('day', timestamp) AS bucket,
                        COUNT(DISTINCT scan_id) AS scans,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_ports
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY 1
                ORDER BY 1
                """,
                (days,),
        )
        return [
                {
                        "label": row["bucket"].date().isoformat() if row.get("bucket") else '--',
                        "scans": int(row.get("scans") or 0),
                        "open_ports": int(row.get("open_ports") or 0),
                }
                for row in rows
        ]


def _build_status_breakdown(days: int) -> List[Dict[str, Any]]:
        rows = _query_rows(
                """
                SELECT status, COUNT(*) AS total
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY status
                """,
                (days,),
        )
        lookup = {row["status"]: int(row.get("total") or 0) for row in rows}
        return [
                {"label": STATUS_LABELS[status], "value": lookup.get(status, 0), "color": STATUS_COLORS[status]}
                for status in STATUS_ORDER
        ]


def _build_top_ports(days: int, limit: int = 10) -> List[Dict[str, Any]]:
        rows = _query_rows(
                """
                SELECT
                        port,
                        COALESCE(NULLIF(service, ''), 'unknown') AS service,
                        COUNT(*) AS hits,
                        COUNT(DISTINCT target_ip) AS hosts,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_hits
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY port, COALESCE(NULLIF(service, ''), 'unknown')
                ORDER BY open_hits DESC, hits DESC, port ASC
                LIMIT %s
                """,
                (days, limit),
        )
        return [
                {
                        "port": int(row["port"]),
                        "service": row.get("service") or 'unknown',
                        "hits": int(row.get("hits") or 0),
                        "hosts": int(row.get("hosts") or 0),
                        "open_hits": int(row.get("open_hits") or 0),
                }
                for row in rows
        ]


def _build_top_hosts(days: int, limit: int = 10) -> List[Dict[str, Any]]:
        rows = _query_rows(
                """
                SELECT
                        target_ip,
                        COUNT(*) AS checks,
                        SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_ports,
                        COUNT(DISTINCT port) AS distinct_ports
                FROM scans
                WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                GROUP BY target_ip
                ORDER BY open_ports DESC, checks DESC, target_ip ASC
                LIMIT %s
                """,
                (days, limit),
        )
        return [
                {
                        "target_ip": row["target_ip"],
                        "checks": int(row.get("checks") or 0),
                        "open_ports": int(row.get("open_ports") or 0),
                        "distinct_ports": int(row.get("distinct_ports") or 0),
                }
                for row in rows
        ]


def build_dashboard(days: int = 30, limit: int = 12) -> Dict[str, Any]:
        days = _safe_int(days, default=30, minimum=1, maximum=3650)
        limit = _safe_int(limit, default=12, minimum=1, maximum=100)
        findings = _build_findings(days)
        return {
                "db_available": bool(DATABASE_URL),
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "window_days": days,
                "summary": _build_summary(days, findings),
                "history": _build_history(days, limit),
                "findings": findings,
                "timeline": _build_timeline(days),
                "status_breakdown": _build_status_breakdown(days),
                "top_ports": _build_top_ports(days),
                "top_hosts": _build_top_hosts(days),
        }


@app.route("/")
def index():
        return HTML_TEMPLATE


@app.route("/api/dashboard")
def api_dashboard():
        if not DATABASE_URL:
                return jsonify({"error": "DATABASE_URL not set", "db_available": False, "history": [], "findings": [], "timeline": [], "status_breakdown": [], "top_ports": [], "top_hosts": [], "summary": {"total_checks": 0, "total_scans": 0, "total_hosts": 0, "open_ports": 0, "closed_ports": 0, "filtered_ports": 0, "error_ports": 0, "risky_open_ports": 0, "distinct_services": 0, "finding_count": 0, "latest_seen": None}}), 503

        days = _safe_int(request.args.get("days", 30), default=30, minimum=1, maximum=3650)
        limit = _safe_int(request.args.get("limit", 12), default=12, minimum=1, maximum=100)
        try:
                return jsonify(build_dashboard(days=days, limit=limit))
        except Exception as exc:
                logger.exception("Dashboard build failed: %s", exc)
                return jsonify({"error": "Failed to load dashboard data"}), 500


@app.route("/api/scans")
def api_scans():
        if not DATABASE_URL:
                return jsonify([]), 503

        days = _safe_int(request.args.get("days", 30), default=30, minimum=1, maximum=3650)
        limit = _safe_int(request.args.get("limit", 200), default=200, minimum=1, maximum=1000)
        offset = _safe_int(request.args.get("offset", 0), default=0, minimum=0, maximum=100000)
        scan_id = request.args.get("scan_id")
        target_ip = request.args.get("ip")
        port = request.args.get("port")
        status = request.args.get("status")

        query = [
                "SELECT scan_id, target_ip, port, status, service, timestamp",
                "FROM scans",
                "WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')",
        ]
        params: List[Any] = [days]

        if scan_id:
                query.append("AND scan_id = %s")
                params.append(scan_id)
        if target_ip:
                query.append("AND target_ip = %s")
                params.append(target_ip)
        if port:
                query.append("AND port = %s")
                params.append(_safe_int(port, minimum=1, maximum=65535))
        if status:
                query.append("AND status = %s")
                params.append(status)

        query.append("ORDER BY timestamp DESC")
        query.append("LIMIT %s OFFSET %s")
        params.extend([limit, offset])

        try:
                return jsonify(_query_rows(" ".join(query), params))
        except Exception as exc:
                logger.exception("DB error in /api/scans: %s", exc)
                return jsonify([]), 500


@app.route("/api/scans/<scan_id>")
def api_scan_detail(scan_id: str):
        if not DATABASE_URL:
                return jsonify([]), 503
        try:
                rows = _query_rows(
                        """
                        SELECT scan_id, target_ip, port, status, service, timestamp
                        FROM scans
                        WHERE scan_id = %s
                        ORDER BY timestamp DESC
                        """,
                        (scan_id,),
                )
                return jsonify(rows)
        except Exception as exc:
                logger.exception("DB error in /api/scans/<scan_id>: %s", exc)
                return jsonify([]), 500


@app.route("/api/stats")
def api_stats():
        if not DATABASE_URL:
                return jsonify({"open": 0, "closed": 0, "filtered": 0, "error": 0}), 503
        days = _safe_int(request.args.get("days", 30), default=30, minimum=1, maximum=3650)
        try:
                rows = _query_rows(
                        """
                        SELECT status, COUNT(*) AS total
                        FROM scans
                        WHERE timestamp >= NOW() - (%s * INTERVAL '1 day')
                        GROUP BY status
                        """,
                        (days,),
                )
                stats = {status: 0 for status in STATUS_ORDER}
                for row in rows:
                        stats[row["status"]] = int(row.get("total") or 0)
                return jsonify(stats)
        except Exception as exc:
                logger.exception("DB error in /api/stats: %s", exc)
                return jsonify({"open": 0, "closed": 0, "filtered": 0, "error": 0}), 500


@app.route("/api/findings")
def api_findings():
        if not DATABASE_URL:
                return jsonify([]), 503
        days = _safe_int(request.args.get("days", 30), default=30, minimum=1, maximum=3650)
        try:
                return jsonify(_build_findings(days))
        except Exception as exc:
                logger.exception("DB error in /api/findings: %s", exc)
                return jsonify([]), 500


@app.route("/scans")
def scans_list():
        return api_scans()


@app.route("/scans/<scan_id>")
def scans_detail(scan_id: str):
        return api_scan_detail(scan_id)


@app.route("/stats")
def stats():
        return api_stats()


if __name__ == "__main__":
        app.run(host="127.0.0.1", port=5000, debug=True)
