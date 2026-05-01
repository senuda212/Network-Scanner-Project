"""webapp.py - simple Flask dashboard and API for scan results"""
import os
import logging
from flask import Flask, jsonify, request, render_template_string
import psycopg2

from env_loader import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)
app = Flask(__name__)

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    logger.warning("DATABASE_URL not set; webapp will be read-only without DB")

BASIC_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Network Scanner Dashboard</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="p-4">
<div class="container">
  <h1 class="mb-4">Network Scanner — Dashboard</h1>
  <div id="summary" class="mb-4"></div>
  <div id="table"></div>
</div>
<script>
async function load() {
  const resp = await fetch('/scans');
  const data = await resp.json();
  const table = document.createElement('table');
  table.className = 'table table-striped';
  table.innerHTML = `<thead><tr><th>scan_id</th><th>ip</th><th>port</th><th>status</th><th>timestamp</th></tr></thead>`;
  const tbody = document.createElement('tbody');
  data.forEach(r => {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${r.scan_id}</td><td>${r.target_ip}</td><td>${r.port}</td><td>${r.status}</td><td>${r.timestamp}</td>`;
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  document.getElementById('table').appendChild(table);
}
load();
</script>
</body>
</html>
"""


def get_db_conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL not set")
    return psycopg2.connect(dsn=DATABASE_URL)


@app.route('/')
def index():
    return render_template_string(BASIC_HTML)


@app.route('/scans')
def scans_list():
    # Optional filters
    ip = request.args.get('ip')
    port = request.args.get('port')
    status = request.args.get('status')
    limit = int(request.args.get('limit', 200))
    q = "SELECT scan_id, target_ip, port, status, timestamp FROM scans"
    where = []
    params = []
    if ip:
        where.append("target_ip = %s")
        params.append(ip)
    if port:
        where.append("port = %s")
        params.append(int(port))
    if status:
        where.append("status = %s")
        params.append(status)
    if where:
        q += " WHERE " + " AND ".join(where)
    q += " ORDER BY timestamp DESC LIMIT %s"
    params.append(limit)
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(q, params)
            rows = cur.fetchall()
            results = [dict(scan_id=r[0], target_ip=r[1], port=r[2], status=r[3], timestamp=r[4].isoformat()) for r in rows]
        conn.close()
        return jsonify(results)
    except Exception as exc:
        logger.exception("DB error in /scans: %s", exc)
        return jsonify([]), 500


@app.route('/scans/<scan_id>')
def scans_detail(scan_id):
    q = "SELECT scan_id, target_ip, port, status, timestamp FROM scans WHERE scan_id = %s ORDER BY timestamp DESC"
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(q, (scan_id,))
            rows = cur.fetchall()
            results = [dict(scan_id=r[0], target_ip=r[1], port=r[2], status=r[3], timestamp=r[4].isoformat()) for r in rows]
        conn.close()
        return jsonify(results)
    except Exception as exc:
        logger.exception("DB error in /scans/<scan_id>: %s", exc)
        return jsonify([]), 500


@app.route('/stats')
def stats():
    q = "SELECT status, COUNT(*) FROM scans GROUP BY status"
    try:
        conn = get_db_conn()
        with conn.cursor() as cur:
            cur.execute(q)
            rows = cur.fetchall()
            stats = {r[0]: r[1] for r in rows}
        conn.close()
        return jsonify(stats)
    except Exception as exc:
        logger.exception("DB error in /stats: %s", exc)
        return jsonify({}), 500


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)
