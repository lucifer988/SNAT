"""Health probe blueprint. Returns a minimal payload (no env/config leakage)."""
import sqlite3
from flask import Blueprint, jsonify, Response
from web import app as _app  # 仅引用模块，避免循环 import

bp = Blueprint('health', __name__)


@bp.route('/healthz', methods=['GET'])
def healthz():
    try:
        conn = sqlite3.connect(_app.DB_FILE, timeout=10)
        conn.execute('SELECT 1')
        conn.close()
        return jsonify({'status': 'ok'})
    except Exception:
        return jsonify({'status': 'error'}), 500


@bp.route('/metrics', methods=['GET'])
def metrics():
    try:
        conn = sqlite3.connect(_app.DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM servers')
        servers_total = int(c.fetchone()[0] or 0)
        c.execute("SELECT COUNT(*) FROM servers WHERE status = 'online'")
        servers_online = int(c.fetchone()[0] or 0)
        c.execute("SELECT COUNT(*) FROM servers WHERE status = 'offline'")
        servers_offline = int(c.fetchone()[0] or 0)
        c.execute("SELECT COUNT(*) FROM servers WHERE status = 'token_invalid'")
        servers_token_invalid = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM rules')
        rules_total = int(c.fetchone()[0] or 0)
        c.execute('SELECT COUNT(*) FROM rules WHERE enabled = 1')
        rules_enabled = int(c.fetchone()[0] or 0)
        c.execute("SELECT COUNT(*) FROM rules WHERE status = 'desynced'")
        rules_desynced = int(c.fetchone()[0] or 0)
        c.execute('SELECT COALESCE(SUM(traffic_used_bytes), 0) FROM rules')
        traffic_total_bytes = int(c.fetchone()[0] or 0)
        c.execute('SELECT COALESCE(SUM(active_connections), 0) FROM rules WHERE enabled = 1')
        active_connections = int(c.fetchone()[0] or 0)
        conn.close()
        lines = [
            '# HELP snat_servers_total Total servers',
            '# TYPE snat_servers_total gauge',
            f'snat_servers_total {servers_total}',
            '# HELP snat_servers_online Online servers',
            '# TYPE snat_servers_online gauge',
            f'snat_servers_online {servers_online}',
            '# HELP snat_servers_offline Offline servers',
            '# TYPE snat_servers_offline gauge',
            f'snat_servers_offline {servers_offline}',
            '# HELP snat_servers_token_invalid Token invalid servers',
            '# TYPE snat_servers_token_invalid gauge',
            f'snat_servers_token_invalid {servers_token_invalid}',
            '# HELP snat_rules_total Total rules',
            '# TYPE snat_rules_total gauge',
            f'snat_rules_total {rules_total}',
            '# HELP snat_rules_enabled Enabled rules',
            '# TYPE snat_rules_enabled gauge',
            f'snat_rules_enabled {rules_enabled}',
            '# HELP snat_rules_desynced Desynced rules',
            '# TYPE snat_rules_desynced gauge',
            f'snat_rules_desynced {rules_desynced}',
            '# HELP snat_traffic_used_bytes Total tracked traffic bytes',
            '# TYPE snat_traffic_used_bytes gauge',
            f'snat_traffic_used_bytes {traffic_total_bytes}',
            '# HELP snat_active_connections Enabled rules active connections',
            '# TYPE snat_active_connections gauge',
            f'snat_active_connections {active_connections}',
        ]
        return Response('\n'.join(lines) + '\n', mimetype='text/plain; version=0.0.4')
    except Exception:
        return Response('snat_metrics_error 1\n', mimetype='text/plain; version=0.0.4', status=500)
