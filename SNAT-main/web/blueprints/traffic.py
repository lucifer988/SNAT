"""Traffic and active-connection monitoring endpoints."""
import hmac
import sqlite3
import requests
from flask import Blueprint, request, jsonify

from web import app as _app

bp = Blueprint('traffic', __name__)


@bp.route('/api/check_all_traffic', methods=['POST'])
@_app.login_required
def check_all_traffic():
    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT r.*, s.host, s.port, s.token
                FROM rules r JOIN servers s ON r.server_id = s.id
                WHERE r.enabled = 1''')
    rule_rows = [dict(row) for row in c.fetchall()]
    _app.log_event('INFO', f"检查 {len(rule_rows)} 条规则的流量")

    stopped_rules = []
    updated_count = 0
    for rule in rule_rows:
        try:
            url = f"http://{rule['host']}:{rule['port']}/get_traffic/{rule['local_port']}"
            resp = _app.agent_get(url, _app.decrypt_token(rule['token']), timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                current_counter = int(data.get('current_counter', 0) or 0)
                total_bytes = int(data.get('bytes', current_counter) or 0)

                c.execute(
                    'UPDATE rules SET traffic_used_bytes = ?, last_iptables_bytes = ?, last_agent_counter = ? WHERE id = ?',
                    (total_bytes, current_counter, current_counter, rule['id'])
                )
                updated_count += 1

                if rule['traffic_limit_gb'] > 0:
                    limit_bytes = rule['traffic_limit_gb'] * (1024 ** 3)
                    if total_bytes >= limit_bytes:
                        _app.log_event('WARNING', f"规则 {rule['id']} 超限: {total_bytes} >= {limit_bytes}")
                        try:
                            _app.agent_post(
                                f"http://{rule['host']}:{rule['port']}/check_traffic_limit",
                                _app.decrypt_token(rule['token']),
                                {'local_port': rule['local_port'],
                                 'traffic_limit_gb': rule['traffic_limit_gb'],
                                 'current_bytes': total_bytes},
                                timeout=3
                            )
                        except Exception:
                            pass
                        c.execute('UPDATE rules SET enabled = 0 WHERE id = ?', (rule['id'],))
                        stopped_rules.append(rule['id'])
            else:
                _app.log_event('ERROR', f"规则 {rule['id']} 流量查询失败: HTTP {resp.status_code}")
        except Exception as e:
            _app.log_event('ERROR', f"检查规则 {rule['id']} 流量失败: {e}")

    conn.commit()
    conn.close()
    _app.log_event('INFO', f"流量检查完成，更新 {updated_count} 条，停止 {len(stopped_rules)} 条规则")
    return jsonify({'success': True, 'updated': updated_count, 'stopped_count': len(stopped_rules)})


@bp.route('/api/traffic/summary', methods=['GET'])
@_app.login_required
def traffic_summary():
    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT r.id, r.local_port, r.remark, r.traffic_used_bytes, r.traffic_limit_gb, r.enabled, s.name as server_name FROM rules r JOIN servers s ON r.server_id=s.id ORDER BY r.traffic_used_bytes DESC')
    rows = [dict(row) for row in c.fetchall()]
    conn.close()
    total_bytes = sum(r['traffic_used_bytes'] or 0 for r in rows)
    return jsonify({
        'success': True,
        'total_bytes': total_bytes,
        'rules_count': len(rows),
        'enabled_count': sum(1 for r in rows if r['enabled']),
        'top_rules': rows[:10]
    })


@bp.route('/api/check_all_connections', methods=['POST'])
@_app.login_required
def check_all_connections():
    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT r.id, r.local_port, r.server_id, s.host, s.port, s.token
                 FROM rules r JOIN servers s ON r.server_id = s.id
                 WHERE r.enabled = 1''')
    rule_rows = [dict(row) for row in c.fetchall()]

    updated = 0
    failures = []
    for rule in rule_rows:
        try:
            url = f"http://{rule['host']}:{rule['port']}/get_connections/{rule['local_port']}"
            resp = _app.agent_get(url, _app.decrypt_token(rule['token']), timeout=3)
            if resp.status_code == 200:
                data = resp.json()
                active_connections = int(data.get('active_connections', 0) or 0)
                c.execute('UPDATE rules SET active_connections = ? WHERE id = ?', (active_connections, rule['id']))
                updated += 1
            else:
                failures.append({'rule_id': rule['id'], 'status_code': resp.status_code})
        except Exception as e:
            failures.append({'rule_id': rule['id'], 'error': str(e)})

    conn.commit()
    conn.close()
    return jsonify({'success': True, 'updated': updated, 'failures': failures})


@bp.route('/api/connections/summary', methods=['GET'])
@_app.login_required
def connections_summary():
    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id AS rule_id, active_connections FROM rules WHERE enabled = 1')
    items = [dict(r) for r in c.fetchall()]
    conn.close()
    total = sum(r.get('active_connections', 0) or 0 for r in items)
    return jsonify({'success': True, 'items': items, 'total_active_connections': total})


@bp.route('/api/agents/report_connections', methods=['POST'])
def report_connections():
    """Agent → Panel 反向回报：用 Agent 自己的 token + HMAC 签名校验。"""
    data = request.get_json(silent=True) or {}
    server_host = str(data.get('server_host', '')).strip()
    if not server_host:
        return jsonify({'success': False, 'error': 'missing server_host'}), 400

    token = _app.extract_bearer_token(request.headers.get('Authorization', ''))
    expected_token = _app.get_server_token_by_host(server_host)
    if not expected_token or not hmac.compare_digest(token, expected_token):
        return jsonify({'success': False, 'error': 'unauthorized'}), 401

    ok, reason = _app.verify_signed_request(
        token,
        request.method,
        request.path,
        request.headers.get('X-Timestamp', ''),
        request.headers.get('X-Signature', ''),
        request.get_data(as_text=True) or ''
    )
    if not ok:
        return jsonify({'success': False, 'error': reason}), 401

    samples = data.get('samples', [])
    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    updated = 0
    for s in samples:
        local_port = s.get('local_port')
        connections = int(s.get('active_connections', 0) or 0)
        if local_port:
            c.execute(
                'UPDATE rules SET active_connections = ? WHERE local_port = ? AND server_id IN (SELECT id FROM servers WHERE host = ?)',
                (connections, local_port, server_host)
            )
            updated += c.rowcount
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'updated': updated})
