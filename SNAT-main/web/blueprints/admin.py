"""Admin / ops endpoints: dashboard, diag, logs, backup, snapshots, import/export, audit."""
import os
import csv
import io
import shutil
import sqlite3
import requests
from collections import deque
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template

from web import app as _app

bp = Blueprint('admin', __name__)


@bp.route('/')
def index():
    if not session.get('logged_in'):
        return redirect(url_for('auth.login'))
    return render_template(
        'index.html',
        must_change_password=session.get('must_change_password', False),
        force_https=_app.is_force_https_enabled(),
        app_env=_app.APP_ENV
    )


@bp.route('/api/diag', methods=['GET'])
@_app.login_required
def diag():
    _app.log_event('INFO', "触发系统诊断")
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers')
    server_rows = [dict(row) for row in c.fetchall()]
    conn.close()

    results = []
    for server in server_rows:
        try:
            resp = _app.agent_get(
                f"http://{server['host']}:{server['port']}/health",
                _app.decrypt_token(server['token']),
                timeout=3
            )
            if resp.status_code == 200:
                health = resp.json()
                results.append({
                    'server_id': server['id'],
                    'server_name': server['name'],
                    'status': 'healthy',
                    'ip_forward': health.get('ip_forward', False),
                    'iptables_ok': health.get('iptables_ok', False),
                    'docker_ok': health.get('docker_ok', True)
                })
            else:
                results.append({
                    'server_id': server['id'],
                    'server_name': server['name'],
                    'status': 'error',
                    'error': f'HTTP {resp.status_code}'
                })
        except Exception as e:
            results.append({'server_id': server['id'], 'server_name': server['name'], 'status': 'offline', 'error': str(e)})

    return jsonify({'servers': results})


@bp.route('/api/logs', methods=['GET'])
@_app.login_required
def get_logs():
    try:
        lines = list(_app.log_buffer)
        if os.path.exists(_app.LOG_FILE):
            with open(_app.LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                tail = deque(f, maxlen=200)
            for line in tail:
                line = line.rstrip('\n')
                if line and (not lines or line != lines[-1]):
                    lines.append(line)
        return jsonify({'success': True, 'lines': lines[-300:]})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@bp.route('/api/audit_logs', methods=['GET'])
@_app.login_required
def get_audit_logs():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'items': rows})


@bp.route('/api/backup', methods=['POST'])
@_app.login_required
def create_backup_api():
    path = _app.create_backup('api')
    _app.log_event('INFO', f"创建备份: {path}")
    return jsonify({'success': True, 'path': path})


@bp.route('/api/backup/list', methods=['GET'])
@_app.login_required
def list_backups():
    os.makedirs(_app.BACKUP_DIR, exist_ok=True)
    items = [
        {'name': name, 'path': os.path.join(_app.BACKUP_DIR, name)}
        for name in sorted(os.listdir(_app.BACKUP_DIR), reverse=True)
        if os.path.isdir(os.path.join(_app.BACKUP_DIR, name))
    ]
    return jsonify({'success': True, 'items': items})


@bp.route('/api/backup/restore', methods=['POST'])
@_app.login_required
def restore_backup():
    data = request.json or {}
    if data.get('confirm') != 'RESTORE':
        return jsonify({'success': False, 'error': '需要 confirm=RESTORE'}), 400

    raw_path = data.get('path', '')
    if not _app._backup_path_is_safe(raw_path):
        _app.audit_log('restore_backup', str(raw_path), 'rejected', 'path outside BACKUP_DIR')
        _app.log_event('WARNING', f"拒绝恢复备份：路径不在 BACKUP_DIR 范围内 ({raw_path})")
        return jsonify({'success': False, 'error': '备份路径不合法'}), 400

    backup_dir = os.path.realpath(raw_path)
    ok, reason = _app._verify_backup_manifest(backup_dir)
    if not ok:
        _app.audit_log('restore_backup', backup_dir, 'rejected', reason)
        return jsonify({'success': False, 'error': f'备份校验失败: {reason}'}), 400

    db_path = os.path.join(backup_dir, 'snat_manager.db')
    if not os.path.exists(db_path):
        return jsonify({'success': False, 'error': '备份不存在'}), 404

    try:
        _app.create_backup('pre-restore')
    except Exception as e:
        _app.log_event('WARNING', f"pre-restore 备份失败: {e}")

    # 用 SQLite backup API 把备份内容写回在线库：
    # 直接 copy2 覆盖一个正被 WAL 模式打开的库文件，残留的 -wal/-shm 会与新文件不一致，
    # 轻则恢复内容被 WAL 回放覆盖、重则整库损坏。backup API 在数据库层做替换，天然一致。
    try:
        _app._sqlite_backup(db_path, _app.DB_FILE)
    except Exception as e:
        _app.audit_log('restore_backup', backup_dir, 'failed', str(e))
        return jsonify({'success': False, 'error': f'恢复失败: {e}'}), 500
    _app.audit_log('restore_backup', backup_dir)
    return jsonify({'success': True})


@bp.route('/api/snapshots', methods=['GET', 'POST'])
@_app.login_required
def snapshots():
    if request.method == 'POST':
        sid = _app.create_rule_snapshot((request.json or {}).get('reason', 'manual'))
        return jsonify({'success': True, 'id': sid})
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, username, reason, created_at FROM rule_snapshots ORDER BY id DESC LIMIT 100')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify({'success': True, 'items': rows})


@bp.route('/api/snapshots/<int:snapshot_id>', methods=['DELETE'])
@_app.login_required
def delete_snapshot(snapshot_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('DELETE FROM rule_snapshots WHERE id = ?', (snapshot_id,))
    conn.commit()
    conn.close()
    _app.audit_log('delete_snapshot', str(snapshot_id))
    return jsonify({'success': True})


@bp.route('/api/snapshots/<int:snapshot_id>/restore', methods=['POST'])
@_app.login_required
def restore_snapshot(snapshot_id):
    data = request.json or {}
    if data.get('confirm') != 'RESTORE':
        return jsonify({'success': False, 'error': '需要 confirm=RESTORE'}), 400
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT payload FROM rule_snapshots WHERE id = ?', (snapshot_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': 'snapshot not found'}), 404
    payload = _app.json.loads(row['payload'])
    c.execute('DELETE FROM rules')
    for rule in payload:
        c.execute(
            'INSERT INTO rules (id, server_id, local_port, target_host, target_ip, target_port, remark, status, enabled, traffic_limit_gb, traffic_used_bytes, last_iptables_bytes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (rule['id'], rule['server_id'], rule['local_port'], rule.get('target_host', ''), rule['target_ip'],
             rule['target_port'], rule.get('remark', ''), rule.get('status', 'active'), rule.get('enabled', 1),
             rule.get('traffic_limit_gb', 0), rule.get('traffic_used_bytes', 0), rule.get('last_iptables_bytes', 0),
             rule.get('created_at'))
        )
    conn.commit()
    conn.close()
    _app.audit_log('restore_snapshot', str(snapshot_id))
    return jsonify({'success': True})


@bp.route('/api/export/servers', methods=['GET'])
@_app.login_required
def export_servers():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT name,host,port,token,status FROM servers ORDER BY id')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['name', 'host', 'port', 'token', 'status'])
    writer.writeheader()
    writer.writerows(rows)
    _app.audit_log('export_servers', 'servers', 'success', f'count={len(rows)}')
    return output.getvalue(), 200, {'Content-Type': 'text/csv; charset=utf-8'}


@bp.route('/api/export/rules', methods=['GET'])
@_app.login_required
def export_rules():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT server_id,local_port,target_host,target_ip,target_port,remark,enabled,traffic_limit_gb FROM rules ORDER BY id')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=['server_id', 'local_port', 'target_host', 'target_ip', 'target_port', 'remark', 'enabled', 'traffic_limit_gb'])
    writer.writeheader()
    writer.writerows(rows)
    _app.audit_log('export_rules', 'rules', 'success', f'count={len(rows)}')
    return output.getvalue(), 200, {'Content-Type': 'text/csv; charset=utf-8'}


@bp.route('/api/import/servers', methods=['POST'])
@_app.login_required
def import_servers():
    data = request.json or {}
    rows = data.get('rows', [])
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    inserted = 0
    skipped = 0
    for row in rows:
        try:
            host = str(row.get('host', '')).strip()
            ok_host, _err = _app.validate_agent_host(host)
            if not ok_host or not str(row.get('name', '')).strip() or not str(row.get('token', '')).strip():
                skipped += 1
                continue
            port = int(row.get('port', 8888))
            if not (1 <= port <= 65535):
                skipped += 1
                continue
            c.execute('INSERT INTO servers (name, host, port, token) VALUES (?, ?, ?, ?)',
                      (str(row['name']).strip(), host, port, _app.encrypt_token(str(row['token']).strip())))
            inserted += 1
        except Exception:
            skipped += 1
    conn.commit()
    conn.close()
    _app.audit_log('import_servers', 'servers', 'success', f'inserted={inserted} skipped={skipped}')
    return jsonify({'success': True, 'inserted': inserted, 'skipped': skipped})


@bp.route('/api/import/rules', methods=['POST'])
@_app.login_required
def import_rules():
    data = request.json or {}
    rows = data.get('rows', [])
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('SELECT id FROM servers')
    valid_server_ids = {r[0] for r in c.fetchall()}
    inserted = 0
    skipped = 0
    for row in rows:
        try:
            server_id = int(row['server_id'])
            local_port = int(row['local_port'])
            target_port = int(row['target_port'])
            target_ip = str(row.get('target_ip', '')).strip()
            # 与手动新增规则保持同一套校验口径，杜绝脏数据经导入通道落库
            if server_id not in valid_server_ids:
                skipped += 1
                continue
            if not (1 <= local_port <= 65535) or not (1 <= target_port <= 65535) or not target_ip:
                skipped += 1
                continue
            c.execute(
                'INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, enabled, traffic_limit_gb) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                (server_id, local_port, str(row.get('target_host', ''))[:253], target_ip,
                 target_port, str(row.get('remark', ''))[:200], 1 if int(row.get('enabled', 1)) else 0,
                 max(0, int(row.get('traffic_limit_gb', 0))))
            )
            inserted += 1
        except Exception:
            skipped += 1
    conn.commit()
    conn.close()
    _app.audit_log('import_rules', 'rules', 'success', f'inserted={inserted} skipped={skipped}')
    return jsonify({'success': True, 'inserted': inserted, 'skipped': skipped})
