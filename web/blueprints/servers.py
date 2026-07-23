"""Server CRUD and health check endpoints."""
import sqlite3
from sqlite3 import OperationalError
import ipaddress
import requests
from flask import Blueprint, request, jsonify

from web import app as _app

bp = Blueprint('servers', __name__)


@bp.route('/api/servers', methods=['GET', 'POST'])
@_app.login_required
def servers():
    conn = _app.get_db_conn(row_factory=True)
    c = conn.cursor()

    if request.method == 'GET':
        c.execute('SELECT id,name,host,port,status,last_check,created_at,sort_order FROM servers ORDER BY sort_order ASC, id DESC')
        server_list = [dict(row) for row in c.fetchall()]
        for server in server_list:
            server['token_set'] = True
            server['display_id'] = _app.circled_num(server['id'])
        conn.close()
        return jsonify(server_list)

    if not _app._recent_auth_ok():
        conn.close()
        return jsonify({'success': False, 'error': '新增服务器需要重新验证密码', 'reauth_required': True}), 403

    data = request.json or {}
    try:
        host = data['host'].strip()
        ok_host, host_err = _app.validate_agent_host(host)
        if not ok_host:
            conn.close()
            return jsonify({'success': False, 'error': host_err}), 400
        try:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if len(host) > 253 or not all(part and len(part) < 64 for part in host.split('.')):
                    raise ValueError
            port = int(data.get('port', 8888))
            if not (1 <= port <= 65535):
                raise ValueError
        except Exception:
            conn.close()
            return jsonify({'success': False, 'error': '服务器地址或端口无效'}), 400
        c.execute('SELECT COALESCE(MIN(sort_order), 0) - 1 FROM servers')
        next_sort_order = c.fetchone()[0]
        c.execute('INSERT INTO servers (name, host, port, token, sort_order) VALUES (?, ?, ?, ?, ?)',
                  (data['name'].strip(), host, port, _app.encrypt_token(data['token'].strip()), next_sort_order))
        conn.commit()
        server_id = c.lastrowid
        conn.close()
        _app.log_event('INFO', f"新增服务器 {server_id}: {data['name']} {data['host']}:{data.get('port', 8888)}")
        _app.audit_log('add_server', f"{_app.circled_num(server_id)}{data['name'].strip()}", 'success', f'{host}:{port}')
        return jsonify({'success': True, 'id': server_id})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': '服务器名称已存在'}), 400


@bp.route('/api/servers/<int:server_id>', methods=['PUT'])
@_app.login_required
@_app.require_recent_auth()
def update_server(server_id):
    data = request.json or {}
    # 字段缺失/类型错误时返回 400 而非未捕获异常 500
    for k in ('name', 'host'):
        if not isinstance(data.get(k), str) or not data.get(k).strip():
            return jsonify({'success': False, 'error': f'缺少必填字段: {k}'}), 400
    host = data['host'].strip()
    ok_host, host_err = _app.validate_agent_host(host)
    if not ok_host:
        return jsonify({'success': False, 'error': host_err}), 400
    try:
        port = int(data.get('port', 8888))
        if not (1 <= port <= 65535):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': '端口无效'}), 400

    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    try:
        new_token=(data.get('token') or '').strip()
        if new_token:
            c.execute('UPDATE servers SET name=?,host=?,port=?,token=? WHERE id=?',(data['name'].strip(),host,port,_app.encrypt_token(new_token),server_id))
        else:
            c.execute('UPDATE servers SET name=?,host=?,port=? WHERE id=?',(data['name'].strip(),host,port,server_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': '服务器名称已存在'}), 400
    conn.close()
    _app.audit_log('update_server', f"{_app.circled_num(server_id)}{data['name'].strip()}")
    return jsonify({'success': True})


@bp.route('/api/servers/reorder', methods=['POST'])
@_app.login_required
def reorder_servers():
    data = request.json or {}
    server_ids = data.get('server_ids')
    if not isinstance(server_ids, list) or not server_ids:
        return jsonify({'success': False, 'error': 'server_ids 必须是非空数组'}), 400
    try:
        server_ids = [int(value) for value in server_ids]
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': '服务器编号必须为整数'}), 400
    if len(server_ids) != len(set(server_ids)) or any(value < 1 for value in server_ids):
        return jsonify({'success': False, 'error': '服务器编号重复或无效'}), 400

    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    current_ids = [row[0] for row in conn.execute('SELECT id FROM servers').fetchall()]
    if set(server_ids) != set(current_ids) or len(server_ids) != len(current_ids):
        conn.close()
        return jsonify({'success': False, 'error': '服务器列表已变化，请刷新后重试'}), 409
    conn.executemany('UPDATE servers SET sort_order = ? WHERE id = ?',
                     [(position, server_id) for position, server_id in enumerate(server_ids)])
    conn.commit()
    conn.close()
    _app.audit_log('reorder_servers', 'servers', 'success', _app.json.dumps(server_ids))
    return jsonify({'success': True, 'server_ids': server_ids})


@bp.route('/api/servers/<int:server_id>', methods=['DELETE'])
@_app.login_required
@_app.require_recent_auth()
def delete_server(server_id):
    force=request.args.get('force')=='1'
    conn=sqlite3.connect(_app.DB_FILE,timeout=10); conn.row_factory=sqlite3.Row; c=conn.cursor()
    server=c.execute('SELECT * FROM servers WHERE id=?',(server_id,)).fetchone()
    if not server: conn.close(); return jsonify({'success':False,'error':'服务器不存在'}),404
    server=dict(server); rules=[dict(x) for x in c.execute('SELECT id,local_port FROM rules WHERE server_id=?',(server_id,)).fetchall()]
    failed=[]
    for rule in rules:
        try:
            resp=_app.agent_post(f"http://{server['host']}:{server['port']}/delete_rule",_app.decrypt_token(server['token']),{'local_port':rule['local_port']},timeout=5)
            payload=resp.json() or {}
            if resp.status_code!=200 or payload.get('success') is not True: failed.append({'rule_id':rule['id'],'local_port':rule['local_port'],'error':f'HTTP {resp.status_code}'})
        except Exception as exc: failed.append({'rule_id':rule['id'],'local_port':rule['local_port'],'error':str(exc)[:200]})
    if failed and not force:
        conn.close(); return jsonify({'success':False,'error':'远端规则未确认清理','cleanup_failed':failed,'require_force':True}),409
    c.execute('DELETE FROM rules WHERE server_id=?',(server_id,)); c.execute('DELETE FROM servers WHERE id=?',(server_id,)); conn.commit(); conn.close()
    _app.audit_log('delete_server', f"{_app.circled_num(server_id)}{server['name']}")
    if failed: _app.audit_log('delete_server_forced',f"{_app.circled_num(server_id)}{server['name']}",'warning',_app.json.dumps({'orphaned':failed},ensure_ascii=False))
    return jsonify({'success':True,'orphaned':failed})


@bp.route('/api/servers/<int:server_id>/check', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def check_server(server_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers WHERE id = ?', (server_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return jsonify({'success': False, 'error': '服务器不存在'}), 404
    server = dict(row)

    try:
        resp = _app.agent_get(
            f"http://{server['host']}:{server['port']}/health",
            _app.decrypt_token(server['token']),
            timeout=3
        )
        if resp.status_code == 200:
            status = 'online'
        elif resp.status_code == 401:
            status = 'token_invalid'
        else:
            status = 'offline'
        c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?', (status, server_id))
        conn.commit()
        if status == 'token_invalid':
            _app.mark_token_invalid(server_id, 'health 401')
        _app.log_event('INFO', f"服务器检查 {server_id}: {status}")
    except Exception as e:
        c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?', ('offline', server_id))
        conn.commit()
        status = 'offline'
        _app.log_event('WARNING', f"服务器检查失败 {server_id}: {e}")

    conn.close()
    return jsonify({'success': True, 'status': status})


@bp.route('/api/servers/bulk_check', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def bulk_check_servers():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers ORDER BY id DESC')
    server_list = [dict(row) for row in c.fetchall()]
    conn.close()
    results = []
    updates = []
    for server in server_list:
        try:
            resp = _app.agent_get(
                f"http://{server['host']}:{server['port']}/health",
                _app.decrypt_token(server['token']), timeout=3)
            status = 'online' if resp.status_code == 200 else ('token_invalid' if resp.status_code == 401 else 'offline')
            results.append({'id': server['id'], 'name': server['name'], 'status_code': resp.status_code, 'ok': status == 'online', 'status': status})
        except Exception as e:
            status = 'offline'
            results.append({'id': server['id'], 'name': server['name'], 'ok': False, 'status': status, 'error': str(e)})
        updates.append((status, server['id']))
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.executemany('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?', updates)
    conn.commit(); conn.close()
    return jsonify({'success': True, 'results': results})
