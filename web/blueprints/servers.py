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
        c.execute('SELECT * FROM servers ORDER BY id DESC')
        server_list = [dict(row) for row in c.fetchall()]

        for server in server_list:
            try:
                resp = _app.agent_get(
                    f"http://{server['host']}:{server['port']}/health",
                    _app.decrypt_token(server['token']),
                    timeout=2
                )
                if resp.status_code == 200:
                    status = 'online'
                    try:
                        c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
                                  (status, server['id']))
                    except OperationalError as e:
                        _app.log_event('WARNING', f"更新服务器状态跳过(locked) {server['id']}: {e}")
                elif resp.status_code == 401:
                    status = 'token_invalid'
                    _app.mark_token_invalid(server['id'], 'health 401')
                else:
                    status = 'offline'
                    try:
                        c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
                                  (status, server['id']))
                    except OperationalError as e:
                        _app.log_event('WARNING', f"更新服务器状态跳过(locked) {server['id']}: {e}")
                server['status'] = status
            except Exception as e:
                server['status'] = 'offline'
                try:
                    c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
                              ('offline', server['id']))
                except OperationalError as oe:
                    _app.log_event('WARNING', f"离线状态写回跳过(locked) {server['id']}: {oe}")
                _app.log_event('WARNING', f"服务器健康检查失败 {server['id']}: {e}")

        try:
            conn.commit()
        except OperationalError as e:
            _app.log_event('WARNING', f"servers接口提交跳过(locked): {e}")
        conn.close()
        return jsonify(server_list)

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
        c.execute('INSERT INTO servers (name, host, port, token) VALUES (?, ?, ?, ?)',
                  (data['name'].strip(), host, port, _app.encrypt_token(data['token'].strip())))
        conn.commit()
        server_id = c.lastrowid
        conn.close()
        _app.log_event('INFO', f"新增服务器 {server_id}: {data['name']} {data['host']}:{data.get('port', 8888)}")
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
    for k in ('name', 'host', 'token'):
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
        c.execute('UPDATE servers SET name = ?, host = ?, port = ?, token = ? WHERE id = ?',
                  (data['name'].strip(), host, port,
                   _app.encrypt_token(data['token'].strip()), server_id))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({'success': False, 'error': '服务器名称已存在'}), 400
    conn.close()
    _app.audit_log('update_server', str(server_id))
    return jsonify({'success': True})


@bp.route('/api/servers/<int:server_id>', methods=['DELETE'])
@_app.login_required
@_app.require_recent_auth()
def delete_server(server_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('DELETE FROM servers WHERE id = ?', (server_id,))
    c.execute('DELETE FROM rules WHERE server_id = ?', (server_id,))
    conn.commit()
    conn.close()
    _app.log_event('INFO', f"删除服务器 {server_id}")
    return jsonify({'success': True})


@bp.route('/api/servers/<int:server_id>/check', methods=['GET'])
@_app.login_required
def check_server(server_id):
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers WHERE id = ?', (server_id,))
    server = dict(c.fetchone())

    try:
        resp = _app.agent_get(
            f"http://{server['host']}:{server['port']}/health",
            _app.decrypt_token(server['token']),
            timeout=3
        )
        if resp.status_code == 200:
            c.execute('UPDATE servers SET status = ? WHERE id = ?', ('online', server_id))
            conn.commit()
            status = 'online'
        elif resp.status_code == 401:
            status = 'token_invalid'
            _app.mark_token_invalid(server_id, 'health 401')
        else:
            status = 'offline'
        _app.log_event('INFO', f"服务器检查 {server_id}: {status}")
    except Exception as e:
        c.execute('UPDATE servers SET status = ? WHERE id = ?', ('offline', server_id))
        conn.commit()
        status = 'offline'
        _app.log_event('WARNING', f"服务器检查失败 {server_id}: {e}")

    conn.close()
    return jsonify({'success': True, 'status': status})


@bp.route('/api/servers/bulk_check', methods=['POST'])
@_app.login_required
def bulk_check_servers():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers ORDER BY id DESC')
    server_list = [dict(row) for row in c.fetchall()]
    conn.close()
    results = []
    for server in server_list:
        try:
            resp = _app.agent_get(
                f"http://{server['host']}:{server['port']}/health",
                _app.decrypt_token(server['token']),
                timeout=3
            )
            results.append({'id': server['id'], 'name': server['name'], 'status_code': resp.status_code, 'ok': resp.status_code == 200})
        except Exception as e:
            results.append({'id': server['id'], 'name': server['name'], 'ok': False, 'error': str(e)})
    return jsonify({'success': True, 'results': results})
