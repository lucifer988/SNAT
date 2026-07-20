from flask import Blueprint, jsonify, request
import ipaddress
import secrets
import time

from web import app as _app

bp = Blueprint('wireguard_enroll', __name__)


def _valid_pubkey(value):
    if not isinstance(value, str) or len(value) != 44:
        return False
    try:
        import base64
        base64.b64decode(value, validate=True)
        return True
    except Exception:
        return False


def _read_hub():
    import os, re
    path = os.getenv('SNAT_WG_CONFIG', '/etc/wireguard/wg0.conf')
    try:
        text = open(path, encoding='utf-8').read()
        m = re.search(r'^Address\s*=\s*([^/\s]+)/([0-9]+)', text, re.M)
        if not m:
            return None
        return ipaddress.ip_interface(f'{m.group(1)}/{m.group(2)}')
    except OSError:
        return None


@bp.route('/api/wireguard/enrollment', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def create_enrollment():
    data = request.json or {}
    try:
        name = str(data.get('name', '')).strip()
        ip = ipaddress.ip_address(str(data.get('agent_ip', '')).strip())
        if not name or len(name) > 64 or not __import__('re').fullmatch(r'[A-Za-z0-9._-]{1,64}', name):
            raise ValueError
        hub = _read_hub()
        if not hub or ip.version != 4 or ip not in hub.network or ip == hub.ip:
            raise ValueError
    except ValueError:
        return jsonify({'success': False, 'error': '名称或 Agent WG 地址无效'}), 400
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    conn = _app.sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.execute('INSERT INTO wg_enrollment_tokens (token,name,agent_ip,expires_at,created_at) VALUES (?,?,?,?,?)',
                 (token, name, str(ip), now + 600, now))
    conn.commit(); conn.close()
    _app.audit_log('create_wg_enrollment', name, 'success', str(ip))
    return jsonify({'success': True, 'token': token, 'expires_in': 600, 'agent_ip': str(ip)})


@bp.route('/api/wireguard/enrollment/claim', methods=['POST'])
def claim_enrollment():
    data = request.json or {}
    token = data.get('token'); pub = data.get('public_key')
    if not isinstance(token, str) or len(token) < 32 or not _valid_pubkey(pub):
        return jsonify({'success': False, 'error': '注册码或公钥无效'}), 400
    now = int(time.time())
    conn = _app.sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = _app.sqlite3.Row
    row = conn.execute('SELECT * FROM wg_enrollment_tokens WHERE token=? AND used_at IS NULL AND expires_at>?', (token, now)).fetchone()
    if not row:
        conn.close(); return jsonify({'success': False, 'error': '注册码不存在、已使用或已过期'}), 403
    cur = conn.execute('UPDATE wg_enrollment_tokens SET used_at=? WHERE token=? AND used_at IS NULL', (now, token))
    if cur.rowcount != 1:
        conn.close(); return jsonify({'success': False, 'error': '注册码已被使用'}), 403
    conn.commit()
    try:
        import json, socket
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(15); sock.connect('/run/snat-wg-peer.sock')
        sock.sendall((json.dumps({'op':'add','name':row['name'],'public_key':pub,'agent_ip':row['agent_ip']}, separators=(',', ':'))+'\n').encode())
        result = json.loads(sock.recv(4096).decode()); sock.close()
        if not result.get('success'): raise RuntimeError(result.get('error', 'peer helper failed'))
    except Exception:
        conn.execute('UPDATE wg_enrollment_tokens SET used_at=NULL WHERE token=? AND used_at=?', (token, now))
        conn.commit()
        conn.close(); return jsonify({'success': False, 'error': 'WireGuard peer 写入失败'}), 503
    conn.close()
    return jsonify({'success': True, 'name': row['name'], 'agent_ip': row['agent_ip']})
