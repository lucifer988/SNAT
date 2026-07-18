"""System settings, whitelist, alerts blueprints."""
import sqlite3
import ipaddress
from flask import Blueprint, request, jsonify

from web import app as _app

bp = Blueprint('settings', __name__)


@bp.route('/api/settings', methods=['GET'])
@_app.login_required
def get_settings():
    return jsonify({
        'ip_whitelist': _app.get_ip_whitelist(),
        'rate_limit': _app.RATE_LIMIT_REQUESTS,
        'max_attempts': _app.MAX_ATTEMPTS,
        'force_https': _app.is_force_https_enabled()
    })


@bp.route('/api/settings/https', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def update_force_https():
    data = request.json or {}
    enabled = 1 if data.get('force_https') else 0
    _app.set_setting('force_https', str(enabled))
    _app.audit_log('update_force_https', 'settings', 'success', str(enabled))
    return jsonify({'success': True, 'force_https': bool(enabled), 'message': '设置已保存，建议重启 Web/反向代理后确认 HTTPS 生效'})


@bp.route('/api/settings/ip_whitelist', methods=['POST'])
@_app.login_required
@_app.require_recent_auth()
def update_ip_whitelist():
    data = request.json or {}
    new_whitelist = data.get('whitelist', [])

    for ip in new_whitelist:
        if not ip.strip():
            continue
        try:
            if '/' in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            return jsonify({'success': False, 'error': f'IP 格式错误: {ip}'}), 400

    normalized = [ip.strip() for ip in new_whitelist if ip.strip()]
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('DELETE FROM ip_whitelist')
    c.executemany('INSERT INTO ip_whitelist (ip, description) VALUES (?, ?)', [(ip, 'settings') for ip in normalized])
    conn.commit()
    conn.close()

    _app.log_event('INFO', f"更新 IP 白名单: {len(normalized)} 条")
    _app.audit_log('update_ip_whitelist', 'settings', 'success', str(len(normalized)))
    return jsonify({'success': True, 'whitelist': normalized})


@bp.route('/api/whitelist', methods=['GET', 'POST', 'DELETE'])
@_app.login_required
def whitelist():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if request.method == 'GET':
        c.execute('SELECT * FROM ip_whitelist ORDER BY id DESC')
        items = [dict(row) for row in c.fetchall()]
        conn.close()
        return jsonify(items)

    # 白名单增删属于控制面边界修改（会话被盗后可用来“把管理员锁在门外”），要求二次认证。
    if not _app._recent_auth_ok():
        conn.close()
        return jsonify({'success': False, 'error': '修改访问白名单需要重新验证密码', 'reauth_required': True}), 403

    if request.method == 'POST':
        data = request.json or {}
        ip = str(data.get('ip', '')).strip()
        if not ip:
            conn.close()
            return jsonify({'success': False, 'error': 'IP 不能为空'}), 400
        try:
            if '/' in ip:
                ipaddress.ip_network(ip, strict=False)
            else:
                ipaddress.ip_address(ip)
        except ValueError:
            conn.close()
            return jsonify({'success': False, 'error': f'IP 格式错误: {ip}'}), 400
        try:
            c.execute('INSERT INTO ip_whitelist (ip, description) VALUES (?, ?)',
                      (ip, str(data.get('description', ''))))
            conn.commit()
            conn.close()
            _app.log_event('INFO', f"添加白名单 IP: {ip}")
            return jsonify({'success': True})
        except sqlite3.IntegrityError:
            conn.close()
            return jsonify({'success': False, 'error': 'IP 已存在'}), 400

    # DELETE
    ip_id = request.args.get('id')
    c.execute('DELETE FROM ip_whitelist WHERE id = ?', (ip_id,))
    conn.commit()
    conn.close()
    _app.log_event('INFO', f"删除白名单 IP: {ip_id}")
    return jsonify({'success': True})


@bp.route('/api/settings/alerts', methods=['GET', 'POST'])
@_app.login_required
def alert_settings():
    if request.method == 'GET':
        # tg_bot_token 为敏感凭据：前端只回传是否已配置，不回显明文，避免页面/日志泄露。
        token = _app.get_secret_setting('tg_bot_token', '')
        return jsonify({
            'tg_bot_token_set': bool(token),
            'tg_chat_id': _app.get_setting('tg_chat_id', ''),
            'offline_seconds': int(_app.get_setting('alert_offline_seconds', '300') or '300'),
            'command_enabled': _app._setting_bool('tg_command_enabled', '0'),
            'daily_summary_enabled': _app._setting_bool('tg_enable_daily_summary', '1'),
            'daily_summary_time': _app.get_setting('tg_daily_summary_time', '09:00') or '09:00',
            'audit_enabled': _app._setting_bool('tg_enable_audit', '1'),
            'limit_alerts_enabled': _app._setting_bool('tg_enable_limit_alerts', '1')
        })
    data = request.json or {}
    # 仅当传入了非空 token 时才更新，留空表示「保持原值不变」，便于前端不回显也能改其它项。
    new_token = (data.get('tg_bot_token') or '').strip()
    if new_token:
        # 修改告警密钥属于敏感操作：要求会话最近二次验证过密码。
        if not _app._recent_auth_ok():
            return jsonify({'success': False, 'error': '修改告警 token 需要重新验证密码', 'reauth_required': True}), 403
        _app.set_secret_setting('tg_bot_token', new_token)
    _app.set_setting('tg_chat_id', (data.get('tg_chat_id') or '').strip())
    try:
        _app.set_setting('alert_offline_seconds', str(int(data.get('offline_seconds', 300))))
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'offline_seconds 必须为整数'}), 400
    _app.set_setting('tg_command_enabled', '1' if data.get('command_enabled', False) else '0')
    _app.set_setting('tg_enable_daily_summary', '1' if data.get('daily_summary_enabled', True) else '0')
    _app.set_setting('tg_daily_summary_time', str((data.get('daily_summary_time') or '09:00')).strip()[:5] or '09:00')
    _app.set_setting('tg_enable_audit', '1' if data.get('audit_enabled', True) else '0')
    _app.set_setting('tg_enable_limit_alerts', '1' if data.get('limit_alerts_enabled', True) else '0')
    _app.audit_log('update_alert_settings', 'alerts')
    return jsonify({'success': True})


@bp.route('/api/alerts/test', methods=['POST'])
@_app.login_required
def test_alert():
    ok, detail = _app.send_alert('SNAT test alert')
    _app.audit_log('test_alert', 'alerts', 'success' if ok else 'failed', detail)
    return jsonify({'success': ok, 'detail': detail})


@bp.route('/api/alerts/check', methods=['POST'])
@_app.login_required
def check_alerts():
    conn = sqlite3.connect(_app.DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM servers ORDER BY id DESC')
    server_rows = [dict(r) for r in c.fetchall()]
    conn.close()
    fired = []
    for server in server_rows:
        if server.get('status') in ('offline', 'token_invalid'):
            ok, detail = _app.send_alert(f"SNAT服务器 {server['name']} 状态异常: {server['status']}")
            fired.append({'server': server['name'], 'ok': ok, 'detail': detail})
    _app.audit_log('check_alerts', 'servers', 'success', _app.json.dumps(fired, ensure_ascii=False))
    return jsonify({'success': True, 'alerts': fired})
