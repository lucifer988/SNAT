"""Authentication: login / logout / change_password / csrf_token."""
import sqlite3
from flask import Blueprint, request, jsonify, session, redirect, url_for, render_template

from web import app as _app

bp = Blueprint('auth', __name__)


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    data = request.json or {}
    username = data.get('username', '')
    password = data.get('password', '')

    if not _app.check_login_attempts(username):
        return jsonify({'success': False, 'error': '登录失败'}), 401

    conn = sqlite3.connect(_app.DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()

    stored_hash = user['password'] if user else None
    # 无论用户是否存在都执行常量时间校验，消除“用户名是否存在”的计时侧信道。
    password_ok = _app.verify_password_constant_time(stored_hash, password)
    if user and password_ok:
        _app.upgrade_password_hash_if_needed(username, password, user['password'])
        session['logged_in'] = True
        session['username'] = username
        session['must_change_password'] = bool(user['must_change_password'])
        session.permanent = True
        _app.app.logger.info(f"Login success for {username}")
        _app.record_login_attempt(username, True)
        _app.log_event('INFO', f"用户登录成功: {username}")
        _app.audit_log('login', username)
        csrf = _app.generate_csrf_token()
        return jsonify({'success': True, 'must_change_password': bool(user['must_change_password']), 'csrf_token': csrf})

    _app.record_login_attempt(username, False)
    _app.log_event('WARNING', f"用户登录失败: {username}")
    _app.audit_log('login', username, 'failed')
    return jsonify({'success': False, 'error': '登录失败'}), 401


@bp.route('/logout')
def logout():
    user = session.get('username', '-')
    session.clear()
    _app.log_event('INFO', f"用户登出: {user}")
    return redirect(url_for('auth.login'))


@bp.route('/api/change_password', methods=['POST'])
@_app.login_required
def change_password():
    data = request.json or {}
    old_password = data.get('old_password', '')
    new_password = data.get('new_password', '')

    err = _app.validate_password_strength(new_password)
    if err:
        return jsonify({'success': False, 'error': err}), 400

    conn = sqlite3.connect(_app.DB_FILE)
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
    user = c.fetchone()

    if user and _app.verify_password(user[0], old_password):
        c.execute(
            'UPDATE users SET password = ?, must_change_password = 0, password_changed_at = CURRENT_TIMESTAMP WHERE username = ?',
            (_app.hash_password(new_password), session['username'])
        )
        conn.commit()
        conn.close()
        session['must_change_password'] = False
        _app.log_event('INFO', f"用户修改密码: {session.get('username','-')}")
        _app.audit_log('change_password', session.get('username', '-'))
        return jsonify({'success': True})

    conn.close()
    return jsonify({'success': False, 'error': '原密码错误'}), 401


@bp.route('/api/csrf_token')
def get_csrf_token():
    if not session.get('logged_in'):
        return jsonify({'error': '未登录'}), 401
    token = _app.generate_csrf_token()
    _app.log_event('INFO', "生成 CSRF Token")
    return jsonify({'token': token})
