#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNAT Manager - Web 管理端
"""
from flask import Flask, request, jsonify, session, render_template, g, has_request_context
import sqlite3
import requests
import json
import hmac
import hashlib
import secrets
import time
import os
import ipaddress
import base64
import shutil
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
import logging
from urllib.parse import urlsplit
import threading
from uuid import uuid4
import sys

# ---------------------------------------------------------------------------
# 直接运行入口修复（python3 -m web.app / python3 web/app.py）
# ---------------------------------------------------------------------------
# 以 __main__ 身份执行时，blueprints 里的 `from web import app` 会把本文件当作
# `web.app` 再完整导入一遍，两个半初始化副本互相 import 触发
# "partially initialized module ... has no attribute 'bp'" 的循环导入崩溃
# （此前只有 gunicorn 的 web.wsgi 入口能启动，开发/调试直跑必挂）。
# 处理：
#   1) `python3 web/app.py` 直跑文件时，把仓库根目录补进 sys.path，让 `web` 包可导入；
#   2) 把当前 __main__ 模块登记为规范的 `web.app`，后续 import 一律复用本副本。
if __name__ == '__main__':
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)
    sys.modules.setdefault('web.app', sys.modules['__main__'])


# 是否在签名请求里仍附带 Authorization: Bearer <token>。
# 默认关闭：Agent 已优先验签，签名模式下再带明文 token 只会增加它在链路/日志/抓包/错误转储里
# 暴露的机会，让“仅签名模式”名不副实。仅当对接尚未升级、只认 Bearer 的老 Agent 时，才显式
# 设 SNAT_AGENT_SEND_BEARER=1 临时回退（同时需要 Agent 侧 AGENT_ALLOW_BEARER=1）。
AGENT_SEND_BEARER = os.getenv('SNAT_AGENT_SEND_BEARER', '0').lower() in ('1', 'true', 'yes')


def build_agent_headers(token, method, path, body=''):
    """构造带 HMAC 签名的 Agent 请求头。

    message = "{method}\n{path}\n{timestamp}\n{nonce}\n{body}"，与 Agent 端 verify_signed_request 一致。
    每次调用生成一次性 nonce（X-Nonce），绑定进签名用于防“时间窗内重放”。
    默认不再附带 Bearer token（见 AGENT_SEND_BEARER）。
    """
    ts = str(int(time.time()))
    nonce = secrets.token_urlsafe(16)
    body = body or ''
    message = f"{method}\n{path}\n{ts}\n{nonce}\n{body}".encode()
    sig = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
    headers = {
        'X-Timestamp': ts,
        'X-Nonce': nonce,
        'X-Signature': sig,
    }
    if has_request_context() and getattr(g, 'request_id', ''):
        headers['X-Request-ID'] = g.request_id
    if AGENT_SEND_BEARER:
        headers['Authorization'] = f'Bearer {token}'
    return headers


class AgentHostBlocked(Exception):
    """运行期拒绝向该 Agent 主机发起请求（如仅 IP 模式下命中域名主机）。

    继承自 Exception，调用方现有的 try/except 会把它当作一次失败处理（服务器判为
    offline/error 并记录），从而彻底停止对该主机的访问，而不是仅在新增/编辑时拦截。
    """


def _enforce_agent_host_runtime(url):
    """请求前的硬校验：仅 IP 模式下，非字面量 IP 的 Agent 主机一律拒绝发起请求。

    修复“SNAT_AGENT_HOST_IP_ONLY 只挡新增/编辑、挡不住库里历史域名主机”的迁移尾巴：
    只要开了仅 IP 模式，无论主机来自新表单还是老数据库，运行期都不再向域名主机发请求，
    彻底切断 DNS 重绑定/TOCTOU 通道。
    """
    if not AGENT_HOST_IP_ONLY:
        return
    host = urlsplit(url).hostname or ''
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise AgentHostBlocked(f'仅 IP 模式下拒绝访问域名 Agent 主机: {host or url}')


def agent_post(url, token, payload, timeout=5):
    _enforce_agent_host_runtime(url)
    path = urlsplit(url).path or '/'
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    return requests.post(
        url,
        data=body.encode(),
        headers={**build_agent_headers(token, 'POST', path, body), 'Content-Type': 'application/json'},
        timeout=timeout,
        allow_redirects=False  # 禁止跟随重定向：否则被控/被诱导的 Agent 可用 302 把签名请求重定向到 169.254.169.254 等元数据地址（SSRF 绕过）
    )


def agent_get(url, token, timeout=5):
    """带 HMAC 签名的 GET 请求（list_rules / health / get_traffic / get_connections）。

    与 agent_post 一致，让所有面板→Agent 调用都可被 Agent 验签，而不仅是写操作。
    同样禁止重定向，防止 302 → 云元数据的 SSRF；并在仅 IP 模式下拒绝域名主机。
    """
    _enforce_agent_host_runtime(url)
    path = urlsplit(url).path or '/'
    return requests.get(url, headers=build_agent_headers(token, 'GET', path, ''), timeout=timeout, allow_redirects=False)

# 持久化 secret_key，避免重启后所有 session 失效
_SECRET_KEY_FILE = os.getenv('SNAT_SECRET_KEY_FILE') or os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
def _load_secret_key():
    # 优先用环境变量注入（install.sh / systemd / Secrets Manager 已提供 SNAT_SECRET_KEY），
    # 这样密钥不必落到磁盘文件，便于集中托管与轮换；未提供时再回退到文件持久化。
    env_key = os.getenv('SNAT_SECRET_KEY', '').strip()
    if env_key:
        return env_key
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    # 用 O_CREAT|O_EXCL + 0o600 原子创建，避免"先以默认权限落盘、再 chmod"这段时间里
    # 密钥文件短暂 world-readable 的 TOCTOU 窗口。若并发已创建则回读现有值。
    try:
        fd = os.open(_SECRET_KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, key.encode())
        finally:
            os.close(fd)
    except FileExistsError:
        with open(_SECRET_KEY_FILE, 'r') as f:
            return f.read().strip()
    return key

app = Flask(__name__)
app.secret_key = _load_secret_key()
# 公网管理面板的会话不宜太长：7 天窗口一旦 cookie 泄露可用期过长。默认 12 小时，
# 且 Flask 默认 SESSION_REFRESH_EACH_REQUEST=True，会在每次请求时续期 —— 相当于“滑动
# 闲置超时”：持续使用不掉线，闲置超过窗口即失效。可用 SNAT_SESSION_LIFETIME_HOURS 调整。
try:
    _session_hours = float(os.getenv('SNAT_SESSION_LIFETIME_HOURS', '12'))
    if _session_hours <= 0:
        _session_hours = 12
except (TypeError, ValueError):
    _session_hours = 12
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=_session_hours)
app.config['SESSION_REFRESH_EACH_REQUEST'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
# Strict 提供更强的 CSRF 防护；仍保留独立的 X-CSRF-Token 校验作为第二道防线。
app.config['SESSION_COOKIE_SAMESITE'] = os.getenv('SESSION_COOKIE_SAMESITE', 'Strict')
APP_ENV = os.getenv('APP_ENV', 'production').lower()
FORCE_HTTPS = os.getenv('FORCE_HTTPS', '0').lower() not in ('0', 'false', 'no')
# 默认不信任 X-Forwarded-* 头：直连部署时盲信会让攻击者伪造 HTTPS 标志位。
# 反向代理后台部署时显式设置 TRUST_PROXY=1。
TRUST_PROXY = os.getenv('TRUST_PROXY', '0').lower() in ('1', 'true', 'yes')
# 反代后台必须修正 remote_addr：否则限流/登录锁定/IP 白名单全会把所有客户端看成代理本机(127.0.0.1)。
# 仅在显式信任代理时启用（信任 1 跳）；直连部署保持原始 remote_addr，不可被伪造。
if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
BACKUP_DIR = os.getenv('BACKUP_DIR', '/var/backups/snat-manager')
TOKEN_SECRET = os.getenv('SNAT_TOKEN_SECRET', '')
WEB_HOST = os.getenv('WEB_HOST', '0.0.0.0')
WEB_PORT = int(os.getenv('WEB_PORT', '5000'))
SIGNED_REQUEST_TTL = int(os.getenv('SIGNED_REQUEST_TTL', '300'))
app.config['SESSION_COOKIE_SECURE'] = FORCE_HTTPS
# 限制请求体大小：import/restore 等接口接收 JSON 数组，单进程下超大 body 会撑爆内存。
# 默认 4MB，足够正常导入；超限由 Werkzeug 直接返回 413，不进入业务逻辑。
app.config['MAX_CONTENT_LENGTH'] = int(os.getenv('WEB_MAX_CONTENT_LENGTH', str(4 * 1024 * 1024)))
DB_FILE = os.getenv('SNAT_DB_FILE') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snat_manager.db')

LOG_FILE = os.getenv('SNAT_LOG_FILE') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snat_web.log')
LOG_BUFFER_MAX = 500
log_buffer = deque(maxlen=LOG_BUFFER_MAX)
BACKUP_RETENTION = int(os.getenv('SNAT_BACKUP_RETENTION', '30'))

# 配置日志（7天自动清理）
handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=7)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)


class RequestIDFilter(logging.Filter):
    def filter(self, record):
        record.request_id = getattr(g, 'request_id', '-') if has_request_context() else '-'
        return True


for _h in app.logger.handlers:
    _h.addFilter(RequestIDFilter())
    _h.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [req:%(request_id)s] %(message)s'))

# 请求频率限制
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 60  # 每分钟最多60次请求
RATE_LIMIT_WINDOW = 60  # 时间窗口60秒

# token 校验失败时的安全策略
TOKEN_INVALID_DISABLE = True

# IP 白名单（可选，留空则不限制）
IP_WHITELIST = []  # 例如：['192.168.1.0/24', '10.0.0.1']


def _session_is_valid():
    """校验服务端会话记录；Cookie 只保存随机 ID，不再单独代表授权。"""
    sid = session.get('session_id')
    username = session.get('username')
    if app.config.get('TESTING') and not sid:
        return bool(session.get('logged_in') and username)
    if not sid or not username:
        return False
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        row = conn.execute(
            '''SELECT s.expires_at, s.revoked, s.session_version, u.session_version
               FROM web_sessions s JOIN users u ON u.username=s.username
               WHERE s.id=? AND s.username=?''',
            (sid, username),
        ).fetchone()
        conn.close()
        return bool(row and not row[1] and int(row[2]) == int(row[3]) and float(row[0]) > time.time())
    except sqlite3.Error:
        return False


def create_server_session(username):
    sid = secrets.token_urlsafe(32)
    expires_at = time.time() + app.permanent_session_lifetime.total_seconds()
    conn = sqlite3.connect(DB_FILE, timeout=10)
    version = conn.execute('SELECT session_version FROM users WHERE username=?', (username,)).fetchone()[0]
    conn.execute(
        'INSERT INTO web_sessions (id,username,session_version,expires_at) VALUES (?,?,?,?)',
        (sid, username, version, expires_at),
    )
    conn.commit(); conn.close()
    session['session_id'] = sid
    session['session_version'] = version
    return sid


def revoke_server_session(sid):
    if not sid:
        return
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute('UPDATE web_sessions SET revoked=1 WHERE id=?', (sid,))
    conn.commit(); conn.close()

# CSRF Token 存储（在 session 中）

def check_rate_limit():
    """检查请求频率"""
    client_ip = request.remote_addr
    now = time.time()
    
    # 清理过期记录
    rate_limit_store[client_ip] = [t for t in rate_limit_store[client_ip] if now - t < RATE_LIMIT_WINDOW]
    
    # 控制缓存大小，避免内存增长
    if len(rate_limit_store) > 10000:
        for ip in list(rate_limit_store.keys())[:2000]:
            rate_limit_store.pop(ip, None)
    
    # 检查频率
    if len(rate_limit_store[client_ip]) >= RATE_LIMIT_REQUESTS:
        return False
    
    rate_limit_store[client_ip].append(now)
    return True

def generate_csrf_token():
    """生成 CSRF Token"""
    token = secrets.token_hex(32)
    session['csrf_token'] = token
    return token

def verify_csrf_token(token):
    """验证 CSRF Token（常量时间比较，防时序侧信道）"""
    expected = session.get('csrf_token')
    if not token or not expected:
        return False
    return hmac.compare_digest(str(token), str(expected))

def hash_password(password):
    """密码哈希（显式指定 pbkdf2:sha256，避免依赖 OpenSSL 版本是否启用 scrypt）"""
    return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)


def is_legacy_sha256_hash(stored_hash):
    return (
        isinstance(stored_hash, str)
        and len(stored_hash) == 64
        and all(ch in '0123456789abcdef' for ch in stored_hash.lower())
    )


def verify_password(stored_hash, password):
    if not stored_hash:
        return False
    if is_legacy_sha256_hash(stored_hash):
        return stored_hash == hashlib.sha256(password.encode()).hexdigest()
    try:
        return check_password_hash(stored_hash, password)
    except ValueError:
        return False


def upgrade_password_hash_if_needed(username, password, stored_hash):
    if not is_legacy_sha256_hash(stored_hash):
        return
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute(
        'UPDATE users SET password = ?, password_changed_at = CURRENT_TIMESTAMP WHERE username = ?',
        (hash_password(password), username)
    )
    conn.commit()
    conn.close()


# 用户不存在时仍执行一次等价开销的哈希校验，抹平“用户存在/不存在”的响应时间差，
# 避免攻击者据此枚举有效用户名。值是随机的，永不匹配真实密码。
_DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(24))


def verify_password_constant_time(stored_hash, password):
    """登录专用：无论用户是否存在都进行一次哈希校验，消除计时侧信道。"""
    if not stored_hash:
        verify_password(_DUMMY_PASSWORD_HASH, password)
        return False
    return verify_password(stored_hash, password)


def is_secure_request():
    if request.is_secure:
        return True
    if TRUST_PROXY and request.headers.get('X-Forwarded-Proto', '').lower() == 'https':
        return True
    return False


_COMMON_WEAK_PASSWORDS = {
    'password', 'passw0rd', 'password1', 'password123', '12345678', '123456789',
    '1234567890', 'qwertyuiop', 'admin123', 'administrator', 'letmein123',
    'welcome123', 'changeme123', 'iloveyou1', 'abc12345', 'snatmanager',
    'p@ssw0rd', 'passw0rd1', 'qwerty123', 'admin1234',
}


def validate_password_strength(password):
    if len(password) < 10:
        return '密码至少10位'
    if password.lower() == password or password.upper() == password:
        return '密码必须同时包含大小写字母'
    if not any(ch.isdigit() for ch in password):
        return '密码必须包含数字'
    lowered = password.lower()
    if lowered in _COMMON_WEAK_PASSWORDS:
        return '该密码过于常见，请更换'
    # 纯连续/纯重复（如 aaaaaaaaaa、abcdefghij）视为弱口令
    stripped = lowered
    if len(set(stripped)) <= 3:
        return '密码字符过于单一，请增加复杂度'
    return None


# Token 加密说明
# ------------------------------------------------------------------
# v1 ('enc:')  : Fernet(key = sha256(TOKEN_SECRET))    —— 仅用于读取历史数据，向后兼容。
# v2 ('enc2:') : Fernet(key = scrypt(TOKEN_SECRET, ...))—— 写入时一律使用，KDF 抵抗暴破。
# 旧密文在读取后会被 _maybe_reencrypt_servers() 重新加密为 v2。
SCRYPT_SALT = b'snat-manager-token-salt-v2'
SCRYPT_PARAMS = {'n': 2 ** 15, 'r': 8, 'p': 1}
_TOKEN_CIPHER_CACHE = {'v1': None, 'v2': None}


def _get_token_cipher_v1():
    if _TOKEN_CIPHER_CACHE['v1'] is not None:
        return _TOKEN_CIPHER_CACHE['v1']
    if not TOKEN_SECRET:
        return None
    key = hashlib.sha256(TOKEN_SECRET.encode()).digest()
    cipher = Fernet(base64.urlsafe_b64encode(key))
    _TOKEN_CIPHER_CACHE['v1'] = cipher
    return cipher


def _get_token_cipher_v2():
    if _TOKEN_CIPHER_CACHE['v2'] is not None:
        return _TOKEN_CIPHER_CACHE['v2']
    if not TOKEN_SECRET:
        return None
    kdf = Scrypt(salt=SCRYPT_SALT, length=32, n=SCRYPT_PARAMS['n'], r=SCRYPT_PARAMS['r'], p=SCRYPT_PARAMS['p'])
    key = kdf.derive(TOKEN_SECRET.encode())
    cipher = Fernet(base64.urlsafe_b64encode(key))
    _TOKEN_CIPHER_CACHE['v2'] = cipher
    return cipher


def encrypt_token(token):
    """新增加密一律使用 v2（scrypt KDF）。"""
    cipher = _get_token_cipher_v2()
    if not cipher or not token:
        return token
    if isinstance(token, bytes):
        token = token.decode()
    if isinstance(token, str) and (token.startswith('enc:') or token.startswith('enc2:')):
        return token
    return 'enc2:' + cipher.encrypt(token.encode()).decode()


def decrypt_token(token):
    if not token:
        return token
    s = str(token)
    if s.startswith('enc2:'):
        cipher = _get_token_cipher_v2()
        if not cipher:
            return token
        try:
            return cipher.decrypt(s[5:].encode()).decode()
        except InvalidToken:
            return token
    if s.startswith('enc:'):
        cipher = _get_token_cipher_v1()
        if not cipher:
            return token
        try:
            return cipher.decrypt(s[4:].encode()).decode()
        except InvalidToken:
            return token
    return token


def _maybe_reencrypt_servers():
    """启动时把存量 v1 token 升级到 v2。失败的留待下次启动。"""
    if not _get_token_cipher_v2():
        return
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute('SELECT id, token FROM servers WHERE token LIKE ?', ('enc:%',))
        rows = c.fetchall()
        migrated = 0
        for row_id, enc1 in rows:
            plain = decrypt_token(enc1)
            if plain == enc1:
                continue  # 解不开，跳过
            new_enc = encrypt_token(plain)
            if new_enc.startswith('enc2:'):
                c.execute('UPDATE servers SET token = ? WHERE id = ?', (new_enc, row_id))
                migrated += 1
        if migrated:
            conn.commit()
            app.logger.info(f'token migration: re-encrypted {migrated} servers to enc2')
        conn.close()
    except Exception as e:
        app.logger.warning(f'token migration skipped: {e}')


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()


def _sqlite_backup(src_db_path, dst_db_path):
    """用 SQLite 在线备份 API 复制数据库。

    直接 copy2 一个开启了 WAL 的库，-wal 中未合并的事务会丢失甚至得到不一致快照；
    backup API 会拿到某个一致时点的完整数据（含 WAL 中已提交内容）。
    """
    src = sqlite3.connect(src_db_path, timeout=10)
    try:
        dst = sqlite3.connect(dst_db_path)
        try:
            src.backup(dst)
            dst.commit()
        finally:
            dst.close()
    finally:
        src.close()


def create_backup(reason='manual'):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_path = os.path.join(BACKUP_DIR, f'snat-backup-{reason}-{ts}')
    os.makedirs(backup_path, exist_ok=True)
    manifest = {'reason': reason, 'created_at': datetime.now().isoformat(), 'files': {}}
    for label, src in (('snat_manager.db', DB_FILE), ('snat_web.log', LOG_FILE)):
        if os.path.exists(src):
            dst = os.path.join(backup_path, label)
            if label == 'snat_manager.db':
                _sqlite_backup(src, dst)  # WAL 一致性快照
            else:
                shutil.copy2(src, dst)
            manifest['files'][label] = {'sha256': _sha256_file(dst), 'bytes': os.path.getsize(dst)}
    with open(os.path.join(backup_path, 'MANIFEST.json'), 'w') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    _cleanup_old_backups()
    return backup_path


def _cleanup_old_backups():
    if BACKUP_RETENTION <= 0:
        return
    try:
        items = [
            os.path.join(BACKUP_DIR, name)
            for name in sorted(os.listdir(BACKUP_DIR), reverse=True)
            if os.path.isdir(os.path.join(BACKUP_DIR, name))
        ]
        for stale in items[BACKUP_RETENTION:]:
            shutil.rmtree(stale, ignore_errors=True)
    except Exception as e:
        app.logger.warning(f'backup retention cleanup failed: {e}')


def _backup_path_is_safe(candidate):
    """校验 candidate 必须位于 BACKUP_DIR 真实路径内，防止 ../ 跳出或绝对路径攻击。"""
    if not candidate:
        return False
    try:
        base = os.path.realpath(BACKUP_DIR)
        target = os.path.realpath(candidate)
    except Exception:
        return False
    if not os.path.isdir(target):
        return False
    # commonpath 在不同盘/不同根目录会抛 ValueError
    try:
        common = os.path.commonpath([base, target])
    except ValueError:
        return False
    return common == base and target != base


def _verify_backup_manifest(backup_dir):
    """校验备份目录内文件与 MANIFEST.json 一致。"""
    manifest_path = os.path.join(backup_dir, 'MANIFEST.json')
    if not os.path.exists(manifest_path):
        return False, 'manifest missing'
    try:
        with open(manifest_path, 'r') as f:
            manifest = json.load(f)
    except Exception as e:
        return False, f'manifest unreadable: {e}'
    for name, meta in (manifest.get('files') or {}).items():
        file_path = os.path.join(backup_dir, name)
        if not os.path.exists(file_path):
            return False, f'file missing: {name}'
        if _sha256_file(file_path) != meta.get('sha256'):
            return False, f'checksum mismatch: {name}'
    return True, 'ok'

def get_db_conn(row_factory=False):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.execute('PRAGMA busy_timeout=10000')
    conn.execute('PRAGMA journal_mode=WAL')
    if row_factory:
        conn.row_factory = sqlite3.Row
    return conn


def get_ip_whitelist():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('SELECT ip FROM ip_whitelist ORDER BY id')
    whitelist = [row[0] for row in c.fetchall()]
    conn.close()
    return whitelist


def extract_bearer_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        return ''
    return auth_header[7:].strip()


class _NonceCache:
    """有界 TTL 去重缓存：记录 TTL 窗口内已见过的 nonce，防“时间窗内重放”。线程安全、有容量上限。"""
    def __init__(self, ttl, max_size=50000):
        self.ttl = ttl
        self.max_size = max_size
        self._store = {}
        import threading as _t
        self._lock = _t.Lock()

    def seen(self, nonce):
        now = time.time()
        with self._lock:
            expired = [k for k, exp in self._store.items() if exp <= now]
            for k in expired:
                self._store.pop(k, None)
            if len(self._store) > self.max_size:
                for k, _exp in sorted(self._store.items(), key=lambda kv: kv[1])[:len(self._store) - self.max_size]:
                    self._store.pop(k, None)
            if nonce in self._store:
                return True
            self._store[nonce] = now + self.ttl
            return False


_INBOUND_NONCE_CACHE = _NonceCache(SIGNED_REQUEST_TTL)
# 反向回报 (Agent → 面板) 是否强制要求 nonce。默认要求；与不带 nonce 的老 Agent 混跑时可临时置 0。
REQUIRE_INBOUND_NONCE = os.getenv('SNAT_REQUIRE_INBOUND_NONCE', '1').lower() in ('1', 'true', 'yes')


def verify_signed_request(token, method, path, timestamp, signature, body='', nonce=''):
    if not token or not timestamp or not signature:
        return False, 'missing_signature'
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid_timestamp'
    now = int(time.time())
    if abs(now - ts) > SIGNED_REQUEST_TTL:
        return False, 'timestamp_expired'
    if REQUIRE_INBOUND_NONCE and not nonce:
        return False, 'missing_nonce'
    message = f"{method}\n{path}\n{timestamp}\n{nonce or ''}\n{body or ''}".encode()
    expected = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, 'bad_signature'
    if nonce and _INBOUND_NONCE_CACHE.seen(nonce):
        return False, 'nonce_replayed'
    return True, 'ok'


# ---------------------------------------------------------------------------
# Agent 主机 SSRF 防护
# ---------------------------------------------------------------------------
# 面板会主动向「服务器(Agent)」的 host:port 发起带签名的 HTTP 请求（health / list_rules /
# add_rule ...）。host 由管理员录入，但面板本身常跑在云主机上，若被诱导填入云元数据地址
# (169.254.169.254) 等链路本地地址，签名请求就会打到元数据服务，泄露云厂商临时凭证 ——
# 这是典型的 SSRF。这里默认拒绝链路本地段；真实 Agent 几乎不会落在该段（WireGuard 用
# 10.x/172.16.x、内网用 192.168.x、同机用 127.0.0.1，均不受影响）。
# 如确有特殊网络需要放行，设 SNAT_AGENT_HOST_ALLOW_ALL=1；或用 SNAT_AGENT_HOST_DENY 追加 CIDR。
_AGENT_HOST_ALLOW_ALL = os.getenv('SNAT_AGENT_HOST_ALLOW_ALL', '0').lower() in ('1', 'true', 'yes')
_DEFAULT_AGENT_DENY_CIDRS = ['169.254.0.0/16', 'fe80::/10']


def _agent_deny_networks():
    cidrs = list(_DEFAULT_AGENT_DENY_CIDRS)
    extra = os.getenv('SNAT_AGENT_HOST_DENY', '')
    for item in extra.split(','):
        item = item.strip()
        if item:
            cidrs.append(item)
    nets = []
    for c in cidrs:
        try:
            nets.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            continue
    return nets


# 是否对主机名做解析校验（默认开启）。解析后若落入拒绝网段则拒绝，堵住
# "把 Agent 主机填成解析到 169.254.169.254 的域名"这类绕过。设 SNAT_AGENT_HOST_RESOLVE_CHECK=0 可关闭。
# 注意：这是尽力而为的校验，无法根治 DNS 重绑定（TOCTOU）——真正的兜底仍是 agent_* 已禁用重定向 +
# Agent 侧 is_target_ip_allowed + 部署侧网络策略。
_AGENT_HOST_RESOLVE_CHECK = os.getenv('SNAT_AGENT_HOST_RESOLVE_CHECK', '1').lower() in ('1', 'true', 'yes')

# 仅 IP 模式：只接受字面量 IP 作为 Agent 地址，直接拒绝域名。域名再怎么做解析校验，都无法根治
# DNS 重绑定 / TOCTOU（校验时解析到安全地址，请求时切到 169.254.169.254）。用 WireGuard 时本
# 就应填固定 WG IP，因此**生产环境强烈建议开启** SNAT_AGENT_HOST_IP_ONLY=1，直接砍掉一整类
# DNS 相关不确定性。默认关闭以兼容既有的域名部署；开启后新增/编辑服务器时域名将被拒绝。
AGENT_HOST_IP_ONLY = os.getenv('SNAT_AGENT_HOST_IP_ONLY', '0').lower() in ('1', 'true', 'yes')


def _hostname_resolves_to_denied(host):
    """解析主机名，若任一解析结果落入拒绝网段则返回 True。解析失败时不阻断（返回 False）。"""
    import socket
    deny = _agent_deny_networks()
    if not deny:
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False  # 解析不了不在此阻断，交由后续网络策略兜底
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr.split('%')[0])
        except ValueError:
            continue
        if any(ip in net for net in deny):
            return True
    return False


def validate_agent_host(host):
    """校验 Agent 主机是否允许被面板访问。返回 (ok, error_msg)。

    - 空 / 过长 / 含非法字符 → 拒绝。
    - 落在拒绝网段（默认链路本地，含云元数据 169.254.169.254）→ 拒绝。
    - 主机名（非字面量 IP）：默认做一次解析校验，解析到危险地址即拒绝（尽力而为，
      无法根治 DNS 重绑定；真正兜底靠 agent_* 禁用重定向 + Agent 侧 target 校验 + 网络策略）。
    """
    if not host or not isinstance(host, str):
        return False, '服务器地址不能为空'
    host = host.strip()
    if not host or len(host) > 253:
        return False, '服务器地址格式无效'
    # 基本字符白名单：IP / 主机名允许的字符，挡掉注入类输入
    if any(ch.isspace() for ch in host) or '/' in host or '\\' in host or '@' in host:
        return False, '服务器地址格式无效'
    if _AGENT_HOST_ALLOW_ALL:
        return True, ''
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # 主机名而非字面 IP
        if AGENT_HOST_IP_ONLY:
            return False, '仅允许填写 Agent 的 IP 地址（当前为仅 IP 模式，不接受域名）'
        if not all(part and len(part) < 64 for part in host.split('.')):
            return False, '服务器地址格式无效'
        if _AGENT_HOST_RESOLVE_CHECK and _hostname_resolves_to_denied(host):
            return False, '该主机名解析到不允许的地址段（疑似云元数据/链路本地地址）'
        return True, ''
    for net in _agent_deny_networks():
        if ip in net:
            return False, '该地址段不允许作为 Agent 主机（疑似云元数据/链路本地地址）'
    return True, ''


# ---------------------------------------------------------------------------
# 敏感设置加密存取（如 Telegram bot token）：复用 server token 的 v2 加密。
# ---------------------------------------------------------------------------
def get_secret_setting(key, default=''):
    return decrypt_token(get_setting(key, default))


def set_secret_setting(key, value):
    set_setting(key, encrypt_token((value or '').strip()))


def get_server_token_by_host(host):
    if not host:
        return None
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT token FROM servers WHERE host = ? LIMIT 1', (host,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return decrypt_token(row['token'])


def check_ip_whitelist():
    whitelist = get_ip_whitelist()

    if not whitelist:
        return True
    client_ip = request.remote_addr
    try:
        ip_obj = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for item in whitelist:
        try:
            if '/' in item:
                if ip_obj in ipaddress.ip_network(item, strict=False):
                    return True
            else:
                if ip_obj == ipaddress.ip_address(item):
                    return True
        except ValueError:
            continue
    return False

@app.context_processor
def _inject_csp_nonce():
    return {'csp_nonce': getattr(g, 'csp_nonce', '')}


# 客户端可控的 X-Request-ID 会被写入日志、回显到响应头、并转发到 Agent 请求头。
# 若不加约束：内嵌换行会让 Werkzeug 在序列化响应头时抛错 → 任意端点（含 /healthz）被
# 未认证请求打成 500；非换行垃圾字符（制表符/超长串）则原样进入日志与下游 Agent 头，
# 形成日志注入 / 请求头污染面。这里只保留安全字符集并限长，非法则回退到自生成 ID。
_REQUEST_ID_MAX_LEN = 64
_REQUEST_ID_SAFE = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-')


def _sanitize_request_id(raw):
    candidate = (raw or '').strip()
    if candidate and len(candidate) <= _REQUEST_ID_MAX_LEN and all(ch in _REQUEST_ID_SAFE for ch in candidate):
        return candidate
    return uuid4().hex[:12]


@app.before_request
def before_request():
    """全局请求前检查"""
    # 为本次请求生成 CSP nonce，供模板内联 <script> 与 after_request 的 CSP 头共用。
    g.csp_nonce = secrets.token_urlsafe(16)
    g.request_id = _sanitize_request_id(request.headers.get('X-Request-ID', ''))
    # SESSION_COOKIE_SECURE 启动时按 FORCE_HTTPS 环境变量固定，但 force_https 可在运行时切换。
    # 在此按运行时设置动态刷新该配置：Flask 在响应末尾 save_session 时会读取它决定是否打 Secure，
    # 从而消除"启动时 FORCE_HTTPS=0 → 运行时开启 HTTPS"期间 session cookie 仍走明文的窗口。
    app.config['SESSION_COOKIE_SECURE'] = is_force_https_enabled()
    if APP_ENV == 'production' and is_force_https_enabled() and not is_secure_request() and request.path != '/healthz':
        return jsonify({'error': 'HTTPS required'}), 403
    # 静态文件放行（登录页的 GET 也走静态样式）
    if request.path.startswith('/static/'):
        return

    # IP 白名单检查（登录页也纳入：白名单未命中直接挡在门外，不给爆破机会）
    if request.path != '/login' or request.method == 'POST':
        if not check_ip_whitelist():
            # 返回 404 而不是 403，不暴露系统信息
            return render_template('login.html'), 404

    # 请求频率限制：登录 POST 也纳入，防止绕过登录锁定做密码爆破 / 哈希 CPU 耗尽 DoS。
    # 仅对 GET 登录页放行（用户正常打开页面）。
    if not (request.path == '/login' and request.method == 'GET'):
        if not check_rate_limit():
            return render_template('login.html'), 429

@app.after_request
def after_request(response):
    """添加安全响应头"""
    # 防止信息泄露
    response.headers['Server'] = 'nginx'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # CSP：script-src 已去掉 'unsafe-inline'，改用 per-request nonce（见 g.csp_nonce）。
    # 页面内所有事件处理器已改为外部 app.js 的事件委托，仅存的内联 <script> 带 nonce 放行。
    # 这样即便发生 HTML 注入，攻击者注入的 <script>/on* 也会被 CSP 拦下，形成 XSS 第二道防线。
    # style-src 暂保留 'unsafe-inline'（页面仍有大量内联 style，风险远低于脚本执行）。
    nonce = getattr(g, 'csp_nonce', '')
    script_src = f"script-src 'self' 'nonce-{nonce}'" if nonce else "script-src 'self'"
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        f"{script_src}; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'"
    )
    # 仅在 HTTPS 链路上下发 HSTS，避免直连 HTTP 时把浏览器锁死在 https。
    if is_secure_request():
        response.headers.setdefault('Strict-Transport-Security', 'max-age=31536000; includeSubDomains')
    response.headers.pop('X-Powered-By', None)
    # API 响应包含服务器列表/规则/审计日志等敏感数据，禁止任何缓存
    if request.path.startswith('/api/'):
        response.headers.setdefault('Cache-Control', 'no-store')
    response.headers.setdefault('X-Request-ID', getattr(g, 'request_id', '-'))
    return response

# 登录失败记录（防暴力破解）
# 双维度限制：
#   1. IP:username 组合 — 同一 IP 对同一用户名连续失败 MAX_ATTEMPTS 次后锁定（原有逻辑）；
#   2. 仅 IP —      同一 IP 在窗口内累计失败 MAX_IP_ATTEMPTS 次后锁定，
#      堵住"每次换一个用户名喷洒"绕过第 1 条的路径。
# 同时给存储加上限（LRU 淘汰最旧记录），防止攻击者用海量随机用户名/IP 撑爆内存。
login_attempts = {}
login_attempts_by_ip = {}
MAX_ATTEMPTS = 5
MAX_IP_ATTEMPTS = 20
LOCKOUT_TIME = 300  # 5分钟
_LOGIN_ATTEMPTS_MAX_KEYS = 10000

def _cleanup_expired_attempts():
    """清理已过期的锁定记录；超过容量上限时淘汰最旧的一批。"""
    now = datetime.now().timestamp()
    for store in (login_attempts, login_attempts_by_ip):
        expired = [k for k, (attempts, last_time) in store.items()
                   if now - last_time >= LOCKOUT_TIME]
        for k in expired:
            store.pop(k, None)
        if len(store) > _LOGIN_ATTEMPTS_MAX_KEYS:
            oldest = sorted(store.items(), key=lambda kv: kv[1][1])[:len(store) - _LOGIN_ATTEMPTS_MAX_KEYS]
            for k, _v in oldest:
                store.pop(k, None)

def check_login_attempts(username):
    """检查登录尝试次数（IP:username 与 纯 IP 两个维度任一触顶即拒绝）"""
    _cleanup_expired_attempts()
    now = datetime.now().timestamp()
    client_ip = request.remote_addr
    key = f"{client_ip}:{username}"
    if key in login_attempts:
        attempts, last_time = login_attempts[key]
        if now - last_time < LOCKOUT_TIME and attempts >= MAX_ATTEMPTS:
            return False
    if client_ip in login_attempts_by_ip:
        attempts, last_time = login_attempts_by_ip[client_ip]
        if now - last_time < LOCKOUT_TIME and attempts >= MAX_IP_ATTEMPTS:
            return False
    return True

def record_login_attempt(username, success):
    """记录登录尝试"""
    _cleanup_expired_attempts()
    now = datetime.now().timestamp()
    client_ip = request.remote_addr
    key = f"{client_ip}:{username}"
    if success:
        login_attempts.pop(key, None)
        login_attempts_by_ip.pop(client_ip, None)
    else:
        for store, k in ((login_attempts, key), (login_attempts_by_ip, client_ip)):
            if k in store:
                attempts, _ = store[k]
                store[k] = (attempts + 1, now)
            else:
                store[k] = (1, now)

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 检查请求频率
        if not check_rate_limit():
            return jsonify({'error': '请求过于频繁'}), 429
        
        # 检查登录状态
        if not session.get('logged_in') or not _session_is_valid():
            session.clear()
            return jsonify({'error': '未登录'}), 401
        
        if session.get('must_change_password') and request.path not in ['/api/change_password', '/api/csrf_token', '/logout']:
            return jsonify({'error': '请先修改默认密码', 'must_change_password': True}), 403

        # POST/PUT/DELETE 请求需要验证 CSRF（GET 请求跳过）
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            csrf_token = request.headers.get('X-CSRF-Token')
            if not csrf_token and request.is_json and request.json:
                csrf_token = request.json.get('csrf_token')
            if not csrf_token or not verify_csrf_token(csrf_token):
                return jsonify({'error': 'CSRF 验证失败', 'csrf_required': True}), 403
        
        return f(*args, **kwargs)
    return decorated_function


# 敏感操作二次认证（step-up）：登录态与“执行高危操作的权限”分离。会话被盗后，攻击者仍需
# 知道当前密码才能导出 token / 恢复备份 / 改密钥 / 批量删除等。要求这些操作在最近
# REAUTH_MAX_AGE 秒内重新验证过密码（通过 POST /api/reauth 刷新 session['last_reauth']）。
REAUTH_MAX_AGE = int(os.getenv('SNAT_REAUTH_MAX_AGE', '600'))  # 默认 10 分钟


def _recent_auth_ok(max_age=None):
    max_age = REAUTH_MAX_AGE if max_age is None else max_age
    last = session.get('last_reauth', 0)
    try:
        last = float(last)
    except (TypeError, ValueError):
        return False
    age = time.time() - last
    return 0 <= age <= max_age


def require_recent_auth(max_age=None):
    """要求会话在 max_age 秒内二次验证过密码，否则返回 403 + reauth_required。

    与 login_required 叠加使用；必须放在 login_required 内层（更靠近视图函数）。
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not _recent_auth_ok(max_age):
                return jsonify({
                    'success': False,
                    'error': '该操作需要重新验证密码',
                    'reauth_required': True
                }), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def log_event(level, message):
    """写日志并缓存到内存"""
    text = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level}] {message}"
    log_buffer.append(text)
    getattr(app.logger, level.lower(), app.logger.info)(message)


def csv_safe_row(row):
    """阻止 Excel/LibreOffice 把不可信 CSV 单元格解释为公式。"""
    safe = {}
    for key, value in dict(row).items():
        if isinstance(value, str):
            probe = value.lstrip(' \t\r\n')
            if value.startswith(('\t', '\r', '\n')) or probe.startswith(('=', '+', '-', '@')):
                value = "'" + value
        safe[key] = value
    return safe


def circled_num(n):
    """1-20 用圈码 ①-⑳ 展示编号（TG 原生可显示），超出回退为 #n。"""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return '#?'
    return chr(0x2460 + n - 1) if 1 <= n <= 20 else f'#{n}'


def audit_log(action, target='', status='success', detail=''):
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute('INSERT INTO audit_logs (username, client_ip, action, target, status, detail) VALUES (?, ?, ?, ?, ?, ?)',
                  (session.get('username', '-'), request.remote_addr, action, target, status, detail))
        conn.commit(); conn.close()
        # TG 推送策略：失败/被拒必推（安全相关：登录失败、二次认证失败、路径穿越拦截等）；
        # 成功事件跳过例行低值动作（reauth 只是前置门槛，真正的敏感操作会各自产生审计）。
        skip_success_actions = {'reauth'}
        should_push = status != 'success' or action not in skip_success_actions
        if should_push and _setting_bool('tg_enable_audit', '1'):
            lines = [
                f"用户: {session.get('username', '-')}",
                f"动作: {action}",
                f"目标: {target or '-'}",
                f"结果: {'成功' if status == 'success' else status}",
                f"来源: {request.remote_addr or '-'}",
                f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ]
            if detail:
                lines.append(f"详情: {detail}")
            telegram_audit_event('\n'.join(lines), dedupe_key=f'audit:{action}:{target}:{detail}:{status}')
    except Exception as e:
        app.logger.warning(f'audit log failed: {e}')


def get_setting(key, default=''):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('SELECT value FROM settings_kv WHERE key = ?', (key,))
    row = c.fetchone(); conn.close()
    return row[0] if row else default


def set_setting(key, value):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('INSERT INTO settings_kv (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP', (key, value))
    conn.commit(); conn.close()

def is_force_https_enabled():
    stored = get_setting('force_https', '')
    if stored != '':
        return stored.lower() not in ('0', 'false', 'no')
    return FORCE_HTTPS


def create_rule_snapshot(reason='manual'):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM rules ORDER BY id')
    payload = json.dumps([dict(r) for r in c.fetchall()], ensure_ascii=False)
    c.execute('INSERT INTO rule_snapshots (username, reason, payload) VALUES (?, ?, ?)', (session.get('username', '-'), reason, payload))
    conn.commit(); sid = c.lastrowid; conn.close(); return sid


def send_alert(message):
    # 与主发送路径统一（含重试），避免两条发送逻辑漂移。
    return send_telegram_message(message)


def _setting_bool(key, default='0'):
    return str(get_setting(key, default)).strip().lower() not in ('0', 'false', 'no', '')


def _setting_int(key, default):
    try:
        return int(get_setting(key, str(default)) or default)
    except (TypeError, ValueError):
        return int(default)


def send_telegram_message(message, chat_id=None):
    bot_token = get_secret_setting('tg_bot_token', '')
    target_chat_id = str(chat_id or get_setting('tg_chat_id', '')).strip()
    if not bot_token or not target_chat_id:
        return False, 'tg bot not configured'
    # 代理链路存在约 1-2 成瞬时失败（实测 SSL EOF/连接重置），重试 3 次再放弃，避免告警丢失。
    last_err = 'unknown'
    for attempt in range(3):
        try:
            resp = requests.post(
                f'https://api.telegram.org/bot{bot_token}/sendMessage',
                json={'chat_id': target_chat_id, 'text': message},
                timeout=10
            )
            if resp.status_code < 300:
                return True, f'http {resp.status_code}'
            last_err = f'http {resp.status_code}'
        except Exception as e:
            last_err = str(e)
        if attempt < 2:
            time.sleep(1.5 * (attempt + 1))
    return False, last_err


def _telegram_dedupe_ok(key, cooldown_seconds=300):
    if not key:
        return True
    now = int(time.time())
    skey = f'tg_last_sent:{key}'
    try:
        last = int(get_setting(skey, '0') or '0')
    except (TypeError, ValueError):
        last = 0
    if last and now - last < max(0, cooldown_seconds):
        return False
    set_setting(skey, str(now))
    return True


def telegram_notify(message, *, dedupe_key='', cooldown_seconds=300, enabled=True, chat_id=None):
    if not enabled:
        return False, 'disabled'
    if not _telegram_dedupe_ok(dedupe_key, cooldown_seconds):
        return False, 'deduped'
    ok, detail = send_telegram_message(message, chat_id=chat_id)
    if not ok:
        app.logger.warning(f'telegram notify failed: {detail}')
    return ok, detail


def telegram_audit_event(message, dedupe_key=''):
    return telegram_notify(
        f'🧾 SNAT 审计\n{message}',
        dedupe_key=dedupe_key,
        cooldown_seconds=5,
        enabled=_setting_bool('tg_enable_audit', '1')
    )


def _build_status_summary(limit_rules=8):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, name, status, host, port FROM servers ORDER BY id')
    servers = [dict(r) for r in c.fetchall()]
    c.execute('''SELECT r.local_port, r.target_ip, r.target_port, r.enabled, r.traffic_used_bytes, r.traffic_limit_gb,
                        r.active_connections, s.name AS server_name
                 FROM rules r JOIN servers s ON r.server_id = s.id
                 ORDER BY r.traffic_used_bytes DESC, r.id DESC LIMIT ?''', (limit_rules,))
    top_rules = [dict(r) for r in c.fetchall()]
    conn.close()
    online = sum(1 for s in servers if s.get('status') == 'online')
    offline = sum(1 for s in servers if s.get('status') == 'offline')
    token_invalid = sum(1 for s in servers if s.get('status') == 'token_invalid')
    lines = [
        '📡 SNAT 当前状态',
        f'服务器: {len(servers)} 台（在线 {online} / 离线 {offline} / Token异常 {token_invalid}）',
    ]
    if servers:
        lines.append('')
        lines.append('节点:')
        for s in servers:
            lines.append(f"- {s['name']}: {s['status']} ({s['host']}:{s['port']})")
    if top_rules:
        lines.append('')
        lines.append('Top 规则:')
        for r in top_rules:
            used_gb = format(float(r.get('traffic_used_bytes', 0)) / (1024 ** 3), '.2f')
            limit = r.get('traffic_limit_gb') or 0
            limit_text = f'{limit} GB' if limit > 0 else '∞'
            lines.append(f"- {r['server_name']}:{r['local_port']} -> {r['target_ip']}:{r['target_port']} | {used_gb}/{limit_text} | 连接 {r.get('active_connections', 0) or 0}")
    return '\n'.join(lines)


def _build_rules_summary(limit=20):
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT r.local_port, r.target_ip, r.target_port, r.enabled, r.traffic_used_bytes, r.traffic_limit_gb,
                        r.active_connections, s.name AS server_name
                 FROM rules r JOIN servers s ON r.server_id = s.id
                 ORDER BY s.name, r.local_port LIMIT ?''', (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    if not rows:
        return '📋 当前没有规则'
    lines = [f'📋 规则列表（前 {len(rows)} 条）']
    for r in rows:
        used_gb = format(float(r.get('traffic_used_bytes', 0)) / (1024 ** 3), '.2f')
        limit = r.get('traffic_limit_gb') or 0
        limit_text = f'{limit} GB' if limit > 0 else '∞'
        status = '启用' if r.get('enabled') else '禁用'
        lines.append(f"- {r['server_name']}:{r['local_port']} -> {r['target_ip']}:{r['target_port']} | {status} | {used_gb}/{limit_text} | 连接 {r.get('active_connections', 0) or 0}")
    return '\n'.join(lines)


def _build_daily_summary():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT COUNT(*) FROM servers')
    servers_total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM servers WHERE status = ?', ('online',))
    servers_online = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM rules')
    rules_total = c.fetchone()[0]
    c.execute('SELECT COUNT(*) FROM rules WHERE enabled = 1')
    rules_enabled = c.fetchone()[0]
    c.execute('SELECT COALESCE(SUM(traffic_used_bytes), 0) FROM rules')
    total_bytes = int(c.fetchone()[0] or 0)
    c.execute('''SELECT r.local_port, r.target_ip, r.target_port, r.traffic_used_bytes, s.name AS server_name
                 FROM rules r JOIN servers s ON r.server_id = s.id
                 ORDER BY r.traffic_used_bytes DESC LIMIT 5''')
    top = [dict(r) for r in c.fetchall()]
    conn.close()
    total_gb = format(total_bytes / (1024 ** 3), '.2f')
    lines = [
        '📊 SNAT 每日简报',
        f'服务器: {servers_online}/{servers_total} 在线',
        f'规则: {rules_enabled}/{rules_total} 启用',
        f'累计流量: {total_gb} GB',
    ]
    if top:
        lines.append('')
        lines.append('Top 5 流量规则:')
        for r in top:
            used_gb = format(float(r.get('traffic_used_bytes', 0)) / (1024 ** 3), '.2f')
            lines.append(f"- {r['server_name']}:{r['local_port']} -> {r['target_ip']}:{r['target_port']} | {used_gb} GB")
    return '\n'.join(lines)


def _bot_api_call(path, method='GET', payload=None):
    """把 TG 命令转成面板内部 API 调用：经 test_client 走真实 WSGI 派发，
    完整复用登录态/CSRF/二次认证/参数校验/失败回滚/规则同步/审计逻辑，不另造一套写路径。

    会话以 admin 身份建立（审计用户显示 admin），REMOTE_ADDR 标记为 telegram-bot 以区分来源渠道。
    注意：若日后在面板配置了 IP 白名单，'telegram-bot' 非字面量 IP 会被拦截，届时 bot 写操作不可用。
    """
    csrf = secrets.token_hex(16)
    try:
        with app.test_request_context('/'):
            session['username'] = 'admin'
            create_server_session('admin')
            sid = session.get('session_id')
        with app.test_client() as client:
            with client.session_transaction() as s:
                s['logged_in'] = True
                s['username'] = 'admin'
                s['must_change_password'] = False
                s['last_reauth'] = time.time()
                s['csrf_token'] = csrf
                if sid:
                    s['session_id'] = sid
            resp = client.open(path, method=method, json=payload,
                               headers={'X-CSRF-Token': csrf},
                               environ_overrides={'REMOTE_ADDR': 'telegram-bot'})
            return resp.status_code, (resp.get_json(silent=True) or {})
    except Exception as e:
        app.logger.warning(f'bot api call failed: {e}')
        return 500, {'success': False, 'error': f'内部调用异常: {e}'}


def _process_telegram_command(text, chat_id):
    parts = (text or '').strip().split()
    cmd = parts[0].lower() if parts else ''
    args = parts[1:]
    if cmd in ('/start', '/help'):
        return send_telegram_message(
            '查询:\n'
            '/status - 当前状态\n'
            '/servers - 服务器列表\n'
            '/rules - 规则列表\n'
            '/summary - 每日汇总\n'
            '/alerts - 检查异常告警\n'
            '操作:\n'
            '/addrule <服务器编号> <本地端口> <目标IP> <目标端口> - 新增规则\n'
            '/delrule <规则编号> - 删除规则\n'
            '/toggle <规则编号> - 启用/停用规则\n'
            '/addserver <名称> <地址> <端口> <token> - 新增服务器\n'
            '/delserver <服务器编号> - 删除服务器(其规则一并删除)', chat_id=chat_id)
    if cmd == '/status':
        return send_telegram_message(_build_status_summary(), chat_id=chat_id)
    if cmd == '/servers':
        code, data = _bot_api_call('/api/servers')
        if not isinstance(data, list):
            return send_telegram_message(f"查询失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
        if not data:
            return send_telegram_message('当前没有服务器', chat_id=chat_id)
        lines = ['🖥 服务器列表:'] + [f"{circled_num(s['id'])}{s['name']}: {s['status']} ({s['host']}:{s['port']})" for s in data]
        return send_telegram_message('\n'.join(lines), chat_id=chat_id)
    if cmd == '/rules':
        return send_telegram_message(_build_rules_summary(), chat_id=chat_id)
    if cmd == '/summary':
        return send_telegram_message(_build_daily_summary(), chat_id=chat_id)
    if cmd == '/alerts':
        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT name, status FROM servers WHERE status IN (?, ?) ORDER BY id DESC', ('offline', 'token_invalid'))
        rows = [dict(row) for row in c.fetchall()]
        conn.close()
        if not rows:
            return send_telegram_message('✅ 当前没有离线或 Token 异常的服务器', chat_id=chat_id)
        lines = ['⚠️ 当前异常服务器:'] + [f"- {r['name']}: {r['status']}" for r in rows]
        return send_telegram_message('\n'.join(lines), chat_id=chat_id)
    if cmd == '/addrule':
        if len(args) != 4 or not all(a.isdigit() for a in (args[0], args[1], args[3])):
            return send_telegram_message('用法: /addrule <服务器编号> <本地端口> <目标IP> <目标端口>', chat_id=chat_id)
        code, data = _bot_api_call('/api/rules', 'POST', {
            'server_id': int(args[0]), 'local_port': int(args[1]),
            'target_ip': args[2], 'target_port': int(args[3]), 'remark': 'via TG bot'})
        if data.get('success'):
            return send_telegram_message(f"✅ 规则已创建: {circled_num(data.get('id'))} 端口 {args[1]} -> {args[2]}:{args[3]}", chat_id=chat_id)
        return send_telegram_message(f"❌ 创建失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
    if cmd == '/delrule':
        if len(args) != 1 or not args[0].isdigit():
            return send_telegram_message('用法: /delrule <规则编号>', chat_id=chat_id)
        code, data = _bot_api_call(f"/api/rules/{int(args[0])}", 'DELETE')
        if data.get('success'):
            return send_telegram_message(f"✅ 规则 {circled_num(int(args[0]))} 已删除", chat_id=chat_id)
        return send_telegram_message(f"❌ 删除失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
    if cmd == '/toggle':
        if len(args) != 1 or not args[0].isdigit():
            return send_telegram_message('用法: /toggle <规则编号>', chat_id=chat_id)
        code, data = _bot_api_call(f"/api/rules/{int(args[0])}/toggle", 'POST')
        if data.get('success'):
            return send_telegram_message(f"✅ 规则 {circled_num(int(args[0]))} 已{'启用' if data.get('enabled') else '停用'}", chat_id=chat_id)
        return send_telegram_message(f"❌ 操作失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
    if cmd == '/addserver':
        if len(args) != 4 or not args[2].isdigit():
            return send_telegram_message('用法: /addserver <名称> <地址> <端口> <token>', chat_id=chat_id)
        code, data = _bot_api_call('/api/servers', 'POST', {
            'name': args[0], 'host': args[1], 'port': int(args[2]), 'token': args[3]})
        if data.get('success'):
            return send_telegram_message(
                f"✅ 服务器已添加: {circled_num(data.get('id'))}{args[0]} ({args[1]}:{args[2]})\n"
                '⚠️ 建议长按删除你刚发送的含 token 的消息', chat_id=chat_id)
        return send_telegram_message(f"❌ 添加失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
    if cmd == '/delserver':
        if len(args) != 1 or not args[0].isdigit():
            return send_telegram_message('用法: /delserver <服务器编号>(该服务器的规则会一并删除)', chat_id=chat_id)
        code, data = _bot_api_call(f"/api/servers/{int(args[0])}", 'DELETE')
        if data.get('success'):
            msg = f"✅ 服务器 {circled_num(int(args[0]))} 已删除"
            if data.get('orphaned'):
                msg += f"\n⚠️ {len(data['orphaned'])} 条远端规则未确认清理，需人工检查"
            return send_telegram_message(msg, chat_id=chat_id)
        return send_telegram_message(f"❌ 删除失败: {data.get('error', f'HTTP {code}')}", chat_id=chat_id)
    return send_telegram_message('未知命令，发送 /help 查看帮助。', chat_id=chat_id)


def _telegram_polling_loop():
    offset = 0
    while True:
        try:
            if not _setting_bool('tg_command_enabled', '0'):
                time.sleep(15)
                continue
            bot_token = get_secret_setting('tg_bot_token', '')
            allowed_chat_id = str(get_setting('tg_chat_id', '')).strip()
            if not bot_token or not allowed_chat_id:
                time.sleep(15)
                continue
            resp = requests.get(
                f'https://api.telegram.org/bot{bot_token}/getUpdates',
                params={'timeout': 20, 'offset': offset + 1},
                timeout=30
            )
            if resp.status_code >= 300:
                time.sleep(10)
                continue
            payload = resp.json() or {}
            for item in payload.get('result', []) or []:
                offset = max(offset, int(item.get('update_id', 0) or 0))
                message = item.get('message') or {}
                text = (message.get('text') or '').strip()
                chat_id = str((message.get('chat') or {}).get('id', '')).strip()
                if not text.startswith('/'):
                    continue
                if allowed_chat_id and chat_id != allowed_chat_id:
                    continue
                _process_telegram_command(text, chat_id)
        except Exception as e:
            app.logger.warning(f'telegram polling loop error: {e}')
            time.sleep(10)


def _check_servers_once():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, name, host, port, token, status FROM servers ORDER BY id')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    for server in rows:
        prev = server.get('status') or 'offline'
        status = 'offline'
        try:
            resp = agent_get(f"http://{server['host']}:{server['port']}/health", decrypt_token(server['token']), timeout=3)
            if resp.status_code == 200:
                status = 'online'
            elif resp.status_code == 401:
                status = 'token_invalid'
                mark_token_invalid(server['id'], 'background health 401')
            else:
                status = 'offline'
        except Exception:
            status = 'offline'
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?', (status, server['id']))
        conn.commit()
        conn.close()
        if status != prev:
            _now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            if status in ('offline', 'token_invalid'):
                telegram_notify(
                    f'⚠️ SNAT服务器异常\n节点: {server["name"]}\n地址: {server["host"]}:{server["port"]}\n状态: {status}\n时间: {_now}',
                    dedupe_key=f'server:{server["id"]}:{status}',
                    cooldown_seconds=max(60, _setting_int('alert_offline_seconds', 300)),
                    enabled=True
                )
            elif prev in ('offline', 'token_invalid') and status == 'online':
                telegram_notify(
                    f'✅ SNAT服务器恢复\n节点: {server["name"]}\n地址: {server["host"]}:{server["port"]}\n状态: online\n时间: {_now}',
                    dedupe_key=f'server-recover:{server["id"]}',
                    cooldown_seconds=30,
                    enabled=True
                )


def _check_traffic_once():
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('''SELECT r.*, s.host, s.port, s.token, s.name AS server_name
                 FROM rules r JOIN servers s ON r.server_id = s.id
                 WHERE r.enabled = 1''')
    rule_rows = [dict(row) for row in c.fetchall()]
    conn.close()
    for rule in rule_rows:
        try:
            url = f"http://{rule['host']}:{rule['port']}/get_traffic/{rule['local_port']}"
            resp = agent_get(url, decrypt_token(rule['token']), timeout=3)
            if resp.status_code != 200:
                continue
            data = resp.json() or {}
            current_counter = int(data.get('current_counter', 0) or 0)
            total_bytes = int(data.get('bytes', current_counter) or 0)
            conn = sqlite3.connect(DB_FILE, timeout=10)
            c = conn.cursor()
            c.execute(
                'UPDATE rules SET traffic_used_bytes = ?, last_iptables_bytes = ?, last_agent_counter = ? WHERE id = ?',
                (total_bytes, current_counter, current_counter, rule['id'])
            )
            conn.commit()
            conn.close()
            if int(rule.get('traffic_limit_gb', 0) or 0) > 0:
                limit_bytes = int(rule['traffic_limit_gb']) * (1024 ** 3)
                if total_bytes >= limit_bytes:
                    stopped=False
                    try:
                        stop=agent_post(f"http://{rule['host']}:{rule['port']}/check_traffic_limit",decrypt_token(rule['token']),{'local_port':rule['local_port'],'traffic_limit_gb':rule['traffic_limit_gb'],'current_bytes':total_bytes},timeout=3)
                        stop_payload = stop.json() or {}
                        stopped=(stop.status_code==200
                                 and stop_payload.get('success') is True
                                 and stop_payload.get('stopped') is True
                                 and stop_payload.get('verified') is True)
                    except Exception: pass
                    conn=sqlite3.connect(DB_FILE,timeout=10); c=conn.cursor()
                    if stopped: c.execute("UPDATE rules SET enabled=0,status='active' WHERE id=?",(rule['id'],))
                    else: c.execute("UPDATE rules SET status='desynced' WHERE id=?",(rule['id'],))
                    conn.commit(); conn.close()
                    telegram_notify(
                        f'🚨 SNAT规则流量超限\n节点: {rule["server_name"]}\n端口: {rule["local_port"]}\n目标: {rule["target_ip"]}:{rule["target_port"]}\n已用: {format(total_bytes / (1024 ** 3), ".2f")} GB\n限制: {rule["traffic_limit_gb"]} GB\n处置: {"已自动停用该规则" if stopped else "停用未确认，已标记 desynced 需人工处理"}',
                        dedupe_key=f'traffic-limit:{rule["id"]}',
                        cooldown_seconds=3600,
                        enabled=_setting_bool('tg_enable_limit_alerts', '1')
                    )
        except Exception as e:
            app.logger.warning(f'background traffic check failed for rule {rule.get("id")}: {e}')


def _maybe_send_daily_summary():
    if not _setting_bool('tg_enable_daily_summary', '1'):
        return
    now = datetime.now()
    configured = (get_setting('tg_daily_summary_time', '09:00') or '09:00').strip()
    today = now.strftime('%Y-%m-%d')
    if now.strftime('%H:%M') != configured:
        return
    if get_setting('tg_daily_last_sent', '') == today:
        return
    ok, _detail = send_telegram_message(_build_daily_summary())
    if ok:
        set_setting('tg_daily_last_sent', today)


def _background_ops_loop():
    while True:
        try:
            _check_servers_once()
            _check_traffic_once()
            _maybe_send_daily_summary()
        except Exception as e:
            app.logger.warning(f'background ops loop error: {e}')
        time.sleep(max(30, _setting_int('tg_background_interval_seconds', 60)))


def init_log_buffer():
    """启动时加载历史日志"""
    if not os.path.exists(LOG_FILE):
        return
    try:
        with open(LOG_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            for line in deque(f, maxlen=LOG_BUFFER_MAX):
                log_buffer.append(line.rstrip('\n'))
    except Exception:
        pass


def mark_token_invalid(server_id, reason):
    """标记 token 异常并按策略停用规则"""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
             ('token_invalid', server_id))
    disabled = 0
    if TOKEN_INVALID_DISABLE:
        c.execute("UPDATE rules SET enabled=0,status='unknown' WHERE server_id=? AND enabled=1",(server_id,))
        disabled = c.rowcount
    conn.commit()
    conn.close()
    log_event('WARNING', f"服务器 {server_id} token 异常: {reason}，自动停用 {disabled} 条规则")
    return disabled


def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DB_FILE, timeout=10)
    c = conn.cursor()
    
    # 用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        must_change_password INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        password_changed_at TIMESTAMP,
        session_version INTEGER DEFAULT 1
    )''')
    for stmt in [
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP",
        "ALTER TABLE users ADD COLUMN session_version INTEGER DEFAULT 1"
    ]:
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass
    
    # 检查是否有默认用户，没有则创建
    c.execute('SELECT COUNT(*) FROM users')
    if c.fetchone()[0] == 0:
        setup_password = os.getenv('SNAT_ADMIN_PASSWORD', '')
        if not setup_password:
            setup_password = secrets.token_urlsafe(18)
        default_password = hash_password(setup_password)
        c.execute('INSERT INTO users (username, password, must_change_password) VALUES (?, ?, ?)', ('admin', default_password, 1))
        print('[!] 默认管理员已初始化；初始密码未写入日志。首次登录后必须修改密码。')

    c.execute('''CREATE TABLE IF NOT EXISTS web_sessions (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        session_version INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at REAL NOT NULL,
        revoked INTEGER DEFAULT 0,
        FOREIGN KEY (username) REFERENCES users(username)
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_web_sessions_user ON web_sessions(username)')
    c.execute('DELETE FROM web_sessions WHERE expires_at <= ?', (time.time(),))
    
    # 服务器表
    c.execute('''CREATE TABLE IF NOT EXISTS servers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        host TEXT NOT NULL,
        port INTEGER DEFAULT 8888,
        token TEXT NOT NULL,
        status TEXT DEFAULT 'offline',
        last_check TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # 转发规则表
    c.execute('''CREATE TABLE IF NOT EXISTS rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        server_id INTEGER NOT NULL,
        local_port INTEGER NOT NULL,
        target_host TEXT DEFAULT '',
        target_ip TEXT NOT NULL,
        target_port INTEGER NOT NULL,
        remark TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        enabled INTEGER DEFAULT 1,
        traffic_limit_gb INTEGER DEFAULT 0,
        traffic_used_bytes INTEGER DEFAULT 0,
        last_iptables_bytes INTEGER DEFAULT 0,
        last_agent_counter INTEGER DEFAULT 0,
        active_connections INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (server_id) REFERENCES servers(id)
    )''')

    for stmt in [
        "ALTER TABLE rules ADD COLUMN last_agent_counter INTEGER DEFAULT 0",
        "ALTER TABLE rules ADD COLUMN active_connections INTEGER DEFAULT 0"
    ]:
        try:
            c.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # 清理重复规则（同一服务器同一端口）
    c.execute('''DELETE FROM rules
                 WHERE id NOT IN (
                     SELECT MAX(id) FROM rules GROUP BY server_id, local_port
                 )''')

    # 规则唯一性约束
    c.execute('''CREATE UNIQUE INDEX IF NOT EXISTS idx_rules_server_port
                 ON rules(server_id, local_port)''')

    # 热点查询索引：check_all_traffic / servers 健康循环频繁按 server_id + enabled 过滤规则。
    for idx_stmt in [
        'CREATE INDEX IF NOT EXISTS idx_rules_server_enabled ON rules(server_id, enabled)',
        'CREATE INDEX IF NOT EXISTS idx_rules_enabled ON rules(enabled)',
    ]:
        try:
            c.execute(idx_stmt)
        except sqlite3.OperationalError:
            pass
    
    try:
        c.execute('SELECT id, token FROM servers')
        rows = c.fetchall()
        for row in rows:
            token = row[1]
            enc = encrypt_token(token)
            if enc != token:
                c.execute('UPDATE servers SET token = ? WHERE id = ?', (enc, row[0]))
    except sqlite3.OperationalError:
        pass

    # 白名单表
    c.execute('''CREATE TABLE IF NOT EXISTS ip_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        client_ip TEXT,
        action TEXT,
        target TEXT,
        status TEXT,
        detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS settings_kv (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    c.execute('''CREATE TABLE IF NOT EXISTS rule_snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        reason TEXT,
        payload TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')

    # 审计日志与快照列表按时间倒序取最近 N 条，补索引避免量大时全表扫描 + 排序。
    for idx_stmt in [
        'CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC)',
        'CREATE INDEX IF NOT EXISTS idx_snapshots_created ON rule_snapshots(created_at DESC)',
    ]:
        try:
            c.execute(idx_stmt)
        except sqlite3.OperationalError:
            pass

    conn.commit()
    conn.close()

def _register_blueprints():
    """在模块底部统一注册 blueprint，避免与 helpers 形成循环 import。"""
    from web.blueprints import health, auth, servers, rules, traffic, settings as settings_bp, admin
    app.register_blueprint(health.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(servers.bp)
    app.register_blueprint(rules.bp)
    app.register_blueprint(traffic.bp)
    app.register_blueprint(settings_bp.bp)
    app.register_blueprint(admin.bp)


_register_blueprints()


SYNC_RETRY_ATTEMPTS = 2
SYNC_OK_STATUSES = {'ok', 'added', 'deleted', 'replaced'}


def _mark_rules_desynced(server_id, rule_ids, reason):
    """把同步失败的规则在 DB 上标记为 desynced，等待后续 reconcile。"""
    if not rule_ids:
        return
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        placeholders = ','.join('?' * len(rule_ids))
        c.execute(
            f'UPDATE rules SET status = ? WHERE id IN ({placeholders})',
            ['desynced', *rule_ids]
        )
        conn.commit()
        conn.close()
        log_event('WARNING', f"标记 {len(rule_ids)} 条规则为 desynced，原因: {reason}")
    except Exception as e:
        log_event('WARNING', f'标记 desynced 失败: {e}')


def _clear_rules_desynced(rule_ids):
    if not rule_ids:
        return
    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        c = conn.cursor()
        placeholders = ','.join('?' * len(rule_ids))
        c.execute(
            f"UPDATE rules SET status = 'active' WHERE status = 'desynced' AND id IN ({placeholders})",
            list(rule_ids)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        log_event('WARNING', f'清除 desynced 标记失败: {e}')


def _retry_agent_call(callable_, attempts=SYNC_RETRY_ATTEMPTS):
    """对 agent 调用做有限次重试；只重试连接级异常，不重试 4xx。"""
    last_exc = None
    for i in range(attempts):
        try:
            return callable_(), None
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            if i < attempts - 1:
                time.sleep(0.2 * (i + 1))
        except Exception as e:
            return None, e
    return None, last_exc


def sync_server_rules(server_id, log_prefix=''):
    """针对单个服务器，将数据库中的启用规则与 Agent 做全量对账。

    设计原则：
    1. 先把 desired / remote 状态全部读完，再做 diff（不边查边改）。
    2. 操作按 delete → add 顺序执行；replace 拆成 delete+add。
    3. 任何一步失败：该规则在 DB 上标记 status='desynced'，等待下次 reconcile。
    4. 网络抖动 (Connection/Timeout) 会重试 SYNC_RETRY_ATTEMPTS 次。
    """
    conn = sqlite3.connect(DB_FILE, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, host, port, token FROM servers WHERE id = ?', (server_id,))
    server_row = c.fetchone()
    if not server_row:
        conn.close()
        return [{'server_id': server_id, 'status': 'server_missing'}]

    server = dict(server_row)
    c.execute('SELECT * FROM rules WHERE server_id = ? AND enabled = 1 ORDER BY id', (server_id,))
    enabled_rules = [dict(r) for r in c.fetchall()]
    conn.close()
    over_limit_rules = [
        rule for rule in enabled_rules
        if int(rule.get('traffic_limit_gb', 0) or 0) > 0
        and int(rule.get('traffic_used_bytes', 0) or 0)
        >= int(rule.get('traffic_limit_gb', 0)) * 1024 ** 3
    ]
    over_limit_ids = {rule['id'] for rule in over_limit_rules}
    over_limit_by_port = {str(rule['local_port']): rule for rule in over_limit_rules}
    desired_rules = [rule for rule in enabled_rules if rule['id'] not in over_limit_ids]

    token = decrypt_token(server['token'])
    base_url = f"http://{server['host']}:{server['port']}"

    # ---- 取远端规则 ----
    def _fetch():
        return agent_get(f"{base_url}/list_rules", token, timeout=5)

    resp, err = _retry_agent_call(_fetch)
    if err is not None:
        _mark_rules_desynced(server_id, [r['id'] for r in desired_rules], f'list_error: {err}')
        return [{'server_id': server_id, 'status': 'list_error', 'error': str(err)}]
    if resp.status_code != 200:
        _mark_rules_desynced(server_id, [r['id'] for r in desired_rules], f'list_http_{resp.status_code}')
        return [{'server_id': server_id, 'status': 'list_failed', 'http': resp.status_code}]

    try:
        remote_payload = resp.json() or {}
    except ValueError:
        remote_payload = {}
    remote_rules = remote_payload.get('rules', remote_payload) if isinstance(remote_payload, dict) else {}

    enabled_by_port = {str(rule['local_port']): rule for rule in enabled_rules}
    desired_by_port = {str(rule['local_port']): rule for rule in desired_rules}
    remote_by_port = {str(p): v for p, v in remote_rules.items()}
    suspended={p for p,v in remote_by_port.items() if isinstance(v,dict) and v.get('suspended')}
    ids=[enabled_by_port[p]['id'] for p in suspended if p in enabled_by_port]
    if ids:
        conn=sqlite3.connect(DB_FILE,timeout=10); c=conn.cursor(); c.executemany('UPDATE rules SET enabled=0 WHERE id=?',[(x,) for x in ids]); conn.commit(); conn.close()
        for p in suspended: desired_by_port.pop(p,None); remote_by_port.pop(p,None)

    # ---- 构建期望差异 ----
    to_delete = []   # 仅远端有，本地无 → 删
    to_add = []      # 仅本地有，远端无 → 加
    to_replace = []  # 两端都有但属性不同 → 删+加

    for port_key, remote_rule in remote_by_port.items():
        desired = desired_by_port.get(port_key)
        if not desired:
            to_delete.append(port_key)
            continue

        if (
            str(remote_rule.get('target_ip', '') or '') == str(desired['target_ip'])
            and int(remote_rule.get('target_port', 0) or 0) == int(desired['target_port'])
            and (str(remote_rule.get('target_host', '') or remote_rule.get('target_ip', '') or '').strip()
                 == (desired.get('target_host') or desired['target_ip'] or '').strip())
        ):
            continue
        to_replace.append(desired)

    for port_key, rule in desired_by_port.items():
        if port_key not in remote_by_port:
            to_add.append(rule)

    # ---- 执行 ----
    results = []
    failed_rule_ids = set()
    succeeded_rule_ids = set()

    def _do_delete(port_key):
        return agent_post(f"{base_url}/delete_rule", token, {'local_port': int(port_key)}, timeout=5)

    def _do_add(rule):
        payload = {
            'local_port': rule['local_port'],
            'target_ip': rule['target_ip'],
            'target_host': rule.get('target_host', '') or rule['target_ip'],
            'target_port': rule['target_port'],
            'traffic_limit_gb': int(rule.get('traffic_limit_gb',0) or 0)
        }
        return agent_post(f"{base_url}/add_rule", token, payload, timeout=5)

    def _agent_confirmed(response):
        if response is None or response.status_code != 200:
            return False
        try:
            return (response.json() or {}).get('success') is True
        except (ValueError, TypeError):
            return False

    # 1) 先删 (orphan)
    for port_key in to_delete:
        del_resp, del_err = _retry_agent_call(lambda pk=port_key: _do_delete(pk))
        if del_err is not None:
            results.append({'local_port': int(port_key), 'status': 'delete_error', 'error': str(del_err)})
            if port_key in over_limit_by_port:
                failed_rule_ids.add(over_limit_by_port[port_key]['id'])
        elif _agent_confirmed(del_resp):
            results.append({'local_port': int(port_key), 'status': 'deleted'})
            if port_key in over_limit_by_port:
                rule_id = over_limit_by_port[port_key]['id']
                conn = sqlite3.connect(DB_FILE, timeout=10)
                c = conn.cursor()
                c.execute("UPDATE rules SET enabled=0,status='active' WHERE id=?", (rule_id,))
                conn.commit()
                conn.close()
                succeeded_rule_ids.add(rule_id)
        else:
            results.append({'local_port': int(port_key), 'status': 'delete_failed', 'http': del_resp.status_code})
            if port_key in over_limit_by_port:
                failed_rule_ids.add(over_limit_by_port[port_key]['id'])

    # 2) 替换 (delete+add)
    for rule in to_replace:
        port_key = str(rule['local_port'])
        del_resp, del_err = _retry_agent_call(lambda pk=port_key: _do_delete(pk))
        if del_err is not None or not _agent_confirmed(del_resp):
            failed_rule_ids.add(rule['id'])
            results.append({
                'rule_id': rule['id'], 'local_port': rule['local_port'],
                'status': 'replace_delete_failed',
                **({'error': str(del_err)} if del_err else {'http': del_resp.status_code})
            })
            continue
        add_resp, add_err = _retry_agent_call(lambda r=rule: _do_add(r))
        if add_err is not None:
            failed_rule_ids.add(rule['id'])
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'replace_error', 'error': str(add_err)})
        elif _agent_confirmed(add_resp):
            succeeded_rule_ids.add(rule['id'])
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'replaced'})
        else:
            failed_rule_ids.add(rule['id'])
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'replace_add_failed', 'http': add_resp.status_code})

    # 3) 新增
    for rule in to_add:
        add_resp, add_err = _retry_agent_call(lambda r=rule: _do_add(r))
        if add_err is not None:
            failed_rule_ids.add(rule['id'])
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'add_error', 'error': str(add_err)})
        elif _agent_confirmed(add_resp):
            succeeded_rule_ids.add(rule['id'])
            item = {'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'added'}
            try:
                payload = add_resp.json() or {}
                if payload.get('resolved_ip') or payload.get('target_host'):
                    item['resolved_ip'] = payload.get('resolved_ip')
                    item['target_host'] = payload.get('target_host')
            except Exception:
                pass
            results.append(item)
            if log_prefix:
                log_event('INFO', f"{log_prefix} 同步规则 {rule['id']} -> {rule['local_port']}: 成功")
        else:
            failed_rule_ids.add(rule['id'])
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'add_failed', 'http': add_resp.status_code})
            if log_prefix:
                log_event('INFO', f"{log_prefix} 同步规则 {rule['id']} -> {rule['local_port']}: 失败")

    # 4) 完全一致的规则也输出 'ok' 占位，保留旧接口契约
    for port_key, rule in desired_by_port.items():
        if rule['id'] in failed_rule_ids or rule['id'] in succeeded_rule_ids:
            continue
        if port_key in remote_by_port and not any(r is rule for r in to_replace):
            results.append({'rule_id': rule['id'], 'local_port': rule['local_port'], 'status': 'ok'})

    # 5) 状态写回 DB
    _mark_rules_desynced(server_id, list(failed_rule_ids), 'agent_sync_failed')
    _clear_rules_desynced(succeeded_rule_ids)

    return results


def _enforce_runtime_policy():
    """启动期安全策略校验：生产环境必须配置 TOKEN_SECRET（用于 Agent token 落库加密）。"""
    if APP_ENV == 'production' and not TOKEN_SECRET:
        raise SystemExit(
            "[!] Refusing to start in production without SNAT_TOKEN_SECRET set.\n"
            "    Generate a strong value (e.g. `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`) "
            "and export SNAT_TOKEN_SECRET before running."
        )


_BOOTSTRAPPED = False


def bootstrap():
    """启动期一次性初始化。供 gunicorn 入口 (web/wsgi.py) 与 `python -m web.app` 共用；幂等。"""
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    _BOOTSTRAPPED = True
    _enforce_runtime_policy()
    init_log_buffer()
    init_db()
    _maybe_reencrypt_servers()
    threading.Thread(target=_background_ops_loop, daemon=True).start()
    threading.Thread(target=_telegram_polling_loop, daemon=True).start()


if __name__ == '__main__':
    bootstrap()
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)
