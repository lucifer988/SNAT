#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNAT Manager - Web 管理端
"""
from flask import Flask, request, jsonify, session, render_template
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


def build_agent_headers(token, method, path, body=''):
    """构造带 HMAC 签名的 Agent 请求头。"""
    ts = str(int(time.time()))
    body = body or ''
    message = f"{method}\n{path}\n{ts}\n{body}".encode()
    sig = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
    return {
        'Authorization': f'Bearer {token}',
        'X-Timestamp': ts,
        'X-Signature': sig,
    }


def agent_post(url, token, payload, timeout=5):
    path = urlsplit(url).path or '/'
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':'))
    return requests.post(
        url,
        data=body.encode(),
        headers={**build_agent_headers(token, 'POST', path, body), 'Content-Type': 'application/json'},
        timeout=timeout
    )


def agent_get(url, token, timeout=5):
    """带 HMAC 签名的 GET 请求（list_rules / health / get_traffic / get_connections）。

    与 agent_post 一致，让所有面板→Agent 调用都可被 Agent 验签，而不仅是写操作。
    """
    path = urlsplit(url).path or '/'
    return requests.get(url, headers=build_agent_headers(token, 'GET', path, ''), timeout=timeout)

# 持久化 secret_key，避免重启后所有 session 失效
_SECRET_KEY_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.secret_key')
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
    with open(_SECRET_KEY_FILE, 'w') as f:
        f.write(key)
    os.chmod(_SECRET_KEY_FILE, 0o600)
    return key

app = Flask(__name__)
app.secret_key = _load_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
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
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snat_manager.db')

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'snat_web.log')
LOG_BUFFER_MAX = 500
log_buffer = deque(maxlen=LOG_BUFFER_MAX)

# 配置日志（7天自动清理）
handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=7)
handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
app.logger.addHandler(handler)
app.logger.setLevel(logging.INFO)

# 登录失败记录（防暴力破解）
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5分钟

# 请求频率限制
rate_limit_store = defaultdict(list)
RATE_LIMIT_REQUESTS = 60  # 每分钟最多60次请求
RATE_LIMIT_WINDOW = 60  # 时间窗口60秒

# token 校验失败时的安全策略
TOKEN_INVALID_DISABLE = True

# IP 白名单（可选，留空则不限制）
IP_WHITELIST = []  # 例如：['192.168.1.0/24', '10.0.0.1']

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
    """验证 CSRF Token"""
    return token and token == session.get('csrf_token')

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
    conn = sqlite3.connect(DB_FILE)
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


def validate_password_strength(password):
    if len(password) < 10:
        return '密码至少10位'
    if password.lower() == password or password.upper() == password:
        return '密码必须同时包含大小写字母'
    if not any(ch.isdigit() for ch in password):
        return '密码必须包含数字'
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
        conn = sqlite3.connect(DB_FILE)
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


def create_backup(reason='manual'):
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.now().strftime('%Y%m%d-%H%M%S')
    backup_path = os.path.join(BACKUP_DIR, f'snat-backup-{reason}-{ts}')
    os.makedirs(backup_path, exist_ok=True)
    manifest = {'reason': reason, 'created_at': datetime.now().isoformat(), 'files': {}}
    for label, src in (('snat_manager.db', DB_FILE), ('snat_web.log', LOG_FILE)):
        if os.path.exists(src):
            dst = os.path.join(backup_path, label)
            shutil.copy2(src, dst)
            manifest['files'][label] = {'sha256': _sha256_file(dst), 'bytes': os.path.getsize(dst)}
    with open(os.path.join(backup_path, 'MANIFEST.json'), 'w') as f:
        json.dump(manifest, f, ensure_ascii=False, indent=2)
    return backup_path


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
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT ip FROM ip_whitelist ORDER BY id')
    whitelist = [row[0] for row in c.fetchall()]
    conn.close()
    return whitelist


def extract_bearer_token(auth_header):
    if not auth_header or not auth_header.startswith('Bearer '):
        return ''
    return auth_header[7:].strip()


def verify_signed_request(token, method, path, timestamp, signature, body=''):
    if not token or not timestamp or not signature:
        return False, 'missing_signature'
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid_timestamp'
    now = int(time.time())
    if abs(now - ts) > SIGNED_REQUEST_TTL:
        return False, 'timestamp_expired'
    message = f"{method}\n{path}\n{timestamp}\n{body or ''}".encode()
    expected = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, 'bad_signature'
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


def validate_agent_host(host):
    """校验 Agent 主机是否允许被面板访问。返回 (ok, error_msg)。

    - 空 / 过长 / 含非法字符 → 拒绝。
    - 落在拒绝网段（默认链路本地，含云元数据 169.254.169.254）→ 拒绝。
    - 主机名（非字面量 IP）放行：是否解析到危险地址由部署侧网络策略兜底，
      面板不在此做 DNS 解析以避免 TOCTOU。
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
        if not all(part and len(part) < 64 for part in host.split('.')):
            return False, '服务器地址格式无效'
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
    conn = sqlite3.connect(DB_FILE)
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

@app.before_request
def before_request():
    """全局请求前检查"""
    if APP_ENV == 'production' and is_force_https_enabled() and not is_secure_request() and request.path != '/healthz':
        return jsonify({'error': 'HTTPS required'}), 403
    # 跳过静态文件和登录页面
    if request.path.startswith('/static/') or request.path == '/login':
        return
    
    # IP 白名单检查
    if not check_ip_whitelist():
        # 返回 404 而不是 403，不暴露系统信息
        return render_template('login.html'), 404
    
    # 请求频率限制（登录页也允许）
    if request.path != '/login' and not check_rate_limit():
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
    # CSP：保留 'unsafe-inline'（页面仍含内联脚本/样式与 onclick），但禁止外部脚本来源、
    # 禁止被 iframe 嵌套（防点击劫持），限制表单与 base 标签目标。前端已移除外链背景图，
    # 因此 img-src 收紧到 'self' data:，不再放行任意 https 来源（减少数据外泄/被追踪面）。
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
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
    return response

# 登录失败记录（防暴力破解）- 按 IP 维度，防止同一 IP 连续失败后阻断登录
login_attempts = {}
MAX_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5分钟

def _cleanup_expired_attempts():
    """清理已过期的锁定记录"""
    now = datetime.now().timestamp()
    expired = [k for k, (attempts, last_time) in login_attempts.items()
               if now - last_time >= LOCKOUT_TIME]
    for k in expired:
        login_attempts.pop(k, None)

def check_login_attempts(username):
    """检查登录尝试次数"""
    _cleanup_expired_attempts()
    client_ip = request.remote_addr
    key = f"{client_ip}:{username}"
    if key in login_attempts:
        attempts, last_time = login_attempts[key]
        if datetime.now().timestamp() - last_time < LOCKOUT_TIME and attempts >= MAX_ATTEMPTS:
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
    else:
        if key in login_attempts:
            attempts, _ = login_attempts[key]
            login_attempts[key] = (attempts + 1, now)
        else:
            login_attempts[key] = (1, now)

def login_required(f):
    """登录验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 检查请求频率
        if not check_rate_limit():
            return jsonify({'error': '请求过于频繁'}), 429
        
        # 检查登录状态
        if not session.get('logged_in'):
            return jsonify({'error': '未登录'}), 401
        
        if session.get('must_change_password') and request.path not in ['/api/change_password', '/api/csrf_token', '/logout']:
            return jsonify({'error': '请先修改默认密码', 'must_change_password': True}), 403

        # POST/PUT/DELETE 请求需要验证 CSRF（GET 请求跳过）
        if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            csrf_token = request.headers.get('X-CSRF-Token')
            if not csrf_token and request.is_json and request.json:
                csrf_token = request.json.get('csrf_token')
            if not csrf_token or not verify_csrf_token(csrf_token):
                return jsonify({'error': 'CSRF 验证失败'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

def log_event(level, message):
    """写日志并缓存到内存"""
    text = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} [{level}] {message}"
    log_buffer.append(text)
    getattr(app.logger, level.lower(), app.logger.info)(message)


def audit_log(action, target='', status='success', detail=''):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO audit_logs (username, client_ip, action, target, status, detail) VALUES (?, ?, ?, ?, ?, ?)',
                  (session.get('username', '-'), request.remote_addr, action, target, status, detail))
        conn.commit(); conn.close()
    except Exception as e:
        app.logger.warning(f'audit log failed: {e}')


def get_setting(key, default=''):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT value FROM settings_kv WHERE key = ?', (key,))
    row = c.fetchone(); conn.close()
    return row[0] if row else default


def set_setting(key, value):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO settings_kv (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=CURRENT_TIMESTAMP', (key, value))
    conn.commit(); conn.close()

def is_force_https_enabled():
    stored = get_setting('force_https', '')
    if stored != '':
        return stored.lower() not in ('0', 'false', 'no')
    return FORCE_HTTPS


def create_rule_snapshot(reason='manual'):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM rules ORDER BY id')
    payload = json.dumps([dict(r) for r in c.fetchall()], ensure_ascii=False)
    c.execute('INSERT INTO rule_snapshots (username, reason, payload) VALUES (?, ?, ?)', (session.get('username', '-'), reason, payload))
    conn.commit(); sid = c.lastrowid; conn.close(); return sid


def send_alert(message):
    bot_token = get_secret_setting('tg_bot_token', '')
    chat_id = get_setting('tg_chat_id', '')
    if not bot_token or not chat_id:
        return False, 'tg bot not configured'
    try:
        resp = requests.post(f'https://api.telegram.org/bot{bot_token}/sendMessage', json={'chat_id': chat_id, 'text': message}, timeout=8)
        return resp.status_code < 300, f'http {resp.status_code}'
    except Exception as e:
        return False, str(e)


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
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE servers SET status = ?, last_check = CURRENT_TIMESTAMP WHERE id = ?',
             ('token_invalid', server_id))
    disabled = 0
    if TOKEN_INVALID_DISABLE:
        c.execute('UPDATE rules SET enabled = 0 WHERE server_id = ? AND enabled = 1', (server_id,))
        disabled = c.rowcount
    conn.commit()
    conn.close()
    log_event('WARNING', f"服务器 {server_id} token 异常: {reason}，自动停用 {disabled} 条规则")
    return disabled


def init_db():
    """初始化数据库"""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # 用户表
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        must_change_password INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        password_changed_at TIMESTAMP
    )''')
    for stmt in [
        "ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 1",
        "ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP"
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
        print(f'[!] 默认用户已创建: admin / {setup_password}')
        print('[!] 首次登录后必须修改密码！')
    
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
        conn = sqlite3.connect(DB_FILE)
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
        conn = sqlite3.connect(DB_FILE)
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
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, host, port, token FROM servers WHERE id = ?', (server_id,))
    server_row = c.fetchone()
    if not server_row:
        conn.close()
        return [{'server_id': server_id, 'status': 'server_missing'}]

    server = dict(server_row)
    c.execute('SELECT * FROM rules WHERE server_id = ? AND enabled = 1 ORDER BY id', (server_id,))
    desired_rules = [dict(r) for r in c.fetchall()]
    conn.close()

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

    desired_by_port = {str(rule['local_port']): rule for rule in desired_rules}
    remote_by_port = {str(p): v for p, v in remote_rules.items()}

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
            'target_port': rule['target_port']
        }
        return agent_post(f"{base_url}/add_rule", token, payload, timeout=5)

    # 1) 先删 (orphan)
    for port_key in to_delete:
        del_resp, del_err = _retry_agent_call(lambda pk=port_key: _do_delete(pk))
        if del_err is not None:
            results.append({'local_port': int(port_key), 'status': 'delete_error', 'error': str(del_err)})
        elif del_resp.status_code == 200:
            results.append({'local_port': int(port_key), 'status': 'deleted'})
        else:
            results.append({'local_port': int(port_key), 'status': 'delete_failed', 'http': del_resp.status_code})

    # 2) 替换 (delete+add)
    for rule in to_replace:
        port_key = str(rule['local_port'])
        del_resp, del_err = _retry_agent_call(lambda pk=port_key: _do_delete(pk))
        if del_err is not None or (del_resp is not None and del_resp.status_code != 200):
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
        elif add_resp.status_code == 200:
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
        elif add_resp.status_code == 200:
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


if __name__ == '__main__':
    bootstrap()
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)
