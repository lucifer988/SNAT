#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SNAT Manager - Agent 客户端
部署在需要做 SNAT 转发的服务器上
"""
from flask import Flask, request, jsonify
import subprocess
import json
import os
import logging
import logging.handlers
import socket
import ipaddress
import threading
import time
import hmac
import hashlib
import traceback
from datetime import datetime, timedelta

app = Flask(__name__)
DEFAULT_AGENT_TOKEN = 'change-me-in-production'
TOKEN = os.getenv('AGENT_TOKEN', DEFAULT_AGENT_TOKEN)
RULES_FILE = os.getenv('AGENT_RULES_FILE', '/var/lib/snat-agent/rules.json')
LOG_FILE = os.getenv('AGENT_LOG_FILE', '/var/log/snat-agent.log')
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 7
MAX_CONTENT_LENGTH = 1024 * 1024
# 子进程（iptables/conntrack/sysctl）执行超时，避免 xtables 锁争用或异常时把工作线程永久挂住。
CMD_TIMEOUT = int(os.getenv('AGENT_CMD_TIMEOUT', '20'))
DNS_REFRESH_INTERVAL = int(os.getenv('DNS_REFRESH_INTERVAL', '60'))
ALLOW_DEFAULT_TOKEN = os.getenv('SNAT_ALLOW_DEFAULT_TOKEN', '0').lower() in ('1', 'true', 'yes')

# 监听地址：外网部署应绑定到 WireGuard 隧道内网 IP（如 10.66.66.2），不要裸露 0.0.0.0。
AGENT_HOST = os.getenv('AGENT_HOST', '127.0.0.1')
AGENT_PORT = int(os.getenv('AGENT_PORT', '8888'))
# 签名请求有效期（秒），用于防重放；面板与 Agent 时钟需大致同步。
SIGNED_REQUEST_TTL = int(os.getenv('AGENT_SIGNED_REQUEST_TTL', '300'))
# nonce 防重放：时间窗只能挡“过期请求”，挡不住有效期内被原样重放的请求。
# 面板每次签名会带一个一次性 X-Nonce，Agent 在 TTL 内记住已见过的 nonce，重复出现直接拒绝。
# 关闭方法：AGENT_REQUIRE_NONCE=0（仅在与不发送 nonce 的老面板混跑时临时使用）。
REQUIRE_NONCE = os.getenv('AGENT_REQUIRE_NONCE', '1').lower() in ('1', 'true', 'yes')
# Bearer-only 认证默认关闭：新部署一律走 HMAC 签名（防重放、防伪造、不在链路上暴露明文 token）。
# 仅当从老面板升级、且暂时无法全部改用签名时，才显式设 AGENT_ALLOW_BEARER=1 临时回退。
ALLOW_BEARER = os.getenv('AGENT_ALLOW_BEARER', '0').lower() in ('1', 'true', 'yes')

# ---------------------------------------------------------------------------
# Agent 访问来源 IP 白名单（公网直连面板时的纵深防御）
# ---------------------------------------------------------------------------
# 公网直连场景下 Agent 端口会被全网扫描/探测。签名校验已能挡住无 token 的请求，但：
#   1. 多一道 IP 白名单可把绝大多数扫描器/爆破直接挡在 Flask 之前，缩小被 0day 打穿的窗口；
#   2. 白名单未命中直接 403，不进入任何业务逻辑，几乎零开销。
# 用法：AGENT_ALLOWED_IPS="1.2.3.4,10.0.0.0/24" —— 只放行面板出口 IP / 网段。
# 留空表示不限制来源（仅靠签名），仅建议在受信内网/隧道内使用。
# 环回地址 (127.0.0.1/::1) 始终放行，供本机健康探针使用。
_AGENT_ALLOWED_IPS_RAW = os.getenv('AGENT_ALLOWED_IPS', '')


def _parse_allowed_networks(raw):
    nets = []
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logging.warning(f"AGENT_ALLOWED_IPS 中的无效条目已忽略: {item}")
    return nets


_AGENT_ALLOWED_NETWORKS = _parse_allowed_networks(_AGENT_ALLOWED_IPS_RAW)


def is_source_ip_allowed(remote_addr):
    """来源 IP 是否允许访问 Agent。未配置白名单则放行（回退到仅签名）。"""
    if not _AGENT_ALLOWED_NETWORKS:
        return True
    if not remote_addr:
        return False
    try:
        ip = ipaddress.ip_address(remote_addr)
    except ValueError:
        return False
    if ip.is_loopback:
        return True
    return any(ip in net for net in _AGENT_ALLOWED_NETWORKS)

# ---------------------------------------------------------------------------
# DNAT 目标地址防护（设备安全）—— 默认保守，按需放开
# ---------------------------------------------------------------------------
# Agent 会把入口端口 DNAT 到面板下发的 target_ip。如果面板被攻破，攻击者可以把一个公网
# 入口端口转发到本机 / 内网地址，把这台 Agent 变成打进内网的“跳板”，或直接打到云元数据
# 服务 (169.254.169.254) 窃取临时凭据。为把这类横向移动风险降到最低，这里默认拒绝：
#   - 回环 127.0.0.0/8 / ::1
#   - 链路本地 169.254.0.0/16（含云元数据）/ fe80::/10
#   - RFC1918 私网 10/8、172.16/12、192.168/16
#   - CGNAT 100.64.0.0/10
#   - IPv6 ULA fc00::/7
#   - 未指定/多播/保留地址
# 说明：不少 SNAT 场景本身就是“公网端口 → 内网目标”。若你确需转发到私网/回环，请显式打开
# AGENT_TARGET_ALLOW_PRIVATE=1（放行 RFC1918/回环/CGNAT/ULA），或用 AGENT_TARGET_ALLOW_CIDRS
# 精确放行某些网段（逗号分隔 CIDR，优先级最高）。AGENT_TARGET_ALLOW_ALL=1 为完全关闭校验的总开关。
# AGENT_TARGET_DENY_CIDRS 可在默认拒绝集之外再追加拒绝网段。
TARGET_ALLOW_ALL = os.getenv('AGENT_TARGET_ALLOW_ALL', '0').lower() in ('1', 'true', 'yes')
TARGET_ALLOW_PRIVATE = os.getenv('AGENT_TARGET_ALLOW_PRIVATE', '0').lower() in ('1', 'true', 'yes')

# 恒定拒绝（无论是否放行私网都拒绝）：链路本地/云元数据。
_ALWAYS_DENY_TARGET_CIDRS = ['169.254.0.0/16', 'fe80::/10']
# 私网类拒绝（仅在未显式 AGENT_TARGET_ALLOW_PRIVATE=1 时生效）。
_PRIVATE_TARGET_DENY_CIDRS = [
    '127.0.0.0/8', '::1/128',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '100.64.0.0/10',  # CGNAT
    'fc00::/7',       # IPv6 ULA
]

# 是否把 FORWARD 链默认策略设为 ACCEPT。历史行为为 1（保持兼容）；置 0 时只依赖按规则注入的
# SNAT_*_FWD_IN/OUT ACCEPT（已插在链首），从而避免把本机变成开放转发，缩小被滥用面。
SET_FORWARD_POLICY_ACCEPT = os.getenv('AGENT_SET_FORWARD_POLICY_ACCEPT', '0').lower() in ('1', 'true', 'yes')


def _parse_cidr_list(raw):
    nets = []
    for item in (raw or '').split(','):
        item = item.strip()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return nets


def _always_deny_networks():
    """恒定拒绝网段：云元数据/链路本地。任何配置都不能覆盖（含 AGENT_TARGET_ALLOW_CIDRS）。"""
    return _parse_cidr_list(','.join(_ALWAYS_DENY_TARGET_CIDRS))


def _operator_deny_networks():
    """运维显式追加的拒绝网段（AGENT_TARGET_DENY_CIDRS）。视为“明确拒绝”，同样不被 allow 覆盖。"""
    return _parse_cidr_list(os.getenv('AGENT_TARGET_DENY_CIDRS', ''))


def _private_deny_networks():
    """内置私网类拒绝（回环/RFC1918/CGNAT/ULA）。仅在未放行私网时生效，可被 allow-cidrs 精确开口。"""
    if TARGET_ALLOW_PRIVATE:
        return []
    return _parse_cidr_list(','.join(_PRIVATE_TARGET_DENY_CIDRS))


def _target_allow_networks():
    """显式放行网段（AGENT_TARGET_ALLOW_CIDRS）。只能覆盖“私网类拒绝”，不能覆盖恒定/运维拒绝。"""
    return _parse_cidr_list(os.getenv('AGENT_TARGET_ALLOW_CIDRS', ''))


def is_target_ip_allowed(ip):
    """目标 IP 是否允许被 DNAT。

    判定优先级（从高到低）：
      1. AGENT_TARGET_ALLOW_ALL=1        —— 完全关闭校验的显式总开关。
      2. 恒定拒绝（云元数据/链路本地）    —— 不可被任何 allow 配置覆盖，堵住“配置即后门”。
      3. 未指定/多播/保留地址            —— 恒定拒绝。
      4. 运维显式拒绝 AGENT_TARGET_DENY_CIDRS —— 明确拒绝优先于放行。
      5. 显式放行 AGENT_TARGET_ALLOW_CIDRS   —— 仅用于在“私网类拒绝”里精确开口。
      6. 内置私网类拒绝（回环/RFC1918/CGNAT/ULA，除非 ALLOW_PRIVATE）。
      7. 其它一律放行（公网目标）。
    """
    if TARGET_ALLOW_ALL:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    # 2 & 3：恒定拒绝，最高优先，allow-cidrs 也无法覆盖
    if addr.is_unspecified or addr.is_multicast or addr.is_reserved or addr.is_link_local:
        return False
    for net in _always_deny_networks():
        if addr in net:
            return False

    # 4：运维显式拒绝也优先于放行
    for net in _operator_deny_networks():
        if addr in net:
            return False

    # 5：显式放行只能覆盖下面的“私网类拒绝”
    for net in _target_allow_networks():
        if addr in net:
            return True

    # 6：内置私网类拒绝
    for net in _private_deny_networks():
        if addr in net:
            return False

    # 7：其它（公网）放行
    return True

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH


@app.before_request
def _enforce_source_ip():
    """来源 IP 白名单：未命中直接 403，不进入任何业务逻辑（含 /healthz 以外全部路径）。"""
    # 本机健康探针路径始终放行（Docker/systemd HEALTHCHECK 从环回访问）。
    if request.path == '/healthz':
        return
    if not is_source_ip_allowed(request.remote_addr):
        logging.warning(f"Blocked request from non-whitelisted IP {request.remote_addr} {request.path}")
        return jsonify({'error': 'Forbidden'}), 403


@app.after_request
def _agent_security_headers(response):
    """Agent 只回 JSON，收紧响应头，去掉可被利用的信息面。"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Server'] = 'nginx'
    response.headers.pop('X-Powered-By', None)
    return response

# iptables 与 rules.json 是进程内共享的临界资源：API 线程与 DNS 刷新线程会并发修改。
# 用一把可重入锁把所有"读规则→改 iptables→写规则"的过程串行化，避免规则文件丢更新或竞态。
STATE_LOCK = threading.RLock()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.handlers.RotatingFileHandler(LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT),
        logging.StreamHandler()
    ]
)

def clean_old_logs():
    """清理7天前的日志"""
    try:
        if os.path.exists(LOG_FILE):
            # 读取日志文件
            with open(LOG_FILE, 'r') as f:
                lines = f.readlines()

            # 保留最近7天的日志
            cutoff_date = datetime.now() - timedelta(days=7)
            new_lines = []
            for line in lines:
                try:
                    # 解析日志时间戳
                    date_str = line.split('[')[0].strip()
                    log_date = datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S,%f')
                    if log_date >= cutoff_date:
                        new_lines.append(line)
                except:
                    new_lines.append(line)

            # 写回文件
            with open(LOG_FILE, 'w') as f:
                f.writelines(new_lines)

            logging.info(f"日志清理完成，保留 {len(new_lines)} 条记录")
    except Exception as e:
        logging.error(f"日志清理失败: {e}")

def load_rules():
    """加载规则。

    rules.json 若因磁盘写坏/人为编辑而损坏，json.load 会抛异常并让所有接口
    连环 500、Agent 重启也起不来。这里把损坏文件挪到 .corrupt 备份后按空规则继续，
    面板下一轮全量对账 (sync_server_rules) 会自动把规则重新下发回来。
    """
    if not os.path.exists(RULES_FILE):
        return {}
    try:
        with open(RULES_FILE, 'r') as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError('rules.json 顶层必须是对象')
        return data
    except (ValueError, OSError) as e:
        corrupt_path = f"{RULES_FILE}.corrupt"
        logging.error(f"rules.json 损坏，已备份到 {corrupt_path} 并按空规则继续: {e}")
        try:
            os.replace(RULES_FILE, corrupt_path)
        except OSError:
            pass
        return {}

def save_rules(rules):
    """保存规则（原子写：先写临时文件再 rename，避免崩溃中断导致 rules.json 损坏）"""
    os.makedirs(os.path.dirname(RULES_FILE), exist_ok=True)
    tmp = f"{RULES_FILE}.tmp"
    with open(tmp, 'w') as f:
        json.dump(rules, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, RULES_FILE)


def _with_iptables_wait(cmd):
    """为 iptables 命令注入 -w（等待 xtables 锁），避免并发调用时偶发 'xtables lock' 失败。"""
    if cmd and cmd[0] == 'iptables' and '-w' not in cmd:
        return [cmd[0], '-w'] + cmd[1:]
    return cmd

class _NonceCache:
    """有界 TTL 去重缓存：记录 TTL 窗口内已见过的 nonce，用于防“时间窗内重放”。

    - 线程安全（面板并发请求 + DNS 刷新线程都可能触发）。
    - 有容量上限，惰性清理过期项，避免攻击者用海量 nonce 撑爆内存。
    """
    def __init__(self, ttl, max_size=50000):
        self.ttl = ttl
        self.max_size = max_size
        self._store = {}
        self._lock = threading.Lock()

    def _purge_locked(self, now):
        expired = [k for k, exp in self._store.items() if exp <= now]
        for k in expired:
            self._store.pop(k, None)
        if len(self._store) > self.max_size:
            # 超限时淘汰最早过期的一批
            for k, _exp in sorted(self._store.items(), key=lambda kv: kv[1])[:len(self._store) - self.max_size]:
                self._store.pop(k, None)

    def seen(self, nonce):
        """若 nonce 之前已出现（未过期）返回 True；否则记录并返回 False。"""
        now = time.time()
        with self._lock:
            self._purge_locked(now)
            if nonce in self._store:
                return True
            self._store[nonce] = now + self.ttl
            return False


_NONCE_CACHE = _NonceCache(SIGNED_REQUEST_TTL)


def verify_signed_request(method, path, timestamp, signature, body='', nonce=''):
    """校验面板下发请求的 HMAC 签名（与 web 端 build_agent_headers 同算法）。

    message = "{method}\n{path}\n{timestamp}\n{nonce}\n{body}"，HMAC-SHA256 以 TOKEN 为密钥。
    时间戳超出 SIGNED_REQUEST_TTL 视为重放/过期。常量时间比较，防时序侧信道。
    nonce 绑定进签名，配合 _NONCE_CACHE 堵住“时间窗内重放”。
    """
    if not signature or not timestamp:
        return False, 'missing_signature'
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid_timestamp'
    if abs(int(time.time()) - ts) > SIGNED_REQUEST_TTL:
        return False, 'timestamp_expired'
    if REQUIRE_NONCE and not nonce:
        return False, 'missing_nonce'
    message = f"{method}\n{path}\n{timestamp}\n{nonce or ''}\n{body or ''}".encode()
    expected = hmac.new(TOKEN.encode(), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, 'bad_signature'
    # 签名有效后再查重放：只有已通过签名校验的 nonce 才会占用缓存，避免被伪造 nonce 污染。
    if nonce and _NONCE_CACHE.seen(nonce):
        return False, 'nonce_replayed'
    return True, 'ok'


def check_auth():
    """认证：优先验签（防重放、防伪造、不依赖明文 token），其次按迁移开关回退到 Bearer。"""
    signature = request.headers.get('X-Signature', '')
    if signature:
        body = request.get_data(as_text=True) or ''
        ok, reason = verify_signed_request(
            request.method, request.path,
            request.headers.get('X-Timestamp', ''), signature, body,
            nonce=request.headers.get('X-Nonce', '')
        )
        if ok:
            return True
        logging.warning(f"Bad signature from {request.remote_addr} {request.path}: {reason}")
        return False

    # 无签名：迁移期可回退到旧的 Bearer-only（仅在受信内网/隧道内安全）。
    if ALLOW_BEARER:
        auth = request.headers.get('Authorization', '')
        if hmac.compare_digest(auth, f'Bearer {TOKEN}'):
            logging.warning(
                f"Legacy bearer auth from {request.remote_addr} {request.path}; "
                "升级面板后请设 AGENT_ALLOW_BEARER=0 关闭"
            )
            return True

    logging.warning(f"Unauthorized request from {request.remote_addr} {request.path}")
    return False

def run_cmd(cmd):
    """执行命令（带超时；iptables 自动加 -w 等待锁，规避并发竞争）"""
    if isinstance(cmd, str):
        raise ValueError('run_cmd 不再接受字符串命令')
    cmd = _with_iptables_wait(cmd)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=CMD_TIMEOUT)
    except subprocess.TimeoutExpired:
        # 命令卡死（如 xtables 长期被占用、conntrack 表巨大）不能拖垮工作线程。
        logging.error(f"命令执行超时(>{CMD_TIMEOUT}s): {' '.join(cmd)}")
        return False, '', f'timeout after {CMD_TIMEOUT}s'
    except (FileNotFoundError, OSError) as e:
        # iptables/conntrack 缺失等：不让单条命令异常把整个 Agent 拖崩。
        logging.error(f"命令无法执行: {' '.join(cmd)} ({e})")
        return False, '', str(e)
    if result.returncode != 0:
        logging.error(f"命令执行失败: {' '.join(cmd)}\n错误: {result.stderr}")
    return result.returncode == 0, result.stdout, result.stderr


def count_active_connections(local_port):
    """从 conntrack 中统计指定入口端口的活跃 TCP 连接数"""
    active_states = {'SYN_SENT', 'SYN_RECV', 'ESTABLISHED', 'FIN_WAIT', 'CLOSE_WAIT', 'LAST_ACK'}

    candidates = ['/proc/net/nf_conntrack', '/proc/net/ip_conntrack']
    path = next((p for p in candidates if os.path.exists(p)), None)
    if path:
        count = 0
        with open(path, 'r') as f:
            for line in f:
                if ' tcp ' not in f' {line} ' or f'dport={local_port}' not in line:
                    continue
                parts = line.split()
                state = parts[5] if len(parts) > 5 else ''
                if state not in active_states:
                    continue
                if f'dport={local_port}' in ' '.join(parts[0:12]):
                    count += 1
        return count

    success, stdout, _ = run_cmd(['conntrack', '-L', '-p', 'tcp'])
    if not success:
        return 0

    count = 0
    for line in stdout.splitlines():
        if f'dport={local_port}' not in line:
            continue
        parts = line.split()
        state = parts[3] if len(parts) > 3 else ''
        if state not in active_states:
            continue
        if f'dport={local_port}' in line:
            count += 1
    return count


def count_matching_rules(table, chain, fragments):
    success, stdout, _ = run_cmd(['iptables', '-t', table, '-S', chain])
    if not success:
        return 0
    lines = [line for line in stdout.splitlines() if all(fragment in line for fragment in fragments)]
    return len(lines)

AGENT_IPV4_ONLY = os.getenv('AGENT_IPV4_ONLY', '1').lower() in ('1', 'true', 'yes')

def resolve_target(target):
    """解析目标；Compose/默认配置仅允许 IPv4，当前 iptables 数据面不支持 IPv6。"""
    try:
        addr = ipaddress.ip_address(target)
        if AGENT_IPV4_ONLY and addr.version != 4:
            logging.warning(f"拒绝 IPv6 目标（当前版本仅支持 IPv4）: {target}")
            return None, None
        return target, target
    except ValueError:
        pass
    try:
        # IPv4-only 模式明确用 gethostbyname，避免 AAAA 结果进入 IPv4 iptables。
        return target, socket.gethostbyname(target)
    except Exception as e:
        logging.error(f"目标解析失败: {target} ({e})")
        return None, None


def is_ip_address(value):
    """判断是否为 IP 地址"""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def remove_duplicate_rules(local_port, target_ip, target_port):
    """清理重复的 DNAT / mangle / MASQUERADE 规则，仅保留一份"""
    while True:
        count = count_matching_rules('nat', 'PREROUTING', [f'--dport {local_port}', f'--to-destination {target_ip}:{target_port}'])
        if count <= 1:
            break
        run_cmd(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f'{target_ip}:{target_port}'])

    duplicate_specs = [
        ('mangle', 'PREROUTING', ['-p', 'tcp', '--dport', str(local_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_IN']),
        ('mangle', 'PREROUTING', ['-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_OUT']),
        ('filter', 'FORWARD', ['-p', 'tcp', '-d', target_ip, '--dport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_IN']),
        ('filter', 'FORWARD', ['-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_OUT']),
    ]
    for table, chain, rule_args in duplicate_specs:
        while True:
            success, _, _ = run_cmd(['iptables'] + (['-t', table] if table != 'filter' else []) + ['-C', chain] + rule_args)
            if not success:
                break
            count = count_matching_rules(table, chain, [f'--comment {rule_args[-1]}'])
            if count <= 1:
                break
            run_cmd(['iptables'] + (['-t', table] if table != 'filter' else []) + ['-D', chain] + rule_args)

    while True:
        count = count_matching_rules('nat', 'POSTROUTING', [f'-d {target_ip}/32', f'--dport {target_port}', '-j MASQUERADE'])
        if count <= 1:
            break
        run_cmd(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-p', 'tcp', '-d', str(target_ip), '--dport', str(target_port), '-j', 'MASQUERADE'])


def _rule_components(local_port, target_ip, target_port):
    return [
      ('dnat',['iptables','-t','nat','-C','PREROUTING','-p','tcp','--dport',str(local_port),'-j','DNAT','--to-destination',f'{target_ip}:{target_port}'],['iptables','-t','nat','-A','PREROUTING','-p','tcp','--dport',str(local_port),'-j','DNAT','--to-destination',f'{target_ip}:{target_port}']),
      ('mangle_in',['iptables','-t','mangle','-C','PREROUTING','-p','tcp','--dport',str(local_port),'-j','RETURN','-m','comment','--comment',f'SNAT_{local_port}_IN'],['iptables','-t','mangle','-I','PREROUTING','1','-p','tcp','--dport',str(local_port),'-j','RETURN','-m','comment','--comment',f'SNAT_{local_port}_IN']),
      ('mangle_out',['iptables','-t','mangle','-C','PREROUTING','-p','tcp','-s',target_ip,'--sport',str(target_port),'-j','RETURN','-m','comment','--comment',f'SNAT_{local_port}_OUT'],['iptables','-t','mangle','-I','PREROUTING','1','-p','tcp','-s',target_ip,'--sport',str(target_port),'-j','RETURN','-m','comment','--comment',f'SNAT_{local_port}_OUT']),
      ('forward_in',['iptables','-C','FORWARD','-p','tcp','-d',target_ip,'--dport',str(target_port),'-j','ACCEPT','-m','comment','--comment',f'SNAT_{local_port}_FWD_IN'],['iptables','-I','FORWARD','1','-p','tcp','-d',target_ip,'--dport',str(target_port),'-j','ACCEPT','-m','comment','--comment',f'SNAT_{local_port}_FWD_IN']),
      ('forward_out',['iptables','-C','FORWARD','-p','tcp','-s',target_ip,'--sport',str(target_port),'-j','ACCEPT','-m','comment','--comment',f'SNAT_{local_port}_FWD_OUT'],['iptables','-I','FORWARD','1','-p','tcp','-s',target_ip,'--sport',str(target_port),'-j','ACCEPT','-m','comment','--comment',f'SNAT_{local_port}_FWD_OUT']),
      ('postrouting',['iptables','-t','nat','-C','POSTROUTING','-p','tcp','-d',str(target_ip),'--dport',str(target_port),'-j','MASQUERADE'],['iptables','-t','nat','-A','POSTROUTING','-p','tcp','-d',str(target_ip),'--dport',str(target_port),'-j','MASQUERADE'])]


def _delete_cmd_for_add(add_cmd):
    """把本项目生成的 -A/-I 命令转换为等价 -D 规格命令。"""
    cmd = list(add_cmd)
    op_index = next(i for i, value in enumerate(cmd) if value in ('-A', '-I'))
    was_insert = cmd[op_index] == '-I'
    cmd[op_index] = '-D'
    if was_insert and op_index + 2 < len(cmd) and cmd[op_index + 2] == '1':
        del cmd[op_index + 2]
    return cmd


def _check_rule(check_cmd):
    """返回 (state, error)：state 为 present/absent/error，避免把权限错误当作不存在。"""
    ok, _, err = run_cmd(check_cmd)
    if ok:
        return 'present', ''
    message = (err or '').strip()
    lower = message.lower()
    absent_markers = (
        'bad rule', 'matching rule exist', 'does a matching rule exist',
        'rule does not exist', 'no such rule', 'missing',
    )
    if any(marker in lower for marker in absent_markers):
        return 'absent', ''
    return 'error', message or 'iptables rule check failed without stderr'


def _rollback_created_components(created_components):
    """只逆序撤销本次新增组件，不破坏调用前已存在的规则。"""
    failures = []
    for stage, check_cmd, add_cmd in reversed(created_components):
        delete_cmd = _delete_cmd_for_add(add_cmd)
        ok, _, err = run_cmd(delete_cmd)
        if not ok:
            failures.append({'component': stage, 'error': (err or '')[:200]})
            continue
        state, check_error = _check_rule(check_cmd)
        if state != 'absent':
            failures.append({
                'component': f'rollback_verify_{stage}',
                'error': check_error or '本次新增组件回滚后仍存在',
            })
    return not failures, failures


def add_snat_rule(local_port, target_ip, target_port, target_host=None):
    """补偿事务式下发：只回滚本次新增组件，并返回真实回滚/校验状态。"""
    created = []

    def fail(stage, rollback=True, error=''):
        rolled_back = False
        rollback_failures = []
        if rollback:
            rolled_back, rollback_failures = _rollback_created_components(created)
        return {
            'ok': False,
            'stage': stage,
            'rolled_back': rolled_back,
            'verified': False,
            'error': error,
            'rollback_failures': rollback_failures,
        }

    ok, _, err = run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    if not ok:
        return fail('ip_forward', False, err)
    if SET_FORWARD_POLICY_ACCEPT:
        ok, _, err = run_cmd(['iptables', '-P', 'FORWARD', 'ACCEPT'])
        if not ok:
            return fail('forward_policy', False, err)

    parts = _rule_components(local_port, target_ip, target_port)
    for stage, check_cmd, add_cmd in parts:
        state, check_error = _check_rule(check_cmd)
        if state == 'error':
            return fail(f'{stage}_check', bool(created), check_error)
        if state == 'absent':
            ok, _, err = run_cmd(add_cmd)
            if not ok:
                return fail(stage, bool(created), err)
            created.append((stage, check_cmd, add_cmd))

    remove_duplicate_rules(local_port, target_ip, target_port)
    for stage, check_cmd, _ in parts:
        state, check_error = _check_rule(check_cmd)
        if state != 'present':
            return fail(f'verify_{stage}', bool(created), check_error or '规则不存在')
    return {'ok': True, 'stage': 'done', 'rolled_back': False, 'verified': True}


def delete_snat_rule(local_port, target_ip, target_port, keep_masquerade=False):
    """逐组件删除并逐项校验；查询错误和删除错误均不得假成功。"""
    failures = []
    parts = _rule_components(local_port, target_ip, target_port)
    for stage, check_cmd, add_cmd in parts:
        if stage == 'postrouting' and keep_masquerade:
            continue
        delete_cmd = _delete_cmd_for_add(add_cmd)
        for _ in range(50):
            state, check_error = _check_rule(check_cmd)
            if state == 'absent':
                break
            if state == 'error':
                failures.append({'component': f'{stage}_check', 'error': check_error[:200]})
                break
            ok, _, err = run_cmd(delete_cmd)
            if not ok:
                failures.append({'component': stage, 'error': (err or '')[:200]})
                break
        else:
            failures.append({'component': stage, 'error': '删除次数超过安全上限'})

        if not any(item['component'] in (stage, f'{stage}_check') for item in failures):
            state, check_error = _check_rule(check_cmd)
            if state == 'present':
                failures.append({'component': f'verify_{stage}', 'error': '规则删除后仍存在'})
            elif state == 'error':
                failures.append({'component': f'verify_{stage}', 'error': check_error[:200]})
    return not failures, failures


def _other_rules_share_target(rules,local_port,target_ip,target_port):
    return any(str(p)!=str(local_port) and str(r.get('target_ip'))==str(target_ip) and str(r.get('target_port'))==str(target_port) for p,r in rules.items())

@app.route('/add_rule', methods=['POST'])
def add_rule():
    """添加转发规则"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    local_port = data.get('local_port')
    target_input = data.get('target_host') or data.get('target_ip')
    target_port = data.get('target_port')

    if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
        return jsonify({'error': 'Invalid local_port'}), 400
    if not isinstance(target_port, int) or not (1 <= target_port <= 65535):
        return jsonify({'error': 'Invalid target_port'}), 400
    if not isinstance(target_input, str) or not target_input:
        return jsonify({'error': 'Invalid target_ip'}), 400

    target_host, resolved_ip = resolve_target(target_input)
    if not resolved_ip:
        return jsonify({'error': 'Invalid target_ip'}), 400
    if not is_target_ip_allowed(resolved_ip):
        logging.warning(f"拒绝转发目标(疑似链路本地/云元数据地址): {target_input} -> {resolved_ip}")
        return jsonify({'error': 'Target address not allowed'}), 400

    # 串行化 iptables + rules.json 改动，避免与 DNS 刷新线程并发冲突
    with STATE_LOCK:
        result = add_snat_rule(local_port, resolved_ip, target_port, target_host=target_host)
        if isinstance(result, bool): result={'ok':result,'stage':'legacy','rolled_back':False,'verified':result}

        if result['ok']:
            # 保存到配置文件；若是重新启用/重建同端口规则，保留既有流量累计，只有删规则时才清零
            rules = load_rules()
            existing = rules.get(str(local_port), {}) if isinstance(rules.get(str(local_port), {}), dict) else {}
            rules[str(local_port)] = {
                'target_host': target_host,
                'target_ip': resolved_ip,
                'target_port': target_port,
                'traffic_bytes': int(existing.get('traffic_bytes', 0) or 0),
                # 暂停后重新启用会创建全新的 iptables 计数器，基线必须从 0 开始；
                # 历史累计仍保留在 traffic_bytes 中。
                'last_counter': 0 if existing.get('suspended') else int(existing.get('last_counter', 0) or 0),
                'traffic_limit_gb': max(0, int(data.get('traffic_limit_gb', existing.get('traffic_limit_gb', 0)) or 0))
            }
            save_rules(rules)
            return jsonify({'success': True, 'target_host': target_host, 'resolved_ip': resolved_ip, 'stage': result['stage'], 'verified': result['verified']})

            return jsonify({'success': False, 'error': 'iptables 命令失败', **result}), 500

def get_forward_counter(port, rule=None):
    """优先读取带注释的 FORWARD 计数；兼容历史未命名旧规则。"""
    total_bytes = 0
    target_ip = str((rule or {}).get('target_ip', '') or '')
    target_port = str((rule or {}).get('target_port', '') or '')

    success, stdout, _ = run_cmd(['iptables', '-L', 'FORWARD', '-n', '-v', '-x'])
    if not success:
        return 0

    for line in stdout.splitlines():
        line = line.strip()
        if not line or 'tcp' not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            line_bytes = int(parts[1])
        except ValueError:
            continue

        if f'SNAT_{port}_FWD_IN' in line or f'SNAT_{port}_FWD_OUT' in line:
            total_bytes += line_bytes
            continue

        if target_ip and target_port:
            if f' {target_ip} ' in f' {line} ' and f'tcp dpt:{target_port}' in line:
                total_bytes += line_bytes
                continue
            if f' {target_ip} ' in f' {line} ' and f'tcp spt:{target_port}' in line:
                total_bytes += line_bytes
                continue

    return total_bytes


def get_traffic_counter(port, rule=None):
    """读取当前规则计数，兼容只有 mangle 注释计数的历史规则。"""
    current_bytes = get_forward_counter(port, rule)
    if current_bytes != 0:
        return current_bytes
    success, stdout, _ = run_cmd(['iptables', '-t', 'mangle', '-L', 'PREROUTING', '-n', '-v', '-x'])
    if not success:
        return 0
    line = next((item for item in stdout.splitlines() if f'SNAT_{port}_IN' in item), '')
    if not line:
        return 0
    parts = line.strip().split()
    try:
        return int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        return 0


@app.route('/get_traffic/<int:port>', methods=['GET'])
def get_traffic(port):
    """获取端口流量统计（优先 FORWARD 口径，兼容历史累积）"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    if not (1 <= port <= 65535):
        return jsonify({'error': 'Invalid port'}), 400

    rules = load_rules()
    rule = rules.get(str(port), {})

    current_bytes = get_traffic_counter(port, rule)

    if str(port) not in rules:
        return jsonify({'success': True, 'bytes': current_bytes, 'current_counter': current_bytes})

    historical_bytes = int(rules[str(port)].get('traffic_bytes', 0) or 0)
    last_counter = int(rules[str(port)].get('last_counter', 0) or 0)

    if current_bytes < last_counter:
        total_bytes = historical_bytes + current_bytes
    else:
        total_bytes = historical_bytes + (current_bytes - last_counter)

    rules[str(port)]['traffic_bytes'] = total_bytes
    rules[str(port)]['last_counter'] = current_bytes
    save_rules(rules)

    return jsonify({'success': True, 'bytes': total_bytes, 'current_counter': current_bytes})

@app.route('/get_connections/<int:port>', methods=['GET'])
def get_connections(port):
    """获取端口活跃连接数（依赖 conntrack）"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    if not (1 <= port <= 65535):
        return jsonify({'error': 'Invalid port'}), 400

    try:
        active_connections = count_active_connections(port)
        return jsonify({'success': True, 'active_connections': active_connections})
    except Exception as e:
        logging.error(f"获取端口 {port} 连接数失败: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/check_traffic_limit', methods=['POST'])
def check_traffic_limit():
    """检查流量限制并自动禁用超限规则"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    local_port = data.get('local_port')
    if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
        return jsonify({'error': 'Invalid local_port'}), 400
    try:
        traffic_limit_bytes = int(data.get('traffic_limit_gb', 0)) * (1024**3)
        current_bytes = int(data.get('current_bytes', 0))
    except (TypeError, ValueError):
        return jsonify({'error': 'Invalid traffic figures'}), 400

    if traffic_limit_bytes > 0 and current_bytes >= traffic_limit_bytes:
        with STATE_LOCK:
            rules = load_rules(); entry = rules.get(str(local_port))
            if entry and not entry.get('suspended'):
                keep = _other_rules_share_target(rules, local_port, entry['target_ip'], entry['target_port'])
                ok, failures = delete_snat_rule(local_port, entry['target_ip'], entry['target_port'], keep)
                if not ok:
                    entry.update(suspend_pending=True, suspend_failures=failures)
                    save_rules(rules)
                    return jsonify({'success': False, 'stopped': False, 'verified': False,
                                    'failures': failures}), 500
                entry.pop('suspend_pending', None)
                entry.pop('suspend_failures', None)
                entry.update(suspended=True, suspended_reason='traffic_limit',
                             suspended_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                save_rules(rules)
                return jsonify({'success': True, 'stopped': True, 'verified': True, 'failures': []})
            if entry and entry.get('suspended'):
                return jsonify({'success':True,'stopped':True,'verified':True,'already':True})
    return jsonify({'success': True, 'stopped': False})

@app.route('/delete_rule', methods=['POST'])
def delete_rule():
    """删除转发规则"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    local_port = data.get('local_port')
    if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
        return jsonify({'error': 'Invalid local_port'}), 400
    local_port = str(local_port)

    with STATE_LOCK:
        rules = load_rules()
        if local_port in rules:
            rule = rules[local_port]
            keep = _other_rules_share_target(rules, local_port, rule['target_ip'], rule['target_port'])
            ok, failures = delete_snat_rule(int(local_port), rule['target_ip'], rule['target_port'], keep)
            if not ok:
                return jsonify({'success':False,'verified':False,'failures':failures}), 500
            del rules[local_port]
            save_rules(rules)

    return jsonify({'success': True})

@app.route('/disable_rule', methods=['POST'])
def disable_rule():
    """停用转发但保留规则及累计流量，供后续重新启用。"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400
    local_port = data.get('local_port')
    if not isinstance(local_port, int) or not (1 <= local_port <= 65535):
        return jsonify({'error': 'Invalid local_port'}), 400

    with STATE_LOCK:
        rules = load_rules()
        key = str(local_port)
        rule = rules.get(key)
        if not isinstance(rule, dict):
            return jsonify({'success': True, 'verified': True, 'already': True})
        keep = _other_rules_share_target(rules, local_port, rule['target_ip'], rule['target_port'])
        current = get_traffic_counter(local_port, rule)
        historical = int(rule.get('traffic_bytes', 0) or 0)
        last = int(rule.get('last_counter', 0) or 0)
        rule['traffic_bytes'] = historical + (current if current < last else current - last)
        rule['last_counter'] = current
        ok, failures = delete_snat_rule(local_port, rule['target_ip'], rule['target_port'], keep)
        if not ok:
            return jsonify({'success': False, 'verified': False, 'failures': failures}), 500
        rule['suspended'] = True
        rule['suspended_reason'] = 'manual'
        rule.pop('suspend_pending', None)
        rule.pop('suspend_failures', None)
        save_rules(rules)

    return jsonify({'success': True, 'verified': True, 'suspended': True})

@app.route('/list_rules', methods=['GET'])
def list_rules():
    """列出所有规则。

    仅返回“配置中存在且内核规则仍在”的活动规则；已暂停规则仍保留，供面板识别为可恢复状态。
    这样可避免 rules.json 残留导致面板误判“规则已生效”。
    """
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    rules = load_rules()
    visible_rules = {}
    for local_port, rule in rules.items():
        if not isinstance(rule, dict):
            continue
        if rule.get('suspended'):
            visible_rules[str(local_port)] = rule
            continue

        target_ip = str(rule.get('target_ip', '') or '')
        target_port = rule.get('target_port')
        try:
            target_port = int(target_port)
        except (TypeError, ValueError):
            continue

        parts = _rule_components(int(local_port), target_ip, target_port)
        kernel_present = True
        for _stage, check_cmd, _add_cmd in parts:
            state, _check_error = _check_rule(check_cmd)
            if state != 'present':
                kernel_present = False
                break
        if kernel_present:
            visible_rules[str(local_port)] = rule

    return jsonify(visible_rules)

@app.route('/health', methods=['GET'])
def health():
    """健康检查接口。
    - 无 Authorization 头：仅返回 {'status': 'ok'}（适合容器探针/反代健康检查）。
    - Bearer Token 错误：返回 401（面板据此识别 token_invalid 状态）。
    - Bearer Token 正确：返回完整诊断信息。
    """
    # 无任何凭据（既无签名也无 Authorization）→ 仅返回存活，供容器/反代探针使用。
    if not request.headers.get('X-Signature') and not request.headers.get('Authorization'):
        return jsonify({'status': 'ok'})
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    ip_forward = False
    try:
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            ip_forward = f.read().strip() == '1'
    except Exception:
        pass

    iptables_ok = True
    success, _, _ = run_cmd(['iptables', '-t', 'nat', '-L', 'PREROUTING', '-n'])
    if not success:
        iptables_ok = False

    docker_ok = True
    success, stdout, _ = run_cmd(['iptables', '-t', 'nat', '-L', 'POSTROUTING', '-n'])
    if success and stdout:
        if 'docker' not in stdout.lower() and '172.17' not in stdout:
            docker_ok = False

    rules = load_rules()
    return jsonify({
        'status': 'ok',
        'ip_forward': ip_forward,
        'iptables_ok': iptables_ok,
        'docker_ok': docker_ok,
        'rules_count': len(rules),
        'dns_refresh_interval': DNS_REFRESH_INTERVAL
    })

@app.route('/healthz', methods=['GET'])
def healthz():
    """Kubernetes/容器健康探针：始终匿名可访问，仅返回存活状态。"""
    return jsonify({'status': 'ok'})

def refresh_dns_rules():
    """定时刷新域名解析并更新规则"""
    if DNS_REFRESH_INTERVAL <= 0:
        logging.info("DNS 刷新已关闭")
        return

    while True:
        try:
            time.sleep(DNS_REFRESH_INTERVAL)
            with STATE_LOCK:
                rules = load_rules()
                updated = 0
                for local_port, rule in rules.items():
                    if rule.get('suspended'): continue
                    target_host = rule.get('target_host')
                    if not target_host or is_ip_address(target_host):
                        continue

                    _, resolved_ip = resolve_target(target_host)
                    if not resolved_ip or resolved_ip == rule.get('target_ip'):
                        continue
                    if not is_target_ip_allowed(resolved_ip):
                        logging.warning(f"DNS 刷新拒绝(疑似链路本地/云元数据地址): {target_host} -> {resolved_ip} (port {local_port})")
                        continue

                    old_ip = rule.get('target_ip')
                    target_port = rule.get('target_port')
                    keep_masquerade = _other_rules_share_target(
                        rules, local_port, old_ip, target_port)
                    deleted, failures = delete_snat_rule(
                        int(local_port), old_ip, target_port, keep_masquerade)
                    if not deleted:
                        logging.error(
                            f"DNS 刷新删除旧规则失败: {target_host} {old_ip}:{target_port} "
                            f"(port {local_port}, failures={failures})")
                        continue
                    result = add_snat_rule(
                        int(local_port), resolved_ip, target_port, target_host=target_host)
                    if result.get('ok'):
                        rule['target_ip'] = resolved_ip
                        updated += 1
                        logging.info(f"DNS 刷新: {target_host} {old_ip} -> {resolved_ip}:{target_port} (port {local_port})")
                    else:
                        rollback = add_snat_rule(
                            int(local_port), old_ip, target_port, target_host=target_host)
                        logging.error(
                            f"DNS 刷新失败: {target_host} -> {resolved_ip}:{target_port} "
                            f"(port {local_port}, rollback_ok={rollback.get('ok')})")

                if updated:
                    save_rules(rules)
                    logging.info(f"DNS 刷新完成，更新 {updated} 条规则")
        except Exception as e:
            logging.error(f"DNS 刷新线程异常: {e}\n{traceback.format_exc()}")


def restore_rules():
    """启动时恢复规则（只清理 SNAT 规则，保留其他规则）"""
    logging.info("清理旧的 SNAT 规则...")

    # 只删除 SNAT 相关规则（通过 comment 识别）
    # 清理 mangle 表的 SNAT 统计规则
    success, stdout, _ = run_cmd(['iptables', '-t', 'mangle', '-L', 'PREROUTING', '-n', '--line-numbers'])
    if success and stdout:
        lines = stdout.strip().split('\n')
        for line in reversed(lines):  # 从后往前删除，避免行号变化
            if 'SNAT_' in line and ('_IN' in line or '_OUT' in line):
                parts = line.split()
                if parts and parts[0].isdigit():
                    run_cmd(['iptables', '-t', 'mangle', '-D', 'PREROUTING', str(parts[0])])

    # 清理 filter/FORWARD 表的 SNAT 统计规则
    success, stdout, _ = run_cmd(['iptables', '-L', 'FORWARD', '-n', '--line-numbers'])
    if success and stdout:
        lines = stdout.strip().split('\n')
        for line in reversed(lines):
            if 'SNAT_' in line and ('_FWD_IN' in line or '_FWD_OUT' in line):
                parts = line.split()
                if parts and parts[0].isdigit():
                    run_cmd(['iptables', '-D', 'FORWARD', str(parts[0])])

    # 清理 nat 表的 DNAT 规则（只删除我们添加的）
    # 注意：这里无法通过 comment 识别，所以需要从配置文件读取端口
    rules = load_rules()
    for local_port, rule in rules.items():
        # 循环删除可能重复的规则
        while True:
            success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f"{rule['target_ip']}:{rule['target_port']}"])
            if success:
                run_cmd(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f"{rule['target_ip']}:{rule['target_port']}"])
            else:
                break

        # 删除 POSTROUTING 的 MASQUERADE 规则
        while True:
            success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-p', 'tcp', '-d', str(rule['target_ip']), '--dport', str(rule['target_port']), '-j', 'MASQUERADE'])
            if success:
                run_cmd(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-p', 'tcp', '-d', str(rule['target_ip']), '--dport', str(rule['target_port']), '-j', 'MASQUERADE'])
            else:
                break

    # 设置 FORWARD 策略（可通过 AGENT_SET_FORWARD_POLICY_ACCEPT=0 关闭全局放行）
    if SET_FORWARD_POLICY_ACCEPT:
        run_cmd(['iptables', '-P', 'FORWARD', 'ACCEPT'])

    # 恢复保存的 SNAT 规则
    logging.info(f"恢复 {len(rules)} 条规则")
    for local_port, rule in rules.items():
        if rule.get('suspended'): continue
        # 与 /add_rule、DNS 刷新一致：恢复前重新校验目标地址。避免“规则保存后目标策略收紧
        # （如新增了 AGENT_TARGET_DENY_CIDRS 或关闭了 ALLOW_PRIVATE）”时，历史规则在重启后
        # 被静默重新下发，重新打开一条通往内网/回环/云元数据的转发路径。
        if not is_target_ip_allowed(str(rule.get('target_ip', ''))):
            logging.warning(f"恢复时拒绝规则(目标不符合当前策略): port {local_port} -> {rule.get('target_ip')}")
            continue
        add_snat_rule(int(local_port), rule['target_ip'], rule['target_port'], target_host=rule.get('target_host'))

_WEAK_TOKENS={DEFAULT_AGENT_TOKEN,'change-me','changeme','password','passw0rd','token','secret','admin','test','123456','12345678','default','replace-with-64-random-hex-characters','replace-with-64-random-hex-characters-DO-NOT-USE'}
def _enforce_token_policy():
    if (TOKEN in _WEAK_TOKENS or len(TOKEN)<16) and not ALLOW_DEFAULT_TOKEN:
        raise SystemExit('[!] Refusing to start: AGENT_TOKEN is weak or shorter than 16 characters.')
    if len(TOKEN)<32: logging.warning('AGENT_TOKEN is shorter than 32 characters.')

TRAFFIC_LIMIT_CHECK_INTERVAL = int(os.getenv('AGENT_TRAFFIC_LIMIT_CHECK_INTERVAL', '60'))


def _compute_total_bytes_locked(local_port, rules):
    """按计数器增量累计流量，处理 iptables 计数器重置，避免后台循环重复累加。"""
    entry = rules.get(str(local_port))
    if not entry:
        return 0
    current = get_forward_counter(int(local_port), entry)
    historical = int(entry.get('traffic_bytes', 0) or 0)
    last = int(entry.get('last_counter', 0) or 0)
    if current < last:
        historical += current
    else:
        historical += current - last
    entry['traffic_bytes'] = historical
    entry['last_counter'] = current
    return historical


def traffic_limit_loop():
    while TRAFFIC_LIMIT_CHECK_INTERVAL > 0:
        time.sleep(TRAFFIC_LIMIT_CHECK_INTERVAL)
        try:
            with STATE_LOCK:
                rules = load_rules()
                dirty = False
                for port, entry in rules.items():
                    limit = int(entry.get('traffic_limit_gb', 0) or 0)
                    if entry.get('suspended') or limit <= 0:
                        continue
                    total = _compute_total_bytes_locked(port, rules)
                    dirty = True
                    if total >= limit * (1024 ** 3):
                        keep = _other_rules_share_target(
                            rules, port, entry['target_ip'], entry['target_port'])
                        ok, failures = delete_snat_rule(
                            int(port), entry['target_ip'], entry['target_port'], keep)
                        if ok:
                            entry.pop('suspend_pending', None)
                            entry.pop('suspend_failures', None)
                            entry.update(
                                suspended=True,
                                suspended_reason='traffic_limit',
                                suspended_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                suspend_verified=True,
                            )
                        else:
                            entry.update(
                                suspend_pending=True,
                                suspend_verified=False,
                                suspend_failures=failures,
                            )
                if dirty:
                    save_rules(rules)
        except Exception as exc:
            logging.error(f'限额检查线程异常: {exc}')

_BOOTSTRAPPED = False


def bootstrap():
    """启动期一次性初始化：token 策略校验、清日志、恢复规则、起 DNS 刷新线程。

    供 gunicorn 入口 (wsgi.py) 与 `python agent.py` 直跑共用；幂等，多次调用只生效一次。
    """
    global _BOOTSTRAPPED
    if _BOOTSTRAPPED:
        return
    _BOOTSTRAPPED = True
    _enforce_token_policy()
    clean_old_logs()
    restore_rules()
    threading.Thread(target=refresh_dns_rules, daemon=True).start()
    threading.Thread(target=traffic_limit_loop, daemon=True).start()


if __name__ == '__main__':
    bootstrap()
    app.run(host=AGENT_HOST, port=AGENT_PORT)
