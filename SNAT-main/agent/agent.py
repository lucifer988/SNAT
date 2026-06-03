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
AGENT_HOST = os.getenv('AGENT_HOST', '0.0.0.0')
AGENT_PORT = int(os.getenv('AGENT_PORT', '8888'))
# 签名请求有效期（秒），用于防重放；面板与 Agent 时钟需大致同步。
SIGNED_REQUEST_TTL = int(os.getenv('AGENT_SIGNED_REQUEST_TTL', '300'))
# 迁移期默认仍接受旧的 Bearer-only 认证；待面板全部升级后设 AGENT_ALLOW_BEARER=0 进入「仅签名」严格模式。
ALLOW_BEARER = os.getenv('AGENT_ALLOW_BEARER', '1').lower() in ('1', 'true', 'yes')

# ---------------------------------------------------------------------------
# DNAT 目标地址防护（设备安全）
# ---------------------------------------------------------------------------
# Agent 会把入口端口 DNAT 到面板下发的 target_ip。若目标被指向链路本地/云元数据地址
# (169.254.169.254)，相当于把一个对外端口直接打通到本机元数据服务，可窃取云厂商临时凭据；
# 域名目标还可能被 DNS 重绑定到该地址。这里默认拒绝链路本地段，对正常的公网/私网目标无影响。
# 如确有特殊需要放行，设 AGENT_TARGET_ALLOW_ALL=1；或用 AGENT_TARGET_DENY_CIDRS 追加（逗号分隔 CIDR）。
TARGET_ALLOW_ALL = os.getenv('AGENT_TARGET_ALLOW_ALL', '0').lower() in ('1', 'true', 'yes')
_DEFAULT_TARGET_DENY_CIDRS = ['169.254.0.0/16', 'fe80::/10']

# 是否把 FORWARD 链默认策略设为 ACCEPT。历史行为为 1（保持兼容）；置 0 时只依赖按规则注入的
# SNAT_*_FWD_IN/OUT ACCEPT（已插在链首），从而避免把本机变成开放转发，缩小被滥用面。
SET_FORWARD_POLICY_ACCEPT = os.getenv('AGENT_SET_FORWARD_POLICY_ACCEPT', '1').lower() in ('1', 'true', 'yes')


def _target_deny_networks():
    cidrs = list(_DEFAULT_TARGET_DENY_CIDRS)
    for item in os.getenv('AGENT_TARGET_DENY_CIDRS', '').split(','):
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


def is_target_ip_allowed(ip):
    """目标 IP 是否允许被 DNAT。默认仅拒绝链路本地/元数据段。"""
    if TARGET_ALLOW_ALL:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for net in _target_deny_networks():
        if addr in net:
            return False
    return True

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

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
    """加载规则"""
    if os.path.exists(RULES_FILE):
        with open(RULES_FILE, 'r') as f:
            return json.load(f)
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

def verify_signed_request(method, path, timestamp, signature, body=''):
    """校验面板下发请求的 HMAC 签名（与 web 端 build_agent_headers 同算法）。

    message = "{method}\n{path}\n{timestamp}\n{body}"，HMAC-SHA256 以 TOKEN 为密钥。
    时间戳超出 SIGNED_REQUEST_TTL 视为重放/过期。常量时间比较，防时序侧信道。
    """
    if not signature or not timestamp:
        return False, 'missing_signature'
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False, 'invalid_timestamp'
    if abs(int(time.time()) - ts) > SIGNED_REQUEST_TTL:
        return False, 'timestamp_expired'
    message = f"{method}\n{path}\n{timestamp}\n{body or ''}".encode()
    expected = hmac.new(TOKEN.encode(), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, 'bad_signature'
    return True, 'ok'


def check_auth():
    """认证：优先验签（防重放、防伪造、不依赖明文 token），其次按迁移开关回退到 Bearer。"""
    signature = request.headers.get('X-Signature', '')
    if signature:
        body = request.get_data(as_text=True) or ''
        ok, reason = verify_signed_request(
            request.method, request.path,
            request.headers.get('X-Timestamp', ''), signature, body
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

def resolve_target(target):
    """解析目标地址，返回 (target_host, target_ip)"""
    try:
        ipaddress.ip_address(target)
        return target, target
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(target)
        return target, resolved
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


def add_snat_rule(local_port, target_ip, target_port, target_host=None):
    """添加 SNAT 转发规则（幂等）"""
    display = f"{target_host}({target_ip})" if target_host and target_host != target_ip else target_ip
    logging.info(f"添加规则: {local_port} -> {display}:{target_port}")

    # 启用 IP 转发
    success, _, _ = run_cmd(['sysctl', '-w', 'net.ipv4.ip_forward=1'])
    if not success:
        logging.error("启用 IP 转发失败")
        return False

    # 设置 FORWARD 链默认策略为 ACCEPT（可通过 AGENT_SET_FORWARD_POLICY_ACCEPT=0 关闭，
    # 关闭后仅依赖按规则注入的 SNAT_*_FWD ACCEPT，避免本机成为开放转发）
    if SET_FORWARD_POLICY_ACCEPT:
        run_cmd(['iptables', '-P', 'FORWARD', 'ACCEPT'])

    # 检查 DNAT 规则是否已存在（幂等）
    success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f'{target_ip}:{target_port}'])
    if not success:
        # 不存在，添加
        success, _, _ = run_cmd(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f'{target_ip}:{target_port}'])
        if not success:
            logging.error(f"添加 DNAT 规则失败: {local_port}")
            return False
    else:
        logging.info(f"DNAT 规则已存在: {local_port}")
    # mangle 表：分别记录入/出方向流量，便于后续统计
    success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_IN'])
    if not success:
        success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1', '-p', 'tcp', '--dport', str(local_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_IN'])
        if not success:
            return False
    success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_OUT'])
    if not success:
        success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-I', 'PREROUTING', '1', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_OUT'])
        if not success:
            return False

    # FORWARD 链：为新规则打上稳定注释，后续统计只认面板托管规则
    success, _, _ = run_cmd(['iptables', '-C', 'FORWARD', '-p', 'tcp', '-d', target_ip, '--dport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_IN'])
    if not success:
        run_cmd(['iptables', '-I', 'FORWARD', '1', '-p', 'tcp', '-d', target_ip, '--dport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_IN'])
    success, _, _ = run_cmd(['iptables', '-C', 'FORWARD', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_OUT'])
    if not success:
        run_cmd(['iptables', '-I', 'FORWARD', '1', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_OUT'])

    # 检查 SNAT 规则是否已存在
    success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-p', 'tcp', '-d', str(target_ip), '--dport', str(target_port), '-j', 'MASQUERADE'])
    if not success:
        success, _, _ = run_cmd(['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-p', 'tcp', '-d', str(target_ip), '--dport', str(target_port), '-j', 'MASQUERADE'])
        if not success:
            logging.error(f"添加 SNAT 规则失败: {target_ip}:{target_port}")
            return False
    else:
        logging.info(f"SNAT 规则已存在: {target_ip}:{target_port}")

    remove_duplicate_rules(local_port, target_ip, target_port)
    logging.info(f"规则添加成功: {local_port} -> {display}:{target_port}")
    return True

def delete_snat_rule(local_port, target_ip, target_port):
    """删除 SNAT 转发规则（循环删除直到不存在）"""
    logging.info(f"删除规则: {local_port} -> {target_ip}:{target_port}")

    # 循环删除 DNAT 规则（可能有重复）
    while True:
        success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f'{target_ip}:{target_port}'])
        if success:
            run_cmd(['iptables', '-t', 'nat', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'DNAT', '--to-destination', f'{target_ip}:{target_port}'])
            logging.info(f"DNAT 规则已删除: {local_port}")
        else:
            break

    # 循环删除 mangle 统计规则
    while True:
        success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_IN'])
        if success:
            run_cmd(['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-p', 'tcp', '--dport', str(local_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_IN'])
        else:
            break

    while True:
        success, _, _ = run_cmd(['iptables', '-t', 'mangle', '-C', 'PREROUTING', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_OUT'])
        if success:
            run_cmd(['iptables', '-t', 'mangle', '-D', 'PREROUTING', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'RETURN', '-m', 'comment', '--comment', f'SNAT_{local_port}_OUT'])
        else:
            break

    while True:
        success, _, _ = run_cmd(['iptables', '-C', 'FORWARD', '-p', 'tcp', '-d', target_ip, '--dport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_IN'])
        if success:
            run_cmd(['iptables', '-D', 'FORWARD', '-p', 'tcp', '-d', target_ip, '--dport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_IN'])
        else:
            break

    while True:
        success, _, _ = run_cmd(['iptables', '-C', 'FORWARD', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_OUT'])
        if success:
            run_cmd(['iptables', '-D', 'FORWARD', '-p', 'tcp', '-s', target_ip, '--sport', str(target_port), '-j', 'ACCEPT', '-m', 'comment', '--comment', f'SNAT_{local_port}_FWD_OUT'])
        else:
            break

    # 循环删除 SNAT 规则
    while True:
        success, _, _ = run_cmd(['iptables', '-t', 'nat', '-C', 'POSTROUTING', '-p', 'tcp', '-d', str(target_ip), '--dport', str(target_port), '-j', 'MASQUERADE'])
        if success:
            run_cmd(['iptables', '-t', 'nat', '-D', 'POSTROUTING', '-p', 'tcp', '-d', str(target_ip), '--dport', str(target_port), '-j', 'MASQUERADE'])
            logging.info(f"SNAT 规则已删除: {target_ip}:{target_port}")
        else:
            break

    logging.info(f"规则删除完成: {local_port}")
    return True

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
        success = add_snat_rule(local_port, resolved_ip, target_port, target_host=target_host)

        if success:
            # 保存到配置文件
            rules = load_rules()
            rules[str(local_port)] = {
                'target_host': target_host,
                'target_ip': resolved_ip,
                'target_port': target_port,
                'traffic_bytes': 0
            }
            save_rules(rules)
            return jsonify({'success': True, 'target_host': target_host, 'resolved_ip': resolved_ip})
        else:
            return jsonify({'success': False, 'error': 'iptables 命令失败'}), 500

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


@app.route('/get_traffic/<int:port>', methods=['GET'])
def get_traffic(port):
    """获取端口流量统计（优先 FORWARD 口径，兼容历史累积）"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    if not (1 <= port <= 65535):
        return jsonify({'error': 'Invalid port'}), 400

    rules = load_rules()
    rule = rules.get(str(port), {})

    current_bytes = get_forward_counter(port, rule)
    if current_bytes == 0:
        success, stdout, _ = run_cmd(['iptables', '-t', 'mangle', '-L', 'PREROUTING', '-n', '-v', '-x'])
        if success:
            stdout = next((line for line in stdout.splitlines() if f'SNAT_{port}_IN' in line), '')
            if stdout:
                parts = stdout.strip().split()
                if len(parts) > 1:
                    current_bytes = int(parts[1])

    if str(port) not in rules:
        return jsonify({'success': True, 'bytes': current_bytes, 'current_counter': current_bytes})

    historical_bytes = rules[str(port)].get('traffic_bytes', 0)
    last_counter = rules[str(port)].get('last_counter', 0)

    if current_bytes < last_counter:
        total_bytes = historical_bytes + current_bytes
        rules[str(port)]['traffic_bytes'] = total_bytes
        rules[str(port)]['last_counter'] = current_bytes
        save_rules(rules)
    else:
        total_bytes = historical_bytes + (current_bytes - last_counter)
        if current_bytes - last_counter > 1024*1024*100:
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

    # 如果超过限制，自动删除规则
    if traffic_limit_bytes > 0 and current_bytes >= traffic_limit_bytes:
        with STATE_LOCK:
            rules = load_rules()
            if str(local_port) in rules:
                rule = rules[str(local_port)]
                delete_snat_rule(local_port, rule['target_ip'], rule['target_port'])
                del rules[str(local_port)]
                save_rules(rules)
                logging.warning(f"规则 {local_port} 已达流量限制，自动停止")
                return jsonify({'success': True, 'stopped': True})

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
            delete_snat_rule(int(local_port), rule['target_ip'], rule['target_port'])
            del rules[local_port]
            save_rules(rules)

    return jsonify({'success': True})

@app.route('/list_rules', methods=['GET'])
def list_rules():
    """列出所有规则"""
    if not check_auth():
        return jsonify({'error': 'Unauthorized'}), 401

    rules = load_rules()
    return jsonify(rules)

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
                    delete_snat_rule(int(local_port), old_ip, target_port)
                    success = add_snat_rule(int(local_port), resolved_ip, target_port, target_host=target_host)
                    if success:
                        rule['target_ip'] = resolved_ip
                        updated += 1
                        logging.info(f"DNS 刷新: {target_host} {old_ip} -> {resolved_ip}:{target_port} (port {local_port})")
                    else:
                        logging.error(f"DNS 刷新失败: {target_host} -> {resolved_ip}:{target_port} (port {local_port})")

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
        add_snat_rule(int(local_port), rule['target_ip'], rule['target_port'], target_host=rule.get('target_host'))

def _enforce_token_policy():
    if TOKEN == DEFAULT_AGENT_TOKEN and not ALLOW_DEFAULT_TOKEN:
        raise SystemExit(
            "[!] Refusing to start: AGENT_TOKEN is still the default value.\n"
            "    Set AGENT_TOKEN to a strong random value, or set "
            "SNAT_ALLOW_DEFAULT_TOKEN=1 to override (NOT recommended)."
        )
    if len(TOKEN) < 16:
        logging.warning("AGENT_TOKEN is shorter than 16 characters; consider using a stronger value.")


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


if __name__ == '__main__':
    bootstrap()
    app.run(host=AGENT_HOST, port=AGENT_PORT)
