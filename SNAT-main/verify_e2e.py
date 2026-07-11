#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端验证：真起一个 Agent 进程，走真实 HTTP 验证签名认证链路。

与 tests_smoke.py 不同，这里不 mock —— 它启动真正的 WSGI 服务（优先 gunicorn，
没有则回退到 `python agent.py`），用面板侧同款 HMAC 签名算法发请求，断言：

  正常路径：healthz 匿名 / health 匿名 / 签名 GET / 签名 POST(幂等) 通过
  攻击路径：坏签名 / 过期签名 / 篡改 body / 严格模式下的 Bearer-only —— 全部 401

iptables 缺失（如 macOS）不影响认证层验证：list_rules / health 不依赖 iptables。
用法：  python3 verify_e2e.py
"""
import os
import sys
import time
import json
import hmac
import socket
import shutil
import hashlib
import tempfile
import subprocess

import requests

AGENT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent')
TOKEN = 'e2e-verify-token-' + hashlib.sha256(os.urandom(8)).hexdigest()[:16]

_passed = 0
_failed = 0


def check(name, cond):
    global _passed, _failed
    if cond:
        _passed += 1
        print(f"  \033[32mPASS\033[0m  {name}")
    else:
        _failed += 1
        print(f"  \033[31mFAIL\033[0m  {name}")


def free_port():
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sign_headers(method, path, body=''):
    ts = str(int(time.time()))
    msg = f"{method}\n{path}\n{ts}\n{body}".encode()
    sig = hmac.new(TOKEN.encode(), msg, hashlib.sha256).hexdigest()
    return {'X-Timestamp': ts, 'X-Signature': sig}


def start_agent(port, allow_bearer):
    env = dict(os.environ)
    tmp = tempfile.mkdtemp(prefix='snat-e2e-')
    env.update({
        'AGENT_TOKEN': TOKEN,
        'AGENT_HOST': '127.0.0.1',
        'AGENT_PORT': str(port),
        'AGENT_RULES_FILE': os.path.join(tmp, 'rules.json'),
        'AGENT_LOG_FILE': os.path.join(tmp, 'agent.log'),
        'DNS_REFRESH_INTERVAL': '0',
        'AGENT_ALLOW_BEARER': '1' if allow_bearer else '0',
    })
    if shutil.which('gunicorn'):
        cmd = ['gunicorn', '--chdir', AGENT_DIR, '--workers', '1', '--threads', '4',
               '--bind', f'127.0.0.1:{port}', 'wsgi:app']
    else:
        cmd = [sys.executable, os.path.join(AGENT_DIR, 'agent.py')]
    proc = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f'http://127.0.0.1:{port}'
    for _ in range(50):
        try:
            if requests.get(f'{base}/healthz', timeout=1).status_code == 200:
                return proc, base, tmp
        except requests.RequestException:
            time.sleep(0.2)
    proc.terminate()
    raise RuntimeError('agent 未能在超时内启动')


def run_phase(label, allow_bearer):
    port = free_port()
    proc, base, tmp = start_agent(port, allow_bearer)
    print(f"\n[{label}] agent 已启动于 {base} (AGENT_ALLOW_BEARER={'1' if allow_bearer else '0'})")
    try:
        # --- 匿名探针 ---
        r = requests.get(f'{base}/healthz', timeout=3)
        check('healthz 匿名可访问', r.status_code == 200 and r.json().get('status') == 'ok')
        r = requests.get(f'{base}/health', timeout=3)
        check('health 无凭据仅返回存活', r.status_code == 200 and set(r.json().keys()) == {'status'})

        # --- 签名正常路径 ---
        r = requests.get(f'{base}/list_rules', headers=sign_headers('GET', '/list_rules'), timeout=3)
        check('签名 GET /list_rules 通过(无需 Bearer)', r.status_code == 200)

        r = requests.get(f'{base}/health', headers=sign_headers('GET', '/health'), timeout=3)
        check('签名 GET /health 返回完整诊断', r.status_code == 200 and 'ip_forward' in r.json())

        body = json.dumps({'local_port': 59999, 'target_ip': '1.1.1.1', 'target_port': 80}, separators=(',', ':'))
        r = requests.post(f'{base}/add_rule', data=body,
                          headers={**sign_headers('POST', '/add_rule', body), 'Content-Type': 'application/json'},
                          timeout=5)
        # iptables 缺失时返回 500（命令失败），但认证已通过 —— 关键是不被 401 挡下。
        check('签名 POST /add_rule 通过认证(非401)', r.status_code != 401)

        # --- 攻击路径：必须 401 ---
        h = sign_headers('GET', '/list_rules'); h['X-Signature'] = 'deadbeef' * 8
        check('坏签名被拒(401)', requests.get(f'{base}/list_rules', headers=h, timeout=3).status_code == 401)

        stale = str(int(time.time()) - 99999)
        msg = f"GET\n/list_rules\n{stale}\n".encode()
        sig = hmac.new(TOKEN.encode(), msg, hashlib.sha256).hexdigest()
        r = requests.get(f'{base}/list_rules', headers={'X-Timestamp': stale, 'X-Signature': sig}, timeout=3)
        check('过期签名被拒(401, 防重放)', r.status_code == 401)

        signed = json.dumps({'local_port': 1, 'target_ip': '1.1.1.1', 'target_port': 80}, separators=(',', ':'))
        tampered = json.dumps({'local_port': 2, 'target_ip': '9.9.9.9', 'target_port': 80}, separators=(',', ':'))
        r = requests.post(f'{base}/add_rule', data=tampered,
                          headers={**sign_headers('POST', '/add_rule', signed), 'Content-Type': 'application/json'},
                          timeout=3)
        check('篡改 body 后签名失效被拒(401)', r.status_code == 401)

        # --- Bearer-only 行为随模式不同 ---
        r = requests.get(f'{base}/list_rules', headers={'Authorization': f'Bearer {TOKEN}'}, timeout=3)
        if allow_bearer:
            check('迁移模式: Bearer-only 兼容通过(200)', r.status_code == 200)
        else:
            check('严格模式: Bearer-only 被拒(401)', r.status_code == 401)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    runner = 'gunicorn' if shutil.which('gunicorn') else 'python agent.py (gunicorn 未安装)'
    print(f"启动器: {runner}")
    run_phase('迁移模式 ALLOW_BEARER=1', allow_bearer=True)
    run_phase('严格模式 ALLOW_BEARER=0', allow_bearer=False)
    print(f"\n==== 结果: {_passed} 通过, {_failed} 失败 ====")
    sys.exit(1 if _failed else 0)


if __name__ == '__main__':
    main()
