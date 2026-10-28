"""Round 10 回归测试：本轮深度审计发现并修复的三处问题。

1) 会话吊销一致性（缺陷 A，高）：
   `/`（后台首页）与 `/api/csrf_token` 过去只校验 cookie 里的 logged_in，不校验服务端
   会话状态。被吊销/改密/过期的会话仍能加载后台壳页并持续领取有效 CSRF token。
   修复后：这两个端点与受保护数据端点判定一致——服务端会话失效即整体失效。

2) X-Request-ID 净化（缺陷 B，中）：
   客户端可控的 X-Request-ID 会被写入日志、回显到响应头、并转发给 Agent 请求头。
   过去仅做首尾 strip，非法字符/超长串原样透传，形成日志注入 / 头污染面。
   修复后：只保留安全字符集并限长，非法即回退到自生成 ID。

3) Agent 恢复期目标策略校验（缺陷 D，纵深防御）：
   restore_rules() 过去不做 is_target_ip_allowed 校验，规则保存后若目标策略收紧，
   历史规则会在重启后被静默重新下发。修复后：恢复前重新校验，命中拒绝网段则跳过。
"""
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('SNAT_ALLOW_DEFAULT_TOKEN', '1')
os.environ.setdefault('AGENT_LOG_FILE', os.path.join(tempfile.mkdtemp(), 'agent.log'))
os.environ.setdefault('AGENT_RULES_FILE', os.path.join(tempfile.mkdtemp(), 'rules.json'))

from web import app as webapp
from agent import agent as agentapp


class SessionRevocationConsistencyTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.app.config['TESTING'] = True
        # 清空模块级限流/锁定态，避免与其它套件在同进程内串扰导致 429
        webapp.rate_limit_store.clear()
        webapp.login_attempts.clear()
        webapp.login_attempts_by_ip.clear()
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.client = webapp.app.test_client()
        # 真实登录 + 改密 + 再登录，拿到带服务端 session_id 的有效会话
        r = self.client.post('/login', json={'username': 'admin', 'password': 'Admin12345'})
        csrf = r.get_json()['csrf_token']
        self.client.post('/api/change_password',
                         json={'old_password': 'Admin12345', 'new_password': 'NewPass123', 'csrf_token': csrf},
                         headers={'X-CSRF-Token': csrf})
        self.client.post('/login', json={'username': 'admin', 'password': 'NewPass123'})

    def tearDown(self):
        self.tmp.cleanup()

    def _revoke(self):
        conn = sqlite3.connect(webapp.DB_FILE)
        conn.execute("UPDATE web_sessions SET revoked=1 WHERE username='admin'")
        conn.commit()
        conn.close()

    def test_valid_session_baseline(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.get('/api/csrf_token').status_code, 200)

    def test_revoked_session_cannot_load_index(self):
        self._revoke()
        self.assertEqual(self.client.get('/').status_code, 302)

    def test_revoked_session_cannot_mint_csrf(self):
        self._revoke()
        self.assertEqual(self.client.get('/api/csrf_token').status_code, 401)

    def test_revoked_session_data_endpoint_still_rejected(self):
        self._revoke()
        self.assertEqual(self.client.get('/api/rules').status_code, 401)


class RequestIdSanitizationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.app.config['TESTING'] = True
        webapp.init_db()
        self.client = webapp.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_request_id_is_preserved(self):
        rid = 'req-ABC_123.def'
        r = self.client.get('/healthz', headers={'X-Request-ID': rid})
        self.assertEqual(r.headers.get('X-Request-ID'), rid)

    def test_whitespace_and_overlong_are_replaced(self):
        evil = 'junk with spaces\tand\ttabs ' + 'A' * 300
        r = self.client.get('/healthz', headers={'X-Request-ID': evil})
        echoed = r.headers.get('X-Request-ID', '')
        self.assertNotEqual(echoed, evil)
        self.assertLessEqual(len(echoed), 64)
        self.assertTrue(all(ch in webapp._REQUEST_ID_SAFE for ch in echoed))

    def test_helper_rejects_disallowed_chars(self):
        for bad in ('a b', 'a\tb', 'a;b', 'a/b', 'x' * 65, '', '   '):
            out = webapp._sanitize_request_id(bad)
            self.assertTrue(all(ch in webapp._REQUEST_ID_SAFE for ch in out))
            self.assertLessEqual(len(out), 64)


class AgentRestoreTargetPolicyTest(unittest.TestCase):
    """restore_rules() 恢复前应对目标地址做与新增一致的策略校验。"""

    def test_restore_skips_denied_target(self):
        stored = {
            '20001': {'target_ip': '169.254.169.254', 'target_port': 80, 'target_host': None},  # 云元数据，恒定拒绝
            '20002': {'target_ip': '8.8.8.8', 'target_port': 53, 'target_host': None},          # 公网，放行
        }
        added = []

        def fake_add(port, ip, tport, target_host=None):
            added.append(ip)
            return {'ok': True, 'stage': 'done', 'rolled_back': False, 'verified': True}

        def fake_run(cmd):
            # -C（存在性检查）一律返回“不存在”，让 restore_rules 的清理 while 循环立即 break，
            # 避免 mock 恒真导致的无限循环。其余命令按成功处理。
            if '-C' in cmd:
                return (False, '', 'iptables: No chain/target/match by that name.')
            return (True, '', '')

        with patch.object(agentapp, 'load_rules', return_value=stored), \
             patch.object(agentapp, 'run_cmd', side_effect=fake_run), \
             patch.object(agentapp, 'add_snat_rule', side_effect=fake_add):
            agentapp.restore_rules()

        self.assertIn('8.8.8.8', added)
        self.assertNotIn('169.254.169.254', added)  # 被策略拒绝，未恢复


if __name__ == '__main__':
    unittest.main()
