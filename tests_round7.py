import importlib.util
import json
import os
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent
os.environ.setdefault('SNAT_ALLOW_DEFAULT_TOKEN', '1')
os.environ.setdefault('AGENT_RULES_FILE', '/tmp/snat-round7-rules.json')
os.environ.setdefault('AGENT_LOG_FILE', '/tmp/snat-round7-agent.log')

from agent import agent as agentapp
from web import app as webapp


class Round7AgentTests(unittest.TestCase):
    def test_forward_policy_is_fail_closed_by_default(self):
        source = (ROOT / 'agent/agent.py').read_text()
        self.assertIn("AGENT_SET_FORWARD_POLICY_ACCEPT', '0'", source)

    def test_ipv6_literal_is_explicitly_rejected(self):
        self.assertEqual(agentapp.resolve_target('2001:db8::1'), (None, None))

    def test_add_rolls_back_when_late_stage_fails(self):
        calls = []
        def fake_run(cmd):
            calls.append(cmd)
            # Checks report missing; additions succeed except forward-in insertion.
            if '-C' in cmd:
                return False, '', 'missing'
            if '-I' in cmd and 'FORWARD' in cmd and 'FWD_IN' in ' '.join(cmd):
                return False, '', 'injected failure'
            return True, '', ''
        with patch.object(agentapp, 'run_cmd', side_effect=fake_run):
            result = agentapp.add_snat_rule(12345, '1.2.3.4', 8080)
        self.assertIsInstance(result, dict)
        self.assertFalse(result['ok'])
        self.assertEqual(result['stage'], 'forward_in')
        self.assertTrue(result['rolled_back'])

    def test_add_failure_does_not_delete_preexisting_components(self):
        calls = []
        checks = {'dnat': 0}
        def fake_run(cmd):
            calls.append(cmd)
            joined = ' '.join(cmd)
            if '-C' in cmd and 'DNAT' in cmd:
                checks['dnat'] += 1
                return True, '', ''  # 调用前已存在
            if '-C' in cmd:
                return False, '', 'Bad rule (does a matching rule exist in that chain?)'
            if '-I' in cmd and 'FWD_IN' in joined:
                return False, '', 'injected failure'
            return True, '', ''
        with patch.object(agentapp, 'run_cmd', side_effect=fake_run):
            result = agentapp.add_snat_rule(12345, '1.2.3.4', 8080)
        self.assertFalse(result['ok'])
        self.assertFalse(any('-D' in cmd and 'DNAT' in cmd for cmd in calls))

    def test_delete_reports_failed_kernel_removal(self):
        def fake_run(cmd):
            if '-C' in cmd and 'PREROUTING' in cmd and 'DNAT' in cmd:
                return True, '', ''
            if '-D' in cmd and 'PREROUTING' in cmd and 'DNAT' in cmd:
                return False, '', 'permission denied'
            return False, '', 'missing'
        with patch.object(agentapp, 'run_cmd', side_effect=fake_run):
            ok, failures = agentapp.delete_snat_rule(12345, '1.2.3.4', 8080)
        self.assertFalse(ok)
        self.assertTrue(any(x['component'] in ('dnat', 'verify_dnat') for x in failures))

    def test_delete_treats_permission_denied_check_as_failure(self):
        with patch.object(agentapp, 'run_cmd', return_value=(False, '', 'iptables: Permission denied')):
            ok, failures = agentapp.delete_snat_rule(12345, '1.2.3.4', 8080)
        self.assertFalse(ok)
        self.assertTrue(any(x['component'].endswith('_check') for x in failures))

    def test_traffic_limit_suspends_instead_of_forgetting_rule(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080, 'traffic_bytes': 0}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'save_rules') as save, \
             patch.object(agentapp, 'delete_snat_rule', return_value=(True, [])):
            r = agentapp.app.test_client().post('/check_traffic_limit', json={
                'local_port': 12345, 'traffic_limit_gb': 1, 'current_bytes': 2 * 1024 ** 3
            })
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['verified'])
        saved = save.call_args.args[0]
        self.assertIn('12345', saved)
        self.assertTrue(saved['12345']['suspended'])

    def test_traffic_limit_delete_failure_stays_enabled_for_retry(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'save_rules') as save, \
             patch.object(agentapp, 'delete_snat_rule', return_value=(False, [{'component':'dnat'}])):
            r = agentapp.app.test_client().post('/check_traffic_limit', json={
                'local_port': 12345, 'traffic_limit_gb': 1, 'current_bytes': 2 * 1024 ** 3
            })
        self.assertEqual(r.status_code, 500)
        saved = save.call_args.args[0]['12345']
        self.assertFalse(saved.get('suspended', False))
        self.assertTrue(saved['suspend_pending'])

    def test_get_traffic_keeps_reported_total_when_counter_stops_growing(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080, 'traffic_bytes': 0, 'last_counter': 0}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'save_rules'):
            with patch.object(agentapp, 'get_forward_counter', side_effect=[4096, 4096]):
                client = agentapp.app.test_client()
                first = client.get('/get_traffic/12345')
                second = client.get('/get_traffic/12345')
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 200)
        self.assertEqual(first.get_json()['bytes'], 4096)
        self.assertEqual(second.get_json()['bytes'], 4096)

    def test_reenable_rule_preserves_existing_traffic_history(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080, 'traffic_bytes': 987654, 'last_counter': 321}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'resolve_target', return_value=('1.2.3.4', '1.2.3.4')), \
             patch.object(agentapp, 'is_target_ip_allowed', return_value=True), \
             patch.object(agentapp, 'add_snat_rule', return_value={'ok': True, 'stage': 'done', 'verified': True}), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'save_rules') as save:
            r = agentapp.app.test_client().post('/add_rule', json={
                'local_port': 12345, 'target_ip': '1.2.3.4', 'target_port': 8080, 'traffic_limit_gb': 0
            })
        self.assertEqual(r.status_code, 200)
        saved = save.call_args.args[0]['12345']
        self.assertEqual(saved['traffic_bytes'], 987654)
        self.assertEqual(saved['last_counter'], 321)

    def test_reenable_suspended_rule_resets_kernel_counter_baseline(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080,
                           'traffic_bytes': 987654, 'last_counter': 500,
                           'suspended': True, 'suspended_reason': 'manual'}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'resolve_target', return_value=('1.2.3.4', '1.2.3.4')), \
             patch.object(agentapp, 'is_target_ip_allowed', return_value=True), \
             patch.object(agentapp, 'add_snat_rule', return_value={'ok': True, 'stage': 'done', 'verified': True}), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'save_rules') as save:
            r = agentapp.app.test_client().post('/add_rule', json={
                'local_port': 12345, 'target_ip': '1.2.3.4', 'target_port': 8080
            })
        self.assertEqual(r.status_code, 200)
        saved = save.call_args.args[0]['12345']
        self.assertEqual(saved['traffic_bytes'], 987654)
        self.assertEqual(saved['last_counter'], 0)
        self.assertNotIn('suspended', saved)

    def test_disable_rule_removes_kernel_rules_but_keeps_traffic_history(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080,
                           'traffic_bytes': 987654, 'last_counter': 321}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'get_traffic_counter', return_value=500), \
             patch.object(agentapp, 'delete_snat_rule', return_value=(True, [])), \
             patch.object(agentapp, 'save_rules') as save:
            r = agentapp.app.test_client().post('/disable_rule', json={'local_port': 12345})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['success'])
        saved = save.call_args.args[0]['12345']
        self.assertTrue(saved['suspended'])
        self.assertEqual(saved['traffic_bytes'], 987833)
        self.assertEqual(saved['last_counter'], 500)

    def test_delete_rule_removes_traffic_history_permanently(self):
        state = {'12345': {'target_ip': '1.2.3.4', 'target_port': 8080,
                           'traffic_bytes': 987654, 'last_counter': 321}}
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, 'delete_snat_rule', return_value=(True, [])), \
             patch.object(agentapp, 'save_rules') as save:
            r = agentapp.app.test_client().post('/delete_rule', json={'local_port': 12345})
        self.assertEqual(r.status_code, 200)
        self.assertNotIn('12345', save.call_args.args[0])

    def test_list_rules_hides_phantom_active_rule_missing_kernel_state(self):
        state = {
            '12345': {'target_ip': '1.2.3.4', 'target_port': 8080},
            '23456': {'target_ip': '2.2.2.2', 'target_port': 9090, 'suspended': True},
        }
        with patch.object(agentapp, 'check_auth', return_value=True), \
             patch.object(agentapp, 'load_rules', return_value=state), \
             patch.object(agentapp, '_check_rule', side_effect=[('absent', ''), ('present', '')]):
            r = agentapp.app.test_client().get('/list_rules')
        self.assertEqual(r.status_code, 200)
        payload = r.get_json()
        self.assertNotIn('12345', payload)
        self.assertIn('23456', payload)


class Round7WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.client = webapp.app.test_client()
        sid = 'round7-test-session'
        conn = sqlite3.connect(webapp.DB_FILE)
        version = conn.execute("SELECT session_version FROM users WHERE username='admin'").fetchone()[0]
        conn.execute(
            'INSERT INTO web_sessions (id,username,session_version,expires_at) VALUES (?,?,?,?)',
            (sid, 'admin', version, time.time() + 3600),
        )
        conn.commit(); conn.close()
        with self.client.session_transaction() as sess:
            sess.update(logged_in=True, username='admin', must_change_password=False,
                        csrf_token='csrf', last_reauth=time.time(), session_id=sid,
                        session_version=version)

    def tearDown(self):
        self.tmp.cleanup()

    def _server(self):
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO servers(name,host,port,token,status) VALUES('s','127.0.0.1',8888,?,'online')",
                  (webapp.encrypt_token('strong-token-0123456789abcdef'),))
        sid = c.lastrowid
        conn.commit(); conn.close()
        return sid

    def test_server_list_does_not_return_encrypted_token(self):
        self._server()
        r = self.client.get('/api/servers')
        self.assertEqual(r.status_code, 200)
        row = r.get_json()[0]
        self.assertNotIn('token', row)
        self.assertTrue(row['token_set'])

    def test_server_update_blank_token_keeps_existing(self):
        sid = self._server()
        r = self.client.put(f'/api/servers/{sid}', json={'name':'s','host':'127.0.0.1','port':8888,'token':''},
                            headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code, 200)
        conn = sqlite3.connect(webapp.DB_FILE)
        token = conn.execute('SELECT token FROM servers WHERE id=?', (sid,)).fetchone()[0]
        conn.close()
        self.assertEqual(webapp.decrypt_token(token), 'strong-token-0123456789abcdef')

    def test_bulk_disable_does_not_change_db_without_agent_confirmation(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO rules(server_id,local_port,target_ip,target_port,enabled) VALUES(?,12345,'1.2.3.4',80,1)", (sid,))
        rid = c.lastrowid; conn.commit(); conn.close()
        class Resp:
            status_code = 500
            def json(self): return {'success': False}
        with patch.object(webapp, 'agent_post', return_value=Resp()):
            r = self.client.post('/api/rules/bulk', json={'action':'disable','rule_ids':[rid]},
                                 headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(len(r.get_json()['failed']), 1)
        conn = sqlite3.connect(webapp.DB_FILE)
        enabled, status = conn.execute('SELECT enabled,status FROM rules WHERE id=?', (rid,)).fetchone()
        conn.close()
        self.assertEqual(enabled, 1)
        self.assertEqual(status, 'desynced')

    def test_single_disable_uses_non_destructive_agent_endpoint(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO rules(server_id,local_port,target_ip,target_port,enabled) VALUES(?,12345,'1.2.3.4',80,1)", (sid,))
        rid = c.lastrowid; conn.commit(); conn.close()

        class Resp:
            status_code = 200
            def json(self): return {'success': True, 'verified': True}

        calls = []
        def fake_post(url, *args, **kwargs):
            calls.append(url)
            return Resp()

        with patch.object(webapp, 'agent_post', side_effect=fake_post), \
             patch.object(webapp, 'sync_server_rules', return_value=[]):
            r = self.client.post(f'/api/rules/{rid}/toggle', json={},
                                 headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['enabled'], 0)
        self.assertTrue(any(url.endswith('/disable_rule') for url in calls))
        self.assertFalse(any(url.endswith('/delete_rule') for url in calls))

    def test_bulk_disable_uses_non_destructive_agent_endpoint(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO rules(server_id,local_port,target_ip,target_port,enabled) VALUES(?,12345,'1.2.3.4',80,1)", (sid,))
        rid = c.lastrowid; conn.commit(); conn.close()

        class Resp:
            status_code = 200
            def json(self): return {'success': True, 'verified': True}

        calls = []
        def fake_post(url, *args, **kwargs):
            calls.append(url)
            return Resp()

        with patch.object(webapp, 'agent_post', side_effect=fake_post):
            r = self.client.post('/api/rules/bulk', json={'action':'disable','rule_ids':[rid]},
                                 headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['failed'], [])
        self.assertTrue(any(url.endswith('/disable_rule') for url in calls))
        self.assertFalse(any(url.endswith('/delete_rule') for url in calls))

    def test_sync_preserves_disabled_remote_suspended_history(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO rules(server_id,local_port,target_ip,target_port,enabled) VALUES(?,12345,'1.2.3.4',80,0)", (sid,))
        conn.commit(); conn.close()

        class GetResp:
            status_code = 200
            def json(self):
                return {'12345': {'target_ip':'1.2.3.4','target_port':80,
                                  'traffic_bytes':987654,'last_counter':500,
                                  'suspended':True,'suspended_reason':'manual'}}

        with patch.object(webapp, 'agent_get', return_value=GetResp()), \
             patch.object(webapp, 'agent_post') as post:
            result = webapp.sync_server_rules(sid)
        self.assertEqual(result, [])
        post.assert_not_called()

    def test_sync_invalid_remote_payload_fails_closed(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("INSERT INTO rules(server_id,local_port,target_ip,target_port,enabled) VALUES(?,12345,'1.2.3.4',80,1)", (sid,))
        rid = c.lastrowid; conn.commit(); conn.close()

        class GetResp:
            status_code = 200
            def json(self): return {'success': True}

        with patch.object(webapp, 'agent_get', return_value=GetResp()), \
             patch.object(webapp, 'agent_post') as post:
            result = webapp.sync_server_rules(sid)
        self.assertEqual(result[0]['status'], 'list_invalid_payload')
        post.assert_not_called()
        conn = sqlite3.connect(webapp.DB_FILE)
        enabled, status = conn.execute('SELECT enabled,status FROM rules WHERE id=?', (rid,)).fetchone()
        conn.close()
        self.assertEqual(enabled, 1)
        self.assertEqual(status, 'desynced')

    def test_sync_over_limit_delete_failure_does_not_fake_disable(self):
        sid = self._server()
        conn = sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute("""INSERT INTO rules
                     (server_id,local_port,target_ip,target_port,enabled,status,
                      traffic_limit_gb,traffic_used_bytes)
                     VALUES(?,12345,'1.2.3.4',80,1,'active',1,?)""",
                  (sid, 2 * 1024 ** 3))
        rid = c.lastrowid
        conn.commit(); conn.close()
        class GetResp:
            status_code = 200
            def json(self):
                return {'12345': {'target_ip':'1.2.3.4','target_port':80}}
        class DeleteResp:
            status_code = 500
            def json(self):
                return {'success': False, 'verified': False}
        with patch.object(webapp, 'agent_get', return_value=GetResp()), \
             patch.object(webapp, 'agent_post', return_value=DeleteResp()):
            result = webapp.sync_server_rules(sid)
        self.assertTrue(any(item['status'] == 'delete_failed' for item in result))
        conn = sqlite3.connect(webapp.DB_FILE)
        enabled, status = conn.execute(
            'SELECT enabled,status FROM rules WHERE id=?', (rid,)).fetchone()
        conn.close()
        self.assertEqual(enabled, 1)
        self.assertEqual(status, 'desynced')

    def test_telegram_commands_default_to_disabled(self):
        source = (ROOT / 'web/app.py').read_text()
        settings = (ROOT / 'web/blueprints/settings.py').read_text()
        self.assertIn("tg_command_enabled', '0'", source)
        self.assertIn("tg_command_enabled', '0'", settings)

    def test_telegram_commands_can_be_explicitly_enabled(self):
        r = self.client.post('/api/settings/alerts', json={
            'command_enabled': True, 'tg_chat_id': '123', 'offline_seconds': 300
        }, headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(self.client.get('/api/settings/alerts').get_json()['command_enabled'])


class Round7DeploymentTests(unittest.TestCase):
    def test_web_container_does_not_mount_over_code(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertNotIn('snat-web-data:/app/web', compose)
        self.assertIn('./data:/data', compose)
        self.assertIn('read_only: true', compose)

    def test_agent_container_drops_net_raw(self):
        compose = (ROOT / 'docker-compose.yml').read_text()
        self.assertNotIn('- NET_RAW', compose)


if __name__ == '__main__':
    unittest.main(verbosity=2)
