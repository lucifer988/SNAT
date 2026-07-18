import importlib.util
import json
import os
import sqlite3
import tempfile
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


class Round7WebTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.client = webapp.app.test_client()
        with self.client.session_transaction() as sess:
            sess.update(logged_in=True, username='admin', must_change_password=False,
                        csrf_token='csrf', last_reauth=10**20)

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
