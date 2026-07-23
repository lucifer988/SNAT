import os, tempfile, unittest, time, json, hashlib, hmac
from unittest.mock import patch

_TEST_TMP = tempfile.mkdtemp(prefix='snat-test-')
os.environ.setdefault('AGENT_LOG_FILE', os.path.join(_TEST_TMP, 'agent.log'))
os.environ.setdefault('AGENT_RULES_FILE', os.path.join(_TEST_TMP, 'agent-rules.json'))
os.environ.setdefault('SNAT_ALLOW_DEFAULT_TOKEN', '1')

from web import app as webapp
from agent import agent as agentapp


def build_sig(token, method, path, body='', nonce=None):
    import secrets as _secrets
    ts = str(int(time.time()))
    if nonce is None:
        nonce = _secrets.token_urlsafe(12)
    msg = f"{method}\n{path}\n{ts}\n{nonce}\n{body}".encode()
    sig = hmac.new(token.encode(), msg, hashlib.sha256).hexdigest()
    return ts, sig, nonce


class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.BACKUP_DIR = os.path.join(self.tmp.name, 'backups')
        webapp.FORCE_HTTPS = False
        webapp.app.config['TESTING'] = True
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.web_client = webapp.app.test_client()

        agentapp.TOKEN='abc123'
        agentapp.app.config['TESTING'] = True
        self.agent_client = agentapp.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def login_web(self):
        with self.web_client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'
            sess['must_change_password'] = False
            sess['csrf_token'] = 'test-csrf-token'
            sess['last_reauth'] = time.time()

    def insert_server(self, name='s1', host='127.0.0.1', port=8888, token='plain-token'):
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO servers (name, host, port, token, status) VALUES (?, ?, ?, ?, ?)', (name, host, port, token, 'online'))
        conn.commit()
        server_id = c.lastrowid
        conn.close()
        return server_id

    def test_healthz(self):
        r = self.web_client.get('/healthz')
        self.assertEqual(r.status_code, 200)

    def test_server_reorder_persists_without_changing_ids(self):
        self.login_web()
        first = self.insert_server(name='first', host='10.0.0.1')
        second = self.insert_server(name='second', host='10.0.0.2')
        third = self.insert_server(name='third', host='10.0.0.3')
        response = self.web_client.post('/api/servers/reorder', json={'server_ids': [second, third, first]}, headers={'X-CSRF-Token': 'test-csrf-token'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['success'])
        listed = self.web_client.get('/api/servers').get_json()
        self.assertEqual([item['id'] for item in listed], [second, third, first])
        self.assertEqual({item['id'] for item in listed}, {first, second, third})
        webapp.init_db()
        listed_after_restart = self.web_client.get('/api/servers').get_json()
        self.assertEqual([item['id'] for item in listed_after_restart], [second, third, first])

    def test_rule_reorder_is_scoped_to_one_server_and_preserves_rule_ids(self):
        self.login_web()
        server_id = self.insert_server(name='rules-a', host='10.0.1.1')
        other_server_id = self.insert_server(name='rules-b', host='10.0.1.2')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        cursor = conn.cursor()
        rule_ids = []
        for port in (10001, 10002, 10003):
            cursor.execute('INSERT INTO rules (server_id, local_port, target_ip, target_port) VALUES (?, ?, ?, ?)', (server_id, port, '1.1.1.1', 80))
            rule_ids.append(cursor.lastrowid)
        cursor.execute('INSERT INTO rules (server_id, local_port, target_ip, target_port) VALUES (?, ?, ?, ?)', (other_server_id, 20001, '2.2.2.2', 443))
        other_rule_id = cursor.lastrowid
        conn.commit()
        conn.close()
        response = self.web_client.post('/api/rules/reorder', json={'server_id': server_id, 'rule_ids': [rule_ids[2], rule_ids[0], rule_ids[1]]}, headers={'X-CSRF-Token': 'test-csrf-token'})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()['success'])
        listed = self.web_client.get('/api/rules').get_json()
        scoped = [item['id'] for item in listed if item['server_id'] == server_id]
        self.assertEqual(scoped, [rule_ids[2], rule_ids[0], rule_ids[1]])
        self.assertIn(other_rule_id, [item['id'] for item in listed])
        webapp.init_db()
        listed_after_restart = self.web_client.get('/api/rules').get_json()
        scoped_after_restart = [item['id'] for item in listed_after_restart if item['server_id'] == server_id]
        self.assertEqual(scoped_after_restart, [rule_ids[2], rule_ids[0], rule_ids[1]])

    def test_rule_reorder_rejects_cross_server_ids(self):
        self.login_web()
        server_id = self.insert_server(name='scope-a', host='10.0.2.1')
        other_server_id = self.insert_server(name='scope-b', host='10.0.2.2')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        cursor = conn.cursor()
        cursor.execute('INSERT INTO rules (server_id, local_port, target_ip, target_port) VALUES (?, ?, ?, ?)', (server_id, 30001, '3.3.3.3', 80))
        own_rule = cursor.lastrowid
        cursor.execute('INSERT INTO rules (server_id, local_port, target_ip, target_port) VALUES (?, ?, ?, ?)', (other_server_id, 30002, '4.4.4.4', 80))
        foreign_rule = cursor.lastrowid
        conn.commit()
        conn.close()
        response = self.web_client.post('/api/rules/reorder', json={'server_id': server_id, 'rule_ids': [foreign_rule, own_rule]}, headers={'X-CSRF-Token': 'test-csrf-token'})
        self.assertEqual(response.status_code, 400)

    def test_login_and_change_password(self):
        r = self.web_client.post('/login', json={'username':'admin','password':'Admin12345'})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertTrue(data['must_change_password'])

        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('SELECT password FROM users WHERE username = ?', ('admin',))
        upgraded_hash = c.fetchone()[0]
        conn.close()
        self.assertNotEqual(upgraded_hash, webapp.hashlib.sha256('Admin12345'.encode()).hexdigest())

        with self.web_client.session_transaction() as sess:
            sess['csrf_token'] = 'test-csrf-token'

        r2 = self.web_client.post('/api/change_password', json={'old_password':'Admin12345','new_password':'Better12345A'}, headers={'X-CSRF-Token': 'test-csrf-token'})
        self.assertEqual(r2.status_code, 200)
        self.assertTrue(r2.get_json()['success'])


    @patch('agent.agent.add_snat_rule', return_value=True)
    @patch('agent.agent.save_rules', return_value=None)
    @patch('agent.agent.load_rules', return_value={})
    def test_agent_accepts_signed_request_before_command_execution(self, *_):
        body = json.dumps({'local_port': 1234, 'target_ip': '1.1.1.1', 'target_port': 80}, separators=(',', ':'))
        ts, sig, nonce = build_sig(agentapp.TOKEN, 'POST', '/add_rule', body)
        r = self.agent_client.post('/add_rule', data=body, headers={'Authorization': f'Bearer {agentapp.TOKEN}', 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig, 'Content-Type': 'application/json'})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['success'])


    def test_create_rule_rolls_back_when_agent_add_fails(self):
        self.login_web()
        server_id = self.insert_server(host='10.0.0.8', token='panel-token')

        class Resp:
            status_code = 500
            text = 'boom'
            def json(self):
                return {'success': False, 'error': 'boom'}

        with patch('web.app.requests.post', return_value=Resp()):
            r = self.web_client.post(
                '/api/rules',
                json={
                    'csrf_token': 'test-csrf-token',
                    'server_id': server_id,
                    'local_port': 12345,
                    'target_ip': '1.2.3.4',
                    'target_port': 8080,
                    'note': 'case'
                },
                headers={'X-CSRF-Token': 'test-csrf-token'}
            )

        self.assertGreaterEqual(r.status_code, 400)
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('SELECT COUNT(*) FROM rules WHERE local_port = 12345')
        count = c.fetchone()[0]
        conn.close()
        self.assertEqual(count, 0)

    def test_sync_server_rules_reconciles_remote_state(self):
        server_id = self.insert_server(host='10.0.0.9', token='panel-token')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute(
            'INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)',
            (server_id, 12345, '', '1.2.3.4', 8080, 'rule')
        )
        conn.commit()
        conn.close()

        class GetResp:
            status_code = 200
            def json(self):
                return {
                    'success': True,
                    'rules': {
                        '12345': {'target_ip': '9.9.9.9', 'target_port': 9000},
                        '55555': {'target_ip': '5.5.5.5', 'target_port': 5555}
                    }
                }

        post_calls = []

        class PostResp:
            status_code = 200
            text = 'ok'
            def json(self):
                return {'success': True}

        def fake_post(url, data=None, json=None, headers=None, timeout=None, **_kw):
            payload = json if json is not None else __import__('json').loads(data.decode() if isinstance(data, (bytes, bytearray)) else data)
            post_calls.append((url, payload, headers))
            return PostResp()

        with patch('web.app.requests.get', return_value=GetResp()), patch('web.app.requests.post', side_effect=fake_post):
            results = webapp.sync_server_rules(server_id)

        self.assertTrue(results)
        delete_ports = [call[1]['local_port'] for call in post_calls if call[0].endswith('/delete_rule')]
        add_ports = [call[1]['local_port'] for call in post_calls if call[0].endswith('/add_rule')]
        self.assertIn(55555, delete_ports)
        self.assertIn(12345, delete_ports)
        self.assertIn(12345, add_ports)

    def test_agent_get_traffic_uses_forward_counters_for_managed_rules(self):
        rules_state = {
            '12345': {
                'target_ip': '1.2.3.4',
                'target_port': 8080,
                'traffic_bytes': 0,
                'last_counter': 0
            }
        }

        def fake_run(cmd):
            if cmd == ['iptables', '-L', 'FORWARD', '-n', '-v', '-x']:
                return True, '\n'.join([
                    '1 100 ACCEPT tcp -- * * 0.0.0.0/0 1.2.3.4 tcp dpt:8080 /* SNAT_12345_FWD_IN */',
                    '2 200 ACCEPT tcp -- * * 1.2.3.4 0.0.0.0/0 tcp spt:8080 /* SNAT_12345_FWD_OUT */'
                ]), ''
            if cmd == ['iptables', '-t', 'mangle', '-L', 'PREROUTING', '-n', '-v', '-x']:
                return True, '', ''
            return True, '', ''

        with patch('agent.agent.load_rules', return_value=rules_state), patch('agent.agent.save_rules') as mock_save, patch('agent.agent.run_cmd', side_effect=fake_run):
            ts, sig, nonce = build_sig(agentapp.TOKEN, 'GET', '/get_traffic/12345', '')
            r = self.agent_client.get('/get_traffic/12345', headers={'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig})

        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertTrue(data['success'])
        self.assertEqual(data['current_counter'], 300)
        self.assertEqual(data['bytes'], 300)
        mock_save.assert_called()

    def test_ip_whitelist_setting_persists_to_db(self):
        self.login_web()
        r = self.web_client.post(
            '/api/settings/ip_whitelist',
            json={'whitelist': ['127.0.0.1', '192.168.50.0/24', '10.0.0.8']},
            headers={'X-CSRF-Token': 'test-csrf-token'}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['whitelist'], ['127.0.0.1', '192.168.50.0/24', '10.0.0.8'])

        r2 = self.web_client.get('/api/settings')
        self.assertEqual(r2.status_code, 200)
        self.assertEqual(r2.get_json()['ip_whitelist'], ['127.0.0.1', '192.168.50.0/24', '10.0.0.8'])

    def test_report_connections_requires_signed_agent_request(self):
        self.insert_server(host='87.83.105.37', token='panel-token')
        body = json.dumps({'server_host': '87.83.105.37', 'samples': [{'local_port': 11111, 'active_connections': 9}]}, separators=(',', ':'))
        r = self.web_client.post('/api/agents/report_connections', data=body, content_type='application/json')
        self.assertEqual(r.status_code, 401)

    def test_report_connections_accepts_signed_agent_request(self):
        server_id = self.insert_server(host='87.83.105.37', token='panel-token')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute(
            'INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)',
            (server_id, 11111, '', '1.2.3.4', 8080, 'rule')
        )
        conn.commit()
        conn.close()

        body = json.dumps({'server_host': '87.83.105.37', 'samples': [{'local_port': 11111, 'active_connections': 9}]}, separators=(',', ':'))
        ts, sig, nonce = build_sig('panel-token', 'POST', '/api/agents/report_connections', body)
        r = self.web_client.post(
            '/api/agents/report_connections',
            data=body,
            headers={'Authorization': 'Bearer panel-token', 'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig, 'Content-Type': 'application/json'}
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()['updated'], 1)

        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('SELECT active_connections FROM rules WHERE server_id = ? AND local_port = 11111', (server_id,))
        self.assertEqual(c.fetchone()[0], 9)
        conn.close()


    def test_healthz_does_not_leak_env_or_config(self):
        r = self.web_client.get('/healthz')
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(body, {'status': 'ok'})
        for forbidden in ('env', 'force_https', 'db'):
            self.assertNotIn(forbidden, body)

    def test_agent_health_no_auth_returns_only_status(self):
        r = self.agent_client.get('/health')
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertEqual(set(body.keys()), {'status'})

    def test_agent_health_with_bad_token_returns_401(self):
        r = self.agent_client.get('/health', headers={'Authorization': 'Bearer wrong-token'})
        self.assertEqual(r.status_code, 401)

    def test_agent_healthz_is_always_minimal(self):
        r = self.agent_client.get('/healthz')
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {'status': 'ok'})

    def test_backup_restore_rejects_path_outside_backup_dir(self):
        self.login_web()
        r = self.web_client.post(
            '/api/backup/restore',
            json={'confirm': 'RESTORE', 'path': '/etc'},
            headers={'X-CSRF-Token': 'test-csrf-token'}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('不合法', r.get_json()['error'])

    def test_backup_restore_rejects_traversal(self):
        self.login_web()
        evil = os.path.join(webapp.BACKUP_DIR, '..', '..')
        r = self.web_client.post(
            '/api/backup/restore',
            json={'confirm': 'RESTORE', 'path': evil},
            headers={'X-CSRF-Token': 'test-csrf-token'}
        )
        self.assertEqual(r.status_code, 400)

    def test_backup_restore_rejects_tampered_manifest(self):
        self.login_web()
        backup_dir = webapp.create_backup('test')
        # 篡改 db 文件，让 manifest 校验失败
        with open(os.path.join(backup_dir, 'snat_manager.db'), 'ab') as f:
            f.write(b'CORRUPTION')
        r = self.web_client.post(
            '/api/backup/restore',
            json={'confirm': 'RESTORE', 'path': backup_dir},
            headers={'X-CSRF-Token': 'test-csrf-token'}
        )
        self.assertEqual(r.status_code, 400)
        self.assertIn('校验失败', r.get_json()['error'])

    def test_backup_round_trip_succeeds(self):
        self.login_web()
        backup_dir = webapp.create_backup('test')
        r = self.web_client.post(
            '/api/backup/restore',
            json={'confirm': 'RESTORE', 'path': backup_dir},
            headers={'X-CSRF-Token': 'test-csrf-token'}
        )
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()['success'])

    def test_token_encryption_uses_v2_prefix(self):
        webapp.TOKEN_SECRET = 'test-secret-please-ignore'
        webapp._TOKEN_CIPHER_CACHE['v1'] = None
        webapp._TOKEN_CIPHER_CACHE['v2'] = None
        try:
            enc = webapp.encrypt_token('plaintext-token-123')
            self.assertTrue(enc.startswith('enc2:'))
            self.assertEqual(webapp.decrypt_token(enc), 'plaintext-token-123')
        finally:
            webapp.TOKEN_SECRET = ''
            webapp._TOKEN_CIPHER_CACHE['v1'] = None
            webapp._TOKEN_CIPHER_CACHE['v2'] = None

    def test_sync_marks_rule_desynced_on_agent_add_failure(self):
        server_id = self.insert_server(host='10.0.0.10', token='panel-token')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute(
            'INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, enabled) VALUES (?, ?, ?, ?, ?, ?, 1)',
            (server_id, 23456, '', '1.2.3.4', 8080, 'rule')
        )
        conn.commit()
        rule_id = c.lastrowid
        conn.close()

        class GetResp:
            status_code = 200
            def json(self):
                return {'success': True, 'rules': {}}  # 远端没有任何规则

        class PostResp:
            status_code = 500
            text = 'agent broken'
            def json(self):
                return {'success': False}

        with patch('web.app.requests.get', return_value=GetResp()), patch('web.app.requests.post', return_value=PostResp()):
            results = webapp.sync_server_rules(server_id)

        # 该规则应被标记为 desynced
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('SELECT status FROM rules WHERE id = ?', (rule_id,))
        status = c.fetchone()[0]
        conn.close()
        self.assertEqual(status, 'desynced')
        # 结果应包含 add_failed
        statuses = {r.get('status') for r in results}
        self.assertIn('add_failed', statuses)

    def test_sync_clears_desynced_when_recovers(self):
        server_id = self.insert_server(host='10.0.0.11', token='panel-token')
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute(
            "INSERT INTO rules (server_id, local_port, target_host, target_ip, target_port, remark, enabled, status) VALUES (?, ?, ?, ?, ?, ?, 1, 'desynced')",
            (server_id, 34567, '', '1.2.3.4', 8080, 'rule')
        )
        conn.commit()
        rule_id = c.lastrowid
        conn.close()

        class GetResp:
            status_code = 200
            def json(self):
                return {'success': True, 'rules': {}}

        class PostResp:
            status_code = 200
            text = 'ok'
            def json(self):
                return {'success': True}

        with patch('web.app.requests.get', return_value=GetResp()), patch('web.app.requests.post', return_value=PostResp()):
            webapp.sync_server_rules(server_id)

        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        c = conn.cursor()
        c.execute('SELECT status FROM rules WHERE id = ?', (rule_id,))
        status = c.fetchone()[0]
        conn.close()
        self.assertEqual(status, 'active')

    def test_token_decryption_v1_backward_compatible(self):
        webapp.TOKEN_SECRET = 'legacy-secret'
        webapp._TOKEN_CIPHER_CACHE['v1'] = None
        webapp._TOKEN_CIPHER_CACHE['v2'] = None
        try:
            # 用 v1 的方式构造旧密文：sha256(secret) → Fernet → 'enc:' 前缀
            import base64 as _b64
            from cryptography.fernet import Fernet as _Fernet
            key = webapp.hashlib.sha256(webapp.TOKEN_SECRET.encode()).digest()
            v1_cipher = _Fernet(_b64.urlsafe_b64encode(key))
            old = 'enc:' + v1_cipher.encrypt(b'legacy-token-abc').decode()
            self.assertEqual(webapp.decrypt_token(old), 'legacy-token-abc')
        finally:
            webapp.TOKEN_SECRET = ''
            webapp._TOKEN_CIPHER_CACHE['v1'] = None
            webapp._TOKEN_CIPHER_CACHE['v2'] = None

    @patch('agent.agent.load_rules', return_value={})
    def test_agent_accepts_signed_get_without_bearer(self, *_):
        """仅签名（无 Bearer token）的 GET 也应被接受 —— 这是外网安全的关键。"""
        ts, sig, nonce = build_sig(agentapp.TOKEN, 'GET', '/list_rules')
        r = self.agent_client.get('/list_rules', headers={'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig})
        self.assertEqual(r.status_code, 200)

    def test_agent_strict_mode_rejects_bearer_only(self):
        """ALLOW_BEARER=0（严格模式）下，无签名的 Bearer-only 请求必须被拒。"""
        old = agentapp.ALLOW_BEARER
        agentapp.ALLOW_BEARER = False
        try:
            r = self.agent_client.get('/list_rules', headers={'Authorization': f'Bearer {agentapp.TOKEN}'})
            self.assertEqual(r.status_code, 401)
        finally:
            agentapp.ALLOW_BEARER = old

    def test_agent_rejects_expired_signature(self):
        """超出 TTL 的签名视为重放/过期，必须被拒。"""
        stale_ts = str(int(time.time()) - agentapp.SIGNED_REQUEST_TTL - 60)
        nonce = 'test-nonce-stale'
        msg = f"GET\n/list_rules\n{stale_ts}\n{nonce}\n".encode()
        sig = hmac.new(agentapp.TOKEN.encode(), msg, hashlib.sha256).hexdigest()
        r = self.agent_client.get('/list_rules', headers={'X-Timestamp': stale_ts, 'X-Nonce': nonce, 'X-Signature': sig})
        self.assertEqual(r.status_code, 401)

    @patch('agent.agent.add_snat_rule', return_value=True)
    @patch('agent.agent.save_rules', return_value=None)
    @patch('agent.agent.load_rules', return_value={})
    def test_agent_rejects_tampered_signed_body(self, *_):
        """签名覆盖 body：篡改 body 后签名失效，命令不应执行。"""
        signed_body = json.dumps({'local_port': 2222, 'target_ip': '1.1.1.1', 'target_port': 80}, separators=(',', ':'))
        ts, sig, nonce = build_sig(agentapp.TOKEN, 'POST', '/add_rule', signed_body)
        tampered = json.dumps({'local_port': 3333, 'target_ip': '9.9.9.9', 'target_port': 80}, separators=(',', ':'))
        r = self.agent_client.post('/add_rule', data=tampered,
                                   headers={'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig, 'Content-Type': 'application/json'})
        self.assertEqual(r.status_code, 401)

    @patch('agent.agent.add_snat_rule', return_value=True)
    @patch('agent.agent.save_rules', return_value=None)
    @patch('agent.agent.load_rules', return_value={})
    def test_agent_rejects_replayed_nonce(self, *_):
        """时间窗内重放：同一 (ts, nonce, sig) 第二次到达必须被拒。"""
        body = json.dumps({'local_port': 4455, 'target_ip': '1.1.1.1', 'target_port': 80}, separators=(',', ':'))
        ts, sig, nonce = build_sig(agentapp.TOKEN, 'POST', '/add_rule', body)
        headers = {'X-Timestamp': ts, 'X-Nonce': nonce, 'X-Signature': sig, 'Content-Type': 'application/json'}
        r1 = self.agent_client.post('/add_rule', data=body, headers=headers)
        self.assertEqual(r1.status_code, 200)
        r2 = self.agent_client.post('/add_rule', data=body, headers=headers)
        self.assertEqual(r2.status_code, 401)

    @patch('agent.agent.load_rules', return_value={})
    def test_agent_rejects_missing_nonce_when_required(self, *_):
        """默认要求 nonce：只带 ts+sig（无 X-Nonce）应被拒。"""
        old = agentapp.REQUIRE_NONCE
        agentapp.REQUIRE_NONCE = True
        try:
            tsv = str(int(time.time()))
            msg = f"GET\n/list_rules\n{tsv}\n\n".encode()
            sig = hmac.new(agentapp.TOKEN.encode(), msg, hashlib.sha256).hexdigest()
            r = self.agent_client.get('/list_rules', headers={'X-Timestamp': tsv, 'X-Signature': sig})
            self.assertEqual(r.status_code, 401)
        finally:
            agentapp.REQUIRE_NONCE = old


if __name__ == '__main__':
    unittest.main()


class HardeningTest(unittest.TestCase):
    """v2 加固版新增回归测试：XSS 转义依赖前端，这里覆盖后端可测路径。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.BACKUP_DIR = os.path.join(self.tmp.name, 'backups')
        webapp.app.config['TESTING'] = True
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        webapp.login_attempts.clear()
        webapp.login_attempts_by_ip.clear()
        self.client = webapp.app.test_client()

    def tearDown(self):
        webapp.login_attempts.clear()
        webapp.login_attempts_by_ip.clear()
        self.tmp.cleanup()

    def _login_session(self):
        with self.client.session_transaction() as s:
            s['logged_in'] = True
            s['username'] = 'admin'
            s['must_change_password'] = False
            s['csrf_token'] = 't'
            s['last_reauth'] = time.time()

    def test_per_ip_username_spray_is_locked_out(self):
        """同一 IP 换用户名喷洒，达到 MAX_IP_ATTEMPTS 后应整体锁定。"""
        with webapp.app.test_request_context('/login', environ_base={'REMOTE_ADDR': '9.9.9.9'}):
            for i in range(webapp.MAX_IP_ATTEMPTS):
                webapp.record_login_attempt(f'user{i}', False)
            self.assertFalse(webapp.check_login_attempts('brand-new-user'))

    def test_backup_uses_consistent_sqlite_snapshot(self):
        path = webapp.create_backup('test')
        ok, reason = webapp._verify_backup_manifest(path)
        self.assertTrue(ok, reason)
        # 备份出的 DB 必须可独立打开且包含用户表数据
        conn = webapp.sqlite3.connect(os.path.join(path, 'snat_manager.db'))
        self.assertEqual(conn.execute('SELECT COUNT(*) FROM users').fetchone()[0], 1)
        conn.close()

    def test_import_rules_rejects_invalid_rows(self):
        self._login_session()
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        conn.execute("INSERT INTO servers (name, host, port, token) VALUES ('s1','127.0.0.1',8888,'tok')")
        conn.commit()
        sid = conn.execute('SELECT id FROM servers').fetchone()[0]
        conn.close()
        r = self.client.post('/api/import/rules', headers={'X-CSRF-Token': 't'}, json={'rows': [
            {'server_id': sid, 'local_port': 8080, 'target_ip': '1.2.3.4', 'target_port': 80},
            {'server_id': 424242, 'local_port': 8081, 'target_ip': '1.2.3.4', 'target_port': 80},
            {'server_id': sid, 'local_port': 99999, 'target_ip': '1.2.3.4', 'target_port': 80},
            {'server_id': sid, 'local_port': 8082, 'target_ip': '', 'target_port': 80},
        ]})
        data = r.get_json()
        self.assertEqual(data['inserted'], 1)
        self.assertEqual(data['skipped'], 3)

    def test_api_responses_are_no_store(self):
        self._login_session()
        r = self.client.get('/api/rules')
        self.assertEqual(r.headers.get('Cache-Control'), 'no-store')

    def test_login_success_resets_session(self):
        """会话固定防护：登录前塞入的 session 键在登录成功后不得存活。"""
        with self.client.session_transaction() as s:
            s['attacker_planted'] = 'fixation'
        r = self.client.post('/login', json={'username': 'admin', 'password': 'Admin12345'})
        self.assertEqual(r.status_code, 200)
        with self.client.session_transaction() as s:
            self.assertNotIn('attacker_planted', s)
            self.assertTrue(s.get('logged_in'))


class AgentHardeningTest(unittest.TestCase):
    def test_corrupt_rules_file_is_quarantined(self):
        rules_file = agentapp.RULES_FILE
        os.makedirs(os.path.dirname(rules_file), exist_ok=True)
        with open(rules_file, 'w') as f:
            f.write('{not valid json')
        try:
            self.assertEqual(agentapp.load_rules(), {})
            self.assertTrue(os.path.exists(rules_file + '.corrupt'))
        finally:
            for p in (rules_file, rules_file + '.corrupt'):
                if os.path.exists(p):
                    os.remove(p)


class PublicExposureHardeningTest(unittest.TestCase):
    """针对"公网直连 Agent + 面板加固"新增的安全回归。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.BACKUP_DIR = os.path.join(self.tmp.name, 'backups')
        webapp.app.config['TESTING'] = True
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        webapp.login_attempts.clear()
        webapp.login_attempts_by_ip.clear()
        webapp.rate_limit_store.clear()
        self.client = webapp.app.test_client()

    def tearDown(self):
        webapp.login_attempts.clear()
        webapp.login_attempts_by_ip.clear()
        webapp.rate_limit_store.clear()
        self.tmp.cleanup()

    # --- Agent 来源 IP 白名单 ---
    def test_agent_source_ip_allowlist_blocks_and_allows(self):
        old = agentapp._AGENT_ALLOWED_NETWORKS
        agentapp._AGENT_ALLOWED_NETWORKS = agentapp._parse_allowed_networks('203.0.113.5,10.8.0.0/24')
        try:
            self.assertTrue(agentapp.is_source_ip_allowed('203.0.113.5'))
            self.assertTrue(agentapp.is_source_ip_allowed('10.8.0.9'))
            self.assertTrue(agentapp.is_source_ip_allowed('127.0.0.1'))   # 环回始终放行
            self.assertFalse(agentapp.is_source_ip_allowed('8.8.8.8'))
            self.assertFalse(agentapp.is_source_ip_allowed('10.9.0.1'))
        finally:
            agentapp._AGENT_ALLOWED_NETWORKS = old

    def test_agent_empty_allowlist_allows_all(self):
        old = agentapp._AGENT_ALLOWED_NETWORKS
        agentapp._AGENT_ALLOWED_NETWORKS = []
        try:
            self.assertTrue(agentapp.is_source_ip_allowed('8.8.8.8'))
        finally:
            agentapp._AGENT_ALLOWED_NETWORKS = old

    def test_agent_blocks_non_whitelisted_request_end_to_end(self):
        old = agentapp._AGENT_ALLOWED_NETWORKS
        agentapp._AGENT_ALLOWED_NETWORKS = agentapp._parse_allowed_networks('203.0.113.5')
        try:
            client = agentapp.app.test_client()
            r = client.get('/list_rules', environ_base={'REMOTE_ADDR': '8.8.8.8'})
            self.assertEqual(r.status_code, 403)
            # healthz 例外，始终可达
            r2 = client.get('/healthz', environ_base={'REMOTE_ADDR': '8.8.8.8'})
            self.assertEqual(r2.status_code, 200)
        finally:
            agentapp._AGENT_ALLOWED_NETWORKS = old

    def test_agent_bearer_off_by_default_in_strict_mode(self):
        """新默认 ALLOW_BEARER=0：无签名的 Bearer-only 应被拒。"""
        old = agentapp.ALLOW_BEARER
        agentapp.ALLOW_BEARER = False
        try:
            r = self.client  # noqa
            client = agentapp.app.test_client()
            resp = client.get('/list_rules', headers={'Authorization': f'Bearer {agentapp.TOKEN}'},
                              environ_base={'REMOTE_ADDR': '127.0.0.1'})
            self.assertEqual(resp.status_code, 401)
        finally:
            agentapp.ALLOW_BEARER = old

    # --- 面板登录爆破限流 ---
    def test_login_post_is_rate_limited(self):
        # 连续 POST 登录直到触发全局限流（RATE_LIMIT_REQUESTS 次后 429）
        hit_429 = False
        for _ in range(webapp.RATE_LIMIT_REQUESTS + 5):
            r = self.client.post('/login', json={'username': 'x', 'password': 'y'},
                                 environ_base={'REMOTE_ADDR': '198.51.100.9'})
            if r.status_code == 429:
                hit_429 = True
                break
        self.assertTrue(hit_429, '登录接口应受全局限流保护')

    # --- CSP nonce 且无 unsafe-inline ---
    def test_login_page_csp_has_nonce_without_unsafe_inline_script(self):
        r = self.client.get('/login')
        csp = r.headers.get('Content-Security-Policy', '')
        self.assertIn("script-src 'self' 'nonce-", csp)
        self.assertNotIn("script-src 'self' 'unsafe-inline'", csp)
        # 页面内联 <script> 必须带上与头部一致的 nonce
        self.assertIn('<script nonce="', r.get_data(as_text=True))

    # --- 弱口令字典 ---
    def test_weak_password_dictionary_rejected(self):
        self.assertIsNotNone(webapp.validate_password_strength('Password123'))
        self.assertIsNotNone(webapp.validate_password_strength('aaaaAAAA11'))
        self.assertIsNone(webapp.validate_password_strength('Str0ngPhrase42'))

    # --- 运行时启用 force_https 时 session cookie 补 Secure ---
    def test_session_cookie_gets_secure_when_force_https_runtime(self):
        webapp.set_setting('force_https', '1')
        try:
            with self.client.session_transaction() as s:
                s['logged_in'] = True
                s['username'] = 'admin'
                s['csrf_token'] = 't'
            # 触发一次会写 Set-Cookie 的响应
            r = self.client.get('/api/csrf_token', base_url='https://localhost')
            set_cookie = r.headers.get('Set-Cookie', '')
            if set_cookie:
                self.assertIn('Secure', set_cookie)
        finally:
            webapp.set_setting('force_https', '0')


class SSRFHardeningV3Test(unittest.TestCase):
    """v3 补充：SSRF 重定向绕过 与 主机名解析校验。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.init_db()

    def tearDown(self):
        self.tmp.cleanup()

    def test_agent_calls_disable_redirects(self):
        """agent_get/agent_post 必须禁用重定向（防 302 → 云元数据 SSRF）。"""
        captured = {}

        def fake_get(url, **kw):
            captured.update(kw)
            class R: status_code = 200
            return R()

        with patch('web.app.requests.get', side_effect=fake_get):
            webapp.agent_get('http://1.2.3.4:8888/list_rules', 'tok')
        self.assertFalse(captured.get('allow_redirects', True),
                         'agent_get 必须 allow_redirects=False')

        captured.clear()

        def fake_post(url, **kw):
            captured.update(kw)
            class R: status_code = 200
            return R()

        with patch('web.app.requests.post', side_effect=fake_post):
            webapp.agent_post('http://1.2.3.4:8888/add_rule', 'tok', {'x': 1})
        self.assertFalse(captured.get('allow_redirects', True),
                         'agent_post 必须 allow_redirects=False')

    def test_literal_metadata_ip_rejected(self):
        ok, _ = webapp.validate_agent_host('169.254.169.254')
        self.assertFalse(ok)

    def test_hostname_resolving_to_metadata_rejected(self):
        """主机名解析到链路本地/元数据段应被拒绝。"""
        import socket as _s
        # 伪造 getaddrinfo 让 evil.example 解析到 169.254.169.254
        real = _s.getaddrinfo

        def fake_gai(host, *a, **k):
            if host == 'evil.example':
                return [(2, 1, 6, '', ('169.254.169.254', 0))]
            return real(host, *a, **k)

        with patch('socket.getaddrinfo', side_effect=fake_gai):
            ok, msg = webapp.validate_agent_host('evil.example')
        self.assertFalse(ok, '解析到元数据地址的域名应被拒绝')

    def test_normal_hostname_still_allowed(self):
        import socket as _s
        real = _s.getaddrinfo

        def fake_gai(host, *a, **k):
            if host == 'good.example':
                return [(2, 1, 6, '', ('93.184.216.34', 0))]
            return real(host, *a, **k)

        with patch('socket.getaddrinfo', side_effect=fake_gai):
            ok, _ = webapp.validate_agent_host('good.example')
        self.assertTrue(ok)

    def test_hot_path_indexes_created(self):
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        idx = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
        conn.close()
        for want in ('idx_rules_server_enabled', 'idx_rules_enabled',
                     'idx_audit_created', 'idx_snapshots_created'):
            self.assertIn(want, idx)


class SystematicAuditV5Test(unittest.TestCase):
    """v5 系统化审计：验证核心安全不变量（而非零散漏洞）。"""

    def test_secret_key_file_is_600(self):
        """密钥文件必须以 0600 权限创建（原子，无 world-readable 窗口）。"""
        import stat, importlib, tempfile as _tf
        d = _tf.mkdtemp()
        keyfile = os.path.join(d, '.secret_key')
        # 直接复用生产逻辑：临时指向新路径
        old = webapp._SECRET_KEY_FILE
        webapp._SECRET_KEY_FILE = keyfile
        os.environ.pop('SNAT_SECRET_KEY', None)
        try:
            k = webapp._load_secret_key()
            self.assertTrue(os.path.exists(keyfile))
            mode = stat.S_IMODE(os.stat(keyfile).st_mode)
            self.assertEqual(mode, 0o600, f'密钥文件权限应为 600, 实际 {oct(mode)}')
            # 二次调用应回读同一密钥
            self.assertEqual(webapp._load_secret_key(), k)
        finally:
            webapp._SECRET_KEY_FILE = old

    def test_run_cmd_rejects_string_commands(self):
        """Agent 命令执行必须拒绝字符串命令（强制 list 形式，杜绝 shell 注入）。"""
        with self.assertRaises(ValueError):
            agentapp.run_cmd('iptables -L')

    def test_resolve_target_only_returns_valid_ip(self):
        """resolve_target 对字面 IP 直通，对非法输入返回 None（不会把任意串塞进 iptables）。"""
        host, ip = agentapp.resolve_target('1.2.3.4')
        self.assertEqual(ip, '1.2.3.4')
        host, ip = agentapp.resolve_target('this is not a valid host!!!')
        self.assertIsNone(ip)

    def test_backup_path_traversal_rejected(self):
        """备份恢复路径必须限制在 BACKUP_DIR 内（防 ../ 逃逸）。"""
        self.assertFalse(webapp._backup_path_is_safe('/etc'))
        self.assertFalse(webapp._backup_path_is_safe('/tmp/../etc/passwd'))
        self.assertFalse(webapp._backup_path_is_safe(''))


class FifthRoundHardeningTest(unittest.TestCase):
    """第五轮复审后新增：元数据不可被 allow-cidrs 覆盖 / 白名单变更需二次认证 / 仅IP运行期硬拦。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.app.config['TESTING'] = True
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.client = webapp.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # --- 发现1：AGENT_TARGET_ALLOW_CIDRS 不能放行云元数据/链路本地 ---
    def test_allow_cidrs_cannot_reopen_metadata(self):
        old = os.environ.get('AGENT_TARGET_ALLOW_CIDRS')
        os.environ['AGENT_TARGET_ALLOW_CIDRS'] = '169.254.0.0/16,10.0.0.0/8'
        try:
            self.assertFalse(agentapp.is_target_ip_allowed('169.254.169.254'))  # 元数据仍拒绝
            self.assertFalse(agentapp.is_target_ip_allowed('169.254.1.1'))       # 链路本地仍拒绝
            self.assertTrue(agentapp.is_target_ip_allowed('10.0.0.5'))           # 私网可被精确放行
        finally:
            if old is None:
                os.environ.pop('AGENT_TARGET_ALLOW_CIDRS', None)
            else:
                os.environ['AGENT_TARGET_ALLOW_CIDRS'] = old

    def test_operator_deny_beats_allow(self):
        old_a = os.environ.get('AGENT_TARGET_ALLOW_CIDRS')
        old_d = os.environ.get('AGENT_TARGET_DENY_CIDRS')
        os.environ['AGENT_TARGET_ALLOW_CIDRS'] = '203.0.113.0/24'
        os.environ['AGENT_TARGET_DENY_CIDRS'] = '203.0.113.5/32'
        try:
            self.assertFalse(agentapp.is_target_ip_allowed('203.0.113.5'))  # 显式拒绝优先于放行
            self.assertTrue(agentapp.is_target_ip_allowed('203.0.113.6'))
        finally:
            for k, v in (('AGENT_TARGET_ALLOW_CIDRS', old_a), ('AGENT_TARGET_DENY_CIDRS', old_d)):
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v

    # --- 发现2：白名单/HTTPS 策略变更需要 recent-auth ---
    def _login_no_reauth(self):
        with self.client.session_transaction() as s:
            s['logged_in'] = True
            s['username'] = 'admin'
            s['must_change_password'] = False
            s['csrf_token'] = 't'
            s['last_reauth'] = 0  # 从未二次认证

    def test_whitelist_change_requires_reauth(self):
        self._login_no_reauth()
        r = self.client.post('/api/whitelist', json={'ip': '1.2.3.4'}, headers={'X-CSRF-Token': 't'})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json().get('reauth_required'))

    def test_force_https_change_requires_reauth(self):
        self._login_no_reauth()
        r = self.client.post('/api/settings/https', json={'force_https': True}, headers={'X-CSRF-Token': 't'})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json().get('reauth_required'))

    def test_ip_whitelist_bulk_requires_reauth(self):
        self._login_no_reauth()
        r = self.client.post('/api/settings/ip_whitelist', json={'whitelist': ['1.2.3.4']}, headers={'X-CSRF-Token': 't'})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(r.get_json().get('reauth_required'))

    # --- 发现3：仅 IP 模式在运行期硬拦域名主机（不只是新增/编辑） ---
    def test_ip_only_blocks_runtime_domain_host(self):
        old = webapp.AGENT_HOST_IP_ONLY
        webapp.AGENT_HOST_IP_ONLY = True
        try:
            with self.assertRaises(webapp.AgentHostBlocked):
                webapp.agent_get('http://agent.example.com:8888/health', 'tok')
            with self.assertRaises(webapp.AgentHostBlocked):
                webapp.agent_post('http://agent.example.com:8888/add_rule', 'tok', {'x': 1})
            # 字面量 IP 不受影响（此处仅验证不因 IP-only 抛 AgentHostBlocked；网络错误另计）
            try:
                webapp.agent_get('http://127.0.0.1:9/health', 'tok', timeout=1)
            except webapp.AgentHostBlocked:
                self.fail('literal IP should not be blocked by IP-only mode')
            except Exception:
                pass  # 连接失败可接受
        finally:
            webapp.AGENT_HOST_IP_ONLY = old
