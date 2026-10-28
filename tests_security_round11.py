import os, sqlite3, tempfile, threading, unittest
from unittest.mock import patch

os.environ.setdefault('SNAT_ALLOW_DEFAULT_TOKEN','1')
os.environ.setdefault('APP_ENV','testing')
from web import app as webapp


class SecurityRound11(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        webapp.DB_FILE=os.path.join(self.tmp.name,'db.sqlite')
        webapp.app.config.update(TESTING=True, SECRET_KEY='x'*48)
        webapp.init_db()
        con=sqlite3.connect(webapp.DB_FILE)
        con.execute("UPDATE users SET must_change_password=0")
        con.commit(); con.close()
        self.client=webapp.app.test_client()
        with self.client.session_transaction() as s:
            s['logged_in']=True; s['username']='admin'; s['must_change_password']=False
            s['last_reauth']=0; s['csrf_token']='csrf'
    def tearDown(self): self.tmp.cleanup()

    def test_agent_host_bypass_forms_rejected(self):
        for host in ('169.254.169.254#','169.254.169.254?x','user@169.254.169.254','2852039166','0xA9FEA9FE','0251.0376.0251.0376'):
            self.assertFalse(webapp.validate_agent_host(host)[0], host)

    def test_runtime_revalidates_complete_url(self):
        bad=('http://169.254.169.254:80/x','http://1.2.3.4:80/x?q=1','http://1.2.3.4:80/x#f','http://u@1.2.3.4:80/x')
        for url in bad:
            with self.assertRaises(webapp.AgentHostBlocked, msg=url): webapp._enforce_agent_host_runtime(url)

    def test_alert_chat_or_command_change_needs_reauth(self):
        with patch.object(webapp,'get_setting',side_effect=lambda k,d='': 'old' if k=='tg_chat_id' else d), patch.object(webapp,'_setting_bool',return_value=False):
            r=self.client.post('/api/settings/alerts',json={'tg_chat_id':'new','command_enabled':True},headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code,403); self.assertTrue(r.get_json()['reauth_required'])

    def test_logout_and_server_check_get_rejected(self):
        self.assertEqual(self.client.get('/logout').status_code,405)
        self.assertEqual(self.client.get('/api/servers/1/check').status_code,405)

    def test_healthz_bypasses_management_whitelist(self):
        with patch.object(webapp,'get_ip_whitelist',return_value=['10.0.0.1']):
            r=self.client.get('/healthz',environ_base={'REMOTE_ADDR':'172.17.0.1'})
        self.assertEqual(r.status_code,200)

    def test_rate_limit_single_count_and_thread_safe(self):
        webapp.rate_limit_store.clear(); webapp.RATE_LIMIT_REQUESTS=1000
        def one():
            with webapp.app.test_request_context('/api/rules',environ_base={'REMOTE_ADDR':'1.2.3.4'}): webapp.check_rate_limit()
        ts=[threading.Thread(target=one) for _ in range(30)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(len(webapp.rate_limit_store['1.2.3.4']),30)

    def test_bot_session_revoked_after_use(self):
        code,data=webapp._bot_api_call('/api/servers')
        self.assertEqual(code,200)
        con=sqlite3.connect(webapp.DB_FILE)
        active=con.execute("SELECT COUNT(*) FROM web_sessions WHERE revoked=0").fetchone()[0]
        con.close(); self.assertEqual(active,0)

    def test_bot_blocked_while_default_password_pending(self):
        con=sqlite3.connect(webapp.DB_FILE); con.execute("UPDATE users SET must_change_password=1"); con.commit(); con.close()
        code,data=webapp._bot_api_call('/api/servers')
        self.assertEqual(code,403); self.assertIn('默认密码',data['error'])

    def test_bulk_rules_has_hard_limit(self):
        with self.client.session_transaction() as s: s['last_reauth']=__import__('time').time()
        r=self.client.post('/api/rules/bulk',json={'action':'disable','rule_ids':list(range(1,202))},headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code,400); self.assertIn('200',r.get_json()['error'])

    def test_bot_internal_call_survives_ip_whitelist(self):
        with patch.object(webapp,'get_ip_whitelist',return_value=['10.0.0.1']):
            code,_=webapp._bot_api_call('/api/servers')
        self.assertEqual(code,200)

    def test_alert_partial_update_preserves_command_enabled(self):
        con=sqlite3.connect(webapp.DB_FILE)
        con.execute("INSERT OR REPLACE INTO settings_kv(key,value) VALUES('tg_command_enabled','1')")
        con.commit(); con.close()
        with self.client.session_transaction() as s: s['last_reauth']=__import__('time').time()
        r=self.client.post('/api/settings/alerts',json={'offline_seconds':600},headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code,200)
        con=sqlite3.connect(webapp.DB_FILE)
        value=con.execute("SELECT value FROM settings_kv WHERE key='tg_command_enabled'").fetchone()[0]
        con.close(); self.assertEqual(value,'1')

    def test_alert_invalid_update_is_atomic(self):
        con=sqlite3.connect(webapp.DB_FILE)
        con.execute("INSERT OR REPLACE INTO settings_kv(key,value) VALUES('tg_chat_id','old')")
        con.commit(); con.close()
        with self.client.session_transaction() as s: s['last_reauth']=__import__('time').time()
        r=self.client.post('/api/settings/alerts',json={'tg_chat_id':'new','offline_seconds':'bad'},headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code,400)
        con=sqlite3.connect(webapp.DB_FILE); value=con.execute("SELECT value FROM settings_kv WHERE key='tg_chat_id'").fetchone()[0]; con.close()
        self.assertEqual(value,'old')

    def test_alert_boolean_rejects_string_false(self):
        with self.client.session_transaction() as s: s['last_reauth']=__import__('time').time()
        r=self.client.post('/api/settings/alerts',json={'command_enabled':'false'},headers={'X-CSRF-Token':'csrf'})
        self.assertEqual(r.status_code,400)

if __name__=='__main__': unittest.main()
