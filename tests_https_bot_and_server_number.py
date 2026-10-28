import os
import tempfile
import time
import unittest

os.environ.setdefault('SNAT_ALLOW_DEFAULT_TOKEN', '1')

from web import app as webapp


class HttpsBotAndServerNumberTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.BACKUP_DIR = os.path.join(self.tmp.name, 'backups')
        webapp.app.config['TESTING'] = True
        webapp.FORCE_HTTPS = True
        webapp.APP_ENV = 'production'
        webapp.init_db()
        self.client = webapp.app.test_client()
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'
            sess['must_change_password'] = False
            sess['csrf_token'] = 'csrf'
            sess['last_reauth'] = time.time()

    def tearDown(self):
        webapp.FORCE_HTTPS = False
        webapp.APP_ENV = 'production'
        self.tmp.cleanup()

    def _insert_server(self, name='HK-Vol', host='87.83.105.37', port=8888, token='plain-token'):
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO servers (name, host, port, token, status) VALUES (?, ?, ?, ?, ?)',
            (name, host, port, token, 'online')
        )
        conn.commit()
        sid = cur.lastrowid
        conn.close()
        return sid

    def test_external_http_api_is_rejected_when_force_https_enabled(self):
        r = self.client.get('/api/servers')
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()['error'], 'HTTPS required')

    def test_internal_bot_api_bypasses_https_redirect_gate(self):
        self._insert_server()
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        conn.execute("UPDATE users SET must_change_password=0 WHERE username='admin'")
        conn.commit()
        conn.close()
        code, data = webapp._bot_api_call('/api/servers')
        self.assertEqual(code, 200)
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]['display_id'], '①')

    def test_server_list_exposes_display_id(self):
        self._insert_server(name='DV')
        r = self.client.get('/api/servers', environ_overrides={'wsgi.url_scheme': 'https'})
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        row = data[0]
        self.assertEqual(row['display_id'], '①')
        self.assertEqual(row['id'], 1)


if __name__ == '__main__':
    unittest.main()
