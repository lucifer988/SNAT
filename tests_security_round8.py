import contextlib
import io
import os
import sqlite3
import tempfile
import time
import unittest

from web import app as webapp


class SecurityRound8Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_db = webapp.DB_FILE
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.app.config['TESTING'] = True
        webapp.init_db()
        self.client = webapp.app.test_client()

    def tearDown(self):
        webapp.DB_FILE = self.old_db
        self.tmp.cleanup()

    def _login(self):
        response = self.client.post('/login', json={'username': 'admin', 'password': 'Admin12345'})
        self.assertEqual(response.status_code, 200)
        with self.client.session_transaction() as sess:
            sess['must_change_password'] = False
        return response.get_json()['csrf_token']

    def test_init_db_never_prints_initial_password(self):
        other_db = os.path.join(self.tmp.name, 'other.db')
        webapp.DB_FILE = other_db
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            webapp.init_db()
        self.assertNotIn('Admin12345', output.getvalue())

    def test_password_change_revokes_other_session(self):
        csrf1 = self._login()
        other = webapp.app.test_client()
        login2 = other.post('/login', json={'username': 'admin', 'password': 'Admin12345'})
        self.assertEqual(login2.status_code, 200)
        with other.session_transaction() as sess:
            sess['must_change_password'] = False

        changed = self.client.post(
            '/api/change_password',
            json={'old_password': 'Admin12345', 'new_password': 'Better12345A'},
            headers={'X-CSRF-Token': csrf1},
        )
        self.assertEqual(changed.status_code, 200)
        self.assertEqual(other.get('/api/servers').status_code, 401)

    def test_create_server_requires_recent_auth(self):
        self._login()
        with self.client.session_transaction() as sess:
            sess['last_reauth'] = time.time() - webapp.REAUTH_MAX_AGE - 1
            csrf = sess['csrf_token']
        response = self.client.post(
            '/api/servers',
            json={'name': 's1', 'host': '10.8.0.2', 'port': 8888, 'token': 'x' * 32},
            headers={'X-CSRF-Token': csrf},
        )
        self.assertEqual(response.status_code, 403)
        self.assertTrue(response.get_json()['reauth_required'])

    def test_rule_network_changes_require_recent_auth(self):
        self._login()
        with self.client.session_transaction() as sess:
            sess['last_reauth'] = 0
            csrf = sess['csrf_token']
        response = self.client.post(
            '/api/rules',
            json={'server_id': 1, 'local_port': 1234, 'target_ip': '1.1.1.1', 'target_port': 80},
            headers={'X-CSRF-Token': csrf},
        )
        self.assertEqual(response.status_code, 403)

    def test_metrics_disabled_by_default(self):
        response = self.client.get('/metrics')
        self.assertEqual(response.status_code, 404)

    def test_csv_export_neutralizes_formula_cells(self):
        csrf = self._login()
        conn = sqlite3.connect(webapp.DB_FILE)
        conn.execute(
            'INSERT INTO servers (name, host, port, token) VALUES (?, ?, ?, ?)',
            ('=cmd', '10.8.0.2', 8888, webapp.encrypt_token('x' * 32)),
        )
        conn.commit()
        conn.close()
        response = self.client.get('/api/export/servers')
        self.assertEqual(response.status_code, 200)
        self.assertIn("'=cmd", response.get_data(as_text=True))


if __name__ == '__main__':
    unittest.main()
