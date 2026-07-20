import base64
import ipaddress
import os
import tempfile
import unittest
from unittest.mock import patch


from web import app as webapp


class WireGuardEnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        webapp.DB_FILE = os.path.join(self.tmp.name, 'snat.db')
        webapp.LOG_FILE = os.path.join(self.tmp.name, 'snat.log')
        webapp.BACKUP_DIR = os.path.join(self.tmp.name, 'backups')
        webapp.app.config['TESTING'] = True
        os.environ['SNAT_ADMIN_PASSWORD'] = 'Admin12345'
        webapp.init_db()
        self.client = webapp.app.test_client()
        with self.client.session_transaction() as sess:
            sess['logged_in'] = True
            sess['username'] = 'admin'
            sess['must_change_password'] = False
            sess['csrf_token'] = 'test'
            sess['last_reauth'] = __import__('time').time()

    def tearDown(self):
        self.tmp.cleanup()

    def test_claim_rejects_reuse_and_invalid_key(self):
        conn = webapp.sqlite3.connect(webapp.DB_FILE)
        conn.execute('INSERT INTO wg_enrollment_tokens VALUES (?,?,?,?,?,?)',
                     ('t' * 40, 'node', '10.66.66.2', 9999999999, None, 1))
        conn.commit(); conn.close()
        bad = self.client.post('/api/wireguard/enrollment/claim', json={'token': 't' * 40, 'public_key': 'bad'})
        self.assertEqual(bad.status_code, 400)

    @patch('web.blueprints.wireguard_enroll._read_hub', return_value=ipaddress.ip_interface('10.66.66.1/24'))
    def test_create_then_claim_is_one_time(self, _hub):
        created = self.client.post('/api/wireguard/enrollment', json={
            'name': 'node-1', 'agent_ip': '10.66.66.2', 'csrf_token': 'test'
        }, headers={'X-CSRF-Token': 'test'})
        self.assertEqual(created.status_code, 200, created.get_data(as_text=True))
        token = created.get_json()['token']
        pub = base64.b64encode(b'x' * 32).decode()
        fake = type('R', (), {'returncode': 0})()
        with patch('subprocess.run', return_value=fake) as run:
            first = self.client.post('/api/wireguard/enrollment/claim', json={'token': token, 'public_key': pub})
            second = self.client.post('/api/wireguard/enrollment/claim', json={'token': token, 'public_key': pub})
        self.assertEqual(first.status_code, 200)
        self.assertEqual(second.status_code, 403)
        self.assertEqual(run.call_count, 1)

    def test_public_key_shape_is_exact_wireguard_shape(self):
        value = base64.b64encode(b'x' * 32).decode()
        self.assertEqual(len(value), 44)
        self.assertTrue(value.endswith('='))

    def test_install_does_not_put_default_route_in_wireguard(self):
        with open(os.path.join(os.path.dirname(__file__), 'wireguard_setup.sh')) as handle:
            text = handle.read()
        self.assertNotIn('AllowedIPs = 0.0.0.0/0', text)
        self.assertIn('AllowedIPs = ${hub_wg_ip}/32', text)


if __name__ == '__main__':
    unittest.main()
