import datetime
import re
from types import SimpleNamespace
from unittest.mock import Mock
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from odoo.tests import tagged
from odoo.tools.misc import hash_sign

from .common import CALLBACK, CLIENT, CHALLENGE, FakeDocument, OAuthHttpCase


@tagged('post_install', '-at_install')
class TestAuthorize(OAuthHttpCase):
    def test_duration_options(self):
        self.login('oauth_duration_options')
        _, _, response = self.consent()
        select = re.search(r'<select\b[^>]*id="o_mcp_oauth_duration"[^>]*>(.*?)</select>',
                           response.text, re.DOTALL)
        self.assertIsNotNone(select)
        options = re.findall(r'<option\b[^>]*value="([^"]+)"[^>]*>([^<]+)</option>', select.group(1))
        self.assertEqual(options, [('1', '1 Day'), ('30', '1 Month')])
        self.assertRegex(response.text, r'<option\b[^>]*value="30"[^>]*selected="selected"')
        self.assertNotIn('oe_login_form', response.text)
        self.authenticate('admin', 'admin')
        _, _, response = self.consent()
        select = re.search(r'<select\b[^>]*id="o_mcp_oauth_duration"[^>]*>(.*?)</select>',
                           response.text, re.DOTALL)
        self.assertIsNotNone(select)
        options = re.findall(r'<option\b[^>]*value="([^"]+)"[^>]*>([^<]+)</option>', select.group(1))
        self.assertEqual(options, [('1', '1 Day'), ('30', '1 Month'),
                                   ('365', '1 Year'), ('0', 'Never')])
        self.assertRegex(response.text, r'<option\b[^>]*value="30"[^>]*selected="selected"')

    def test_invalid_approve_durations(self):
        self.login('oauth_invalid_duration')
        blob, csrf, _ = self.consent()
        for duration in ('0', '365', '7', 'abc', ''):
            response = self.decision(blob, csrf, duration=duration)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('Location', response.headers)

    def test_prelogin_gate_and_local_return(self):
        response = self.open(self.authorize_url())
        self.assertEqual(response.status_code, 303)
        location = response.headers['Location']
        self.assertTrue(urlsplit(location).path.startswith('/web/login'))
        self.assertEqual(parse_qs(urlsplit(location).query)['redirect'], [self.authorize_url()])
        self.assertEqual(self.open(self.authorize_url(client_id='https://bad.example/client.json')).status_code, 200)
        self.assertNotIn(CALLBACK, self.open(self.authorize_url(response_type='token')).headers.get('Location', ''))

    def test_consent_and_deny_headers(self):
        self.login()
        blob, csrf, response = self.consent(scope='anything')
        for header, expected in (
            ('X-Frame-Options', 'DENY'),
            ('Content-Security-Policy', "frame-ancestors 'none'"),
            ('Referrer-Policy', 'no-referrer'),
            ('Cache-Control', 'no-store'),
        ):
            self.assertEqual(response.headers[header], expected)
        self.assertIn('Example Client', response.text)
        self.assertIn(self.env.cr.dbname, response.text)
        with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                   side_effect=AssertionError('second CIMD fetch')):
            denial = self.decision(blob, csrf, 'deny')
        self.assertEqual(denial.status_code, 303)
        query = parse_qs(urlsplit(denial.headers['Location']).query)
        self.assertEqual(query['error'], ['access_denied'])
        self.assertEqual(query['state'], ['state-123'])
        self.assertEqual(query['iss'], [self.issuer])
        self.assertEqual(denial.headers['X-Frame-Options'], 'DENY')

    def test_callback_and_pkce_validation(self):
        self.login()
        for callback in (CALLBACK + '/extra', CALLBACK.replace('/cb', '/%63b')):
            response = self.open(self.authorize_url(redirect_uri=callback))
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('Location', response.headers)
        for changes in ({'code_challenge_method': 'plain'},
                        {'code_challenge': 'a' * 42},
                        {'resource': 'https://wrong.example/mcp'}):
            response = self.open(self.authorize_url(**changes))
            self.assertEqual(response.status_code, 303)
            query = parse_qs(urlsplit(response.headers['Location']).query)
            self.assertEqual(query['error'], ['invalid_request'])
            self.assertEqual(query['iss'], [self.issuer])
        self.assertEqual(self.open(self.authorize_url(code_challenge='')).status_code, 200)

    def test_bad_cimd_fails_locally(self):
        self.login()
        for document in (
            {'client_id': 'https://other.example/client.json', 'redirect_uris': [CALLBACK]},
            {'client_id': CLIENT, 'redirect_uris': [CALLBACK + '/extra']},
        ):
            with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                       return_value=FakeDocument(document)):
                response = self.open(self.authorize_url())
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('Location', response.headers)

    def test_tampered_consent_user_switch_and_csrf(self):
        user = self.login()
        blob, csrf, _ = self.consent()
        self.assertNotIn('code=', self.decision(blob + 'x', csrf).headers.get('Location', ''))
        self.assertNotIn('code=', self.decision(blob, '', 'approve').headers.get('Location', ''))
        values = {'uid': user.id + 1000, 'client_id': CLIENT, 'client_name': 'Example',
                  'redirect_uri': CALLBACK, 'code_challenge': CHALLENGE,
                  'resource': self.issuer + '/mcp', 'state': 'state-123'}
        other_blob = hash_sign(self.env(su=True), 'odoo_mcp_oauth.consent', values)
        self.assertEqual(self.decision(other_blob, csrf).status_code, 200)
        self.env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', '')
        self.assertEqual(self.decision(blob, csrf).status_code, 200)

    def test_expired_consent_and_portal_user(self):
        user = self.login()
        blob, csrf, _ = self.consent()
        values = {'uid': user.id, 'client_id': CLIENT, 'client_name': 'Example',
                  'redirect_uri': CALLBACK, 'code_challenge': CHALLENGE,
                  'resource': self.issuer + '/mcp', 'state': 'state-123'}
        expired = hash_sign(self.env(su=True), 'odoo_mcp_oauth.consent', values,
                            expiration=datetime.datetime.now() - datetime.timedelta(seconds=1))
        self.assertEqual(self.decision(expired, csrf).status_code, 200)
        user.group_ids = [(6, 0, [self.env.ref('base.group_portal').id])]
        response = self.open(self.authorize_url())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(parse_qs(urlsplit(response.headers['Location']).query)['error'], ['access_denied'])

    def test_cimd_timeout_and_oversize(self):
        import requests
        self.login()
        with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                   side_effect=requests.Timeout):
            self.assertEqual(self.open(self.authorize_url()).status_code, 200)
        document = FakeDocument()
        document.iter_content = lambda chunk_size=8192: iter([b'x' * 65537])
        with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                   return_value=document):
            self.assertEqual(self.open(self.authorize_url()).status_code, 200)

    def test_cimd_redirect_mismatch_oversize_and_total_deadline(self):
        self.login('oauth_cimd_bad')
        bad_documents = [
            FakeDocument({'client_id': 'https://wrong.example.test/client.json',
                          'redirect_uris': [CALLBACK]}),
            FakeDocument(),
        ]
        bad_documents[1].status_code = 302
        oversize = FakeDocument()
        oversize.iter_content = lambda chunk_size=8192: iter([b'x' * 65537])
        bad_documents.append(oversize)
        for document in bad_documents:
            with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                       return_value=document):
                response = self.open(self.authorize_url())
            self.assertEqual(response.status_code, 200)
            self.assertNotIn('Location', response.headers)
        slow = FakeDocument()
        slow.iter_content = lambda chunk_size=8192: iter([b'{}'])
        fake_time = SimpleNamespace(monotonic=Mock(side_effect=[100, 106]))
        with patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                   return_value=slow), patch('odoo.addons.odoo_mcp_oauth.controllers.main.time', fake_time):
            response = self.open(self.authorize_url())
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Location', response.headers)
        self.assertEqual(fake_time.monotonic.call_count, 2)

    def test_consent_db_scope_and_user_binding(self):
        user = self.login('oauth_consent_owner')
        blob, csrf, _ = self.consent()
        code = self.code()
        self.assertEqual(self.decision(code, csrf).status_code, 200)
        wrong_db = hash_sign(self.env(su=True), 'odoo_mcp_oauth.consent', {
            'uid': user.id, 'client_id': CLIENT, 'client_name': 'Example',
            'redirect_uri': CALLBACK, 'code_challenge': CHALLENGE,
            'resource': self.issuer + '/mcp', 'state': 'state-123',
            'db': 'another_database',
        }, expiration=datetime.timedelta(minutes=10))
        response = self.decision(wrong_db, csrf)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Location', response.headers)
        self.login('oauth_consent_other_user')
        _, other_csrf, _ = self.consent()
        response = self.decision(blob, other_csrf)
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('Location', response.headers)
