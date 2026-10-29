import datetime

from odoo.tests import tagged

from .common import OAuthHttpCase


@tagged('post_install', '-at_install')
class TestMcpAuth(OAuthHttpCase):
    def test_challenges_and_session_cannot_authenticate(self):
        for key, invalid in ((None, False), ('bad-key', True)):
            response = self.mcp(key)
            self.assertEqual(response.status_code, 401)
            challenge = response.headers['WWW-Authenticate']
            self.assertIn(self.issuer + '/.well-known/oauth-protected-resource/mcp', challenge)
            self.assertIn('scope="mcp"', challenge)
            self.assertEqual('invalid_token' in challenge, invalid)
        self.login()
        self.assertEqual(self.mcp().status_code, 401)
        # Without HTTPS no issuer is advertised, but the endpoint still answers 401.
        plain = self.open('/mcp', data=b'{}', secure=False, headers={'Content-Type': 'application/json'})
        self.assertEqual(plain.status_code, 401)
        self.assertEqual(plain.headers['WWW-Authenticate'], 'Bearer')

    def test_mcp_rpc_and_null_keys(self):
        user = self.login()
        keys = self.env['res.users.apikeys'].with_user(user)
        for scope in ('mcp', 'rpc', None):
            key = keys._generate(scope, 'test', datetime.datetime.now() + datetime.timedelta(days=1))
            self.assertEqual(self.mcp(key).status_code, 200, scope)
            if scope == 'mcp':
                response = self.open('/json/2/res.users/search_count', data=b'{}',
                                     headers={'Content-Type': 'application/json',
                                              'Authorization': 'Bearer ' + key})
                self.assertIn(response.status_code, (401, 403))
