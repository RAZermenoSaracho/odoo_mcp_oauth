from unittest.mock import patch

from odoo.tests import tagged
from odoo.tools import config
from odoo.addons.odoo_mcp.ratelimit import SlidingWindow
from odoo.addons.odoo_mcp_oauth.controllers import main

from .common import OAuthHttpCase


@tagged('post_install', '-at_install')
class TestRateLimit(OAuthHttpCase):
    def test_token_throttles_before_verification(self):
        self.login()
        code = self.code()
        for _ in range(30):
            self.assertEqual(self.exchange(code, code_verifier='bad').status_code, 400)
        with patch.object(main, 'verify_hash_signed', side_effect=AssertionError('verified')):
            response = self.exchange(code)
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response.headers)

    def test_database_and_ip_are_separate_buckets(self):
        limiter = SlidingWindow(1, 60)
        self.assertTrue(limiter.check(('db_a', 'ip_a'))[0])
        self.assertFalse(limiter.check(('db_a', 'ip_a'))[0])
        self.assertTrue(limiter.check(('db_b', 'ip_a'))[0])
        self.assertTrue(limiter.check(('db_a', 'ip_b'))[0])

    def test_large_body_rejected(self):
        response = self.open('/oauth/token', data=b'x' * 16385,
                             headers={'Content-Type': 'application/x-www-form-urlencoded'})
        self.assertIn(response.status_code, (400, 413))

    def test_metadata_and_authorize_throttle(self):
        for _ in range(120):
            self.assertEqual(self.open('/.well-known/oauth-protected-resource').status_code, 200)
        response = self.open('/.well-known/oauth-protected-resource')
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response.headers)
        for _ in range(60):
            self.open(self.authorize_url())
        response = self.open(self.authorize_url())
        self.assertEqual(response.status_code, 429)
        self.assertIn('Retry-After', response.headers)

    def test_cloudflared_last_forwarded_ip_and_proxy_off_remote_addr(self):
        body = b'grant_type=authorization_code'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        with patch.object(main, 'TOKEN', SlidingWindow(1, 60)):
            for ip in ('192.0.2.10', '192.0.2.11'):
                response = self.cloudflared_open('/oauth/token', data=body, headers={
                    **headers, 'X-Forwarded-For': '198.51.100.1, ' + ip,
                })
                self.assertEqual(response.status_code, 400)
            response = self.cloudflared_open('/oauth/token', data=body, headers={
                **headers, 'X-Forwarded-For': '198.51.100.2, 192.0.2.10',
            })
            self.assertEqual(response.status_code, 429)
        config['proxy_mode'] = False
        with patch.object(main, 'TOKEN', SlidingWindow(1, 60)):
            first = self.cloudflared_open('/oauth/token', data=body, headers={
                **headers, 'X-Forwarded-For': '192.0.2.10',
            })
            second = self.cloudflared_open('/oauth/token', data=body, headers={
                **headers, 'X-Forwarded-For': '192.0.2.11',
            })
        self.assertEqual(first.status_code, 404)
        self.assertEqual(second.status_code, 429)

    def test_metadata_routes_share_limit_and_retry_after(self):
        with patch.object(main, 'METADATA', SlidingWindow(1, 60)):
            self.assertEqual(self.open('/.well-known/oauth-authorization-server').status_code, 200)
            for path in ('/.well-known/oauth-authorization-server',
                         '/.well-known/oauth-protected-resource',
                         '/.well-known/oauth-protected-resource/mcp'):
                response = self.open(path)
                self.assertEqual(response.status_code, 429)
                self.assertIn('Retry-After', response.headers)
