from odoo.tests import tagged
from odoo.tools import config

from .common import OAuthHttpCase


@tagged('post_install', '-at_install')
class TestMetadata(OAuthHttpCase):
    def test_metadata_exact_fields_and_both_prm_paths(self):
        response = self.open('/.well-known/oauth-authorization-server')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {
            'issuer': self.issuer,
            'authorization_endpoint': self.issuer + '/oauth/authorize',
            'token_endpoint': self.issuer + '/oauth/token',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': ['mcp'],
            'client_id_metadata_document_supported': True,
            'authorization_response_iss_parameter_supported': True,
        })
        for path in ('/.well-known/oauth-protected-resource',
                     '/.well-known/oauth-protected-resource/mcp'):
            response = self.open(path)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.json(), {
                'resource': self.issuer + '/mcp',
                'authorization_servers': [self.issuer],
                'scopes_supported': ['mcp'],
                'bearer_methods_supported': ['header'],
            })

    def test_insecure_origin_is_404(self):
        for path in ('/.well-known/oauth-authorization-server',
                     '/.well-known/oauth-protected-resource',
                     '/.well-known/oauth-protected-resource/mcp'):
            self.assertEqual(self.open(path, secure=False).status_code, 404)

    def test_cloudflared_origin_and_challenge(self):
        path = '/.well-known/oauth-authorization-server'
        response = self.cloudflared_open(path)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['issuer'], self.issuer)
        challenge = self.cloudflared_open('/mcp', data=b'{}',
                                         headers={'Content-Type': 'application/json'})
        self.assertEqual(challenge.status_code, 401)
        self.assertIn('resource_metadata="' + self.issuer +
                      '/.well-known/oauth-protected-resource/mcp"',
                      challenge.headers['WWW-Authenticate'])
        self.assertEqual(self.cloudflared_open(path, secure=False).status_code, 404)
        response = self.cloudflared_open(path, headers={'X-Forwarded-Proto': 'http, https'})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['issuer'], self.issuer)
        config['proxy_mode'] = False
        self.assertEqual(self.cloudflared_open(path).status_code, 404)
        plain = self.cloudflared_open('/mcp', data=b'{}',
                                     headers={'Content-Type': 'application/json'})
        self.assertEqual(plain.status_code, 401)
        self.assertEqual(plain.headers['WWW-Authenticate'], 'Bearer')
