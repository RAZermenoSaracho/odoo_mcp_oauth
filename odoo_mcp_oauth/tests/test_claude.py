import datetime
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import requests

from odoo.tests import tagged

from .common import CLIENT, FakeDocument, OAuthHttpCase

CLAUDE_WEB = 'https://claude.ai/oauth/mcp-oauth-client-metadata'
WEB_CB = 'https://claude.ai/api/mcp/auth_callback'
WEB_DOC = {
    "client_id": CLAUDE_WEB, "client_name": "Claude", "client_uri": "https://claude.ai",
    "redirect_uris": [WEB_CB],
    "grant_types": ["authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
    "response_types": ["code"], "token_endpoint_auth_method": "none"}
CLAUDE_CODE = 'https://claude.ai/oauth/claude-code-client-metadata'
CODE_DOC = {
    "client_id": CLAUDE_CODE, "client_name": "Claude Code", "client_uri": "https://claude.ai",
    "redirect_uris": ["http://localhost/callback", "http://127.0.0.1/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"], "token_endpoint_auth_method": "none"}
DOCS = {CLAUDE_WEB: WEB_DOC, CLAUDE_CODE: CODE_DOC}
KEYS = 'res.users.apikeys'


@tagged('post_install', '-at_install')
class TestClaude(OAuthHttpCase):
    def setUp(self):
        super().setUp()
        self.env['ir.config_parameter'].sudo().set_param(
            'odoo_mcp_oauth.client_ids', '\n'.join([CLIENT, CLAUDE_WEB, CLAUDE_CODE]))
        previous = requests.get  # common.py's fake: other https -> FakeDocument, non-https -> real
        fake = patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                     side_effect=lambda url, *a, **kw: FakeDocument(DOCS[url]) if url in DOCS
                     else previous(url, *a, **kw))
        fake.start()
        self.addCleanup(fake.stop)

    def assertErrorPage(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('name="consent"', response.text)

    def flow(self, client_id, redirect_uri):
        blob, csrf, page = self.consent(client_id=client_id, redirect_uri=redirect_uri)
        response = self.decision(blob, csrf)
        self.assertEqual(response.status_code, 303)
        location = response.headers['Location']
        self.assertTrue(location.startswith(redirect_uri), location)
        code = parse_qs(urlsplit(location).query)['code'][0]
        token = self.exchange(code, client_id=client_id, redirect_uri=redirect_uri)
        self.assertEqual(token.status_code, 200)
        return token.json()['access_token'], page

    def test_discovery_meets_claude_conditions(self):
        meta = self.open('/.well-known/oauth-authorization-server').json()
        self.assertIs(meta['client_id_metadata_document_supported'], True)
        self.assertIn('none', meta['token_endpoint_auth_methods_supported'])
        self.assertEqual(meta['code_challenge_methods_supported'], ['S256'])
        for path in ('/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'):
            resource = self.open(path).json()
            self.assertEqual(resource['resource'], self.issuer + '/mcp')
            self.assertEqual(resource['authorization_servers'][0], self.issuer)
        response = self.mcp()
        self.assertEqual(response.status_code, 401)
        challenge = response.headers['WWW-Authenticate']
        self.assertIn('resource_metadata="' + self.issuer + '/.well-known/oauth-protected-resource/mcp"', challenge)
        self.assertIn('scope="mcp"', challenge)

    def test_claude_web_flow_and_independent_revocation(self):
        user = self.login()
        expiry = datetime.datetime.now() + datetime.timedelta(days=1)
        manual = self.env[KEYS].with_user(user)._generate('rpc', 'Claude API key', expiry)
        global_key = self.env[KEYS].with_user(user)._generate(None, 'global', expiry)
        token, page = self.flow(CLAUDE_WEB, WEB_CB)
        self.assertIn('Claude', page.text)
        self.assertIn('claude.ai', page.text)
        oauth_key = user.api_key_ids.filtered(lambda k: k.name == 'OAuth: Claude')
        self.assertEqual(len(oauth_key), 1)
        self.assertEqual(oauth_key.scope, 'mcp')
        self.assertEqual(oauth_key.sudo().oauth_client_id, CLAUDE_WEB)
        for key in (token, manual, global_key):
            self.assertEqual(self.mcp(key).status_code, 200)
        oauth_key.with_user(user)._remove()
        self.assertEqual(self.mcp(token).status_code, 401)
        for key in (manual, global_key):
            self.assertEqual(self.mcp(key).status_code, 200)
        new_token, _ = self.flow(CLAUDE_WEB, WEB_CB)
        self.assertEqual(self.mcp(new_token).status_code, 200)
        new_key = self.env[KEYS].sudo().search([('oauth_client_id', '=', CLAUDE_WEB)])
        self.assertEqual(len(new_key), 1)
        self.assertNotEqual(new_key.id, oauth_key.id)

    def test_claude_code_loopback_any_port(self):
        user = self.login()
        for redirect in ('http://localhost:3118/callback', 'http://127.0.0.1:53682/callback',
                         'http://localhost/callback'):
            with self.subTest(redirect=redirect):
                token, _ = self.flow(CLAUDE_CODE, redirect)
                self.assertTrue(token)
        self.assertEqual(set(user.api_key_ids.mapped('name')), {'OAuth: Claude Code'})

    def test_claude_code_loopback_rejections(self):
        self.login()
        for redirect in ('http://localhost:3118/other', 'http://evil.test:3118/callback',
                         'http://localhost.evil.test:3118/callback', 'https://localhost:3118/callback',
                         'http://localhost:3118/callback#x', 'http://user@localhost:3118/callback',
                         'http://localhost:abc/callback', 'http://localhost:3118/callback?x=1'):
            with self.subTest(redirect=redirect):
                self.assertErrorPage(self.open(self.authorize_url(client_id=CLAUDE_CODE, redirect_uri=redirect)))
        blob, csrf, _ = self.consent(client_id=CLAUDE_CODE, redirect_uri='http://localhost:3118/callback')
        code = parse_qs(urlsplit(self.decision(blob, csrf).headers['Location']).query)['code'][0]
        response = self.exchange(code, client_id=CLAUDE_CODE, redirect_uri='http://localhost:3119/callback')
        self.assertEqual(response.json()['error'], 'invalid_grant')

    def test_loopback_not_allowed_for_web_client(self):
        self.login()
        self.assertErrorPage(self.open(self.authorize_url(
            client_id=CLAUDE_WEB, redirect_uri='http://localhost:3118/callback')))
