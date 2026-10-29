import base64
import datetime
import hashlib
import json
import re
from unittest.mock import patch

import requests
from urllib.parse import parse_qs, urlsplit

from odoo.tests import HttpCase
from odoo.tools import config

from odoo.addons.odoo_mcp_oauth.controllers import main

CLIENT = 'https://client.example.test/client.json'
CALLBACK = 'https://client.example.test/cb'
VERIFIER = 'v' * 43
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).decode().rstrip('=')


class FakeDocument:
    status_code = 200

    def __init__(self, document=None):
        self.document = document or {
            'client_id': CLIENT, 'redirect_uris': [CALLBACK], 'client_name': 'Example Client',
        }

    def iter_content(self, chunk_size=8192):
        yield json.dumps(self.document).encode()

    def close(self):
        pass


class OAuthHttpCase(HttpCase):
    def setUp(self):
        super().setUp()
        old_proxy = config['proxy_mode']
        config['proxy_mode'] = True
        self.addCleanup(lambda: config.__setitem__('proxy_mode', old_proxy))
        for limiter in (main.TOKEN, main.AUTHORIZE, main.METADATA):
            limiter.clear()
        # main.requests is the shared requests module: only fake https client documents,
        # the test browser launcher also uses requests.get.
        real_get = requests.get
        fake_get = patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get',
                         side_effect=lambda url, *args, **kwargs: FakeDocument() if url.startswith('https://')
                         else real_get(url, *args, **kwargs))
        fake_get.start()
        self.addCleanup(fake_get.stop)
        self.env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', CLIENT)
        self.host = self.env.cr.dbname + '.example.test'
        self.issuer = 'https://' + self.host

    def headers(self, extra=None, secure=True):
        result = {
            'X-Odoo-Database': self.env.cr.dbname,
            'X-Forwarded-Host': self.host,
            'X-Forwarded-Proto': 'https' if secure else 'http',
        }
        result.update(extra or {})
        return result

    def cloudflared_headers(self, extra=None, secure=True):
        """Original Host and forwarded scheme, without X-Forwarded-Host."""
        result = {
            'Host': self.host,
            'X-Odoo-Database': self.env.cr.dbname,
            'X-Forwarded-Proto': 'https' if secure else 'http',
        }
        result.update(extra or {})
        return result

    def cloudflared_open(self, path, data=None, headers=None, secure=True, method=None):
        return self.url_open(path, data=data,
                             headers=self.cloudflared_headers(headers, secure),
                             allow_redirects=False, method=method)

    def open(self, path, data=None, headers=None, secure=True, method=None):
        return self.url_open(path, data=data, headers=self.headers(headers, secure),
                             allow_redirects=False, method=method)

    def auth_params(self, **changes):
        params = {
            'client_id': CLIENT, 'redirect_uri': CALLBACK, 'response_type': 'code',
            'code_challenge': CHALLENGE, 'code_challenge_method': 'S256',
            'resource': self.issuer + '/mcp', 'state': 'state-123',
        }
        params.update(changes)
        return params

    def authorize_url(self, **changes):
        from urllib.parse import urlencode
        return '/oauth/authorize?' + urlencode(self.auth_params(**changes))

    def login(self, name='oauth_user'):
        user = self.env['res.users'].create({
            'name': name, 'login': name, 'password': name,
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        self.authenticate(name, name)
        return user

    def consent(self, **changes):
        response = self.open(self.authorize_url(**changes))
        self.assertEqual(response.status_code, 200)
        blob = re.search(r'name="consent"[^>]*value="([^"]+)', response.text)
        csrf = re.search(r'name="csrf_token"[^>]*value="([^"]+)', response.text)
        self.assertIsNotNone(blob)
        self.assertIsNotNone(csrf)
        return blob.group(1), csrf.group(1), response

    def decision(self, blob, csrf, decision='approve', duration='30'):
        from urllib.parse import urlencode
        params = {
            'consent': blob, 'csrf_token': csrf, 'decision': decision,
        }
        if decision == 'approve':
            params['duration'] = duration
        return self.open('/oauth/authorize', data=urlencode(params).encode(),
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})

    def code(self):
        blob, csrf, _ = self.consent()
        response = self.decision(blob, csrf)
        self.assertEqual(response.status_code, 303)
        return parse_qs(urlsplit(response.headers['Location']).query)['code'][0]

    def exchange(self, code, **changes):
        from urllib.parse import urlencode
        params = {
            'grant_type': 'authorization_code', 'code': code,
            'redirect_uri': CALLBACK, 'client_id': CLIENT,
            'code_verifier': VERIFIER, 'resource': self.issuer + '/mcp',
        }
        params.update(changes)
        return self.open('/oauth/token', data=urlencode(params).encode(),
                         headers={'Content-Type': 'application/x-www-form-urlencoded'})

    def mcp(self, key=None):
        headers = {'Content-Type': 'application/json', 'MCP-Protocol-Version': '2026-07-28',
                   'Mcp-Method': 'tools/list'}
        if key:
            headers['Authorization'] = 'Bearer ' + key
        body = {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list',
                'params': {'_meta': {
                    'io.modelcontextprotocol/protocolVersion': '2026-07-28',
                    'io.modelcontextprotocol/clientInfo': {'name': 'test', 'version': '1'},
                    'io.modelcontextprotocol/clientCapabilities': {},
                }}}
        return self.open('/mcp', data=json.dumps(body).encode(), headers=headers)
