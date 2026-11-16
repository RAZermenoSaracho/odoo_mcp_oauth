import datetime
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import requests

from odoo.exceptions import AccessError, ValidationError
from odoo.tests import tagged
from odoo.tools import mute_logger

from .common import CLIENT, OAuthHttpCase

MUSE = 'https://agent.meta.ai/api/hatch/oauth/callback'
KEYS = 'res.users.apikeys'


@tagged('post_install', '-at_install')
class TestHostedClient(OAuthHttpCase):
    def hosted(self, name='Meta AI Muse', uris=MUSE):
        client = self.env['mcp.oauth.client'].create({'name': name, 'redirect_uris': uris})
        return client, self.issuer + '/oauth/clients/' + client.uuid + '.json'

    def watch_outbound(self):
        """Record requests.get calls; non-https ones still reach the real function."""
        real_get = requests.get
        calls = Mock(side_effect=lambda url, *a, **kw: real_get(url, *a, **kw))
        patcher = patch('odoo.addons.odoo_mcp_oauth.controllers.main.requests.get', calls)
        patcher.start()
        self.addCleanup(patcher.stop)
        return calls

    def hosted_code(self, hid):
        blob, csrf, _ = self.consent(client_id=hid, redirect_uri=MUSE)
        response = self.decision(blob, csrf)
        self.assertEqual(response.status_code, 303)
        return parse_qs(urlsplit(response.headers['Location']).query)['code'][0]

    def hosted_token(self, hid):
        return self.exchange(self.hosted_code(hid), client_id=hid, redirect_uri=MUSE).json()['access_token']

    def assertErrorPage(self, response):
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('name="consent"', response.text)

    def assertOAuthError(self, response, error):
        self.assertEqual(response.status_code, 303)
        self.assertEqual(parse_qs(urlsplit(response.headers['Location']).query)['error'], [error])

    def hosted_keys(self, hid):
        return self.env[KEYS].sudo().search([('oauth_client_id', '=', hid)])

    def test_model_create_uris_and_uuid(self):
        client, _ = self.hosted(uris=MUSE + '\nhttps://other.example.test/cb')
        self.assertTrue(client.active)
        self.assertEqual(len(client.uuid), 32)
        self.assertEqual(len(client.redirect_uris.splitlines()), 2)
        for bad in ['', 'http://x.test/cb', '/cb', 'https://u:p@x.test/cb', 'https://x.test/cb#f', 'https:///cb', 'https://x.test/c b', 'https://x.test\\cb']:
            with self.subTest(uri=bad), mute_logger('odoo.sql_db'), self.assertRaises(ValidationError):
                self.env['mcp.oauth.client'].create({'name': 'Bad', 'redirect_uris': bad})
        with self.assertRaises(ValidationError):
            client.write({'uuid': 'f' * 32})
        other, _ = self.hosted('Second')
        self.assertNotEqual(client.uuid, other.uuid)
        self.assertNotEqual(client.copy().uuid, client.uuid)

    def test_non_admin_denied(self):
        client, _ = self.hosted()
        user = self.env['res.users'].create({
            'name': 'plain', 'login': 'plain',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id])]})
        model = self.env['mcp.oauth.client'].with_user(user)
        with self.assertRaises(AccessError):
            model.search([])
        with self.assertRaises(AccessError):
            model.create({'name': 'X', 'redirect_uris': MUSE})
        with self.assertRaises(AccessError):
            client.with_user(user).write({'name': 'Y'})
        with self.assertRaises(AccessError):
            client.with_user(user).unlink()
        with self.assertRaises(AccessError):
            client.with_user(user).action_revoke_credentials()

    def test_document_route(self):
        client, hid = self.hosted()
        response = self.open('/oauth/clients/%s.json' % client.uuid)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers['Content-Type'].split(';')[0], 'application/json')
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn('Set-Cookie', response.headers)
        self.assertEqual(response.json(), {
            'client_id': hid, 'client_name': 'Meta AI Muse', 'redirect_uris': [MUSE],
            'token_endpoint_auth_method': 'none', 'grant_types': ['authorization_code'],
            'response_types': ['code']})
        self.assertEqual(hid, self.issuer + '/oauth/clients/' + client.uuid + '.json')
        for name in ('nothex.json', 'abc', 'f' * 32 + '.json'):
            self.assertEqual(self.open('/oauth/clients/' + name).status_code, 404, name)
        self.assertEqual(self.open('/oauth/clients/%s.json' % client.uuid, secure=False).status_code, 404)
        client.active = False
        self.assertEqual(self.open('/oauth/clients/%s.json' % client.uuid).status_code, 404)

    def test_hosted_flow_no_outbound_fetch(self):
        user = self.login()
        client, hid = self.hosted()
        outbound = self.watch_outbound()
        _, _, page = self.consent(client_id=hid, redirect_uri=MUSE)
        self.assertIn('agent.meta.ai', page.text)
        self.assertIn('Meta AI Muse', page.text)
        token = self.hosted_token(hid)
        self.assertFalse([c for c in outbound.call_args_list if c.args[0].startswith('https://')])
        key = user.api_key_ids
        self.assertEqual(len(key), 1)
        self.assertEqual(key.name, 'OAuth: Meta AI Muse')
        self.assertEqual(key.scope, 'mcp')
        self.assertEqual(key.sudo().oauth_client_id, hid)
        self.assertEqual(self.mcp(token).status_code, 200)

    def test_authorize_rejections(self):
        self.login()
        _, hid = self.hosted()
        for uri in ('https://agent.meta.ai/api/hatch/oauth', 'https://agent.meta.ai/other'):
            self.assertErrorPage(self.open(self.authorize_url(client_id=hid, redirect_uri=uri)))
        self.assertOAuthError(self.open(self.authorize_url(
            client_id=hid, redirect_uri=MUSE, resource='https://x.test/mcp')), 'invalid_request')
        self.assertErrorPage(self.open(self.authorize_url(client_id=hid, redirect_uri=MUSE, resource='')))
        self.assertOAuthError(self.open(self.authorize_url(
            client_id=hid, redirect_uri=MUSE, code_challenge_method='plain')), 'invalid_request')

    def test_archive(self):
        self.login()
        client, hid = self.hosted()
        code = self.hosted_code(hid)
        client.active = False
        response = self.exchange(code, client_id=hid, redirect_uri=MUSE)
        self.assertEqual(response.json()['error'], 'invalid_grant')
        self.assertFalse(self.hosted_keys(hid))
        self.assertErrorPage(self.open(self.authorize_url(client_id=hid, redirect_uri=MUSE)))
        client.active = True
        token = self.hosted_token(hid)
        client.active = False
        self.assertEqual(self.mcp(token).status_code, 200)

    def test_delete(self):
        self.login()
        client, hid = self.hosted()
        code = self.hosted_code(hid)
        token = self.hosted_token(hid)
        client.unlink()
        self.assertEqual(self.exchange(code, client_id=hid, redirect_uri=MUSE).json()['error'], 'invalid_grant')
        self.assertEqual(self.mcp(token).status_code, 401)
        self.assertFalse(self.hosted_keys(hid))

    def test_revoke_is_per_credential(self):
        user = self.login()
        a, hid_a = self.hosted('A')
        b, hid_b = self.hosted('B')
        token_a, token_b = self.hosted_token(hid_a), self.hosted_token(hid_b)
        external = self.exchange(self.code()).json()['access_token']
        manual = self.env[KEYS].with_user(user)._generate(
            'rpc', 'manual', datetime.datetime.now() + datetime.timedelta(days=1))
        self.assertEqual(self.env[KEYS].sudo().search_count([('oauth_client_id', '=', CLIENT)]), 1)
        a.action_revoke_credentials()
        self.assertEqual(self.mcp(token_a).status_code, 401)
        for key in (token_b, external, manual):
            self.assertEqual(self.mcp(key).status_code, 200)
        self.assertTrue(a.active)

    def test_other_host_path_not_resolved(self):
        self.login()
        client, _ = self.hosted()
        foreign = 'https://other.example.test/oauth/clients/%s.json' % client.uuid
        self.assertErrorPage(self.open(self.authorize_url(client_id=foreign, redirect_uri=MUSE)))

    def test_security_tab_removal_is_per_credential(self):
        # Core's Security tab Delete button calls remove() (identity check) -> _remove().
        user = self.login()
        _, hid = self.hosted()
        muse, chatgpt = self.hosted_token(hid), self.exchange(self.code()).json()['access_token']
        manual = self.env[KEYS].with_user(user)._generate(
            'rpc', 'manual', datetime.datetime.now() + datetime.timedelta(days=1))
        self.hosted_keys(hid).with_user(user)._remove()  # the owner revokes Muse
        self.assertEqual(self.mcp(muse).status_code, 401)
        self.assertEqual(self.mcp(chatgpt).status_code, 200)
        self.assertEqual(self.mcp(manual).status_code, 200)
        # An administrator revokes another user's credential from that user's form.
        self.env[KEYS].search([('oauth_client_id', '=', CLIENT)])._remove()
        self.assertEqual(self.mcp(chatgpt).status_code, 401)
        self.assertEqual(self.mcp(manual).status_code, 200)

    def test_bulk_revoke_spares_lookalike_external_client(self):
        user = self.login()
        a, hid = self.hosted()
        token = self.hosted_token(hid)
        lookalike = 'https://evil.example.test/oauth/clients/%s.json' % a.uuid
        self.env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', CLIENT + '\n' + lookalike)
        other = self.env[KEYS].with_user(user)._generate(
            'mcp', 'OAuth: lookalike', datetime.datetime.now() + datetime.timedelta(days=1))
        self.env.cr.execute("UPDATE res_users_apikeys SET oauth_client_id = %s WHERE index = %s",
                            [lookalike, other[:8]])
        a.action_revoke_credentials()
        self.assertEqual(self.mcp(token).status_code, 401)
        self.assertEqual(self.mcp(other).status_code, 200)
