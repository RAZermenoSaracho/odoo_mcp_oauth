import re
from urllib.parse import parse_qs, urlencode, urlsplit

from odoo import http
from odoo.tests import tagged

from .common import CLIENT, OAuthHttpCase


@tagged('post_install', '-at_install')
class TestLifecycle(OAuthHttpCase):
    def test_settings_removal_deletes_client_keys(self):
        self.login()
        token = self.exchange(self.code()).json()['access_token']
        settings = self.env['res.config.settings'].create({'mcp_oauth_client_ids': ''})
        settings.set_values()
        self.assertFalse(self.env['res.users.apikeys'].sudo().search([
            ('oauth_client_id', '=', CLIENT)]))
        self.assertEqual(self.mcp(token).status_code, 401)

    def test_autovacuum_keeps_replay_marker(self):
        self.login()
        code = self.code()
        self.assertEqual(self.exchange(code).status_code, 200)
        keys = self.env['res.users.apikeys'].sudo()
        # Core GC only drops expired keys; the issued key outlives the 60 s code.
        keys._gc_user_apikeys()
        self.assertEqual(keys.search_count([('oauth_client_id', '=', CLIENT)]), 1)
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')
        self.assertEqual(keys.search_count([('oauth_client_id', '=', CLIENT)]), 1)

    def test_real_login_rotates_session_and_returns_to_consent(self):
        self.env['res.users'].create({
            'name': 'oauth_login', 'login': 'oauth_login', 'password': 'oauth_login',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        self.authenticate(None, None)  # anonymous session, as core's login tests do
        login_url = self.open(self.authorize_url()).headers['Location']
        before = self.opener.cookies.get('session_id')
        redirect = parse_qs(urlsplit(login_url).query)['redirect'][0]
        # Plain test transport: an https-forwarded response would mark the cookie Secure.
        response = self.open('/web/login', data=urlencode({
            'login': 'oauth_login', 'password': 'oauth_login',
            'csrf_token': http.Request.csrf_token(self), 'redirect': redirect,
        }).encode(), headers={'Content-Type': 'application/x-www-form-urlencoded'}, secure=False)
        self.assertEqual(response.status_code, 303)
        self.assertNotEqual(self.opener.cookies.get('session_id'), before)
        back = urlsplit(response.headers['Location'])
        self.assertEqual(back.path, '/oauth/authorize')
        consent = self.open(back.path + '?' + back.query)
        self.assertEqual(consent.status_code, 200)
        self.assertIn('name="consent"', consent.text)

    def test_owns_no_core_apikey_columns(self):
        # Uninstall drops columns of fields this addon owns; core's own columns
        # (index, key, ...) must never be among them or every API key would break.
        owned = self.env['ir.model.data'].sudo().search([
            ('module', '=', 'odoo_mcp_oauth'), ('model', '=', 'ir.model.fields')])
        names = set(self.env['ir.model.fields'].sudo().browse(owned.mapped('res_id')).filtered(
            lambda field: field.model == 'res.users.apikeys').mapped('name'))
        # `id`/`display_name` are shared with base, so uninstall keeps them.
        self.assertEqual(names - {'id', 'display_name'}, {'oauth_client_id', 'oauth_code_hash'})

    def test_native_key_removal_revokes_oauth_token(self):
        user = self.login()
        token = self.exchange(self.code()).json()['access_token']
        key = self.env['res.users.apikeys'].with_user(user).search([('oauth_client_id', '=', CLIENT)])
        key._remove()  # what Preferences > Account Security > API Keys calls
        self.assertEqual(self.mcp(token).status_code, 401)
