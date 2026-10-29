import datetime
import hashlib
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from odoo.tests import tagged
from odoo.tools.misc import hash_sign

from .common import CALLBACK, CHALLENGE, CLIENT, OAuthHttpCase


@tagged('post_install', '-at_install')
class TestToken(OAuthHttpCase):
    def test_happy_path_owner_scope_and_replay(self):
        user = self.login()
        code = self.code()
        generated_su = []
        key_model = type(self.env['res.users.apikeys'])
        original = key_model._generate

        def observe(record, *args):
            generated_su.append(record.env.su)
            return original(record, *args)

        with patch.object(key_model, '_generate', observe), \
                self.assertLogs('odoo.addons.odoo_mcp_oauth', 'INFO') as logs:
            response = self.exchange(code, scope='ignored')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(generated_su, [False])
        body = response.json()
        self.assertEqual(body['scope'], 'mcp')
        self.assertNotIn(code, '\n'.join(logs.output))
        self.assertNotIn(body['access_token'], '\n'.join(logs.output))
        self.assertEqual(body['token_type'], 'Bearer')
        self.assertGreaterEqual(body['expires_in'], 86400)
        self.assertEqual(response.headers['Cache-Control'], 'no-store')
        self.assertNotIn(body['access_token'], response.headers.get('Location', ''))
        self.assertEqual(self.mcp(body['access_token']).status_code, 200)
        record = self.env['res.users.apikeys'].sudo().search([('oauth_client_id', '=', CLIENT)], limit=1)
        self.assertEqual(record.user_id.id, user.id)
        self.assertEqual(record.scope, 'mcp')
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')
        record.invalidate_recordset()
        self.assertEqual(record.scope, 'odoo_mcp_oauth_revoked')
        self.assertEqual(self.mcp(body['access_token']).status_code, 401)
        self.assertTrue(record.oauth_code_hash)
        self.assertEqual(self.env['res.users.apikeys'].sudo().search_count([
            ('oauth_code_hash', '=', record.oauth_code_hash)]), 1)

    def test_invalid_bindings_and_expired_code(self):
        user = self.login()
        code = self.code()
        for changes in ({'code_verifier': 'wrong' * 10},
                        {'redirect_uri': CALLBACK + '/other'},
                        {'resource': 'https://other.example/mcp'},
                        {'client_id': 'https://other.example/client.json'}):
            self.assertEqual(self.exchange(code, **changes).json()['error'], 'invalid_grant')
        self.assertEqual(self.exchange(code, grant_type='refresh_token').json()['error'], 'unsupported_grant_type')
        self.assertEqual(self.exchange(code, client_secret='secret').status_code, 401)
        expired = hash_sign(self.env(su=True), 'odoo_mcp_oauth.code', {
            'uid': user.id, 'client_id': CLIENT, 'client_name': 'Example',
            'redirect_uri': CALLBACK, 'code_challenge': CHALLENGE,
            'resource': self.issuer + '/mcp', 'nonce': 'expired',
        }, expiration=datetime.datetime.now() - datetime.timedelta(seconds=1))
        self.assertEqual(self.exchange(expired).json()['error'], 'invalid_grant')

    def test_removed_client_and_archived_user(self):
        user = self.login()
        code = self.code()
        self.env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', '')
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')
        self.env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', CLIENT)
        user.active = False
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')

    def test_native_duration_for_settings_user(self):
        user = self.login('oauth_settings_user')
        user.group_ids = [(6, 0, [self.env.ref('base.group_user').id,
                                   self.env.ref('base.group_system').id])]
        token = self.exchange(self.code()).json()
        self.assertEqual(token['expires_in'], 30 * 86400)

    def test_admin_durations_and_expiration(self):
        self.authenticate('admin', 'admin')
        for duration in ('1', '30', '365', '0'):
            blob, csrf, _ = self.consent()
            response = self.decision(blob, csrf, duration=duration)
            code = parse_qs(urlsplit(response.headers['Location']).query)['code'][0]
            before = datetime.datetime.now()
            token = self.exchange(code).json()
            self.assertIn('access_token', token)
            record = self.env['res.users.apikeys'].sudo().search([
                ('oauth_code_hash', '=', hashlib.sha256(code.encode()).hexdigest())], limit=1)
            self.assertTrue(record)
            if duration == '0':
                self.assertFalse(record.expiration_date)
                self.assertNotIn('expires_in', token)
            else:
                days = int(duration)
                self.assertAlmostEqual((record.expiration_date - before).total_seconds(),
                                       days * 86400, delta=120)
                self.assertEqual(token['expires_in'], days * 86400)

    def test_token_ignores_duration_params(self):
        user = self.login('oauth_token_params')
        code = self.code()
        token = self.exchange(code, duration='0', expires_in='999999999').json()
        self.assertEqual(token['expires_in'], 30 * 86400)
        record = self.env['res.users.apikeys'].sudo().search([
            ('oauth_code_hash', '=', hashlib.sha256(code.encode()).hexdigest())], limit=1)
        self.assertEqual(record.user_id, user)
        self.assertTrue(record.expiration_date)

    def test_duration_cap_lowered_after_consent(self):
        user = self.login('oauth_cap_later')
        code = self.code()
        before = self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')])
        for group in user.all_group_ids:
            group.api_key_duration = 1
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')
        self.assertEqual(self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')]), before)

    def test_never_revoked_when_admin_rights_lost_before_exchange(self):
        user = self.login('oauth_admin_later')
        system = self.env.ref('base.group_system')
        user.group_ids = [(4, system.id)]
        blob, csrf, response = self.consent()
        self.assertIn('Never', response.text)
        response = self.decision(blob, csrf, duration='0')
        code = parse_qs(urlsplit(response.headers['Location']).query)['code'][0]
        user.group_ids = [(3, system.id)]
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')
        self.assertFalse(self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')]))

    def test_mcp_key_expiration_and_no_extension(self):
        user = self.login('oauth_mcp_expiration')
        code = self.code()
        token = self.exchange(code).json()
        record = self.env['res.users.apikeys'].sudo().search([
            ('oauth_code_hash', '=', hashlib.sha256(code.encode()).hexdigest())], limit=1)
        expiration = record.expiration_date
        self.assertEqual(self.mcp(token['access_token']).status_code, 200)
        record.invalidate_recordset()
        self.assertEqual(record.expiration_date, expiration)
        self.env.cr.execute("""UPDATE res_users_apikeys
                            SET expiration_date = now() - interval '1 minute'
                            WHERE id = %s""", [record.id])
        self.assertEqual(self.mcp(token['access_token']).status_code, 401)

    def test_portal_user_cannot_exchange_after_consent(self):
        user = self.login('oauth_portal_later')
        code = self.code()
        user.group_ids = [(6, 0, [self.env.ref('base.group_portal').id])]
        self.assertEqual(self.exchange(code).json()['error'], 'invalid_grant')

    def test_unique_violation_revokes_preseeded_key(self):
        user = self.login('oauth_replay_preseed')
        code = self.code()
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        key = self.env['res.users.apikeys'].with_user(user)._generate(
            'mcp', 'preseeded', datetime.datetime.now() + datetime.timedelta(days=1))
        record = self.env['res.users.apikeys'].sudo().search([
            ('name', '=', 'preseeded'), ('user_id', '=', user.id)], limit=1)
        self.assertTrue(record)
        record.write({'oauth_code_hash': code_hash, 'oauth_client_id': CLIENT})
        count = self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')])
        response = self.exchange(code)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_grant')
        record.invalidate_recordset()
        self.assertEqual(record.scope, 'odoo_mcp_oauth_revoked')
        self.assertEqual(record.oauth_code_hash, code_hash)
        self.assertEqual(self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')]), count - 1)

    def test_missing_replay_marker_rolls_back_key(self):
        user = self.login('oauth_missing_marker')
        code = self.code()
        key_model = type(self.env['res.users.apikeys'])
        original_generate = key_model._generate
        before = self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')])

        def unfindable(model, *args):
            # A key whose index prefix matches no row: the marker cannot be written.
            return 'z' * 8 + original_generate(model, *args)[8:]

        with patch.object(key_model, '_generate', unfindable):
            response = self.exchange(code)
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.json()['error'], 'server_error')
        self.assertEqual(self.env['res.users.apikeys'].sudo().search_count([
            ('user_id', '=', user.id), ('scope', '=', 'mcp')]), before)

    def test_signed_code_db_and_protocol_rejections(self):
        user = self.login('oauth_negative_token')
        code = self.code()
        wrong_db = hash_sign(self.env(su=True), 'odoo_mcp_oauth.code', {
            'uid': user.id, 'client_id': CLIENT, 'client_name': 'Example',
            'redirect_uri': CALLBACK, 'code_challenge': CHALLENGE,
            'resource': self.issuer + '/mcp', 'nonce': 'wrong-db',
            'db': 'another_database',
        }, expiration=datetime.timedelta(seconds=60))
        for bad_code in (wrong_db, 'ñ', 'not-a-signed-code', self.consent()[0]):
            response = self.exchange(bad_code)
            self.assertEqual(response.status_code, 400)
            self.assertEqual(response.json()['error'], 'invalid_grant')
        for changes in ({'redirect_uri': CALLBACK + '/other'},
                        {'resource': 'https://other.example.test/mcp'}):
            self.assertEqual(self.exchange(code, **changes).json()['error'], 'invalid_grant')
        from urllib.parse import urlencode
        params = {
            'grant_type': 'authorization_code', 'code': code, 'redirect_uri': CALLBACK,
            'client_id': CLIENT, 'code_verifier': 'v' * 43,
            'resource': self.issuer + '/mcp',
        }
        body = urlencode(params).encode()
        for headers in ({'Content-Type': 'application/x-www-form-urlencoded',
                         'Authorization': 'Basic Zm9vOmJhcg=='},):
            response = self.open('/oauth/token', data=body, headers=headers)
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.json()['error'], 'invalid_client')
        response = self.exchange(code, client_secret='secret')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.json()['error'], 'invalid_client')
        response = self.open('/oauth/token', data=body, headers={'Content-Type': 'application/json'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['error'], 'invalid_request')

    def test_settings_user_small_group_duration_cap(self):
        user = self.login('oauth_short_admin')
        for group in user.all_group_ids:
            group.api_key_duration = 0.25
        response = self.open(self.authorize_url())
        self.assertEqual(response.status_code, 303)
        self.assertEqual(parse_qs(urlsplit(response.headers['Location']).query)['error'],
                         ['access_denied'])
