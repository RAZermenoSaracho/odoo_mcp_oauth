import base64
import datetime
import hashlib
import hmac
import json
import logging
import re
import secrets
import time
from urllib.parse import urlencode, urlsplit

import requests
from psycopg2.errors import UniqueViolation
from werkzeug.exceptions import NotFound
from werkzeug.urls import url_quote

from odoo import http
from odoo.exceptions import ValidationError
from odoo.http import request
from odoo.tools import SQL
from odoo.tools.misc import hash_sign, verify_hash_signed
from odoo.addons.odoo_mcp.controllers.main import McpController
from odoo.addons.odoo_mcp.ratelimit import SlidingWindow
from odoo.addons.odoo_mcp_oauth.models.ir_http import client_ip, origin
from odoo.addons.odoo_mcp_oauth.models.oauth_client import CLIENT_PATH, UUID, redirect_uris
from odoo.addons.odoo_mcp_oauth.models.res_config_settings import CLIENT_IDS_PARAM, client_ids

_logger = logging.getLogger(__name__)

# ponytail: Per-worker ceilings multiply by worker count; edge rate limiting is the upgrade path.
TOKEN = SlidingWindow(30, 60)
AUTHORIZE = SlidingWindow(60, 60)
METADATA = SlidingWindow(120, 60)
SAFE_HEADERS = [
    ('X-Frame-Options', 'DENY'),
    ('Content-Security-Policy', "frame-ancestors 'none'"),
    ('Referrer-Policy', 'no-referrer'),
    ('Cache-Control', 'no-store'),
]
NO_STORE = [('Cache-Control', 'no-store')]
CHALLENGE = re.compile(r'^[A-Za-z0-9_-]{43}$')
VERIFIER = re.compile(r'^[A-Za-z0-9._~-]{43,128}$')
DURATIONS = [('1', '1 Day'), ('30', '1 Month'), ('365', '1 Year'), ('0', 'Never')]


def _limited(limiter, json_response=False):
    allowed, retry = limiter.check((request.db, client_ip()))
    if allowed:
        return None
    headers = [('Retry-After', str(retry)), *NO_STORE]
    if json_response:
        return request.make_json_response({'error': 'invalid_request'}, headers=headers, status=429)
    return request.make_response('Rate limit exceeded', headers=headers, status=429)


def _issuer():
    issuer = origin()
    if not issuer:
        raise NotFound()
    return issuer


def _hosted_record(issuer, client_id):
    """Active hosted client of this database for ``client_id``, resolved without any fetch."""
    prefix = issuer + CLIENT_PATH
    if not client_id.startswith(prefix) or not client_id.endswith('.json'):
        return None
    client_uuid = client_id[len(prefix):-len('.json')]
    if not UUID.fullmatch(client_uuid):
        return None
    # Public route and pre-consent lookup: read one active record by its exact identifier.
    return request.env['mcp.oauth.client'].sudo().search([('uuid', '=', client_uuid)], limit=1) or None


def _hosted_document(issuer, client_id):
    client = _hosted_record(issuer, client_id)
    if not client:
        return None
    return {
        'client_id': client_id,
        'client_name': client.name,
        'redirect_uris': redirect_uris(client.redirect_uris),
        'token_endpoint_auth_method': 'none',
        'grant_types': ['authorization_code'],
        'response_types': ['code'],
    }


def _is_allowed(client_id):
    """Allow-listed external CIMD URL, or an active hosted client of this issuer."""
    if not isinstance(client_id, str) or not client_id:
        return False
    if client_id in client_ids(request.env['ir.config_parameter'].sudo().get_param(CLIENT_IDS_PARAM)):
        return True
    issuer = origin()
    return bool(issuer and _hosted_record(issuer, client_id))


def _json_error(error, status=400):
    return request.make_json_response({'error': error}, headers=NO_STORE, status=status)


def _error_page():
    return request.render('odoo_mcp_oauth.error', headers=SAFE_HEADERS)


def _redirect(uri, values):
    separator = '&' if '?' in uri else '?'
    response = request.redirect(uri + separator + urlencode(values), code=303, local=False)
    response.headers.update(SAFE_HEADERS)
    return response


def _valid_user(user):
    return user.exists() and user.active and user._is_internal()


def _durations(user):
    allowed = dict(request.env['res.users.apikeys.description'].with_user(user)._selection_duration())
    return [(value, label) for value, label in DURATIONS if value in allowed]


LOOPBACK = {'localhost', '127.0.0.1', '::1'}


def _loopback(parts):
    return parts.scheme == 'http' and parts.hostname in LOOPBACK


def _redirect_matches(redirect_uri, registered):
    """Exact match, plus RFC 8252 7.3: a registered port-less loopback http URI matches any port."""
    if not isinstance(registered, list):
        return False
    if redirect_uri in registered:
        return True
    try:
        requested = urlsplit(redirect_uri)
        requested.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    if not _loopback(requested) or requested.username or requested.password or requested.fragment:
        return False
    for uri in registered:
        try:
            candidate = urlsplit(uri) if isinstance(uri, str) else None
            if (candidate and _loopback(candidate) and candidate.port is None
                    and not candidate.username and not candidate.password and not candidate.fragment
                    and (candidate.hostname, candidate.path, candidate.query)
                    == (requested.hostname, requested.path, requested.query)):
                return True
        except ValueError:
            continue
    return False


def _client_document(url, redirect_uri):
    try:
        client = urlsplit(url)
        callback = urlsplit(redirect_uri)
        if (client.scheme != 'https' or not client.hostname or not callback.hostname
                or (callback.scheme != 'https' and not _loopback(callback))):
            return None
        response = requests.get(url, timeout=5, allow_redirects=False, stream=True,
                                headers={'Accept': 'application/json'})
        if response.status_code != 200:
            return None
        data = bytearray()
        deadline = time.monotonic() + 5  # requests' timeout is per socket read, not total
        for chunk in response.iter_content(chunk_size=8192):
            data.extend(chunk)
            if len(data) > 65536 or time.monotonic() > deadline:
                return None
        document = json.loads(data)
        if not isinstance(document, dict) or document.get('client_id') != url:
            return None
        if not _redirect_matches(redirect_uri, document.get('redirect_uris')):
            return None
        return document
    except (requests.RequestException, ValueError, TypeError, UnicodeError):
        return None
    finally:
        if 'response' in locals():
            response.close()


class OAuthController(McpController):

    @http.route(auth='mcp_oauth')
    def mcp(self):
        return super().mcp()

    @http.route('/.well-known/oauth-authorization-server', type='http', auth='none',
                methods=['GET'], csrf=False, sitemap=False, save_session=False)
    def authorization_server(self):
        if response := _limited(METADATA):
            return response
        issuer = _issuer()
        return request.make_json_response({
            'issuer': issuer,
            'authorization_endpoint': issuer + '/oauth/authorize',
            'token_endpoint': issuer + '/oauth/token',
            'response_types_supported': ['code'],
            'grant_types_supported': ['authorization_code'],
            'code_challenge_methods_supported': ['S256'],
            'token_endpoint_auth_methods_supported': ['none'],
            'scopes_supported': ['mcp'],
            'client_id_metadata_document_supported': True,
            'authorization_response_iss_parameter_supported': True,
        }, headers=NO_STORE)

    @http.route(['/.well-known/oauth-protected-resource',
                 '/.well-known/oauth-protected-resource/mcp'], type='http', auth='none',
                methods=['GET'], csrf=False, sitemap=False, save_session=False)
    def protected_resource(self):
        if response := _limited(METADATA):
            return response
        issuer = _issuer()
        return request.make_json_response({
            'resource': issuer + '/mcp',
            'authorization_servers': [issuer],
            'scopes_supported': ['mcp'],
            'bearer_methods_supported': ['header'],
        }, headers=NO_STORE)

    @http.route('/oauth/clients/<string:client_file>', type='http', auth='none',
                methods=['GET'], csrf=False, sitemap=False, save_session=False)
    def hosted_client(self, client_file):
        if response := _limited(METADATA, json_response=True):
            return response
        issuer = _issuer()
        document = _hosted_document(issuer, issuer + CLIENT_PATH + client_file)
        if not document:
            raise NotFound()
        return request.make_json_response(document, headers=NO_STORE)

    @http.route('/oauth/authorize', type='http', auth='public', methods=['GET'],
                sitemap=False, website=True)
    def authorize(self, **kw):
        if response := _limited(AUTHORIZE):
            return response
        issuer = _issuer()
        client_id = kw.get('client_id')
        redirect_uri = kw.get('redirect_uri')
        missing = [key for key in ('redirect_uri', 'code_challenge', 'code_challenge_method', 'resource')
                   if not kw.get(key)]
        if not _is_allowed(client_id) or kw.get('response_type') != 'code' or missing:
            # Names only, never values: enough to see what a new client actually sends.
            _logger.info('OAuth authorize rejected: client allowed=%s, response_type ok=%s, missing=%s',
                         _is_allowed(client_id), kw.get('response_type') == 'code', missing)
            return _error_page()
        if request.env.user._is_public():
            local_url = request.httprequest.full_path.rstrip('?')
            return request.redirect('/web/login?redirect=' + url_quote(local_url, safe=''), code=303)
        hosted = client_id.startswith(issuer + CLIENT_PATH)
        # Hosted IDs are resolved from this database only, never fetched.
        document = (_hosted_document(issuer, client_id) if hosted
                    else _client_document(client_id, redirect_uri))
        if not document or not _redirect_matches(redirect_uri, document['redirect_uris']):
            _logger.info('OAuth authorize rejected: unknown client document or redirect_uri mismatch')
            return _error_page()
        state = kw.get('state', '')
        if (kw.get('code_challenge_method') != 'S256'
                or not CHALLENGE.fullmatch(kw['code_challenge'])
                or kw['resource'] != issuer + '/mcp'):
            _logger.info('OAuth authorize rejected: S256 ok=%s, challenge ok=%s, resource ok=%s',
                         kw.get('code_challenge_method') == 'S256',
                         bool(CHALLENGE.fullmatch(kw['code_challenge'])), kw['resource'] == issuer + '/mcp')
            return _redirect(redirect_uri, {'error': 'invalid_request',
                                            'error_description': 'Invalid authorization request',
                                            'state': state, 'iss': issuer})
        user = request.env.user
        if not _valid_user(user):
            return _redirect(redirect_uri, {'error': 'access_denied', 'state': state, 'iss': issuer})
        durations = _durations(user)
        if not durations:
            return _redirect(redirect_uri, {'error': 'access_denied', 'state': state, 'iss': issuer})
        name = document.get('client_name')
        if not isinstance(name, str) or not name:
            name = urlsplit(client_id).hostname
        values = {
            'uid': user.id, 'client_id': client_id, 'client_name': name,
            'redirect_uri': redirect_uri, 'code_challenge': kw['code_challenge'],
            'resource': kw['resource'], 'state': state, 'db': request.db,
        }
        # The signing secret is system-only; the rest of the request keeps the user's ACLs.
        consent = hash_sign(request.env(su=True), 'odoo_mcp_oauth.consent', values,
                            expiration=datetime.timedelta(minutes=10))
        return request.render('odoo_mcp_oauth.consent', {
            'client_name': name,
            # A hosted Client ID names this server; show where the code will go instead.
            'client_host': urlsplit(redirect_uri if hosted else client_id).hostname,
            'database': request.db, 'user_name': user.name,
            'durations': durations, 'default_duration': '30' if '30' in dict(durations) else durations[0][0],
            'consent': consent,
        }, headers=SAFE_HEADERS)

    @http.route('/oauth/authorize', type='http', auth='user', methods=['POST'],
                csrf=True, sitemap=False, website=True, max_content_length=16 * 1024, readonly=False)
    def authorize_post(self, **kw):
        if response := _limited(AUTHORIZE):
            return response
        issuer = _issuer()
        try:
            # Signature verification needs database.secret, which is system-only.
            values = verify_hash_signed(request.env(su=True), 'odoo_mcp_oauth.consent',
                                        kw.get('consent', ''))
        except (TypeError, ValueError, UnicodeError):
            values = None
        if (not isinstance(values, dict) or values.get('uid') != request.env.uid
                or not _is_allowed(values.get('client_id'))
                or not _valid_user(request.env.user)
                or kw.get('decision') not in ('approve', 'deny')
                or not all(key in values for key in (
                    'redirect_uri', 'code_challenge', 'resource', 'client_name'))
                or values.get('resource') != issuer + '/mcp'
                or values.get('db') != request.db):
            return _error_page()
        redirect_uri = values['redirect_uri']
        state = values.get('state', '')
        if kw['decision'] == 'deny':
            return _redirect(redirect_uri, {'error': 'access_denied', 'state': state, 'iss': issuer})
        if kw.get('duration') not in dict(_durations(request.env.user)):
            return _error_page()
        code_values = {key: values[key] for key in (
            'uid', 'client_id', 'client_name', 'redirect_uri', 'code_challenge', 'resource', 'db')}
        code_values['duration'] = kw['duration']
        code_values['nonce'] = secrets.token_urlsafe(16)
        code = hash_sign(request.env(su=True), 'odoo_mcp_oauth.code', code_values,
                         expiration=datetime.timedelta(seconds=60))
        return _redirect(redirect_uri, {'code': code, 'state': state, 'iss': issuer})

    @http.route('/oauth/token', type='http', auth='none', methods=['POST'], csrf=False,
                sitemap=False, save_session=False, max_content_length=16 * 1024, readonly=False)
    def token(self, **kw):
        if response := _limited(TOKEN, json_response=True):
            return response
        issuer = _issuer()
        if (request.httprequest.content_length or 0) > 16 * 1024:
            return _json_error('invalid_request')
        if request.httprequest.mimetype != 'application/x-www-form-urlencoded':
            return _json_error('invalid_request')
        if kw.get('grant_type') != 'authorization_code':
            return _json_error('unsupported_grant_type')
        if request.httprequest.headers.get('Authorization') or kw.get('client_secret'):
            return _json_error('invalid_client', 401)
        if any(not kw.get(key) for key in ('code', 'redirect_uri', 'client_id', 'code_verifier', 'resource')):
            return _json_error('invalid_request')
        if not VERIFIER.fullmatch(kw['code_verifier']):
            return _json_error('invalid_grant')
        try:
            # Signature verification needs database.secret, which is system-only.
            values = verify_hash_signed(request.env(su=True), 'odoo_mcp_oauth.code', kw['code'])
        except (TypeError, ValueError, UnicodeError):
            values = None
        if not isinstance(values, dict):
            return _json_error('invalid_grant')
        if (any(values.get(key) != kw[key] for key in ('client_id', 'redirect_uri', 'resource'))
                or values.get('resource') != issuer + '/mcp'
                or values.get('db') != request.db
                or not _is_allowed(values['client_id'])):
            return _json_error('invalid_grant')
        challenge = base64.urlsafe_b64encode(hashlib.sha256(kw['code_verifier'].encode()).digest()).decode().rstrip('=')
        if not hmac.compare_digest(challenge, values.get('code_challenge', '')):
            return _json_error('invalid_grant')
        uid = values.get('uid')
        user = request.env['res.users'].sudo().browse(uid) if isinstance(uid, int) else request.env['res.users']
        if not _valid_user(user):
            return _json_error('invalid_grant')
        duration = values.get('duration')
        if duration not in dict(_durations(user)):
            return _json_error('invalid_grant')
        days = int(duration)
        now = datetime.datetime.now()
        expiration = now + datetime.timedelta(days=days) if days else None
        code_hash = hashlib.sha256(kw['code'].encode()).hexdigest()
        try:
            with request.env.cr.savepoint():
                # _generate reads env.user and checks the owner's native duration limit.
                key = request.env['res.users.apikeys'].with_user(uid)._generate(
                    'mcp', 'OAuth: ' + str(values.get('client_name') or urlsplit(values['client_id']).hostname),
                    expiration)
                # Core's `index` column is not an ORM field (declaring it would make this
                # addon own it, and uninstall would drop it), so use plain SQL like core.
                request.env.cr.execute(SQL(
                    """UPDATE res_users_apikeys SET oauth_client_id = %s, oauth_code_hash = %s
                        WHERE id = (SELECT id FROM res_users_apikeys
                                     WHERE index = %s AND user_id = %s AND scope = 'mcp'
                                       AND oauth_code_hash IS NULL
                                  ORDER BY id DESC LIMIT 1)
                    RETURNING id""",
                    values['client_id'], code_hash, key[:8], uid))
                if request.env.cr.rowcount != 1:
                    # Without the marker the code would stay replayable: issue nothing.
                    raise ValueError('issued key not found')
        except ValidationError:
            return _json_error('invalid_grant')
        except ValueError:
            # The savepoint already rolled the unmarked key back.
            _logger.error('OAuth key issued without a replay marker was rolled back')
            return _json_error('server_error', 500)
        except UniqueViolation:
            # Odoo transactions are REPEATABLE READ: a concurrent winner committed after
            # this request began is invisible here, so revoke through a fresh cursor
            # (which also keeps the revocation if this request rolls back).
            # Plain SQL like core's own API-key code (the table is _auto=False).
            with request.env.registry.cursor() as cr:
                cr.execute(SQL(
                    'UPDATE res_users_apikeys SET scope = %s WHERE oauth_code_hash = %s RETURNING id',
                    'odoo_mcp_oauth_revoked', code_hash))
                revoked = cr.rowcount
            request.env.registry.clear_cache()
            _logger.info('OAuth code replay: client host %s, uid %s, revoked %s key(s)',
                         urlsplit(values['client_id']).hostname, uid, revoked)
            return _json_error('invalid_grant')
        _logger.info('OAuth key issued: client host %s, uid %s', urlsplit(values['client_id']).hostname, uid)
        result = {'access_token': key, 'token_type': 'Bearer', 'scope': 'mcp'}
        if expiration:
            result['expires_in'] = int((expiration - now).total_seconds())
        return request.make_json_response(result, headers=NO_STORE)
