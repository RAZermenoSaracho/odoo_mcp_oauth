import re

from werkzeug.exceptions import Unauthorized
from werkzeug.wrappers import Response

from odoo import models
from odoo.http import request
from odoo.tools import config


def origin():
    """Return ``https://<host>`` for this request, or None when it is not HTTPS.

    Core only runs ProxyFix when X-Forwarded-Host is present; proxies such as
    cloudflared send the original Host plus X-Forwarded-Proto instead. Under
    ``proxy_mode`` (the same trust Odoo already gives those headers) the
    forwarded scheme is honoured. The host is the one dbfilter used.
    """
    httprequest = request.httprequest
    scheme = httprequest.scheme
    if config['proxy_mode']:
        forwarded = httprequest.headers.get('X-Forwarded-Proto', '').split(',')[-1].strip().lower()
        scheme = forwarded or scheme
    if scheme != 'https' or not request.db:
        return None
    return f'https://{httprequest.host}'


def client_ip():
    httprequest = request.httprequest
    if config['proxy_mode'] and not httprequest.headers.get('X-Forwarded-Host'):
        # Same choice as core's ProxyFix(x_for=1): the address the proxy appended.
        forwarded = httprequest.headers.get('X-Forwarded-For', '').split(',')[-1].strip()
        if forwarded:
            return forwarded
    return httprequest.remote_addr


class IrHttp(models.AbstractModel):
    _inherit = 'ir.http'

    @classmethod
    def _auth_method_mcp_oauth(cls):
        request.session.can_save = False
        match = re.match(r'^Bearer\s+(.+)$', request.httprequest.headers.get('Authorization', ''), re.I)
        token = match.group(1) if match else None
        uid = None
        if token:
            keys = request.env['res.users.apikeys']
            uid = keys._check_credentials(scope='mcp', key=token)
            if not uid:
                uid = keys._check_credentials(scope='rpc', key=token)
        if not uid:
            params = []
            if issuer := origin():
                params += [f'resource_metadata="{issuer}/.well-known/oauth-protected-resource/mcp"',
                           'scope="mcp"']
            if token:
                params.append('error="invalid_token"')
            # Built by hand: werkzeug leaves token values unquoted, RFC 6750 examples quote them.
            raise Unauthorized(response=Response(
                status=401, headers={'WWW-Authenticate': ' '.join(['Bearer', ', '.join(params)]).strip()}))
        request.update_env(user=uid)
