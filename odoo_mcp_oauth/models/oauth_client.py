import re
import uuid
from urllib.parse import urlsplit

from odoo import _, api, fields, models
from odoo.exceptions import AccessError, ValidationError
from odoo.http import request

from .ir_http import origin
from .res_config_settings import CLIENT_IDS_PARAM, client_ids

CLIENT_PATH = '/oauth/clients/'
UUID = re.compile(r'^[0-9a-f]{32}$')


def redirect_uris(value):
    return [line.strip() for line in (value or '').splitlines() if line.strip()]


def valid_redirect_uri(uri):
    try:
        parsed = urlsplit(uri)
    except ValueError:
        return False
    return (len(uri) <= 2048 and parsed.scheme == 'https' and bool(parsed.hostname)
            and parsed.username is None and parsed.password is None
            and not parsed.fragment and not re.search(r'[\s\\#]', uri))


class McpOauthClient(models.Model):
    _name = 'mcp.oauth.client'
    _description = 'Hosted MCP OAuth client'
    _order = 'name, id'

    name = fields.Char(required=True)
    active = fields.Boolean(default=True)
    redirect_uris = fields.Text(
        string='Redirect URIs', required=True,
        help='One exact HTTPS callback URL per line, as the client sends it.')
    uuid = fields.Char(
        string='Identifier', required=True, readonly=True, copy=False, index=True,
        default=lambda self: uuid.uuid4().hex)
    client_id = fields.Char(
        string='Client ID', compute='_compute_client_id',
        help='Enter this exact value as the OAuth Client ID in the MCP client. '
             'It uses the host you are browsing on, so open this form on the host the client will use.')

    _uuid_unique = models.Constraint('UNIQUE(uuid)', 'The client identifier must be unique.')

    def _compute_client_id(self):
        issuer = origin() if request else None
        for client in self:
            client.client_id = issuer + CLIENT_PATH + client.uuid + '.json' if issuer and client.uuid else False

    @api.constrains('redirect_uris')
    def _check_redirect_uris(self):
        for client in self:
            uris = redirect_uris(client.redirect_uris)
            if not uris or not all(valid_redirect_uri(uri) for uri in uris):
                raise ValidationError(_(
                    'Redirect URIs must be absolute HTTPS URLs with a host, without user info or fragment.'))

    @api.constrains('uuid')
    def _check_uuid(self):
        if any(not UUID.fullmatch(client.uuid or '') for client in self):
            raise ValidationError(_('Invalid client identifier.'))

    def write(self, vals):
        if 'uuid' in vals and any(client.uuid != vals['uuid'] for client in self):
            raise ValidationError(_('The client identifier cannot be changed.'))
        return super().write(vals)

    def _attributed_keys(self):
        """API keys issued to these hosted clients, matched on the stored Client ID."""
        external = list(client_ids(self.env['ir.config_parameter'].sudo().get_param(CLIENT_IDS_PARAM)))
        keys = self.env['res.users.apikeys']
        for client in self:
            # The uuid is 32 hex chars, so it carries no LIKE wildcard; allow-listed
            # external URLs are excluded so no external client can ever match.
            keys |= keys.search([
                ('oauth_client_id', '=like', 'https://%' + CLIENT_PATH + client.uuid + '.json'),
                ('oauth_client_id', 'not in', external),
            ])
        return keys

    def _revoke_credentials(self):
        if not self.env.is_system():
            raise AccessError(_('Only administrators can revoke OAuth client credentials.'))
        # Core removal: system check, audit log, unlink and credential cache clear.
        self._attributed_keys()._remove()

    def action_revoke_credentials(self):
        self._revoke_credentials()
        return True

    def unlink(self):
        self._revoke_credentials()
        return super().unlink()
