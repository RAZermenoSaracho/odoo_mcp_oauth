from urllib.parse import urlsplit

from odoo import fields, models


CLIENT_IDS_PARAM = 'odoo_mcp_oauth.client_ids'


def client_ids(value):
    result = set()
    for line in (value or '').splitlines():
        url = line.strip()
        try:
            parsed = urlsplit(url)
        except ValueError:
            continue
        if parsed.scheme == 'https' and parsed.hostname and not parsed.username:
            result.add(url)
    return result


class ResConfigSettings(models.TransientModel):
    _inherit = 'res.config.settings'

    mcp_oauth_client_ids = fields.Char(
        string='OAuth client metadata URLs',
        config_parameter=CLIENT_IDS_PARAM,
        help='One exact HTTPS client metadata URL per line.',
    )

    def set_values(self):
        previous = client_ids(self.env['ir.config_parameter'].sudo().get_param(CLIENT_IDS_PARAM))
        removed = previous - client_ids(self.mcp_oauth_client_ids)
        result = super().set_values()
        if removed:
            self.env['res.users.apikeys'].sudo().search([
                ('oauth_client_id', 'in', list(removed)),
            ]).unlink()
            self.env.registry.clear_cache()
        return result
