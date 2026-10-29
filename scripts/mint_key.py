"""Run with: odoo-bin shell -d DB < scripts/mint_key.py (disposable DB only).

Prints keys and signed authorization codes for scripts/isolation_check.py.
"""
import base64
import datetime
import hashlib
import secrets

from odoo.tools.misc import hash_sign

CLIENT = 'https://client.example.test/client.json'
CALLBACK = 'https://client.example.test/cb'

admin = env.ref('base.user_admin')
keys = env['res.users.apikeys'].with_user(admin)
expiry = datetime.datetime.now() + datetime.timedelta(days=1)
env['ir.config_parameter'].sudo().set_param('odoo_mcp_oauth.client_ids', CLIENT)
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
print('mcp=' + keys._generate('mcp', 'isolation', expiry))
print('legacy=' + keys._generate(None, 'isolation legacy', expiry))
print('verifier=' + verifier)
for name in ('code', 'code2'):
    # Longer than the addon's 60 s so the check script has time to run.
    print(name + '=' + hash_sign(env(su=True), 'odoo_mcp_oauth.code', {
        'uid': admin.id, 'client_id': CLIENT, 'client_name': 'Isolation',
        'redirect_uri': CALLBACK, 'code_challenge': challenge,
        'resource': f'https://{env.cr.dbname}.example.test/mcp',
        'nonce': secrets.token_urlsafe(16), 'db': env.cr.dbname, 'duration': '1',
    }, expiration=datetime.timedelta(minutes=10)))
env.cr.commit()
