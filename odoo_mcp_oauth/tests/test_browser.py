from unittest.mock import patch

from odoo.http import request
from odoo.tests import tagged

from .common import OAuthHttpCase

MAIN = 'odoo.addons.odoo_mcp_oauth.controllers.main.'
# Wait for public interactions, pick a duration, then approve.
APPROVE = """(async () => {
    await new Promise(resolve => setTimeout(resolve, 1500));
    const select = document.querySelector("select[name='duration']");
    if (select) { select.value = '%s'; }
    [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Approve').click();
})()"""
DENY = """(async () => {
    await new Promise(resolve => setTimeout(resolve, 1500));
    [...document.querySelectorAll('button')].find(b => b.textContent.trim() === 'Deny').click();
})()"""


@tagged('post_install', '-at_install')
class TestConsentBrowser(OAuthHttpCase):
    """The consent form as a real browser submits it, public JS included."""

    def decision_in_browser(self, decision, duration='30'):
        self.env['res.users'].create({
            'name': 'oauth_browser', 'login': 'oauth_browser', 'password': 'oauth_browser',
            'group_ids': [(6, 0, [self.env.ref('base.group_user').id])],
        })
        seen = []

        def redirect(uri, values):
            seen.append(dict(values))
            signal = ('test successful' if 'code' in values or values.get('error') == 'access_denied'
                      else 'unexpected redirect')
            return request.make_response(f"<script>console.log('{signal}')</script>")

        def error_page():
            return request.make_response("<script>console.error('oauth error page')</script>")

        # The browser cannot send X-Forwarded-Proto; the issuer is the test host.
        with patch(MAIN + 'origin', return_value=self.issuer), \
                patch(MAIN + '_redirect', side_effect=redirect), \
                patch(MAIN + '_error_page', side_effect=error_page):
            script = APPROVE % duration if decision == 'approve' else DENY
            self.browser_js(self.authorize_url(), script, login='oauth_browser', timeout=30)
        return seen[-1]

    def test_browser_approve_issues_code(self):
        values = self.decision_in_browser('approve', '1')
        self.assertEqual(values['state'], 'state-123')
        self.assertEqual(values['iss'], self.issuer)
        with patch(MAIN + 'origin', return_value=self.issuer):
            response = self.exchange(values['code'])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['expires_in'], 86400)

    def test_browser_approve_one_month(self):
        values = self.decision_in_browser('approve', '30')
        with patch(MAIN + 'origin', return_value=self.issuer):
            response = self.exchange(values['code'])
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['expires_in'], 30 * 86400)

    def test_browser_deny(self):
        values = self.decision_in_browser('deny')
        self.assertEqual(values['error'], 'access_denied')
        self.assertEqual(values['state'], 'state-123')
