from odoo import fields, models
from odoo.tools import SQL


class ResUsersApikeys(models.Model):
    _inherit = 'res.users.apikeys'

    oauth_client_id = fields.Char(readonly=True, index=True)
    oauth_code_hash = fields.Char(readonly=True)
    _oauth_code_hash_unique = models.Constraint(
        'UNIQUE(oauth_code_hash)', 'An OAuth code can be exchanged only once.')

    def init(self):
        super().init()
        # Core API keys use _auto=False, so their extension columns and constraint
        # need explicit DDL after core creates the table.
        table = SQL.identifier(self._table)
        self.env.cr.execute(SQL(
            'ALTER TABLE %(table)s ADD COLUMN IF NOT EXISTS oauth_client_id varchar',
            table=table))
        self.env.cr.execute(SQL(
            'ALTER TABLE %(table)s ADD COLUMN IF NOT EXISTS oauth_code_hash varchar',
            table=table))
        self.env.cr.execute(SQL(
            'CREATE INDEX IF NOT EXISTS %(index)s ON %(table)s (oauth_client_id)',
            index=SQL.identifier(self._table + '_oauth_client_id_idx'), table=table))
        self._add_sql_constraints()
