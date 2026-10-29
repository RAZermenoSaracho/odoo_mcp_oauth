{
    "name": "MCP OAuth",
    "version": "19.0.1.0.0",
    "category": "Uncategorized",
    "summary": "OAuth 2.1 authorization (PKCE, CIMD) for the odoo_mcp endpoint using native Odoo API keys",
    "description": """
MCP OAuth
=========

OAuth 2.1 authorization (PKCE, CIMD) for the odoo_mcp endpoint using native Odoo API keys
    """,
    "author": "Ricardo Zermeño",
    "license": "LGPL-3",
    "depends": ["base", "odoo_mcp", "web"],
    "data": [
        "security/ir.model.access.csv",
        "views/res_config_settings_views.xml",
        "views/oauth_templates.xml",
    ],
    "installable": True,
    "application": False,
}
