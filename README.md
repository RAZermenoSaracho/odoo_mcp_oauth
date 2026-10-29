# MCP OAuth for Odoo 19

Install `odoo_mcp`, then install `odoo_mcp_oauth` in each database where OAuth is wanted. The addon extends `/mcp` with OAuth 2.1 authorization code and PKCE using native Odoo login and API keys.

Requirements: Odoo 19 Community, the [`odoo_mcp` addon](https://github.com/RAZermenoSaracho/odoo_mcp) on the addons path, and Python `requests` (ships with Odoo).

In Settings → MCP OAuth, enter one exact HTTPS Client ID Metadata Document (CIMD) URL per line. For ChatGPT, use `https://chatgpt.com/oauth/client.json`. The callback URL comes from that document and must match the request exactly. An empty list disables new authorizations.

The public origin must be HTTPS. Enable Odoo `proxy_mode` and configure `dbfilter` so the request host selects the intended database. A trusted proxy may send `X-Forwarded-Host` and `X-Forwarded-Proto`, or preserve the public `Host` and send `X-Forwarded-Proto: https` without `X-Forwarded-Host`. Odoo must be reachable only through that trusted proxy because it trusts forwarded headers in proxy mode. In multi-host deployments, have the edge remove client-supplied `X-Forwarded-Host` and `Forwarded` headers: Odoo's ProxyFix trusts them for host and database selection. The issuer and MCP resource use the resulting request host (`https://<host>` and `https://<host>/mcp`). Database headers do not select the OAuth issuer.

## Security model

OAuth tokens are native API keys owned by the consenting user; Odoo ACLs and record rules apply. Legacy `rpc` and global API keys remain accepted on `/mcp` for existing bearer clients. Consent shows the client, database, and user; approve only requests you started. The user chooses 1 Day, 1 Month, 1 Year, or Never. Odoo offers Never only to system administrators because only they can hold non-expiring keys; such a key lasts until deleted. Other options are limited by the user's group API key duration (90 days for internal users by default, so 1 Day and 1 Month).

The choice is signed into the authorization code, checked again at exchange, and stored as the key's expiration date; clients cannot change it, and use never extends it. Users can revoke keys in Preferences → Account Security → API Keys. Removing a client URL through Settings → MCP OAuth deletes keys issued to that client; editing `ir.config_parameter` directly does not revoke them. Reusing an authorization code revokes the key issued on its first exchange, so a client network retry of `/oauth/token` revokes its token and requires reauthorization. Deleting a key within the code's 60-second lifetime lets the code holder exchange it again if they have its PKCE verifier. Parallel exchanges rely on the database unique constraint: the loser rolls back its new key, then revokes the winner. Verify this with two concurrent requests on a disposable server before production use.

OAuth metadata, authorization, and token endpoints have per-worker rate limits (120, 60, and 30 requests per minute respectively, keyed by database and IP). With N workers the effective ceiling can be N times each limit; add edge rate limiting if a global ceiling is required.

Run addon tests only on a disposable database, for example: `odoo-bin -d <disposable_db> -i odoo_mcp,odoo_mcp_oauth --test-enable --stop-after-init`. Browser tests in `tests/test_browser.py` need Chrome and the `websocket-client` package; without them Odoo reports them as skipped, not failed. For two disposable databases, mint keys using `odoo-bin shell -d <disposable_db> < scripts/mint_key.py`, then run `python3 scripts/isolation_check.py --base http://127.0.0.1:<port> --db-a <disposable_db_a> --db-b <disposable_db_b> --key-a <key_a> --key-b <key_b> --legacy-key-a <legacy_key_a>`.

No refresh tokens, dynamic client registration, or manual client configuration are provided. Removing this addon restores the original `/mcp` bearer behavior; unexpired `mcp` keys then become inert and expire through core autovacuum. Before production use, validate the actual connector flow, callback, and refresh behavior on a disposable database.

## Troubleshooting

- Metadata returns 404: the origin is not HTTPS (check `proxy_mode` and `X-Forwarded-Proto`), or `dbfilter` did not resolve a database.
- Consent shows "Authorization unavailable": the client is not allow-listed, the redirect URI is absent from the client document, or the document fetch failed.
- `/oauth/token` returns `invalid_grant`: the code is older than 60 seconds, was reused, has the wrong PKCE verifier or resource, or the user's allowed durations changed.
- Browser tests are skipped: Chrome or `websocket-client` is missing.
