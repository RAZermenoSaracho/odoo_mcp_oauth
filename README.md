# MCP OAuth for Odoo 19

Install `odoo_mcp`, then install `odoo_mcp_oauth` in each database where OAuth is wanted. The addon extends `/mcp` with OAuth 2.1 authorization code and PKCE using native Odoo login and API keys.

Requirements: Odoo 19 Community, the [`odoo_mcp` addon](https://github.com/RAZermenoSaracho/odoo_mcp) on the addons path, and Python `requests` (ships with Odoo).

In Settings → MCP OAuth, enter one exact HTTPS Client ID Metadata Document (CIMD) URL per line. For ChatGPT, use `https://chatgpt.com/oauth/client.json`. The callback URL comes from that document and must match the request exactly. An empty list disables new authorizations.

### Authentication methods

`/mcp` accepts two kinds of bearer token, side by side:

1. **API keys (unchanged).** Create one in Preferences → Account Security → New API Key and send it as `Authorization: Bearer <key>`. Keys with `rpc`, `mcp` or no scope work. Existing integrations need no change.
2. **OAuth (Authorization Code + PKCE S256)** for MCP clients that support it. The resulting token is also a native API key named `OAuth: <client>`, owned by the user who consented. It is listed and revocable in Users → [user] → Security, next to the manual keys.

Revoking either kind never affects the other.

### Claude

Claude uses Anthropic's published client metadata documents, so no hosted client is needed. Allow-list the one(s) you use in Settings → MCP OAuth:

- claude.ai and Claude Desktop: `https://claude.ai/oauth/mcp-oauth-client-metadata` (callback `https://claude.ai/api/mcp/auth_callback`)
- Claude Code: `https://claude.ai/oauth/claude-code-client-metadata` (callbacks `http://localhost/callback` and `http://127.0.0.1/callback`). The CLI listens on a random local port, and loopback callbacks match on any port, per RFC 8252.

Then add the server as a connector:

- In claude.ai: Settings → Connectors → Add custom connector, URL `https://<host>/mcp`, then choose to use Claude's published identity.
- In Claude Code: `claude mcp add --transport http <name> https://<host>/mcp`, then run `/mcp` to authenticate.

There are no refresh tokens. When the key you chose at consent expires or is revoked, Claude asks you to authorize again. Claude reaches the server from `160.79.104.0/21` over IPv4, so edge rules must allow that range on `/.well-known/*`, `/oauth/*` and `/mcp`. End-to-end use with a real Claude client is not yet verified for this addon.

### Hosted clients

Some clients, such as Meta AI Muse, publish no metadata document and ask for an OAuth Client ID instead. For those, open Settings → MCP OAuth → Manage hosted clients and create a client with a name and its exact HTTPS callback URLs, one per line. Odoo serves its document at `https://<host>/oauth/clients/<uuid>.json`. That URL is the Client ID: copy it from the form while browsing on the host the client will use. Hosted documents are read from the database, never fetched, and follow the same PKCE, `resource`, consent and redirect checks as any other client. For Muse, enter:

- Client ID: the copied URL
- No client secret
- Authorization URL: `https://<host>/oauth/authorize`
- Token URL: `https://<host>/oauth/token`
- Scope: `mcp`
- Callback to register: `https://agent.meta.ai/api/hatch/oauth/callback`

Muse's full OAuth behavior is not verified yet. A rejected authorization request logs which check failed (parameter names only) at INFO level.

How credentials are revoked:

- **Single connection:** delete the key in Users → [user] → Security (or Preferences → Account Security). Other keys are unaffected.
- **Archive a hosted client:** blocks new authorizations and pending codes. Issued keys keep working until revoked or expired.
- **Revoke All Credentials** (hosted client form, administrators only): deletes every key issued to that client. The client stays active.
- **Delete a hosted client:** blocks it and deletes its keys.

Keys are matched on their stored Client ID, never on their name.

The public origin must be HTTPS. Enable Odoo `proxy_mode` and configure `dbfilter` so the request host selects the intended database. A trusted proxy may send `X-Forwarded-Host` and `X-Forwarded-Proto`, or preserve the public `Host` and send `X-Forwarded-Proto: https` without `X-Forwarded-Host`. Odoo must be reachable only through that trusted proxy because it trusts forwarded headers in proxy mode. In multi-host deployments, have the edge remove client-supplied `X-Forwarded-Host` and `Forwarded` headers: Odoo's ProxyFix trusts them for host and database selection. The issuer and MCP resource use the resulting request host (`https://<host>` and `https://<host>/mcp`). Database headers do not select the OAuth issuer.

## Security model

OAuth tokens are native API keys owned by the consenting user; Odoo ACLs and record rules apply. Legacy `rpc` and global API keys remain accepted on `/mcp` for existing bearer clients. Consent shows the client, database, and user; approve only requests you started. The user chooses 1 Day, 1 Month, 1 Year, or Never. Odoo offers Never only to system administrators because only they can hold non-expiring keys; such a key lasts until deleted. Other options are limited by the user's group API key duration (90 days for internal users by default, so 1 Day and 1 Month).

The choice is signed into the authorization code, checked again at exchange, and stored as the key's expiration date; clients cannot change it, and use never extends it. Users can revoke keys in Preferences → Account Security → API Keys. Removing a client URL through Settings → MCP OAuth deletes keys issued to that client; editing `ir.config_parameter` directly does not revoke them. Reusing an authorization code revokes the key issued on its first exchange, so a client network retry of `/oauth/token` revokes its token and requires reauthorization. Deleting a key within the code's 60-second lifetime lets the code holder exchange it again if they have its PKCE verifier. Parallel exchanges rely on the database unique constraint: the loser rolls back its new key, then revokes the winner. Verify this with two concurrent requests on a disposable server before production use.

OAuth metadata, authorization, and token endpoints have per-worker rate limits (120, 60, and 30 requests per minute respectively, keyed by database and IP). With N workers the effective ceiling can be N times each limit; add edge rate limiting if a global ceiling is required.

Run addon tests only on a disposable database, for example: `odoo-bin -d <disposable_db> -i odoo_mcp,odoo_mcp_oauth --test-enable --stop-after-init`. Browser tests in `tests/test_browser.py` need Chrome and the `websocket-client` package; without them Odoo reports them as skipped, not failed. For two disposable databases, mint keys using `odoo-bin shell -d <disposable_db> < scripts/mint_key.py`, then run `python3 scripts/isolation_check.py --base http://127.0.0.1:<port> --db-a <disposable_db_a> --db-b <disposable_db_b> --key-a <key_a> --key-b <key_b> --legacy-key-a <legacy_key_a>`.

No refresh tokens, dynamic client registration, or client secrets are provided. Removing this addon restores the original `/mcp` bearer behavior; unexpired `mcp` keys then become inert and expire through core autovacuum. Before production use, validate the actual connector flow, callback, and refresh behavior on a disposable database.

## Troubleshooting

- Metadata returns 404: the origin is not HTTPS (check `proxy_mode` and `X-Forwarded-Proto`), or `dbfilter` did not resolve a database.
- Consent shows "Authorization unavailable": the client is not allow-listed or its hosted client is archived, the redirect URI is absent from the client document, or the document fetch failed.
- `/oauth/token` returns `invalid_grant`: the code is older than 60 seconds, was reused, has the wrong PKCE verifier or resource, or the user's allowed durations changed.
- Browser tests are skipped: Chrome or `websocket-client` is missing.
