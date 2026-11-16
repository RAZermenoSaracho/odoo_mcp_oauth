## Context

**Current architecture** (`odoo_mcp_oauth` 19.0.1.0.0):
- **Clients:** CIMD only. Exact HTTPS URLs in `ir.config_parameter` `odoo_mcp_oauth.client_ids`, edited in Settings → MCP OAuth. Documents are fetched at authorize GET (`controllers/main.py:_client_document`) with a 5 s deadline, a 64 KiB cap and no redirects.
- **Flow:** Authorization Code with PKCE S256. `resource` must equal `<issuer>/mcp`. Consent and code are signed with `hash_sign` (10 min and 60 s).
- **Tokens:** the token endpoint issues a native API key (`res.users.apikeys._generate('mcp', 'OAuth: <client_name>', expiry)`) and stamps `oauth_client_id` (the Client ID URL) and `oauth_code_hash` (the replay marker) via SQL.
- **Revocation:** deleting the key (core `remove`, which checks identity and allows the owner or a system user), removing an allow-list URL (deletes keys by `oauth_client_id`), or replaying a code. `_check_apikey_credentials` reads SQL on every request, so revocation takes effect immediately.
- **Issuer:** `ir_http.origin()` returns `https://<request host>` under `proxy_mode`. Because of `dbfilter = ^%d$`, the host's first label picks the database.
- **Live deployment:** `odoo`, `odooers`, `ramzsa-odoo` and `home-nsr-odoo` all allow-list only ChatGPT's CIMD.

**FlowLedger reference:** also CIMD-only. For Muse it serves a hardcoded document at `/oauth/clients/meta-muse.json` through the same pipeline. Its docs note that Muse is not yet proven end to end.

## Goals / Non-Goals

**Goals:** let a client that only accepts a manual Client ID (Muse) use the existing flow; keep a generic admin registry; keep the existing CIMD path and every check byte-for-byte; keep all credentials in Users → Security.

**Non-Goals:** DCR, secrets, refresh tokens, `/revoke`, new scopes, relaxing `resource`, a new token store, changes to `odoo_mcp`.

## Decisions

1. **Hosted client = a self-served CIMD document, resolved locally.** The Client ID is `<issuer>/oauth/clients/<uuid>.json`. If `client_id` starts with `<issuer>/oauth/clients/`, the controller looks the record up via `sudo().search([('uuid','=',u),('active','=',True)], limit=1)` and builds the same dict the fetch would return. It never falls through to an HTTP fetch.
   - *Rejected: Odoo fetching its own URL through the tunnel.* With `workers = 2`, a worker would wait on its sibling (timeouts under load), and the request would hairpin through Cloudflare.
   - *Rejected: hardcoding Muse.*
2. **Allowed set = allow-list ∪ active hosted Client IDs for the current issuer.** `_allowed_clients()` returns the union. It is called unchanged at authorize GET, consent POST and token, so archiving takes effect at every step, including pending codes.
3. **Identifier.** `uuid = fields.Char(default=lambda: uuid.uuid4().hex, readonly=True, copy=False, required=True, index=True)` with a `UNIQUE` constraint. `write()` refuses any change to `uuid`. The route accepts only `^[0-9a-f]{32}$`.
4. **Client ID display.** The computed, non-stored `client_id` uses `ir_http.origin()` when a request exists, and is empty otherwise, with help text. It deliberately does not use `web.base.url`: the issuer the protocol compares against is the request origin, and mixing the two sources would break the equality check whenever they differ.
5. **Canonical origin / trust.** No new trust is introduced. The route uses the same `origin()` and `proxy_mode` trust as the existing metadata routes. A forged Host can only select the database named by its own first label, which won't contain another database's UUID, and the Client ID must equal that same issuer's path. No hostname is hardcoded.
6. **Redirect URIs.** Stored as a Text field, one URI per line, normalized by stripping whitespace and dropping blank lines. A constraint requires at least one URI, `https` scheme, a host, no userinfo, no fragment, and a length of at most 2048. Matching stays exact (`redirect_uri in uris`). Loopback http is not supported for hosted clients (YAGNI: clients with loopback callbacks publish their own CIMD).
7. **Credential attribution.** The existing `oauth_client_id` column already stores the immutable Client ID URL on each key, and hosted URLs embed the UUID. No new column or migration is needed. The key name `OAuth: <client_name>` is display-only and is frozen at issuance (core `name` is readonly). Security-sensitive matching uses `oauth_client_id` only.
8. **Lifecycle (server-enforced).**
   - **Archive:** blocks new authorizations and pending codes, because `_allowed_clients()` drops the ID at every step. Issued keys keep working. It is reversible and destroys nothing.
   - **Delete:** prevents future authorizations and invalidates pending codes the same way, and also revokes the client's keys. Only `base.group_system` can delete (ACL), and the standard Odoo delete confirmation applies. It mirrors the existing allow-list-removal revocation.
   - **Individual revoke:** the core Delete button on the key in Users → Security or Preferences, unchanged.
   - **Bulk revoke:** see decision 9.
9. **Revoke All Credentials (approved).** `action_revoke_credentials` is a button with `confirm=` on the form, `groups="base.group_system"`, and the method also checks `env.is_system()` server-side. Shared helper `_attributed_keys()`: `res.users.apikeys` search (admins can already read all keys under core's `api_key_admin` rule) with domain `[('oauth_client_id', '=like', 'https://%/oauth/clients/<uuid>.json'), ('oauth_client_id', 'not in', <external allow-list>)]`. Matching is on the stable Client ID, never the key name. The UUID is 32 random hex characters (no wildcard), and the database is the current cursor's. Excluding allow-listed URLs guarantees an external CIMD client can never be hit even if it reused the path shape. Revocation calls core `keys._remove()` (system check, logging, unlink, cache clear). Both `unlink` and the button use this helper; `unlink` goes through it before `super().unlink()`.
10. **Consent display.** For hosted clients, `client_host` becomes `urlsplit(redirect_uri).hostname`. External CIMD clients keep their current display.
11. **Diagnostics.** On each early authorize rejection, log at INFO which check failed (for example `missing: resource`), with no values. This is needed to learn what Muse actually sends.
12. **UI.** Standard list and form views and one window action, reached from a "Hosted clients" button in the existing Settings → MCP OAuth block. The views and action are restricted to `base.group_system`, and there is no extra menu. No JS or custom widget: the Client ID uses the stock `CopyClipboardChar` widget, which ships with `web`.

13. **Claude (verified 2026-11-16 by fetching the published documents).**
   - claude.ai/Desktop: `https://claude.ai/oauth/mcp-oauth-client-metadata`, callback `https://claude.ai/api/mcp/auth_callback`, `none`. It works through the existing CIMD path once allow-listed. Claude picks CIMD when AS metadata has `client_id_metadata_document_supported` and `none`, which we already advertise.
   - Claude Code: `https://claude.ai/oauth/claude-code-client-metadata`, with callbacks `http://localhost/callback` and `http://127.0.0.1/callback` used on a random port.
   - The old check (HTTPS-only callback, exact match) rejected Claude Code. Fix: a shared `_redirect_matches()` adds RFC 8252 §7.3 port-agnostic matching only for `http` loopback hosts whose registered entry has no port and the same host, path and query. It is applied wherever document redirect URIs are matched.
   - Hosted clients still allow HTTPS only, so loopback can only come from a client's own published document that an admin allow-listed. Token exchange still needs the exact same URI the code was issued for.
   - No other change: Claude sends `resource` (canonical MCP URL), S256 and form-encoded token requests; we send `scope="mcp"` in the 401.
   - No refresh tokens: when the key expires or is revoked, Claude must reauthorize. That behavior isn't documented and remains unverified.
14. **API keys coexist.** `/mcp` auth (`mcp`/NULL scope, then `rpc`) is untouched. A Claude connection using a manual API key is unaffected by any OAuth action.

## Risks / Trade-offs

- **Muse behavior is unverified.** It may omit `resource`, demand a secret, require refresh tokens, or need Meta approval on platform.muse.ai. Mitigation: the diagnostic log plus manual validation; any fix goes in a separate approved change.
- **Admin form shows the Client ID for the host the admin is browsing on.** On a multi-host database the admin must copy it from the host the client will use. That's acceptable because dbfilter gives one host per database here.
- **Archive keeps keys alive.** That's deliberate. Delete, or Revoke All Credentials, is the kill switch. Documented in the README.
- **Public UUID.** Client IDs are not secrets. Exposure is equal to any public CIMD client: the code goes only to the registered callback and still requires user consent.

- **Removing a redirect URI does not cut in-flight grants.** Consent POST and token trust the signed `redirect_uri`, as they already do for external clients. A consent form (up to 10 min) or code (up to 60 s) issued before the edit can still complete. Archive the client to stop them.
- **Browser tests and `dbfilter`.** The three browser consent tests need a process-local `--db-filter '^<test_db>$'`. Under production's `^%d$`, the test browser's `127.0.0.1` host resolves no database. Command-line only; `odoo.conf` is untouched.

## Migration Plan

1. Run the tests on a disposable database.
2. With operator approval, run `odoo-bin -u odoo_mcp_oauth -d <db>` for each database where the addon is installed, then `pm2 restart odoo --update-env`.
3. No data migration is needed: there is one new table, and `res_users_apikeys` is untouched.

**Rollback:** downgrade the code and upgrade again. The `mcp_oauth_client` table becomes unused. Keys issued to hosted clients stop resolving at authorize, but they still authenticate until deleted or expired, and they remain visible in Users → Security.

- **Claude's network path.** Claude reaches the server from `160.79.104.0/21`, IPv4 only. Cloudflare WAF or Access rules must not block `/.well-known/*`, `/oauth/*` or `/mcp` for that range (manual check).
- **Loopback scope.** Loopback matching trusts any local process on that port, which is standard for native apps and still protected by PKCE. It applies only to documents that list a loopback callback.

## Open Questions

- Does Muse send `resource`, S256, and `scope`? Which discovery paths does it hit? Does it need a secret or refresh? (Manual validation.)
- Claude today uses a manual API key (confirmed by the operator); OAuth is additive.
- How Claude handles the lack of refresh tokens over a long-lived key (unverified; manual).
- Which disposable or staging tenant should be used for Muse validation?
