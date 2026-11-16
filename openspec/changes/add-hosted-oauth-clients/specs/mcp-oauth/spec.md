## MODIFIED Requirements

### Requirement: Explicit single-addon installation and MCP inheritance

`odoo_mcp_oauth` SHALL depend on `['odoo_mcp', 'web']`, SHALL NOT `auto_install`, and SHALL add no pip dependency. Its only new model SHALL be the admin-managed hosted OAuth client registry. It SHALL subclass the existing controller, override method `mcp` with `@http.route(auth='mcp_oauth')`, call `super().mcp()`, and inherit the parent's `/mcp`, POST, HTTP type, CSRF-disabled, session-disabled, and body-limit settings. The parent Origin check and `LIMITER.check((dbname, uid))` SHALL still run; the addon SHALL NOT reimplement the MCP body or modify `odoo_mcp`.

#### Scenario: Opt-in database and legacy suite
- **WHEN** an operator installs the addon in one database and runs the full existing `odoo_mcp` suite with it installed
- **THEN** only that database's MCP auth changes, and the existing endpoint behavior and bearer assertions still pass; compare the three pre-existing `odoo_mcp/tests/test_docs.py` failures against a run without the addon.

#### Scenario: Upgrade preserves existing credentials
- **WHEN** a database with keys already issued to external CIMD clients upgrades to this version
- **THEN** those keys keep authenticating at `/mcp` with unchanged name, scope, expiration and client attribution.

### Requirement: Exact CIMD allow-list and bounded retrieval

One Settings field SHALL store exact HTTPS CIMD client-ID URLs, one per line, in `ir.config_parameter` key `odoo_mcp_oauth.client_ids`; empty is default. Document `https://chatgpt.com/oauth/client.json`. The allowed client set SHALL be the union of this list and the active hosted clients of the current issuer; when both are empty, OAuth authorization is inert. There SHALL be no DCR, client secret, or document cache. After login on authorize GET, a hosted Client ID SHALL be resolved from the database without any outbound request; any other client SHALL be fetched only when its exact URL is allow-listed, using bundled `requests`, HTTPS, `allow_redirects=False`, five-second total deadline in addition to the per-read timeout, streamed 64 KiB cap, JSON, exact document `client_id` equality, and a requested `redirect_uri` that is either an exact HTTPS entry of `redirect_uris` or, per RFC 8252 section 7.3, an `http` loopback URI (`localhost`, `127.0.0.1`, `::1`) whose port-less form with the same host, path and query is listed (any port accepted; no user info or fragment). A Client ID under the current issuer's hosted-client path that does not resolve to an active hosted client SHALL be rejected without a fetch. Consent POST SHALL NOT resolve CIMD again. Invalid client or callback SHALL show an error page and never redirect to the callback. Client ID alone grants no authority.

#### Scenario: Empty or removed allow-list
- **WHEN** the list is empty and no hosted client is active, or the list no longer contains the requested client URL
- **THEN** authorize fails before login and exchange rejects pending codes for that client.

#### Scenario: Good and bad documents
- **WHEN** the allow-listed ChatGPT document lists the exact callback, or instead redirects, times out, exceeds 64 KiB, is invalid JSON, has another client ID, or lacks that exact callback
- **THEN** only the first case can proceed; all bad cases issue no code.

#### Scenario: Redirect manipulation
- **WHEN** a callback is merely a prefix or differently percent-encoded
- **THEN** authorize GET shows an error page and issues no code.

#### Scenario: Loopback callback
- **WHEN** an allow-listed document lists `http://localhost/callback` and the request uses `http://localhost:3118/callback`
- **THEN** authorization proceeds and the code is delivered there; a different path, query, host, scheme (`https://localhost…`), user info or fragment, or a document without a loopback entry, shows the error page.

### Requirement: Revocation, isolation, and rollback

Core autovacuum SHALL delete only keys with `expiration_date < now`; unexpired key rows and their code hash markers SHALL remain. Every selectable duration SHALL be at least one day (or non-expiring), beyond the 60-second code lifetime. Each OAuth credential SHALL be a native API key owned by the consenting user, listed in that user's Preferences > Account Security > API Keys and in the administrator's Users > Security tab, named after its client, with scope `mcp`, creation date and expiration. Deleting one key there SHALL stop it authenticating on the next request and SHALL NOT affect any other key. Removing a URL from Settings, or deleting a hosted client, SHALL delete the keys attributed to that client on save. There SHALL be no uninstall cleanup hook: after uninstall, residual `mcp`-scoped keys are inert because the original `/mcp` bearer route checks `rpc`, and core autovacuum removes them at expiry. Keys and signing secret SHALL remain per DB. A key from A SHALL fail on B's `/mcp`; B's resource SHALL fail at A's authorize/token; `X-Odoo-Database` SHALL not override host selection. `mcp` keys SHALL fail on `/json/2` and `/xmlrpc/2`; legacy `rpc`/NULL keys SHALL work at `/mcp`. Automated isolation SHALL use two disposable DBs; a manual disposable-copy check SHALL try every configured DB name as `X-Odoo-Database` against each host.

#### Scenario: User, admin, and replay revocation
- **WHEN** a user deletes a key, an admin deletes another user's key from the Security tab, an admin removes its client URL or deletes its hosted client, or a code is replayed
- **THEN** affected keys cease authenticating; replay retains the revoked key's marker; removed clients cannot exchange pending codes.

#### Scenario: Revocation is per credential
- **WHEN** a user holds keys for a hosted client, for ChatGPT and a manual API key, and deletes only the hosted client's key
- **THEN** the other two keys keep authenticating.

#### Scenario: Cross-DB and RPC
- **WHEN** A's key goes to B, B's resource goes to A, or an `mcp` key goes to either RPC endpoint
- **THEN** all are rejected without crossing database/user context.

#### Scenario: Uninstall
- **WHEN** the addon is uninstalled with unexpired `mcp`-scoped keys still present
- **THEN** original MCP bearer behavior returns, those keys fail its `rpc` check and expire through core autovacuum.

## ADDED Requirements

### Requirement: Hosted OAuth client registry

Administrators (system group only) SHALL manage hosted OAuth clients with a name, an active flag, one or more redirect URIs, and a random identifier assigned at creation that SHALL NOT change afterwards and SHALL be unique per database. Each redirect URI SHALL be an absolute `https` URL with a host and without user info or fragment; anything else SHALL be rejected on save. The record SHALL display its Client ID, `<issuer>/oauth/clients/<identifier>.json`, where the issuer is the same request origin used by the authorization server metadata. Other users SHALL have no access to the registry. A registry record SHALL grant no access to Odoo data by itself.

#### Scenario: Create and copy
- **WHEN** an administrator creates a client named "Meta AI Muse" with callback `https://agent.meta.ai/api/hatch/oauth/callback`
- **THEN** the record shows a copyable Client ID `https://<host>/oauth/clients/<uuid>.json`, and the identifier cannot be changed by a later write.

#### Scenario: Invalid redirect URIs
- **WHEN** a redirect URI is `http://…`, relative, has user info, a fragment, or is empty
- **THEN** saving is refused.

#### Scenario: Non-admin access
- **WHEN** an internal or portal user without the system group reads, creates, writes or deletes a hosted client
- **THEN** access is denied.

### Requirement: Hosted client metadata document

`GET /oauth/clients/<identifier>.json` SHALL require no session, set no session cookie, never redirect to login, be rate limited like the other metadata routes, and return 404 on an insecure origin or no database. For an active hosted client of the routed database it SHALL return `application/json` with `Cache-Control: no-store` containing exactly `client_id` (equal to the requested URL on the current issuer), `client_name`, `redirect_uris`, `token_endpoint_auth_method: "none"`, `grant_types: ["authorization_code"]`, and `response_types: ["code"]`. A malformed, unknown, archived or other-database identifier SHALL return 404 without revealing whether a record exists.

#### Scenario: Public document
- **WHEN** an anonymous client requests an active hosted client's document over HTTPS
- **THEN** it receives the exact JSON fields above and no login redirect.

#### Scenario: Unknown, archived, or foreign identifier
- **WHEN** the identifier is malformed, unknown, archived, or belongs to another database's host
- **THEN** the response is 404.

### Requirement: Hosted client authorization and lifecycle

A hosted client SHALL follow the same authorize, consent, code and token rules as any CIMD client: PKCE S256, required `resource` equal to `<issuer>/mcp`, exact redirect URI match against its registered URIs, signed consent, 60-second single-use code, and a user-owned `mcp` API key attributed to the Client ID URL. No outbound HTTP request SHALL be made to resolve it. The consent page SHALL show the client name and the callback host for hosted clients. Archiving a hosted client SHALL block new authorizations and the exchange of pending codes, and SHALL leave already-issued keys working until the user revokes them or they expire. Deleting a hosted client SHALL delete the keys attributed to it. A rejected authorize request SHALL log which check failed, naming parameters but not their values.

#### Scenario: Muse-shaped flow
- **WHEN** an active hosted client with callback `https://agent.meta.ai/api/hatch/oauth/callback` completes authorize with S256 and the correct `resource`, the user approves, and the code is exchanged
- **THEN** a Bearer key owned by that user is issued, appears in their API keys as `OAuth: <client name>`, and authenticates at `/mcp`, with no outbound HTTP request made.

#### Scenario: Missing resource
- **WHEN** a hosted client omits `resource` on authorize or token
- **THEN** the request is rejected exactly as for any other client, and authorize logs the missing parameter name.

#### Scenario: Archive versus delete
- **WHEN** an administrator archives a hosted client that has issued keys
- **THEN** new authorizations and pending codes fail and issued keys still authenticate; **WHEN** the administrator then deletes it
- **THEN** its keys stop authenticating and other clients' keys are unaffected.

#### Scenario: Delete invalidates pending codes
- **WHEN** a code was issued for a hosted client and the client is deleted before exchange
- **THEN** the exchange fails with `invalid_grant` and no key is issued.

#### Scenario: Consent shows callback host
- **WHEN** a user reaches consent for a hosted client
- **THEN** the page names the client and the callback host (for example `agent.meta.ai`), not the Odoo host.

### Requirement: Administrative bulk revocation

A hosted client record SHALL offer a Revoke All Credentials action, available only to system administrators, behind an explicit confirmation, and refused server-side for anyone else. It SHALL delete, through the native API-key removal path, every key in the current database attributed to that hosted client's Client ID, identified by the stored Client ID and never by the key name. It SHALL NOT delete keys of other hosted clients, of allow-listed external CIMD clients, manual API keys, or keys in another database, and SHALL leave the client's active state unchanged. Deleting a hosted client SHALL revoke through the same path.

#### Scenario: Bulk revoke one client
- **WHEN** an administrator confirms Revoke All Credentials on hosted client A while users hold keys for A, hosted client B, an external CIMD client, and a manual API key
- **THEN** only A's keys stop authenticating, all others keep working, and A stays active so users can authorize again.

#### Scenario: Non-admin bulk revoke
- **WHEN** a user without the system group invokes the action by RPC
- **THEN** it is refused and no key is deleted.

### Requirement: Claude clients and API-key coexistence

The authorization server SHALL satisfy the documented conditions under which Claude clients use Anthropic's published Client ID Metadata Documents: AS metadata with `client_id_metadata_document_supported: true`, `"none"` in `token_endpoint_auth_methods_supported` and `code_challenge_methods_supported: ["S256"]`; protected resource metadata whose `resource` is `<issuer>/mcp` at both well-known paths; and a 401 from `/mcp` carrying `resource_metadata` and `scope="mcp"`. Allow-listing `https://claude.ai/oauth/mcp-oauth-client-metadata` (claude.ai, Desktop) or `https://claude.ai/oauth/claude-code-client-metadata` (Claude Code, loopback callbacks) SHALL be the only configuration needed, without client-specific code. Existing bearer API keys (`rpc`, `mcp` or global scope) SHALL keep authenticating at `/mcp` unchanged and independently of OAuth credentials: revoking an OAuth credential SHALL NOT affect any API key, and reauthorizing SHALL issue a new user-owned key.

#### Scenario: Claude web flow alongside an API key
- **WHEN** a user who already connects with a manual API key authorizes Claude through its published document and then deletes the resulting `OAuth: Claude` key
- **THEN** the OAuth token stops authenticating, the manual API key keeps working, and a new authorization issues a new working key.

#### Scenario: Claude Code loopback
- **WHEN** Claude Code authorizes with `http://localhost:<random port>/callback` or `http://127.0.0.1:<port>/callback`
- **THEN** the code is delivered to that exact URI and exchanging it with the same URI issues an `OAuth: Claude Code` key; exchanging with another port fails.
