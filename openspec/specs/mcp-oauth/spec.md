# mcp-oauth Specification

## Purpose

One optional per-database addon gives the unchanged Odoo 19 MCP endpoint ChatGPT-compatible OAuth using native login, signatures, and API keys.

## Requirements

### Requirement: Explicit single-addon installation and MCP inheritance

`odoo_mcp_oauth` SHALL depend on `['odoo_mcp', 'web']`, SHALL NOT `auto_install`, and SHALL add no new model or pip dependency. It SHALL subclass the existing controller, override method `mcp` with `@http.route(auth='mcp_oauth')`, call `super().mcp()`, and inherit the parent's `/mcp`, POST, HTTP type, CSRF-disabled, session-disabled, and body-limit settings. The parent Origin check and `LIMITER.check((dbname, uid))` SHALL still run; the addon SHALL NOT reimplement the MCP body or modify `odoo_mcp`.

#### Scenario: Opt-in database and legacy suite
- **WHEN** an operator installs the addon in one database and runs the full existing `odoo_mcp` suite with it installed
- **THEN** only that database's MCP auth changes, and the existing endpoint behavior and bearer assertions still pass; compare the three pre-existing `odoo_mcp/tests/test_docs.py` failures against a run without the addon.

### Requirement: MCP authentication and challenge

`ir.http._auth_method_mcp_oauth` SHALL be a classmethod requiring an Authorization Bearer token. It SHALL NOT copy core bearer's session or Sec-Fetch fallback (`ir_http.py:244-247`). It SHALL check `_check_credentials(scope='mcp')` first (including NULL-scope keys), then `_check_credentials(scope='rpc')` for legacy keys, set the key owner as request user with `su=False`, and set `request.session.can_save=False`. Missing, invalid, expired, revoked, or foreign tokens SHALL return 401 with `WWW-Authenticate: Bearer resource_metadata="<origin>/.well-known/oauth-protected-resource/mcp", scope="mcp"`; add `error="invalid_token"` when a token was presented. On an insecure origin, `/mcp` SHALL keep returning a plain `Bearer` 401 and SHALL accept valid keys regardless of scheme. OAuth routes SHALL return 404 for no DB or insecure origin without an issuer leak. MCP tools SHALL retain owner ACLs and record rules, without token passthrough.

#### Scenario: Missing and rejected token
- **WHEN** HTTPS `/mcp` receives no token or a bad token
- **THEN** both return 401 with this origin's PRM URL; only the presented bad token adds `invalid_token`.

#### Scenario: Session cookie without Bearer token
- **WHEN** a logged-in session cookie calls `/mcp` without an Authorization Bearer token
- **THEN** the request returns 401; neither session nor Sec-Fetch headers authenticate it.

#### Scenario: OAuth and legacy keys
- **WHEN** valid `mcp`, `rpc`, or NULL-scope keys call `/mcp`
- **THEN** each runs as its owner without sudo under normal MCP permissions.

#### Scenario: No DB or insecure origin
- **WHEN** an OAuth route has no selected DB or an insecure origin, or HTTP `/mcp` receives a missing or valid key
- **THEN** the OAuth route returns 404; HTTP `/mcp` returns a plain `Bearer` 401 for the missing key and accepts the valid key without advertising resource metadata.

### Requirement: Request-origin issuer and metadata

For every OAuth route, issuer SHALL be `https://` plus the request Host when, under `proxy_mode`, the last `X-Forwarded-Proto` value is `https`, or when ProxyFix has already set the request scheme to HTTPS; resource SHALL be issuer plus `/mcp`. This SHALL use Odoo's `proxy_mode` forwarded-header trust boundary. `web.base.url` SHALL not be required. An insecure origin or unresolved DB SHALL return 404. `X-Odoo-Database` or session state SHALL NOT override host-filtered DB selection. `GET /.well-known/oauth-authorization-server` SHALL publish `issuer`, `authorization_endpoint`, `token_endpoint`, `response_types_supported=["code"]`, `grant_types_supported=["authorization_code"]`, `code_challenge_methods_supported=["S256"]`, `token_endpoint_auth_methods_supported=["none"]`, `scopes_supported=["mcp"]`, `client_id_metadata_document_supported=true`, and `authorization_response_iss_parameter_supported=true`. Both `GET /.well-known/oauth-protected-resource` and `/mcp` suffix SHALL return the same RFC 9728 document: `resource`, `authorization_servers=[issuer]`, `scopes_supported=["mcp"]`, and `bearer_methods_supported=["header"]`.

Production cloudflared sends the original Host and `X-Forwarded-Proto`, but no `X-Forwarded-Host`, so Odoo's ProxyFix does not run. The production `odoo` DB has auto-recorded `web.base.url` with an HTTP scheme. If `X-Forwarded-Host` is supplied elsewhere, the host and selected database still follow Odoo's host-filtered selection.

#### Scenario: Discovery on host
- **WHEN** AS metadata and both PRM paths are requested at `https://odoo.example.com`
- **THEN** they advertise only that issuer, `https://odoo.example.com/mcp`, and the listed RFC 8414/9728 fields.

#### Scenario: Host, scheme, or database mismatch
- **WHEN** HTTP is used, no DB resolves, or a database header tries to override the host-filtered DB
- **THEN** OAuth routes fail closed or stay in the host-selected DB, never disclosing another issuer or key.

#### Scenario: Production proxy without forwarded host
- **WHEN** `proxy_mode` is enabled, original Host is present, `X-Forwarded-Host` is absent, and the last `X-Forwarded-Proto` value is `https`
- **THEN** OAuth metadata uses `https://<Host>` as issuer even though ProxyFix did not run and `web.base.url` records HTTP; another last proto value makes OAuth routes return 404.

### Requirement: Exact CIMD allow-list and bounded retrieval

One Settings field SHALL store exact HTTPS CIMD client-ID URLs, one per line, in `ir.config_parameter` key `odoo_mcp_oauth.client_ids`; empty is default and makes OAuth authorization inert. Document `https://chatgpt.com/oauth/client.json`. There SHALL be no client model, manual client, DCR, or cache. After login on authorize GET, fetch only an exactly allow-listed URL using bundled `requests`, HTTPS, `allow_redirects=False`, five-second total deadline in addition to the per-read timeout, streamed 64 KiB cap, JSON, exact document `client_id` equality, and an exact HTTPS requested `redirect_uri` in `redirect_uris`. Consent POST SHALL NOT fetch CIMD again. Invalid client or callback SHALL show an error page and never redirect to the callback. Client ID alone grants no authority.

#### Scenario: Empty or removed allow-list
- **WHEN** the list is empty or no longer contains the requested client URL
- **THEN** authorize fails before login and exchange rejects pending codes for that client.

#### Scenario: Good and bad documents
- **WHEN** the allow-listed ChatGPT document lists the exact callback, or instead redirects, times out, exceeds 64 KiB, is invalid JSON, has another client ID, or lacks that exact callback
- **THEN** only the first case can proceed; all bad cases issue no code.

#### Scenario: Redirect manipulation
- **WHEN** a callback is merely a prefix or differently percent-encoded
- **THEN** authorize GET shows an error page and issues no code.

### Requirement: Pre-login validation and explicit consent

`GET /oauth/authorize` SHALL declare `auth='public'`. Before login it SHALL check only that `client_id` is allow-listed and the request is well-formed. If `request.env.user._is_public()`, it SHALL redirect to `/web/login?redirect=<url-quoted local /oauth/authorize URL>`; it SHALL never redirect to the client before login. After login on the same GET, it SHALL fetch and validate CIMD, exact `redirect_uri`, `response_type=code`, S256 challenge and method, and exact `resource=issuer+'/mcp'`. The optional `scope` request parameter SHALL be accepted and ignored; token scope is always `mcp`. Invalid client or redirect SHALL show an error page; other authorization errors SHALL redirect to the validated callback with `error`, original `state` when supplied, and `iss=issuer`. Native login rotation returns to the same local authorize URL. No dispatch/auth-path customization or server-side transaction is needed. Only active `user._is_internal()` users may consent. Portal/public or archived users SHALL get `access_denied` at a validated callback. QWeb consent SHALL display client name/host, DB, user, and lifetime. Consent responses SHALL set `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

`POST /oauth/authorize` SHALL declare `auth='user'` and `readonly=False`. The consent form SHALL carry Odoo's CSRF token and exactly one hidden OAuth parameter: `hash_sign(env, 'odoo_mcp_oauth.consent', {db, uid, client_id, client_name, redirect_uri, code_challenge, resource, state}, expiration=10 minutes)`. POST SHALL verify the signed blob, reject a blob whose `db` differs from the selected database, require blob `uid` to equal the current user, require the client still allow-listed and the user active/internal, and require explicit Approve or Deny. It SHALL NOT fetch CIMD again or compare separate hidden request fields. Approve issues a code; Deny redirects with `access_denied`, state, and iss.

#### Scenario: Pre-login gate and local return
- **WHEN** an unauthenticated request has an unlisted client or malformed request, or has an allow-listed well-formed request
- **THEN** the former shows a local error page and the latter redirects only to `/web/login` with a URL-quoted local authorize return; neither redirects to the client.

#### Scenario: Post-login callback validation
- **WHEN** a logged-in GET has an invalid client or callback, or another authorization error after a callback was validated
- **THEN** the invalid client/callback gets an error page; the other error redirects to the validated callback with `error`, original `state`, and `iss`.

#### Scenario: PKCE, response, and resource downgrade
- **WHEN** challenge is absent, method is `plain`, response type differs from `code`, or resource is missing/foreign
- **THEN** no consent or code is issued; once the callback is validated, the error goes to that callback with state and iss.

#### Scenario: Optional scope parameter
- **WHEN** authorize or token receives any `scope` request parameter
- **THEN** it is ignored, no rejection occurs because of scope, and any issued token has scope `mcp`.

#### Scenario: Login rotation and escape
- **WHEN** login rotates the session or an attacker proposes an external return URL
- **THEN** return is only to the same local authorize URL, post-login GET validates the client and request, and no code reaches the external URL.

#### Scenario: Duplicated database secret
- **WHEN** a consent blob or code from another database has a valid signature because the database was duplicated or restored with the same `database.secret`
- **THEN** the selected database name differs from signed `db`, so consent or exchange is rejected.

#### Scenario: Signed consent, CSRF, and identity
- **WHEN** POST has invalid CSRF, a tampered or expired consent blob, a blob for another user, a removed client, or no explicit Approve/Deny
- **THEN** no code is issued; no second CIMD fetch or separate hidden-field comparison occurs.

#### Scenario: Consent frame protection
- **WHEN** the consent page or consent response is returned
- **THEN** it includes `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`.

#### Scenario: Approval, denial, and portal user
- **WHEN** an active internal user approves or denies, or a portal/archived user reaches consent
- **THEN** only internal approval returns a code; other valid redirects return `access_denied`, all with original state and exact `iss`.

### Requirement: Signed single-use code and replay revocation

Approval SHALL call `odoo.tools.misc.hash_sign(env, 'odoo_mcp_oauth.code', {db, uid, client_id, client_name, redirect_uri, code_challenge, resource, nonce}, expiration=timedelta(seconds=60))`; exchange SHALL call `verify_hash_signed`. Code SHALL bind selected database name, UID, client, client name, exact redirect, S256 challenge, and resource, and exchange SHALL reject a database-name mismatch even if a restored or duplicated database shares `database.secret`; the nonce distinguishes grants. No code model or transaction table SHALL exist. `res.users.apikeys` SHALL add only `oauth_client_id` (Char) and `oauth_code_hash` (Char, unique via `models.Constraint`). Store SHA-256 of code on the issued key. Inside a savepoint, call `_generate`, then require exactly one new row with `index=key[:INDEX_SIZE]` and `oauth_code_hash` unset before updating its `oauth_client_id` and `oauth_code_hash`. Otherwise roll back the key in the savepoint and return HTTP 500 `server_error`; no unmarked key may be issued. A concurrent second UPDATE SHALL wait on the unique index until the first transaction commits, then hit the unique violation. Its savepoint SHALL roll back only its own key row; because Odoo uses REPEATABLE READ and the loser cannot see the committed winner in its transaction, revocation SHALL use a fresh registry cursor and parameterized plain-SQL UPDATE to write only `scope='odoo_mcp_oauth_revoked'` on the winner, retain expiration date and hash, persist revocation, and return generic `invalid_grant`. A client network retry therefore revokes the token and requires reauthorization. The addon SHALL NOT delete key rows on replay.

#### Scenario: Valid, expired, and replayed code
- **WHEN** a bound code is exchanged once within 60 seconds, after expiry, or a second time
- **THEN** only the first timely exchange can succeed; expiry fails and replay revokes its issued key while retaining the hash marker.

#### Scenario: Key row lookup failure
- **WHEN** key generation is followed by zero or multiple matching rows, or the matching row already has `oauth_code_hash`
- **THEN** the savepoint rolls back the generated key and token exchange returns HTTP 500 `server_error` without issuing an unmarked key.

#### Scenario: Parallel exchange
- **WHEN** two requests exchange the same code concurrently
- **THEN** the second blocks on the unique index until the first commits, rolls back its own key row on violation, revokes the first key through a fresh-cursor plain-SQL scope UPDATE, and returns `invalid_grant`; a client retry requires reauthorization.

#### Scenario: Replay after unexpired autovacuum
- **WHEN** a still-valid code is reused after core autovacuum runs while its key is unexpired
- **THEN** its hash marker remains on the row, exchange returns `invalid_grant`, and no second key is minted.

#### Scenario: Removed client code
- **WHEN** an admin removes a client from the allow-list before its code is exchanged
- **THEN** exchange returns `invalid_grant` even if removal deleted the code's key row.

#### Scenario: Redirect substitution
- **WHEN** token `redirect_uri` differs from signed value by prefix, encoding, or any other byte
- **THEN** exchange returns `invalid_grant` without a token.

### Requirement: Token exchange and native lifetime

`POST /oauth/token` SHALL use `auth='none'` (uid None; `ir_http.py:260`), `readonly=False` (Odoo 19 otherwise defaults `auth='none'` to a read-only cursor), `csrf=False`, only `grant_type=authorization_code` and public auth method `none`. Require exact client ID, redirect, resource, and correct S256 verifier; recheck client allow-list and signed user's active/internal state. The optional `scope` parameter SHALL be ignored. Narrow sudo SHALL be used only to (a) call `hash_sign`/`verify_hash_signed`, which read system-only `database.secret` through `ir.config_parameter` (`ir_config_parameter.py:69`, `base ir.model.access.csv:118`); (b) read the signed UID's active/`_is_internal` state; (c) locate the new key by `index=key[:INDEX_SIZE]` and write `oauth_client_id`/`oauth_code_hash` (`res_users.py:1509,1608`; `_generate` returns only the key after a raw INSERT); and (d) update replay revocation scope through a fresh registry cursor and parameterized plain SQL. `res.users.apikeys` has `_auto=False` and core manages it with plain SQL. Employees have read-only apikeys ACL (`ir.model.access.csv:92`). `_generate(scope='mcp', name='OAuth: <client_name>', expiration_date=now + native_max_days)` SHALL run on `env.with_user(uid)` with `su=False`, since it reads `env.user` for owner and duration; a test SHALL assert `su=False` inside `_generate`. Explicitly compute `native_max_days=max(group.api_key_duration for group in user.all_group_ids) or 1.0` for all users, including Settings users. Other keys for the same client SHALL stay usable until the user deletes them in Preferences. Core credential lookup is plain SQL (`res_users.py:1574`), so a replay scope write SHALL immediately make that key fail `mcp` and `rpc`. Respond with `access_token`, `token_type=Bearer`, `expires_in`, `scope=mcp`, and `Cache-Control: no-store`; no refresh token. Use generic errors. Tokens and verifiers SHALL never appear in URLs/logs; codes only on validated callback redirects.

#### Scenario: Valid exchange and owner
- **WHEN** all bindings and PKCE match for an active internal user
- **THEN** one owner-bound `mcp` key is returned in the body with `Cache-Control: no-store`; `_generate` observes `su=False`.

#### Scenario: Wrong verifier or unsupported grant
- **WHEN** verifier is missing/wrong, a different grant is requested, or client-secret authentication is attempted
- **THEN** no token is issued and an appropriate generic protocol error appears.

#### Scenario: User changes after consent
- **WHEN** code owner is archived or made portal before exchange
- **THEN** exchange returns `invalid_grant` and no key.

#### Scenario: Settings and ordinary duration cap
- **WHEN** a Settings or ordinary internal user exchanges a code
- **THEN** expiry respects the explicitly computed native group maximum even where core bypasses Settings users.

#### Scenario: Immediate replay revocation
- **WHEN** a code replay changes the winner key's scope and that key is immediately used at `/mcp` or an RPC endpoint
- **THEN** plain-SQL credential lookup rejects it without waiting for cache invalidation.

### Requirement: Public endpoint abuse limits

Login cooldown SHALL NOT be relied on for OAuth endpoints. The addon SHALL reuse `odoo_mcp.ratelimit.SlidingWindow` with its own per-worker instances keyed by `(dbname, client IP)` (last `X-Forwarded-For` entry under `proxy_mode` when `X-Forwarded-Host` is absent, matching ProxyFix `x_for=1`; otherwise `remote_addr`): `POST /oauth/token` at most 30 requests per 60 seconds, pre-login and post-login `/oauth/authorize` at most 60 per 60 seconds, and metadata routes at most 120 per 60 seconds. A request over the limit SHALL receive `429` with `Retry-After` before any signature verification, key lookup, CIMD fetch, or key generation. The token endpoint SHALL reject request bodies larger than 16 KiB. The per-worker ceiling (N workers => up to N times the limit) is documented; edge rate limiting is the upgrade path.

#### Scenario: Token endpoint throttled
- **WHEN** one client IP sends more than 30 token requests within 60 seconds to one database
- **THEN** further requests get `429` with `Retry-After` and no code is verified and no key is generated

#### Scenario: Proxy client IP
- **WHEN** proxy mode is on and `X-Forwarded-Host` is absent
- **THEN** the limiter uses the last `X-Forwarded-For` entry; without that proxy condition it uses `remote_addr`, under Odoo's existing proxy trust boundary.

#### Scenario: Limits are per database and IP
- **WHEN** a client IP is throttled on database A
- **THEN** the same IP is not throttled on database B, and another IP is not throttled on A

#### Scenario: Oversized token request
- **WHEN** a token request body exceeds 16 KiB
- **THEN** it is rejected without verifying the code

### Requirement: Uninstall preserves core API keys

The addon SHALL own no `res.users.apikeys` field other than `oauth_client_id` and `oauth_code_hash` (fields shared with base such as `id` excepted), so uninstall never drops a core API-key column.

#### Scenario: Uninstall keeps legacy keys working
- **WHEN** the addon is uninstalled from a database with existing legacy and OAuth-issued keys
- **THEN** core's `index` column remains, legacy keys still authenticate on `/mcp`, `mcp`-scoped keys are rejected, and the OAuth routes return 404

### Requirement: Revocation, isolation, and rollback

Core autovacuum SHALL delete only keys with `expiration_date < now`; unexpired key rows and their code hash markers SHALL remain. Native key lifetime SHALL be at least one day, beyond the 60-second code lifetime. Users SHALL revoke through Preferences > Account Security > API Keys. Removing a URL from Settings SHALL delete keys with that `oauth_client_id` on save; pending codes for removed clients SHALL fail the exchange allow-list check. There SHALL be no uninstall cleanup hook: after uninstall, residual `mcp`-scoped keys are inert because the original `/mcp` bearer route checks `rpc`, and core autovacuum removes them at expiry. Keys and signing secret SHALL remain per DB. A key from A SHALL fail on B's `/mcp`; B's resource SHALL fail at A's authorize/token; `X-Odoo-Database` SHALL not override host selection. `mcp` keys SHALL fail on `/json/2` and `/xmlrpc/2`; legacy `rpc`/NULL keys SHALL work at `/mcp`. Automated isolation SHALL use two disposable DBs; a manual disposable-copy check SHALL try every production DB name as `X-Odoo-Database` against each host.

#### Scenario: User, admin, and replay revocation
- **WHEN** a user deletes a key, an admin removes its client URL, or a code is replayed
- **THEN** affected keys cease authenticating; replay retains the revoked key's marker; removed clients cannot exchange pending codes.

#### Scenario: Cross-DB and RPC
- **WHEN** A's key goes to B, B's resource goes to A, or an `mcp` key goes to either RPC endpoint
- **THEN** all are rejected without crossing database/user context.

#### Scenario: Uninstall
- **WHEN** the addon is uninstalled with unexpired `mcp`-scoped keys still present
- **THEN** original MCP bearer behavior returns, those keys fail its `rpc` check and expire through core autovacuum.

### Requirement: Disposable acceptance and deferred features

Before production, a real ChatGPT connector SHALL complete challenge, PRM and AS metadata, login, consent, code exchange, MCP tool call, expiry, and reauthorization on a disposable DB. Its exact callback and refresh/offline, connector-gating, per-tool `securitySchemes`, and `_meta["mcp/www_authenticate"]` expectations remain **UNVERIFIED** until tested. Refresh tokens are deferred unless reauthorization UX is a problem; DCR unless a needed client lacks CIMD; manual clients, RFC 7009, and OIDC until evidenced need; per-tool hints unless ChatGPT verification needs them; generic AS until a second protected resource exists. Production install, edge/tunnel changes, and rollback SHALL each require operator approval.

#### Scenario: Real connector
- **WHEN** a disposable ChatGPT connector uses its observed exact callback and allow-listed CIMD URL
- **THEN** it authorizes an internal user, executes a permitted MCP tool as that user, and reauthorizes after expiry.

#### Scenario: Optional capability needed
- **WHEN** acceptance proves a deferred capability necessary
- **THEN** record the result and scope that change before relying on it in production.
