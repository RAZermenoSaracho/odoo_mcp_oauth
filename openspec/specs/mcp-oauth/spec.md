# mcp-oauth Specification

## Purpose

One optional per-database addon gives the unchanged Odoo 19 MCP endpoint ChatGPT-compatible OAuth using native login, signatures, and API keys.

## Requirements

### Requirement: Explicit single-addon installation and MCP inheritance

`odoo_mcp_oauth` SHALL depend on `['odoo_mcp', 'web']`, SHALL NOT `auto_install`, and SHALL add no pip dependency. Its only new model SHALL be the admin-managed hosted OAuth client registry. It SHALL subclass the existing controller, override method `mcp` with `@http.route(auth='mcp_oauth')`, call `super().mcp()`, and inherit the parent's `/mcp`, POST, HTTP type, CSRF-disabled, session-disabled, and body-limit settings. The parent Origin check and `LIMITER.check((dbname, uid))` SHALL still run; the addon SHALL NOT reimplement the MCP body or modify `odoo_mcp`.

#### Scenario: Opt-in database and legacy suite
- **WHEN** an operator installs the addon in one database and runs the full existing `odoo_mcp` suite with it installed
- **THEN** only that database's MCP auth changes, and the existing endpoint behavior and bearer assertions still pass; compare the three pre-existing `odoo_mcp/tests/test_docs.py` failures against a run without the addon.

#### Scenario: Upgrade preserves existing credentials
- **WHEN** a database with keys already issued to external CIMD clients upgrades to this version
- **THEN** those keys keep authenticating at `/mcp` with unchanged name, scope, expiration and client attribution.

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

A reverse proxy (for example cloudflared) that forwards the original Host and `X-Forwarded-Proto` but no `X-Forwarded-Host` does not trigger Odoo's ProxyFix. If `X-Forwarded-Host` is supplied, the host and selected database still follow Odoo's host-filtered selection.

#### Scenario: Discovery on host
- **WHEN** AS metadata and both PRM paths are requested at `https://odoo.example.com`
- **THEN** they advertise only that issuer, `https://odoo.example.com/mcp`, and the listed RFC 8414/9728 fields.

#### Scenario: Host, scheme, or database mismatch
- **WHEN** HTTP is used, no DB resolves, or a database header tries to override the host-filtered DB
- **THEN** OAuth routes fail closed or stay in the host-selected DB, never disclosing another issuer or key.

#### Scenario: Reverse proxy without forwarded host
- **WHEN** `proxy_mode` is enabled, original Host is present, `X-Forwarded-Host` is absent, and the last `X-Forwarded-Proto` value is `https`
- **THEN** OAuth metadata uses `https://<Host>` as issuer even though ProxyFix did not run; another last proto value makes OAuth routes return 404.

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

### Requirement: Pre-login validation and explicit consent

`GET /oauth/authorize` SHALL declare `auth='public'`. Before login it SHALL check only that `client_id` is allow-listed and the request is well-formed. If `request.env.user._is_public()`, it SHALL redirect to `/web/login?redirect=<url-quoted local /oauth/authorize URL>`; it SHALL never redirect to the client before login. After login on the same GET, it SHALL fetch and validate CIMD, exact `redirect_uri`, `response_type=code`, S256 challenge and method, and exact `resource=issuer+'/mcp'`. The optional `scope` request parameter SHALL be accepted and ignored; token scope is always `mcp`. Invalid client or redirect SHALL show an error page; other authorization errors SHALL redirect to the validated callback with `error`, original `state` when supplied, and `iss=issuer`. Native login rotation returns to the same local authorize URL. No dispatch/auth-path customization or server-side transaction is needed. Only active `user._is_internal()` users may consent. Portal/public or archived users SHALL get `access_denied` at a validated callback. QWeb consent SHALL display client name/host, DB, user, and the selectable access duration (see "User-selected token duration"). Consent responses SHALL set `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `Referrer-Policy: no-referrer`, and `Cache-Control: no-store`.

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

`POST /oauth/token` SHALL use `auth='none'` (uid None; `ir_http.py:260`), `readonly=False` (Odoo 19 otherwise defaults `auth='none'` to a read-only cursor), `csrf=False`, only `grant_type=authorization_code` and public auth method `none`. Require exact client ID, redirect, resource, and correct S256 verifier; recheck client allow-list and signed user's active/internal state. The optional `scope` parameter SHALL be ignored. Narrow sudo SHALL be used only to (a) call `hash_sign`/`verify_hash_signed`, which read system-only `database.secret` through `ir.config_parameter` (`ir_config_parameter.py:69`, `base ir.model.access.csv:118`); (b) read the signed UID's active/`_is_internal` state; (c) locate the new key by `index=key[:INDEX_SIZE]` and write `oauth_client_id`/`oauth_code_hash` (`res_users.py:1509,1608`; `_generate` returns only the key after a raw INSERT); and (d) update replay revocation scope through a fresh registry cursor and parameterized plain SQL. `res.users.apikeys` has `_auto=False` and core manages it with plain SQL. Employees have read-only apikeys ACL (`ir.model.access.csv:92`). `_generate(scope='mcp', name='OAuth: <client_name>', expiration_date=<user-selected duration from the signed code>)` SHALL run on `env.with_user(uid)` with `su=False`, since it reads `env.user` for owner and duration; a test SHALL assert `su=False` inside `_generate`. The duration SHALL be re-checked against the owner's currently permitted durations at exchange. Other keys for the same client SHALL stay usable until the user deletes them in Preferences. Core credential lookup is plain SQL (`res_users.py:1574`), so a replay scope write SHALL immediately make that key fail `mcp` and `rpc`. Respond with `access_token`, `token_type=Bearer`, `expires_in` (omitted for a non-expiring key), `scope=mcp`, and `Cache-Control: no-store`; no refresh token. Use generic errors. Tokens and verifiers SHALL never appear in URLs/logs; codes only on validated callback redirects.

#### Scenario: Valid exchange and owner
- **WHEN** all bindings and PKCE match for an active internal user
- **THEN** one owner-bound `mcp` key is returned in the body with `Cache-Control: no-store`; `_generate` observes `su=False`.

#### Scenario: Wrong verifier or unsupported grant
- **WHEN** verifier is missing/wrong, a different grant is requested, or client-secret authentication is attempted
- **THEN** no token is issued and an appropriate generic protocol error appears.

#### Scenario: User changes after consent
- **WHEN** code owner is archived or made portal before exchange
- **THEN** exchange returns `invalid_grant` and no key.

#### Scenario: Duration permission lowered after consent
- **WHEN** the owner's permitted durations no longer include the signed duration at exchange
- **THEN** exchange returns `invalid_grant` and no key is created.

#### Scenario: Immediate replay revocation
- **WHEN** a code replay changes the winner key's scope and that key is immediately used at `/mcp` or an RPC endpoint
- **THEN** plain-SQL credential lookup rejects it without waiting for cache invalidation.

### Requirement: Browser-submitted consent

The consent page SHALL NOT use the `oe_login_form` class or any other hook of web's public `Login` interaction, which disables the first submit button on submit and so drops a button-carried value from the form data. Approve and Deny SHALL be separate forms whose decision travels in a hidden input. An automated test SHALL submit consent in a real browser with public JavaScript loaded.

#### Scenario: Approve in a real browser
- **WHEN** an internal user clicks Approve on the rendered consent page in a browser with Odoo's frontend assets
- **THEN** the POST carries `decision=approve` and the selected duration, and the client receives a 303 with `code`, `state`, and `iss`.

#### Scenario: Deny in a real browser
- **WHEN** the user clicks Deny
- **THEN** the client receives `error=access_denied` with `state` and `iss`.

### Requirement: User-selected token duration

The consent page SHALL offer 1 Day, 1 Month, 1 Year and Never (values 1, 30, 365, 0 days), filtered by core `res.users.apikeys.description._selection_duration()` for the consenting user: Never only for system administrators (core allows a NULL `expiration_date` only for `is_system()`), the others only up to the user's maximum group `api_key_duration`. The default SHALL be 1 Month when permitted, otherwise the first permitted option. If no option is permitted the client SHALL receive `access_denied`. The POST SHALL reject any duration outside the user's permitted set. The chosen duration SHALL be carried only in the HMAC-signed authorization code; the token endpoint SHALL ignore any client-supplied duration or expiry parameter, re-check the duration against the owner's current permissions, and mint a native key with `expiration_date = now + days` or NULL for Never. Core `_check_credentials` rejects expired keys, nothing extends expiry on use, and core autovacuum deletes expired keys. Revocation stays Preferences > Account Security > API Keys and the Settings allow-list.

#### Scenario: Options follow native permissions
- **WHEN** a plain internal user (90-day group maximum) and a system administrator open consent
- **THEN** the user sees 1 Day and 1 Month, the administrator sees all four, and 1 Month is preselected.

#### Scenario: Chosen expiry is persisted
- **WHEN** a duration is approved and the code exchanged
- **THEN** the key's `expiration_date` is now plus that many days (NULL for Never) and `expires_in` matches (absent for Never).

#### Scenario: Duration tampering
- **WHEN** a non-administrator posts Never, 1 Year, an unlisted value, or none, or a token request adds `duration`/`expires_in`
- **THEN** consent shows the error page, or the extra token parameters are ignored.

#### Scenario: Expired key rejected without extension
- **WHEN** an issued key's `expiration_date` has passed
- **THEN** `/mcp` returns 401; successful calls before expiry never change `expiration_date`.

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

### Requirement: Disposable acceptance and deferred features

Before production, a real ChatGPT connector SHALL complete challenge, PRM and AS metadata, login, consent, code exchange, MCP tool call, expiry, and reauthorization on a disposable DB. Its exact callback and refresh/offline, connector-gating, per-tool `securitySchemes`, and `_meta["mcp/www_authenticate"]` expectations remain **UNVERIFIED** until tested. Refresh tokens are deferred unless reauthorization UX is a problem; DCR unless a needed client lacks both CIMD and hosted-client support; client secrets, RFC 7009, and OIDC until evidenced need; per-tool hints unless ChatGPT verification needs them; generic AS until a second protected resource exists. Production install, edge/tunnel changes, and rollback SHALL each require operator approval.

#### Scenario: Real connector
- **WHEN** a disposable ChatGPT connector uses its observed exact callback and allow-listed CIMD URL
- **THEN** it authorizes an internal user, executes a permitted MCP tool as that user, and reauthorizes after expiry.

#### Scenario: Optional capability needed
- **WHEN** acceptance proves a deferred capability necessary
- **THEN** record the result and scope that change before relying on it in production.

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
