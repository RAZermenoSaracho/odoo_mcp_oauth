## 1. Model and security

- [x] 1.1 Add `models/oauth_client.py`: `mcp.oauth.client` (`name` required, `active`, `redirect_uris` Text, `uuid` immutable unique hex default, computed `client_id`), a redirect-URI constraint, a `write` guard on `uuid`, and `unlink` revoking attributed keys plus a registry cache clear; register it in `models/__init__.py`
- [x] 1.2 Add an `ir.model.access.csv` line: `mcp.oauth.client` full CRUD for `base.group_system` only
- [x] 1.3 Add `_attributed_keys()` (stable Client ID suffix, excluding allow-listed external URLs) and `action_revoke_credentials` (system-only, confirm-guarded button), revoking via core `_remove()`; `unlink` reuses it

## 2. Controller

- [x] 2.1 Add `_hosted_record(issuer, client_id)` / `_hosted_document(...)` helpers returning the active record / CIMD dict, or None (regex-checked UUID, `sudo` search limited to that UUID)
- [x] 2.2 `_is_allowed(client_id)` (replaces `_allowed_clients()`): allow-listed external URL, or an active hosted client of the current issuer
- [x] 2.3 Authorize GET: resolve hosted IDs locally via `_hosted_document`; `_client_document()` is never called for a URL under `<issuer>/oauth/clients/`
- [x] 2.4 Add the `GET /oauth/clients/<string:client_file>` route (`<uuid>.json` checked by regex) (`auth='none'`, `save_session=False`, `csrf=False`, `METADATA` limit, 404 for no issuer or an unknown or archived client, `NO_STORE`)
- [x] 2.5 Consent: `client_host` becomes the callback host for hosted clients
- [x] 2.6 Authorize: an INFO log naming the failed check or missing parameter names (no values)

## 3. Views and manifest

- [x] 3.1 Add `views/oauth_client_views.xml`: list, form (Client ID with `CopyClipboardChar`) and window action, all limited to `base.group_system`
- [x] 3.2 Add a "Hosted clients" button in `views/res_config_settings_views.xml`
- [x] 3.3 `__manifest__.py`: add the view file after security, bump the version to `19.0.1.1.0`, update the summary

## 4. Tests (disposable DB only)

- [x] 4.1 `tests/test_hosted_client.py` (model): create/persist; unique and immutable UUID; Client ID format; multiple URIs; invalid URIs rejected; non-admin ACL denied; unlink revokes only its keys
- [x] 4.2 Same file (HTTP): public JSON fields and content type, no login redirect, no `Set-Cookie`; 404 for malformed, unknown, archived, foreign-host and insecure-origin requests
- [x] 4.3 Same file (flow): Muse-shaped authorize → consent → token with `requests.get` patched to fail (proves no outbound call); prefix/encoded redirect, non-S256, missing or wrong `resource`, archived-before-exchange; consent shows the callback host; the key appears in `user.api_key_ids` named `OAuth: <name>` with `oauth_client_id` set
- [x] 4.4 Bulk revoke: revokes only client A's keys (B, external CIMD and manual keys survive); A stays active; a non-admin call is refused; deleting before exchange invalidates the pending code
- [x] 4.5 Revocation (incl. core Security-tab `_remove` by owner and by admin; lookalike external URL spared by bulk revoke): delete the hosted key → `/mcp` returns 401 on the next request; ChatGPT-CIMD and manual keys for the same user still return 200; archive keeps the key valid, delete kills it
- [x] 4.6 Regression: the full existing `odoo_mcp_oauth` suite and the `odoo_mcp` suite pass unchanged (the external CIMD flow, allow-list removal revocation, replay, durations, browser consent)

## 4b. Claude compatibility

- [x] 4b.1 Verify Claude's published CIMD documents and documented discovery/PKCE/resource/scope conditions
- [x] 4b.2 Add `_redirect_matches()` (exact + RFC 8252 loopback any-port) and use it in `_client_document` and authorize GET
- [x] 4b.3 `tests/test_claude.py`: discovery conditions, Claude web flow, Claude Code loopback any port and rejections, API-key coexistence, individual revocation, reauthorization
- [x] 4b.4 Full regression (`odoo_mcp_oauth`, `odoo_mcp`)

## 5. Docs

- [x] 5.1 README: authentication methods (API key + OAuth), Claude configuration, hosted clients, the Muse values to enter, archive vs delete vs individual vs bulk revoke semantics, the diagnostic log
- [x] 5.2 Sync the spec delta into `openspec/specs/mcp-oauth/spec.md` at archive time

## 6. Deployment (separate operator approval)

- [x] 6.1 Upgrade on a disposable copy, then on approved tenants: `odoo-bin -d <db> -u odoo_mcp_oauth --stop-after-init`, then `pm2 restart odoo --update-env`
- [x] 6.2 Confirm that pre-existing keys still authenticate after the upgrade

## Deployment record (2026-11-16)

- Backups: `pg_dump -Fc` of `odoo`, `odooers`, `ramzsa-odoo` and `home-nsr-odoo`, plus filestore tarballs, in `/Users/razs/backups/odoo/pre-mcp-oauth-1.1.0-20261116/`. The `odoo` dump was test-restored.
- `pm2 stop odoo`; `-u odoo_mcp_oauth` on all four databases (each exited 0 with no errors); `pm2 start odoo`. About 64 s of downtime.
- API-key rows identical before and after; the existing Claude API-key connections (`odoo`, `odooers`) still work.
- Claude CIMD URLs appended to the allow-list of `odoo` and `odooers` (ChatGPT entry kept). Tenant databases left unchanged.
- Production smoke on `odoo.razs.dev` and `odooers.razs.dev`: discovery, 401 challenge, authorize gate for Claude web, Claude Code loopback and ChatGPT, unknown client rejected, hosted document 200/404, bulk and individual revocation, archive and delete. All passed, using disposable clients and keys only.

## 7. Manual validation (real clients, not automatable). Pending external validation

- [ ] 7.1 On the chosen tenant: create the Muse hosted client and enter the Client ID, `/oauth/authorize`, `/oauth/token`, scope `mcp` and no secret in Muse
- [ ] 7.2 Capture the logs: discovery paths hit, authorize params present (`resource`, `scope`, `code_challenge_method`), token result
- [ ] 7.3 On success: run one MCP tool call, check the key shows in Users → Security, delete it, confirm Muse gets 401
- [ ] 7.4 On failure: record the exact failing check and propose the smallest standards-compliant fix as a new change
- [ ] 7.5 Re-check that ChatGPT still connects, and that the existing Claude API-key connection is unaffected
- [ ] 7.6 Claude OAuth (with operator approval): allow-list the Claude document(s), add a second connector in claude.ai (Settings → Connectors → Add custom connector, URL `https://<host>/mcp`, "Use Claude's published identity") and/or `claude mcp add --transport http <name> https://<host>/mcp`; then authorize, call a tool, delete the `OAuth: Claude` key, and confirm 401 while the API-key connector keeps working
