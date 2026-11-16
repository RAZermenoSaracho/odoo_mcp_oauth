## Why

Some MCP clients publish no Client ID Metadata Document (CIMD) and instead ask the user for an explicit OAuth Client ID. Meta AI Muse is the observed case: its connector UI asks for a Client ID, and its callback is `https://agent.meta.ai/api/hatch/oauth/callback`. Today `odoo_mcp_oauth` accepts only admin-allow-listed CIMD URLs published by the client itself, so there is nothing such a client can enter.

FlowLedger works around this by hosting the client document itself (`/oauth/clients/meta-muse.json`) and passing it through its normal CIMD pipeline. This change adopts the same idea, in a form that works for any client: administrators register **hosted clients** in Odoo, and Odoo serves and resolves their CIMD documents locally.

## What Changes

- New admin-only model `mcp.oauth.client`: name, active flag, redirect URIs, and a random, immutable UUID. Its Client ID is `<issuer>/oauth/clients/<uuid>.json`, shown in the form so the admin can copy it.
- New public route `GET /oauth/clients/<uuid>.json` that serves the CIMD document for an active hosted client, and returns 404 otherwise.
- Hosted Client IDs are resolved from the database, never fetched over HTTP. Active hosted clients on the current issuer count as allowed, alongside the existing CIMD allow-list, at authorize, consent and token.
- For hosted clients, the consent page shows the callback host instead of the Client ID host (which would be Odoo's own domain).
- Lifecycle, enforced server-side:
  - Archiving a hosted client blocks new authorizations and pending codes; its issued keys keep working.
  - Deleting it also revokes its issued keys, as removing an allow-list URL already does.
  - An admin-only, confirm-guarded **Revoke All Credentials** action revokes that client's keys without archiving it, through core's API-key `_remove()`.
- Claude compatibility: claude.ai/Desktop and Claude Code use Anthropic's published CIMD documents, so they only need adding to the allow-list. Claude Code's loopback callbacks (`http://localhost/callback` used on a random port) need one standards change: RFC 8252 §7.3 port-agnostic loopback redirect matching for documents that list a port-less loopback URI. Existing API-key bearer auth on `/mcp` is unchanged and coexists.
- A rejected authorize request logs the reason (parameter names only, no values), so Muse's real behavior can be diagnosed during manual validation.
- Unchanged: PKCE S256, required `resource`, exact redirect match, signed single-use code, API-key tokens, the existing allow-list and its revocation, discovery metadata, and `odoo_mcp`.

Non-goals: Dynamic Client Registration, client secrets, refresh tokens, a `/revoke` endpoint, new scopes, Muse-specific logic, relaxing the `resource` check, and changes to `odoo_mcp`.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `mcp-oauth`: adds hosted clients (model, CIMD endpoint, local resolution, lifecycle, consent display) and lifts the "no client model / no manual client" restriction.

## Impact

- Code: `odoo_mcp_oauth` only. New model, views, ACL line and tests. Small edits to `controllers/main.py` and the consent template. Version bump to `19.0.1.1.0`.
- Data: one new table, `mcp_oauth_client`. There are no schema changes to `res_users_apikeys` and no migration of existing keys.
- Deployment: running `-u odoo_mcp_oauth` on each database that has it installed requires operator approval. Those are currently `odoo`, `odooers`, `ramzsa-odoo` and `home-nsr-odoo`.
