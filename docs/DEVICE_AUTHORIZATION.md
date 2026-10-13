# Tenant-bound device authorization

This contract supersedes the audience/scope examples in the supplied kiosk
guides. The public visitor screen does not need a human login. Device credentials
belong in the installed kiosk agent/secure OS storage, outside that public screen.

## Identifiers and token contract

- `client_id`: stable identifier unique to one installed device; use different
  values for different kiosks. A duplicated client ID requires operator approval
  and replaces the old pairing, not a second active device.
- `device_id`: UUID of the SSO machine registration. Returned by approval,
  token, refresh, inventory, detail and device status.
- `organization_id`: SSO organization UUID; optional in authorize for legacy
  clients. The server derives it from the approving operator's active membership;
  a supplied legacy hint must match that context.
- `tenant_id`: public ArnaSite tenant UUID, verified against the selected
  organization's active `/tenants/` records on review and approval. It is optional
  during authorize and derived from the operator's verified workspace. It is not an
  ArnaSite integer database ID or schema name.
- `organization_member`: UUID of a **human** organization membership, used by
  IAM user roles/permissions. Devices do not have that membership.
- `device_code`: private, one-time exchange credential; never put it in a QR,
  URL or log. `user_code`: short public approval code, not a device/member ID.

Default audience: `photobooth-api`. Default allowed scopes:
`photobooth.session`, `photobooth.session.write`. The application should request
only the scope it actually implements. Commerce remains a product-backend service
call. File Manager uses a separate `storage` resource token with current SSO IAM
permissions, as described below; do not add storage scopes to pairing requests.

Device JWTs are RS256 with `iss=https://sso.arnatech.id`, `aud`, `sub=device_id`,
`token_type=device`, `principal_type=device`, `device_id`, `client_id`, `org_id`,
`organization_id`, `tenant_id`, `scopes`, `credential_version`, `iat`, `exp`, `jti`.
Default access lifetime: **300 seconds**, refresh lifetime: 30 days, pairing code:
600 seconds. Refresh credentials rotate on every successful refresh.

## Endpoints

New clients use `/api/v1/devices/`. `/api/auth/device/` retains the existing pairing,
inventory, status and introspection aliases. Context, access and resource-token
endpoints are available only under `/api/v1/devices/`. Service credential exchange remains
`POST /api/auth/service-token/`.

| Method and suffix | Authentication | Behavior |
| --- | --- | --- |
| POST `authorize/` | Public; optional device DPoP proof | Validate input, audience and scopes; create pairing codes |
| POST `review/` | Human SSO access token | Verify permission and tenant; return name, client, organization, tenant, audience, scopes, binding, expiry |
| POST `verification/` | Human SSO access token | Explicit approve/deny; repeat permission and tenant checks on approval |
| POST `token/` | Private device code; proof if key-bound | Poll and consume an approved grant once |
| POST `refresh/` | Opaque refresh credential; proof if key-bound | Rotate only the current active pairing's credential |
| POST `revoke/` | Organization owner or member with `device.activate` | Set inactive, increment credential version, revoke refresh credentials |
| GET `registrations/` | Authorized human | Active organization/tenant-scoped paginated inventory |
| GET `registrations/{device_id}/` | Authorized human | Organization/tenant-scoped details |
| GET `status/` | Device access token; proof/token hash if key-bound | Check this device's active registration/version and return its IDs |
| POST `introspect/` | Dedicated backend service token | Verify device JWT/registration; return `active:false` for invalid/revoked/replaced/out-of-context credentials |
| GET/POST `context/` | Human SSO access token | List verified active workspaces; select one verified tenant |
| GET/PUT `registrations/{device_id}/access/` | Tenant owner/authorized admin | Inspect or replace assigned roles and direct permissions |
| POST `resource-token/` | Human or device subject token; proof if bound | Issue a short-lived storage token using current SSO IAM permissions |

Authorize body:

```json
{
  "client_id": "photobooth-kiosk-01",
  "device_name": "Photobooth lobby",
  "audience": "photobooth-api",
  "scopes": ["photobooth.session"]
}
```

Review body: `user_code`. Decision adds `action: "approve" | "deny"`. Inventory
accepts `page` (default 1), `page_size` (default 20, maximum 100). Organization and
tenant come from the human's active, verified workspace. One active tenant is
selected automatically; with several tenants, call GET `context/`, then POST
`context/` with `{"tenant_id":"<one returned UUID>"}`. Legacy organization/tenant
hints must match this context. Superuser status alone grants no pairing authority.
Pairing requires an active membership and organization ownership or the
organization-scoped `device.activate` permission.

Poll with `grant_type=urn:ietf:params:oauth:grant-type:device_code` and
`device_code`, no faster than `interval` (default 5 seconds). On `slow_down`, the
interval increases by 5 seconds and applies to all further polls. Expected 400
codes: `authorization_pending`, `slow_down`, `expired_token`, `access_denied`,
`invalid_grant`, `unsupported_grant_type`. Field errors are 400 with explicit
field details; unauthorized organization/tenant is 403; active cross-org client
conflict is 409; unavailable ArnaSite verification is 503 and cannot approve.
Every API error includes `error`, `detail`, `request_id`; every response has
`X-Request-ID`.

## Pairing replacement and revocation

Approval is one-time and atomic. Pairing again increments the credential version
and revokes old refresh credentials. Previously approved, unconsumed codes cannot
mint credentials for the new assignment. The version is checked by status and
introspection, along with the exact registered org, tenant, audience, scopes and
key. An active client in another organization cannot be overwritten: the old
organization must first revoke it, then the new organization approves pairing.
Changing tenant within an organization also requires a new explicit approval.
Reassignment to another organization or tenant clears device IAM assignments;
replacement within the same workspace retains them.

Local logout deletes local access/refresh credentials without changing SSO
registration. Administrative revoke is the separate server-side action above.
Resource APIs must check status via introspection for immediate revoke; a service
that only verifies JWT offline can keep accepting the old token until expiry.

## Optional device key binding (DPoP)

SSO supports ES256/P-256 or RS256 (RSA >=2048 bits) DPoP proofs following
[RFC 9449](https://www.rfc-editor.org/rfc/rfc9449.html). The device keeps its private
key locally. Send a signed JWT in the `DPoP` header on authorize, token and
refresh: header `typ=dpop+jwt`, supported `alg`, public `jwk`; payload `htm`,
`htu` (exact public endpoint URI without query/fragment), `iat`, unique `jti`.
The configured trusted origin is `DEVICE_PUBLIC_ORIGIN`; it must match the actual
public URL. Proof age <=120 seconds, future clock tolerance <=30 seconds. Replay
protection uses PostgreSQL across replicas. A bare `public_key_thumbprint` without
a matching proof is rejected, never accepted as evidence of key possession.
P-256 JWK `x` and `y` must each encode 32 bytes, including leading zeroes
([RFC 7518](https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.1.2)); check
your client's JWK serializer rather than truncating coordinates to integer width.

SSO derives `cnf.jkt` from the verified public key and returns `token_type=DPoP`.
For `status/`, use `Authorization: DPoP <access_token>` plus a fresh GET proof
containing `ath` (base64url SHA256 of the access token). For unbound devices use
`Authorization: Bearer <access_token>`. At a photobooth resource API, that backend
must additionally verify DPoP signature, key thumbprint, method, target URI,
timestamp, replay and `ath` for **its own** incoming request. Introspection does
not replace that proof validation. SSO does not implement mTLS client certificates
or server-issued DPoP nonces in this release.

## Backend integration

Provision a dedicated active SSO `ServiceAccount` with only
`audiences=["arna-sso-devices"]`, `scopes=["sso.device.introspect"]`. Set its
`organization_id` and optional `tenant_id` to constrain inspection to that
assignment. Global accounts are for trusted platform backends only. Exchange its
secret server-side for a 300-second service JWT. Then POST to `introspect/` with:

```json
{"access_token": "<device JWT>", "audience": "photobooth-api"}
```

Verify `active:true`, org, tenant, scope and device ID before handling a resource.
The product backend still owns event/session-to-device assignment checks and
Commerce calls. File Manager validates device storage tokens directly and calls
this introspection endpoint with `audience: "storage"`. The device never receives the introspection service
secret or token. Fail closed on SSO dependency failure. If caching introspection,
its cache TTL must meet your documented revoke delay and never exceed JWT expiry.

## Configuration and rollout

See `.env.example`: `DEVICE_AUDIENCE_SCOPES` is an explicit audience-to-scope JSON
map; `DEVICE_ALLOWED_AUDIENCES` remains an additional allowlist. Configure
`DEVICE_ARNASITE_TENANTS_URL` to the trusted ArnaSite tenant-list URL; it defaults
to `CRM_ARNASITE_TENANTS_URL` / `https://site.arnatech.id/tenants/`. Redirects and
incomplete/paginated/cross-org responses cannot establish tenant ownership.
No frontend secret or tenant-specific environment variable is required.

## File Manager IAM and tenant ownership

Humans and devices use the same organization-scoped `Role` and `Permission`
catalogue. Device assignments use `DeviceRole` and `DevicePermission`, never a
fake human `organization_member`. A new device receives no implicit file grants
and does not inherit the approver's permissions or owner status.

PUT `registrations/{device_id}/access/` replaces assignments with:

```json
{"role_ids": ["<existing organization role UUID>"], "permission_ids": []}
```

The owner can assign the organization's roles/permissions. A delegated admin
needs `device.activate`, `organization.manage_roles` for changed roles, and
`organization.manage_permissions` for changed direct permissions; it may delegate
only permissions it currently holds. Cross-organization assignments are rejected.
The frontend provides workspace selection and an access editor in device inventory.

The storage catalogue contains `storage.files.read`, `storage.files.create`,
`storage.files.update`, `storage.files.delete`, `storage.files.share`, and
`storage.folders.create`. Catalogue creation grants nothing automatically.
The organization owner receives those permissions for human storage tokens.

After pairing, send POST `resource-token/` with `{"audience":"storage"}` and
the current device access token. Human clients exchange their current SSO access
token at the same endpoint. A subject without storage permissions receives 403.
The resulting RS256 token has issuer `https://sso.arnatech.id`, audience `storage`,
verified `org_id` and `tenant_id`, and current IAM storage permissions. Lifetime
is at most 300 seconds and never exceeds the source token's expiry. Device tokens
retain `principal_type=device`, `device_id`, credential version and key binding;
human tokens retain `user_id` and `principal_type=user`.

Call File Manager with this token, not the photobooth audience token. For a bound
device, both the SSO exchange and every File Manager request require a fresh DPoP
proof with the relevant target URL and `ath` of that request's access token.
File Manager validates JWT/proof locally and introspects every device request;
revocation, replacement or changed storage permissions invalidate old tokens.
Dependency failures return 503, and missing permissions return a clear 403.

File Manager uses `owner_scope=org` with the verified organization and tenant;
devices cannot create personal files. `created_by_device_id` records the actor
while ownership remains with the tenant. Humans with permission in the same
workspace can use those files. Organization files with an old null tenant are
not guessed or silently backfilled into a workspace; map them explicitly before
granting tenant access. Explicit public/share links retain their link semantics.

## Release sequence for this change

Apply `authentication.0016`, `organization.0005`, and `iam.0011`/`iam.0012` in
SSO. Apply File Manager `authn.0001` and `files.0003`. These migrations add workspace
context, device assignments, storage catalogue, tenant/audit fields and shared
proof replay storage. They do not assign device permissions or infer legacy file
tenants. The earlier `authentication.0015` behavior described below still applies
if that migration has not yet been run.

Configure File Manager's `JWT_ISSUER`, `JWT_AUDIENCE=storage`, `SSO_BASE_URL`,
`SSO_INTROSPECTION_CLIENT_ID`, and `SSO_INTROSPECTION_CLIENT_SECRET`. Provision the
dedicated inspection service account described above; keep its credentials in
backend configuration. Deploy migrated SSO, then migrated File Manager with these
credentials, then the frontend. The updated human client and download proxy now
exchange storage tokens; older clients must adopt the same exchange.

Migration `authentication.0015_device_pairing_security` adds pairing versions,
requested organization and shared DPoP replay storage. It **deactivates all legacy
device registrations, revokes their refresh credentials and denies outstanding
legacy grants**, because previous pairings never verified tenant ownership/key
possession. Operators must pair those devices again. No human memberships or IAM
roles are migrated. Reversing the migration does not resurrect old credentials.
Deploy the backend migration/code before the frontend that calls these new APIs.
Pause device pairing/refresh traffic during the migration and replica replacement;
all SSO replicas must run this release before that traffic resumes. Legacy workers
must not keep approving devices against the migrated tables.
Old kiosk Bearer clients remain compatible after re-pairing with allowed scopes;
old pending grants cannot be resumed.

Use the existing Jenkins/Swarm migration gate before rollout; do not run
`makemigrations` in production. Tests run `scripts/test_gift_registration.py`
against disposable PostgreSQL and synthetic RSA keys, including device contract
tests. This guide describes implementation behavior, not confirmation that a
production rollout has occurred.
