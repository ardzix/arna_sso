# Website customer phone verification

The registered `arna-site-website` client exchanges an S256 PKCE authorization
code for a restricted, RS256-signed phone identity proof. The SSO user must be
active and have a verified phone both when the code is issued and when exchanged.
The code is consumed with a conditional database update to prevent concurrent reuse.

The response contains `access`, `token_type: Bearer`, and `expires_in: 1800`.
There is no refresh token. The JWT carries `token_type: website_customer`, `sub`,
`phone_number`, `phone_verified: true`, `scope: website.customer`, expiry and JTI.
It carries no organization, tenant, role or permission claims. Ordinary SSO
access/refresh token classes reject this purpose-specific type.

Issuer and audience use existing `SIMPLE_JWT` values when explicitly configured.
Their production defaults for this proof alone are `https://sso.arnatech.id` and
`arna-site-website`. Global JWT settings and other clients' access/refresh token
responses are unchanged. An unregistered client or redirect still fails the
existing exact registration checks.

CRM validates the production public key, issuer, audience, expiry, proof type and
exact pending phone before creating a tenant-scoped customer-only session. The
proof stays in the website backend and never becomes a dashboard credential.
Configure `WEBSITE_SSO_TOKEN_TYPE=website_customer` alongside the website-specific
verification key, issuer and audience in CRM.

The localhost phone flow registers
`https://127.0.0.1:3000/api/v1/website/customer/callback`. The BFF validates the
returned URI and exchanges the code directly; it does not navigate the browser
to that URI. This exception in presentation applies only to the current backend
phone verification flow; browser redirects need an actual matching HTTPS handler.

The 2026-10-07 production release overlays only `authentication/sso_views.py` and
`authentication/website_proof.py` on the existing immutable SSO image. The base
source hash is checked before rollout. Tests run without network access against
fresh SQLite state and ephemeral signing keys; no production credentials enter
the test container. Swarm rolls replicas one at a time with start-first ordering,
HTTP health checks and rollback on failure. `docker service rollback sso_service`
restores the preceding service definition and image; exact redirect registration
is retained independently in SSO's database. No database migration is required.
