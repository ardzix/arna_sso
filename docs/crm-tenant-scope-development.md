# DRAFT: tenant-scoped human CRM access

Development only. Do not merge, migrate, deploy, or create live grants from this
branch until the release gates below pass. No existing membership is changed.

## Contract
CRMTenantGrant belongs to one OrganizationMember and one tenant UUID. The issuer
intersects it with the active tenant directory returned by ArnaSite for that
organization. A non-owner receives exactly one tenant and that grant's CRM-only
permissions, never the organization's role/permission union. active_tenant_id is
a selector, not authority. With one grant and no selection it is selected; with
multiple grants an explicit authorized selection is required. Invalid or stale
selection fails closed.

An actual organization owner retains the existing all-owned-tenant behavior.
There is intentionally no automatic migration from organization-wide crm.manage
to every tenant. Existing non-owner CRM users therefore need explicitly reviewed
tenant assignments before rollout. No management API or UI is exposed yet:
assignment must not be made via generic organization-role UI.

## Revocation
New CRM proofs expire within 60 seconds and contain no refresh token. Deactivating
a grant prevents the next proof, but previously signed access is NOT immediately
revoked. Allow for verifier clock leeway and in-flight requests. Old tokens minted
before rollout retain their original expiry. Deployment must drain their actual
maximum lifetime or introduce an independently reviewed live introspection /
revocation mechanism. This draft does not implement instant revocation.

Membership/session and grant changes can race with issuance, so the expiry bound
also applies to issuance concurrent with revocation. No claim of linearizable
revocation is made.

## Issuance / compatibility
- arna-site-crm PKCE exchange invokes crm_dashboard_proof, now scoped.
- Generic human authorization-code creation rejects product audience, tenant
  claims, device principals, pre-auth and non-access tokens.
- Browser-session entry already requires human/base-audience proof.
- Current APP_CLIENTS does not include arna-site-crm. App resolve is not a CRM
  refresh path. Website customer proof and service/device tokens are separate
  contracts and must not gain human grants.
- CRM validates the signed tenant set before CRMAccess checks crm.manage. Existing
  CRMAccess requires no permission-name change.
- BNK must handle a 60-second proof expiry and reauthorize transparently, without
  widening to generic SSO tokens or replaying writes.
- JWT audience policy and all alternative issuers must be reviewed with the
  paired CRM backend before release. Do not rely only on a frontend tenant menu.

## Tests and gates
Executed here: 9 pure policy tests (including malformed-permission subcases).
Django/DRF integration tests are provided in authentication/tests/test_crm_dashboard.py
but NOT executed in the current read-only environment (Django absent).
Required before release:
1. Run Django migration consistency and full authentication/IAM test suites in an
   isolated test database. Existing force_authenticate fixtures that omit request.auth
   need real base-audience token fixtures rather than bypassing the new guard.
2. Real signed-JWT tests for wrong audience, refresh rejection, same-org/different
   tenant, foreign organization, browser-supplied claims, and every token issuer.
3. CRM endpoint CRUD isolation tests plus BFF expiry/reauthorization behavior.
4. Review grant provisioning authorization, audit trail and tenant ownership checks
   in the eventual admin API. The model alone is NOT a public grant endpoint.
5. Confirm owner compatibility, enumerate existing non-owner access, approve bounded
   revocation or implement introspection, and obtain deployment authorization.

No production or user grant is included in this development branch.

## Independent review: unresolved release blockers
- Authorization codes currently bind client/user/redirect/PKCE but not authorized
  organization/tenant. Add explicit context binding and reject switches between
  authorization and exchange before release.
- CRM exchange must revalidate originating central browser session/fingerprint
  when a browser_session_key is present, rather than relying solely on code TTL.
- Review every consumer/issuer for audience laundering. The authorize-code guard
  here is only one boundary, not proof all generic authenticated SSO APIs are safe.
- Preserve service website_chat's dedicated narrow contract. Generic service
  accounts with arna-crm audience must not be mistaken for human dashboard grants.
- Owner multi-tenant behavior is deliberately preserved in this draft, pending
  a compatibility decision; this is not a claim all CRM tokens are singleton.
- Existing tests using force_authenticate without a token require fixture updates.
