# Tenant-scoped CRM: development-only draft

NOT RELEASE READY. No deployment, production migration or user grant is authorized
by this branch. Main is untouched.

## Implemented
- CRMTenantGrant binds one OrganizationMember and tenant UUID to CRM-only permissions.
- Issuer intersects active explicit grants with ArnaSite's active tenants for the
  current organization. Non-owner permissions replace, never union, organization IAM.
- Every CRM human proof is singleton, including owner proofs. Owner retains
  authorization to owned tenants but must select one (sole tenant auto-selects).
- Optional tenant_id at authorization is only a selector. Exchange ignores any
  browser-submitted tenant or permission. Code stores member/org/tenant/ownership,
  original active selector and grant revision; changes require new authorization.
- Exchange checks browser session/fingerprint for browser-issued codes and caps
  proof expiry at min(60 seconds, original credential/session expiry).
- New proofs carry sub and principal_type=user but OMIT the base SimpleJWT user ID
  claim. Standard SSO JWTAuthentication therefore cannot resolve them as users at
  any generic token-minting endpoint (including org switch). Configuring base
  USER_ID_CLAIM=sub fails closed for CRM issuance.
- Authorize-code also explicitly rejects non-human/product proofs. No generic
  serializer or existing password/social/OTP/MFA token format was changed.
- No public grant-management endpoint exists yet. Model validation is not actor
  authorization or tenant-ownership validation; provisioning needs both plus audit.

## Revocation and rollback
New proofs have bounded expiry, NOT instant revocation. Denial applies at next
issuance; an in-flight request or previously signed JWT may survive until expiry
plus consumer clock leeway. ORM bulk updates bypass model save/updated_at: grant
management must use a reviewed version-incrementing path; no such API shipped here.

Old tokens remain usable by existing consumers until their original expiry. Before
cutover, determine actual maximum old TTL and leeway or deploy a fail-closed
consumer marker/cutoff gate in BOTH CRM and BNK. A rollback to the old issuer can
mint broad organization-wide grants again: retain the consumer gate / stop
issuance during rollback. Additive schema alone does not make rollback safe.

## Isolated tests, executed
36 tests passed with Django 5.0.6 + DRF + real signed RS256 JWT, real model persistence
in ephemeral SQLite, ArnaSite mocked and ephemeral test-only signing keys.
Tests include base login, proof singleton, standard JWTAuthentication rejecting CRM
proof as a user, authorize rejection, pending-code revoke, permission/revision
change, org/tenant/owner switches, logout, original credential expiry, code reuse,
legacy unbound code, directory failures and pure policy cases.
This is NOT the full SSO suite, production database migration test, endpoint-level
CRM CRUD test or complete frontend E2E. AppConfig signal hooks and migrations are
deliberately disabled in the isolated harness to avoid unrelated integrations.

Reproduce in an isolated checkout / virtualenv:
    pip install -r scripts/crm_scope_test/requirements.txt
    PYTHONPATH=scripts/crm_scope_test:$PYTHONPATH DJANGO_SETTINGS_MODULE=isolated_settings \
      python -m django test authentication.tests.test_crm_dashboard \
        authentication.tests.test_crm_bound_codes iam.test_crm_scope

## Remaining coordinated release blockers
1. BNK session-client renews at exp<=now+60: incompatible with new60s token TTL.
   Lower renewal skew and test deduplicated parallel401, polling, denied renewals.
2. BNK start/resume/callback must carry the selected tenant; its dashboard selector
   differs from SSO's active_tenant_id. Generic SSO selection must not silently
   authorize the wrong tenant. New guard compatibility needs all-client tests.
3. BNK and CRM currently union tenant_id with tenant_ids. Enforce consistent
   singleton human proofs, principal user and marker/cutoff at both consumers.
4. Audit service/device/website paths independently. crm.website_chat is a
   separate exact-scope tenant service contract and must not become dashboard
   access. AppSession APP_CLIENTS currently excludes arna-site-crm.
5. Run full migration consistency and auth/IAM regression on isolated PostgreSQL,
   plus actual CRM CRUD/FE E2E and concurrent exchange tests.
6. Owner multi-tenant selection is now deliberate fail-closed behavior; verify
   callers send tenant choice before rollout. Existing non-owner users require
   explicit reviewed grants, never auto-grant all tenants.
