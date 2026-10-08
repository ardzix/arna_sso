# CRM dashboard authorization

The registered `arna-site-crm` client uses the existing S256 authorization-code endpoints. It may authenticate through the native SSO page, or through the dashboard's server bridge using its existing SSO access credential. The dashboard never treats its legacy token's claims as CRM authority.

For this client, `/api/auth/sso/token/` returns only a short-lived access token with RS256, `iss`, `aud=arna-crm`, `sub`, current `org_id`/`organization_id`, current IAM permissions/owner status, and `tenant_ids` resolved from ArnaSite. No CRM refresh credential is issued. Generic client token pairs and `arna-site-website` customer proofs retain their previous behavior.

Organization membership is resolved from SSO records at exchange time, not supplied by the browser. SSO delegates a short user access token with the ArnaSite audience to `GET https://site.arnatech.id/tenants/`. The configured HTTPS endpoint must return canonical `tenant_id` UUIDs, matching `sso_organization_id`, and `is_active`; mismatched or invalid context fails closed. No other service database is read. Empty active workspaces produce 403; directory failures produce 503. Membership is rechecked after the lookup, and authorization codes are consumed atomically only after successful proof generation.

Register this exact production client/callback pair as active in `SSOAllowedRedirectURI`:

```text
client_id: arna-site-crm
redirect_uri: https://www.bisnisnaikkelas.com/api/crm/auth/callback
```

The global `SSO_ALLOWED_REDIRECT_URIS` list alone cannot enable a CRM client callback. Plain PKCE is rejected. Explicit loopback HTTP development callbacks may use the local settings allowlist only while DEBUG is enabled.

Global optional configuration:

```dotenv
CRM_ARNASITE_TENANTS_URL=https://site.arnatech.id/tenants/
```

This is the default; no new variable is needed for the standard production deployment. Deploy this SSO change before `arna_site_fe`'s matching `fix/crm-dashboard-single-sign-on` branch. No schema migration or per-tenant registration is required. CRM permissions and Commerce entitlement enforcement are unchanged.

Regression coverage is in `authentication.tests.test_crm_dashboard`, alongside the existing browser-code and website-proof suites.
