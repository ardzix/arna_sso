# Website CRM service credentials

ArnaSite owns the verified domain-to-organization-and-tenant mapping. Provision a
separate SSO `ServiceAccount` for each website tenant using that trusted mapping.
Set its `organization_id`, `tenant_id`, scopes to exactly `['crm.website_chat']`,
and audiences to exactly `['arna-crm']`. Keep its client secret in the frontend
server's secret manager. Do not copy a visitor or dashboard token.

`POST /api/auth/service-token/` still exchanges client ID/secret and one registered
audience. For this narrow website scope it returns a five-minute RS256 token with
`token_type=service`, `principal_type=service`, issuer, audience, client/service IDs,
the registered organization/tenant, and `scope=crm.website_chat`. Requests cannot
change signed ownership or scopes. Missing tenant/organization or additional
scopes/audiences prevent issuance. Other service clients retain their existing
access-token contract.

Migration `0012_serviceaccount_tenant` adds one nullable column and a constraint
requiring an organization when a tenant is set. Existing registrations remain
compatible. Older application images can run with the additive column retained;
rollback should restore the previous image without dropping registrations.

Consumers verify signature, issuer, audience, expiry, service/client identity,
scope, and ownership before use. Renew before expiry; failed renewal fails closed.
Disabling the account prevents new tokens, while already-issued tokens expire
within the configured five-minute lifetime. No refresh or permanent bearer token
is issued.
