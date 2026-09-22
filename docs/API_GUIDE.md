# Arna SSO API Integration Guide

Base API URL: `https://sso.arnatech.id/api`.

Protected user endpoints require `Authorization: Bearer <access_token>`. A user
access token contains the active organization context (`org_id`, `org_name`),
roles, permissions, and `is_owner`. Treat access and refresh tokens as secrets.

## Endpoint map

| Area | Endpoint group | Purpose |
| --- | --- | --- |
| User authentication | `/auth/register/`, `/auth/login/`, `/auth/mfa/*`, `/auth/token/*`, `/auth/logout/` | Create accounts, sign in, complete MFA, refresh/verify/revoke sessions. |
| Email recovery | `/auth/verify-email/`, `/auth/resend-email-otp/`, `/auth/password-reset-*`, `/auth/change-password/` | Verify email, resend OTP, reset or change password. |
| Social and passkeys | `/auth/google-login/`, `/auth/passkeys/*` | Sign in with Google or manage/passwordlessly sign in with WebAuthn. |
| WhatsApp | `/auth/wa/*` | Link a number, register, or log in through WhatsApp OTP. `/reverse/` routes OTP delivery through n8n after the user initiates chat. |
| Browser SSO | `/auth/sso/authorize-code/`, `/auth/sso/token/` | PKCE authorization-code exchange for registered product redirect URIs. |
| Service credentials | `/auth/service-token/` | Server-to-server access token for a configured service account. |
| Device credentials | `/auth/device/*` | OAuth device authorization for CLIs, agents, smart devices, and other headless clients. |
| Organizations | `/organizations/`, `/organizations/current/`, `/organizations/members/` | Create/list organizations, switch active org, and manage membership. |
| IAM | `/iam/permissions/`, `/iam/roles/`, `/iam/user-roles/`, `/iam/user-permissions/` | Define tenant permissions/roles and assign them to members. |
| Profiles/audit | `/profiles/`, `/audit-logs/` | Manage the current user profile and view audit information where enabled. |

## Email/password with optional MFA

1. Register with `POST /auth/register/` using email and password.
2. If email verification is enabled for the account, submit the received code to
   `POST /auth/verify-email/`; call `POST /auth/resend-email-otp/` if needed.
3. Sign in through `POST /auth/login/`.
4. When the login response has `mfa_required: true`, keep the returned pre-auth
   token and call `POST /auth/mfa/verify/` with the TOTP code.
5. Use the resulting `access` token for API calls and send `refresh` to
   `POST /auth/token/refresh/` as it approaches expiry.
6. On logout, call `POST /auth/logout/` with the refresh token to blacklist it.

Use `GET /auth/mfa/status/` to display whether MFA is active. A user starts MFA
once using `POST /auth/mfa/set/`; a repeat call is intentionally rejected to
avoid replacing an existing authenticator secret. To disable MFA, call
`POST /auth/mfa/disable/` with the current password or a valid TOTP code.

## Organization and IAM

1. Authenticate and create/list organizations at `/organizations/`.
2. Make one organization active with `POST /organizations/current/` and an
   `organization_id`. Store the returned token pair: its claims now reflect this organization.
3. Create permissions at `/iam/permissions/` and roles at `/iam/roles/`. Their
   organization is inferred from the active organization; callers cannot override it.
4. Add members using the organization-members endpoint, then grant a role through
   `/iam/user-roles/` or exception permissions through `/iam/user-permissions/`.
5. After switching organization, refresh any existing user token through
   `/auth/token/refresh/`; the returned claims are rehydrated from the latest
   active session, including roles, permissions, and `is_owner`.

## Browser SSO (PKCE)

Use this for a web product that redirects a user through SSO.

1. Register the exact product `redirect_uri` and client ID in SSO administration.
2. Product frontend generates a PKCE verifier and S256 challenge, then directs
   the user through its SSO login experience.
3. After authentication, call `/auth/sso/authorize-code/` using the user JWT,
   `client_id`, registered `redirect_uri`, challenge, and a CSRF `state` value.
4. Redirect to `redirect_url` from the response.
5. Product backend validates `state`, then exchanges the one-time code and its
   original verifier at `/auth/sso/token/`.

## Service account flow

Use for a trusted backend rather than an end user.

1. Create a Service Account with a client ID, secret, scopes, and allowed audience.
2. Store its secret only in a secret manager.
3. POST `client_id`, `client_secret`, and `audience` to `/auth/service-token/`.
4. Use returned `access` as a Bearer token for the configured audience.
5. Request another service token after expiry. No refresh token is issued.

## Device authorization flow

Use for a CLI, worker installed at a customer site, smart device, or agent that
cannot show a secure browser login itself.

1. Device calls `/auth/device/authorize/` with `client_id`, friendly
   `device_name`, `tenant_id`, allowed `audience`, and requested `scopes`.
2. Device shows the returned `user_code` and `verification_uri_complete` to an
   operator. Do not put `device_code` on screen or in logs.
3. An authenticated organization owner or a member with `device.activate` opens
   the browser URI and submits the code, target `organization_id`, and `approve`
   or `deny` to `/auth/device/verification/`.
4. Device polls `/auth/device/token/` using the opaque `device_code`, waiting at
   least `interval` seconds between attempts. `authorization_pending` is normal;
   on `slow_down`, use the returned larger interval.
5. After approval, store the returned access/refresh pair in secure device storage.
   The access token is short-lived and includes device, tenant, organization,
   audience, and scope claims.
6. Rotate the refresh token through `/auth/device/refresh/`. A successful refresh
   invalidates the submitted refresh credential; persist the new one atomically.
7. Revoke a lost or retired device through `/auth/device/revoke/`. It immediately
   disables future refreshes; any issued access token expires normally shortly after.

### Device flow request examples

Start from the device (no user bearer token):

```bash
curl -X POST https://sso.arnatech.id/api/auth/device/authorize/ \
  -H 'Content-Type: application/json' \
  -d '{
    "client_id": "arna-social-ai-worker",
    "device_name": "Campaign Worker - production",
    "tenant_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "audience": "arna_social_ai",
    "scopes": ["arna_social_ai.campaign.read", "arna_social_ai.report.upload"]
  }'
```

Approve from the browser application after the operator has signed in:

```bash
curl -X POST https://sso.arnatech.id/api/auth/device/verification/ \
  -H 'Authorization: Bearer <operator_access_token>' \
  -H 'Content-Type: application/json' \
  -d '{
    "user_code": "ABCD-EFGH",
    "organization_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "action": "approve"
  }'
```

Poll from the device, respecting the `interval` returned by authorize:

```bash
curl -X POST https://sso.arnatech.id/api/auth/device/token/ \
  -H 'Content-Type: application/json' \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
    "device_code": "<device_code_from_authorize>"
  }'
```

Rotate a device refresh token:

```bash
curl -X POST https://sso.arnatech.id/api/auth/device/refresh/ \
  -H 'Content-Type: application/json' \
  -d '{"refresh_token":"<current_device_refresh_token>"}'
```

## WebAuthn/passkeys

The begin/complete pairs use a server session cookie. Browser clients must send
cookies (`credentials: "include"` in `fetch`) for both steps.

1. To add a passkey while signed in, call `/auth/passkeys/register/begin/`, pass
   response `publicKey` to `navigator.credentials.create()`, then post that result
   to `/auth/passkeys/register/complete/`.
2. To sign in with a passkey, call `/auth/passkeys/login/begin/`, pass response
   `publicKey` to `navigator.credentials.get()`, then post the assertion to
   `/auth/passkeys/login/complete/`.
3. List/revoke a signed-in user's passkeys at `/auth/passkeys/`.

## Operational rules

- Never log passwords, TOTP values, authorization codes, device codes, refresh tokens, or service secrets.
- Use TLS for every integration.
- Keep scopes minimal and audience-specific.
- Treat a 401 as an authentication failure, a 403 as authenticated-but-not-authorized,
  and inspect structured 400 errors for invalid grant/OTP/PKCE/device state.
- Refer to the operation description in Swagger for exact payload fields and examples.
