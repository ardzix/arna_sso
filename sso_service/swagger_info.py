from drf_yasg import openapi

api_info = openapi.Info(
    title="SSO Service API (Generated)",
    default_version='v1',
    description="""# Arna SSO API Guide

All API URLs use the `/api` base path. Protected user endpoints require
`Authorization: Bearer <access_token>`. Token claims include the current active
organization, roles, direct permissions, and `is_owner`; switch organization
before making organization-scoped IAM calls.

## Pick the authentication flow

| Need | Start here | Next steps |
| --- | --- | --- |
| Email/password user login | `POST /auth/login/` | If response says `mfa_required`, submit its pre-auth token and TOTP to `/auth/mfa/verify/`. |
| New account or email verification | `POST /auth/register/` | Verify its OTP at `/auth/verify-email/`; resend with `/auth/resend-email-otp/`. |
| Password recovery | `POST /auth/password-reset-request/` | Submit email OTP and new password to `/auth/password-reset-confirm/`. |
| WebAuthn/passkey | `/auth/passkeys/*/begin/` | Browser calls `navigator.credentials.*`, then client posts result to matching `/complete/`. Keep the session cookie. |
| WhatsApp OTP | `/auth/wa/send-otp/` or `/auth/wa/register-request/` | Verify received OTP using `/auth/wa/verify-otp/` or `/auth/wa/register-verify/`. |
| Browser SSO into another product | `/auth/sso/authorize-code/` | Product backend exchanges one-time PKCE code at `/auth/sso/token/`. |
| Machine-to-machine service | `/auth/service-token/` | Send configured `client_id`, `client_secret`, and audience; use returned access token. |
| Headless device / CLI / agent | `/auth/device/authorize/` | Show its user code, approve it in browser, poll `/auth/device/token/`, then rotate at `/auth/device/refresh/`. |

## Organization and IAM guide

1. Create or list organizations through `/organizations/`.
2. Select the current organization through `POST /organizations/current/`.
   This returns fresh tokens containing that organization's IAM claims.
3. Create organization-scoped permissions and roles at `/iam/permissions/` and
   `/iam/roles/`; their organization is always derived from the active session.
4. Add members, assign roles, or assign direct permissions through the
   organization-members and IAM endpoints.
5. If a client refreshes a user token after switching organization, the refresh
   endpoint rehydrates organization, role, permission, and owner claims from the
   current active session.

Each operation below documents its purpose, required authentication, request
example, expected response, and any multi-step flow or security constraint.
""",
    contact=openapi.Contact(email="contact@arnatech.id"),
    license=openapi.License(name="BSD License"),
)
