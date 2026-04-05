# MFA Walkthrough (Frontend Guide)

This guide explains how frontend apps should integrate MFA (TOTP) with Arna SSO.

## 1. MFA Endpoints

- `POST /api/auth/mfa/set/` (JWT required)
- `GET /api/auth/mfa/status/` (JWT required)
- `POST /api/auth/mfa/disable/` (JWT required)
- `POST /api/auth/login/` (public, MFA-aware)
- `POST /api/auth/mfa/verify/` (public, requires pre-auth token from login step)

## 2. High-Level FE Flows

### A. Enable MFA

1. User is logged in with normal JWT.
2. Call `POST /api/auth/mfa/set/` with `Authorization: Bearer <access_token>`.
3. Backend returns:
   - `mfa_secret`
   - `qr_code_url` (otpauth URL)
4. FE displays QR code (or manual key) to user in authenticator app.
5. FE should ask user to verify by logging in again and completing MFA flow.

### B. Login With MFA Enabled

1. FE calls `POST /api/auth/login/` with email and password.
2. If user has MFA, backend returns:
   - `mfa_required: true`
   - `token` (short-lived pre-auth token)
3. FE shows OTP input UI (6-digit code).
4. FE calls `POST /api/auth/mfa/verify/` with:
   - `token` (from login step)
   - `mfa_token` (OTP code)
5. On success, backend returns normal JWT pair:
   - `access`
   - `refresh`

### C. Disable MFA

User can disable MFA with either:
- account password, or
- valid current TOTP code

Call `POST /api/auth/mfa/disable/` with one of:
- `{ "password": "current_password" }`
- `{ "totp": "123456" }`

## 3. Request and Response Examples

### Login (MFA-aware)

Request:
```json
{
  "email": "user@example.com",
  "password": "secret"
}
```

Response when MFA required:
```json
{
  "mfa_required": true,
  "message": "MFA is required. Please provide your MFA token.",
  "token": "<pre_auth_token>"
}
```

Response when MFA not required:
```json
{
  "refresh": "<jwt_refresh>",
  "access": "<jwt_access>"
}
```

### MFA Verify

Request:
```json
{
  "token": "<pre_auth_token>",
  "mfa_token": "123456"
}
```

Response:
```json
{
  "refresh": "<jwt_refresh>",
  "access": "<jwt_access>"
}
```

## 4. FE Error Handling

Common cases:

- `400 Missing token or MFA code`
  - FE payload incomplete.
- `401 Invalid token type` or `Invalid or expired session`
  - Pre-auth token expired or wrong.
  - FE should restart login flow from password step.
- `400 Invalid MFA code`
  - Wrong OTP; allow retry.
- `429` on verify endpoint
  - Too many attempts (throttled). Show cooldown message.

## 5. FE State Model (Recommended)

- `idle`
- `password_submitting`
- `mfa_required`
- `mfa_submitting`
- `authenticated`
- `error`

Do not store OTP in persistent storage.
Store pre-auth token in memory only and clear it after success/failure timeout.

## 6. Security Notes for FE

- Always use HTTPS.
- Never log OTP or pre-auth token to console in production.
- Do not reuse expired pre-auth token; restart login flow.
- Use server time as source of truth for expiry behavior.

## 7. Quick FE Checklist

- Password login handles both MFA and non-MFA responses.
- OTP form accepts exactly 6 digits.
- `mfa/verify` retry UX is clear.
- Expired pre-auth token redirects user back to login step.
- Tokens are stored only after successful MFA verification.

