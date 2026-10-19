# MFA enrollment and login

Migration `authentication.0017_shared_mfa_state` must run before this release's
API replicas start. No additional environment variables or Redis are required.
Existing configured MFA accounts stay protected. This migration never disables
or resets an account's factor.

## Enrollment (authenticated user)

1. POST `/api/auth/mfa/set/` with the user's access token. Render the returned
   `qr_code_url` (an `otpauth://` URI) locally; never send it to a remote QR service.
2. The generated secret is pending for ten minutes. Generating or abandoning
   the QR does not enable MFA. Retrying within that time returns the same secret.
3. POST `/api/auth/mfa/confirm/` with the same authenticated user's access token
   and `{"mfa_token":"123456"}`. Only a matching authenticator code enables MFA.
   The response contains `mfa_enabled:true`, not login tokens.
4. The old authenticated profile payload at `/api/auth/mfa/verify/` remains a
   compatibility adapter when no pre-auth `token` is provided.

## Login

1. Complete the existing first-factor login. An MFA account receives a short-lived
   pre-auth `token`, not access to protected resources.
2. POST `/api/auth/mfa/verify/` with `token` and `mfa_token`.
3. Success issues the normal access/refresh pair. The challenge is consumed once;
   a TOTP time step cannot be reused, including with a different challenge or
   replica. After reset/re-enrollment, old challenges cannot verify the new factor.

Each account has five verification attempts per minute, shared between enrollment
confirmation and login, all workers and replicas. Fresh challenges do not reset
the budget. Invalid challenges have a separate database-backed IP budget. The
global anonymous daily quota does not apply to this endpoint.

Clients must distinguish HTTP 429 (wait `Retry-After`, retain pending state), 401
(restart first-factor login), 400 (code/setup error), and dependency failures.
Pre-auth tokens issued before this release lack the factor binding and require
one fresh first-factor login. Do not log secrets, OTP codes or JWTs. Audit events
record enrollment start, enable, disable and successful MFA login.
