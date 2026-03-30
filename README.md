
# SSO Service

An **SSO (Single Sign-On) service** built with Django. Handles authentication, JWT token management (RS256), MFA, and role-based access control (RBAC) for use across multiple microservices.

## Table of Contents
- [Features](#features)
- [Technology Stack](#technology-stack)
- [Setup Instructions](#setup-instructions)
- [Environment Variables](#environment-variables)
- [Login Methods](#login-methods)
- [API Endpoints](#api-endpoints)
- [Integration with Other Services](#integration-with-other-services)

---

## Features

- **JWT Authentication** — RS256-signed access & refresh tokens with rotation + blacklisting
- **4 Login Methods** — Password, Google OAuth, WhatsApp OTP, and Passkeys (WebAuthn/FIDO2)
- **Passkeys (WebAuthn)** — Phishing-resistant, passwordless login; skips MFA by design
- **MFA (TOTP)** — Time-based one-time passwords via authenticator apps
- **Role-based Access Control (RBAC)** — Roles and permissions decoded from JWT by downstream services
- **Audit Logging** — Key actions (registration, login, MFA, passkey use) logged asynchronously
- **Microservices Integration** — Distribute `public.pem` to other services for token verification

---

## Technology Stack

| Library | Purpose |
|---------|---------|
| Django 5 | Web framework |
| Django REST Framework | API layer |
| Simple JWT (RS256) | Token management |
| django-passkeys | WebAuthn / FIDO2 passkey support |
| PyOTP | TOTP-based MFA |
| Google Auth | Google OAuth token verification |
| Django-Q2 | Async task queue (audit logging) |
| uWSGI + Supervisor | Production server |

---

## Setup Instructions

> **Prerequisites (local only):** Python 3.11+, Redis

| Step | 🐳 Docker | 💻 Local (venv) |
|------|-----------|------------------|
| **1. Clone** | `git clone <repository-url> && cd arna_sso` | `git clone <repository-url> && cd arna_sso` |
| **2. Setup env** | *(uses `.env` file automatically)* | `python3 -m venv venv && source venv/bin/activate` |
| **3. Install deps** | *(handled by Dockerfile)* | `pip install -r requirements.txt` |
| **4. Start** | `docker compose up --build` | `python manage.py runserver` |
| **5. Migrate** | `docker compose exec web python manage.py migrate` | `python manage.py migrate` |
| **6. Superuser** | `docker compose exec web python manage.py createsuperuser` | `python manage.py createsuperuser` |

Service: `http://localhost:8001`  
Swagger UI: `http://localhost:8001/swagger/`

### Key Generation (RS256)

```bash
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in private.pem -out public.pem
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | Django secret key | *(required)* |
| `FIDO_SERVER_ID` | Passkey RP ID — must match the browser's origin domain | `localhost` |
| `FIDO_SERVER_NAME` | Passkey RP display name | `Arna SSO` |
| `SESSION_COOKIE_SAMESITE` | Cookie policy (`Lax` / `None`) | `Lax` |
| `SESSION_COOKIE_SECURE` | Set `True` in HTTPS production | `False` |
| `ACCESS_TOKEN_LIFETIME_MINUTES` | JWT access token lifetime | `5` |
| `REFRESH_TOKEN_LIFETIME_DAYS` | JWT refresh token lifetime | `1` |
| `WAHA_API_URL` | WhatsApp WAHA API base URL | — |
| `WAHA_API_KEY` | WhatsApp WAHA API key | — |
| `N8N_WEBHOOK_URL` | n8n webhook base URL (reverse WA OTP) | — |
| `N8N_WEBHOOK_ID` | n8n webhook UUID | — |
| `N8N_WEBHOOK_AUTH_TOKEN` | n8n webhook auth token | — |

> **Passkey production note:** Set `FIDO_SERVER_ID` to your actual domain (e.g. `sso.arnatech.id`). It must exactly match the domain the browser connects to.

---

## Login Methods

Users have **4 login options**. All return the same JWT token shape:

```json
{
  "refresh": "eyJ...",
  "access":  "eyJ...",
  "email":   "user@example.com",
  "full_name": "User Name"
}
```

### 1. Password Login
Standard email + password. Supports MFA (TOTP).

```
POST /auth/login/
{ "email": "...", "password": "..." }
```

If MFA is enabled → returns `mfa_required: true` + a pre-auth token → complete at `POST /auth/mfa/verify/`.

### 2. Google Login
Send the Google ID token from `gsi.client` / `google.accounts.id.initialize`.

```
POST /auth/google-login/
{ "token": "<google-id-token>" }
```

Respects the user's MFA setting. Automatically creates user if new.

### 3. WhatsApp OTP
Two flows: **push** (WAHA sends OTP to the user) and **reverse** (user messages the bot first).

```
POST /auth/wa/send-otp/       { "phone_number": "628..." }
POST /auth/wa/verify-otp/     { "phone_number": "628...", "otp": "123456" }
```

### 4. Passkeys (WebAuthn / FIDO2) ✨

Passwordless, phishing-resistant login — Face ID, Touch ID, Windows Hello, or hardware security keys. **MFA is skipped** (passkeys are strong 2FA by default).

#### Login flow (no prior auth)

```
GET  /api/auth/passkeys/login/begin/     → returns PublicKeyCredentialRequestOptions
POST /api/auth/passkeys/login/complete/  → verify assertion → returns JWT tokens
```

#### Registration flow (authenticated user adds a passkey)

```
GET  /api/auth/passkeys/register/begin/     → (JWT required) → returns PublicKeyCredentialCreationOptions
POST /api/auth/passkeys/register/complete/  → (JWT required) → stores credential
```

> For full browser console test snippets, see [PASSKEY_WALKTHROUGH.md](PASSKEY_WALKTHROUGH.md).

---

## API Endpoints

### Authentication

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/register/` | — | Register new user |
| `POST` | `/auth/login/` | — | Password login (MFA-aware) |
| `POST` | `/auth/google-login/` | — | Google OAuth login |
| `POST` | `/auth/logout/` | JWT | Blacklist refresh token |
| `POST` | `/auth/token/refresh/` | — | Refresh access token |
| `POST` | `/auth/token/verify/` | — | Verify a token |

### MFA

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `POST` | `/auth/mfa/set/` | JWT | Enable TOTP MFA |
| `POST` | `/auth/mfa/disable/` | JWT | Disable MFA |
| `POST` | `/auth/mfa/verify/` | — | Verify MFA code → JWT |

### Passkeys (WebAuthn)

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/auth/passkeys/login/begin/` | — | Get assertion options |
| `POST` | `/api/auth/passkeys/login/complete/` | Session cookie | Verify → JWT (MFA skipped) |
| `GET` | `/api/auth/passkeys/register/begin/` | JWT | Get creation options |
| `POST` | `/api/auth/passkeys/register/complete/` | JWT + cookie | Store passkey |
| `GET` | `/api/auth/passkeys/` | JWT | List registered passkeys |
| `DELETE` | `/api/auth/passkeys/<id>/` | JWT | Delete a passkey |

### WhatsApp OTP

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/auth/wa/send-otp/` | Push OTP via WAHA |
| `POST` | `/auth/wa/verify-otp/` | Verify OTP → JWT |
| `POST` | `/auth/wa/send-link-otp/` | OTP for phone linking |
| `POST` | `/auth/wa/verify-link/` | Verify phone link OTP |
| `POST` | `/auth/wa/register-request/` | Register with phone |
| `POST` | `/auth/wa/register-verify/` | Verify registration OTP |
| `POST` | `/auth/wa/reverse/send-otp/` | Reverse OTP (n8n webhook) |

### User & Password

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET/PATCH` | `/auth/me/` | JWT | Get / update current user |
| `POST` | `/auth/verify-email/` | — | Verify email with OTP |
| `POST` | `/auth/resend-email-otp/` | — | Resend email OTP |
| `POST` | `/auth/password-reset-request/` | — | Request password reset OTP |
| `POST` | `/auth/password-reset-confirm/` | — | Reset password with OTP |
| `POST` | `/auth/change-password/` | JWT | Change password |

> Full interactive docs available at `/swagger/` when the service is running.

---

## Integration with Other Services

1. **Token Distribution**: After login, include the access token in every request:
   ```http
   Authorization: Bearer <JWT-ACCESS-TOKEN>
   ```

2. **Public Key Distribution**: Copy `public.pem` to downstream services so they can verify JWT signatures without calling back to the SSO service.

3. **Role-Based Access Control**: Decode the JWT payload to read user roles and permissions.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
