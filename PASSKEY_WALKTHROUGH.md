# Passkey (WebAuthn / FIDO2) — Implementation Walkthrough

> Passwordless, phishing-resistant login for **Arna SSO** using `django-passkeys` and the WebAuthn standard.

---

## Table of Contents

- [What Changed](#what-changed)
- [Bugs Fixed](#bugs-fixed)
- [Login Flow](#login-flow)
- [API Endpoints](#api-endpoints)
- [Smoke Test Results](#smoke-test-results)
- [Environment Variables](#environment-variables)
- [Browser Test Guide](#browser-test-guide)

---

## What Changed

| File | Summary |
|------|---------|
| `requirements.txt` | Added `django-passkeys==1.3.0.1`, `ua-parser`, `user-agents` |
| `sso_service/settings.py` | Env-var-ized `FIDO_SERVER_ID` / `FIDO_SERVER_NAME`; `KEY_ATTACHMENT=None`; session cookie config |
| `authentication/passkeys_api_views.py` | **Full rewrite** — bugs fixed, 6 Swagger-documented endpoints |
| `authentication/urls.py` | Added `passkeys/` (list) and `passkeys/<pk>/` (delete) routes |

---

## Bugs Fixed

| # | Bug | Fix |
|---|-----|-----|
| 1 | `request.user` always `AnonymousUser` after `auth_complete()` | Read `key.user` directly from DB after verifying assertion |
| 2 | CSRF blocking all POST endpoints | Removed `SessionAuthentication` from all passkey view auth classes |

---

## Login Flow

The service supports **4 login methods**, all returning the same JWT shape:

| Method | Endpoint |
|--------|----------|
| Password | `POST /api/auth/login/` |
| Google OAuth | `POST /api/auth/google-login/` |
| WhatsApp OTP | `POST /api/auth/wa/send-otp/` → `verify-otp/` |
| **Passkey** | `GET + POST /api/auth/passkeys/login/...` |

> **Note:** Passkey login skips MFA — passkeys are phishing-resistant 2FA by design.

---

## API Endpoints

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| `GET` | `/api/auth/passkeys/login/begin/` | — | Get assertion challenge |
| `POST` | `/api/auth/passkeys/login/complete/` | Session cookie | Verify assertion → JWT |
| `GET` | `/api/auth/passkeys/register/begin/` | JWT Bearer | Get creation options |
| `POST` | `/api/auth/passkeys/register/complete/` | JWT + session cookie | Store new credential |
| `GET` | `/api/auth/passkeys/` | JWT Bearer | List user's passkeys |
| `DELETE` | `/api/auth/passkeys/<id>/` | JWT Bearer | Delete a passkey |

---

## Smoke Test Results

| Endpoint | Expected Response | Status |
|----------|-------------------|--------|
| `GET /api/auth/passkeys/login/begin/` | `{ publicKey: { challenge, rpId } }` | Pass |
| `POST /api/auth/passkeys/login/complete/` *(no session)* | `"No active login session..."` | Pass |
| `GET /api/auth/passkeys/register/begin/` *(no JWT)* | `401 Authentication credentials not provided` | Pass |

---

## Environment Variables

Add to `.env` or Docker environment:

```env
FIDO_SERVER_ID=localhost         # Must match the browser's origin domain in production
FIDO_SERVER_NAME=Arna SSO
SESSION_COOKIE_SAMESITE=Lax     # Use 'None' for cross-origin prod (requires HTTPS)
SESSION_COOKIE_SECURE=False      # Set True in production
```

> **Production:** Set `FIDO_SERVER_ID` to your actual domain (e.g. `sso.arnatech.id`). It must exactly match the domain the browser connects to, or passkey auth will silently fail.

---

## Browser Test Guide

Open `http://localhost:8001/swagger/`, log in to get a JWT, then paste these snippets into the browser **DevTools console**.

### Step 1 — Register a passkey

```javascript
// Helper functions
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// 1. Get options (replace TOKEN)
const opts = await (await fetch('/api/auth/passkeys/register/begin/', {
  headers: { 'Authorization': 'Bearer TOKEN' }
})).json();

// 2. Decode binary fields
opts.publicKey.challenge = dec(opts.publicKey.challenge);
opts.publicKey.user.id   = dec(opts.publicKey.user.id);
if (opts.publicKey.excludeCredentials)
  opts.publicKey.excludeCredentials = opts.publicKey.excludeCredentials.map(c => ({ ...c, id: dec(c.id) }));

// 3. Create credential (triggers Face ID / Touch ID / security key prompt)
const cred = await navigator.credentials.create(opts);

// 4. Send to server
const res = await fetch('/api/auth/passkeys/register/complete/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer TOKEN' },
  body: JSON.stringify({
    id: cred.id, rawId: enc(cred.rawId), type: cred.type, key_name: 'My Browser',
    response: {
      attestationObject: enc(cred.response.attestationObject),
      clientDataJSON:    enc(cred.response.clientDataJSON),
    }
  })
});
console.log(await res.json());
// Expected: { "status": "OK", "key_name": "My Browser" }
```

### Step 2 — Login with passkey

> Open a new tab or log out first, then run:

```javascript
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// 1. Get challenge
const opts = await (await fetch('/api/auth/passkeys/login/begin/')).json();
opts.publicKey.challenge = dec(opts.publicKey.challenge);
if (opts.publicKey.allowCredentials)
  opts.publicKey.allowCredentials = opts.publicKey.allowCredentials.map(c => ({ ...c, id: dec(c.id) }));

// 2. Authenticate (triggers biometric prompt)
const asr = await navigator.credentials.get(opts);

// 3. Verify and get JWT
const res = await fetch('/api/auth/passkeys/login/complete/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    id: asr.id, rawId: enc(asr.rawId), type: asr.type,
    response: {
      authenticatorData: enc(asr.response.authenticatorData),
      clientDataJSON:    enc(asr.response.clientDataJSON),
      signature:         enc(asr.response.signature),
      userHandle: asr.response.userHandle ? enc(asr.response.userHandle) : null,
    }
  })
});
console.log(await res.json());
// Expected: { "refresh": "eyJ...", "access": "eyJ...", "email": "...", "full_name": "..." }
```
