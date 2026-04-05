# Passkey WebAuthn Walkthrough (Frontend Guide)

This document is for frontend developers implementing passkey registration and login against Arna SSO.

## 1. What Is Implemented in Backend

- Passkey registration begin and complete
- Passkey login begin and complete
- List and delete registered passkeys
- Passkey login skips MFA
- Inactive users (`is_active=false`) are blocked from passkey login

## 2. Required Environment in SSO

```env
FIDO_SERVER_ID=arnatech.id
FIDO_SERVER_NAME=Arnatech SSO Service
SESSION_COOKIE_SAMESITE=Lax
SESSION_COOKIE_SECURE=True
```

Notes:
- Use parent domain `arnatech.id` so multiple subdomains can use passkeys (`account.arnatech.id`, `clockin.arnatech.id`, etc.).
- If your browser treats your frontend->SSO requests as cross-site and session is not sent, switch to:
  - `SESSION_COOKIE_SAMESITE=None`
  - `SESSION_COOKIE_SECURE=True`

## 3. API Endpoints

- `GET /api/auth/passkeys/register/begin/` (JWT required)
- `POST /api/auth/passkeys/register/complete/` (JWT + session cookie)
- `GET /api/auth/passkeys/login/begin/` (public)
- `POST /api/auth/passkeys/login/complete/` (session cookie)
- `GET /api/auth/passkeys/` (JWT required)
- `DELETE /api/auth/passkeys/{id}/` (JWT required)

Important:
- Begin and complete are stateful. They depend on session cookie.
- Use `credentials: 'include'` on all passkey `fetch` calls.

## 4. Frontend Flow

### A. Register Passkey

1. User is already logged in with JWT.
2. Call `GET /api/auth/passkeys/register/begin/` with:
   - `Authorization: Bearer <access_token>`
   - `credentials: 'include'`
3. Convert `publicKey.challenge` and `publicKey.user.id` from base64url to `Uint8Array`.
4. Convert `excludeCredentials[].id` too (if present).
5. Call `navigator.credentials.create({ publicKey })`.
6. Send credential result to `POST /api/auth/passkeys/register/complete/` with:
   - `Authorization: Bearer <access_token>`
   - `Content-Type: application/json`
   - `credentials: 'include'`

### B. Login With Passkey

1. Call `GET /api/auth/passkeys/login/begin/` with `credentials: 'include'`.
2. Convert `publicKey.challenge` and `allowCredentials[].id` to `Uint8Array`.
3. Call `navigator.credentials.get({ publicKey })`.
4. Send assertion result to `POST /api/auth/passkeys/login/complete/` with:
   - `Content-Type: application/json`
   - `credentials: 'include'`
5. Backend returns JWT tokens on success.

## 5. Exact Browser Example

Use this in browser console during integration testing.

```javascript
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// REGISTER BEGIN
const regBegin = await fetch('/api/auth/passkeys/register/begin/', {
  method: 'GET',
  headers: { Authorization: 'Bearer ACCESS_TOKEN' },
  credentials: 'include',
});
const regOpts = await regBegin.json();
regOpts.publicKey.challenge = dec(regOpts.publicKey.challenge);
regOpts.publicKey.user.id = dec(regOpts.publicKey.user.id);
if (regOpts.publicKey.excludeCredentials) {
  regOpts.publicKey.excludeCredentials = regOpts.publicKey.excludeCredentials.map(c => ({
    ...c,
    id: dec(c.id),
  }));
}

const regCred = await navigator.credentials.create(regOpts);

// REGISTER COMPLETE
const regComplete = await fetch('/api/auth/passkeys/register/complete/', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    Authorization: 'Bearer ACCESS_TOKEN',
  },
  credentials: 'include',
  body: JSON.stringify({
    id: regCred.id,
    rawId: enc(regCred.rawId),
    type: regCred.type,
    key_name: 'My Device',
    response: {
      attestationObject: enc(regCred.response.attestationObject),
      clientDataJSON: enc(regCred.response.clientDataJSON),
    },
  }),
});
console.log('register:', await regComplete.json());
```

```javascript
const dec = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
const enc = b => btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

// LOGIN BEGIN
const loginBegin = await fetch('/api/auth/passkeys/login/begin/', {
  method: 'GET',
  credentials: 'include',
});
const loginOpts = await loginBegin.json();
loginOpts.publicKey.challenge = dec(loginOpts.publicKey.challenge);
if (loginOpts.publicKey.allowCredentials) {
  loginOpts.publicKey.allowCredentials = loginOpts.publicKey.allowCredentials.map(c => ({
    ...c,
    id: dec(c.id),
  }));
}

const assertion = await navigator.credentials.get(loginOpts);

// LOGIN COMPLETE
const loginComplete = await fetch('/api/auth/passkeys/login/complete/', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  credentials: 'include',
  body: JSON.stringify({
    id: assertion.id,
    rawId: enc(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: enc(assertion.response.authenticatorData),
      clientDataJSON: enc(assertion.response.clientDataJSON),
      signature: enc(assertion.response.signature),
      userHandle: assertion.response.userHandle ? enc(assertion.response.userHandle) : null,
    },
  }),
});
console.log('login:', await loginComplete.json());
```

## 6. Common Errors and Causes

- `No active login session...`
  - Missing `credentials: 'include'`
  - Begin and complete called from different browser session/context
- `Passkey verification failed`
  - Payload not base64url-encoded correctly
  - `allowCredentials` / challenge not converted to `Uint8Array`
- `Account is not active...`
  - User must verify email/phone first (activate account) before passkey login

## 7. FE Checklist Before Deploy

- Passkey requests use `credentials: 'include'`
- Begin/complete are called in the same browser session
- Base64url conversion helpers are implemented
- JWT storage flow after login complete is wired
- Error messages are surfaced clearly in UI

## 8. Backend CORS and Cookie Requirements

For browser passkey flow to work from another frontend domain:

- Backend must allow frontend origins explicitly (do not rely on wildcard with credentials).
- Backend must allow credentials in CORS.
- Frontend fetch must send credentials.
- Browser must receive and send SSO session cookie between begin and complete.
