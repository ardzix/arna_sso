# Local browser SSO callbacks

Development registration: `client_id = arna-local-dev`.

Exact callbacks requested for this client:

- `http://localhost:3000/api/auth/callback`
- `http://127.0.0.1:3000/api/auth/callback`

The operator registers both as active `SSOAllowedRedirectURI` rows. Registration
is stored in SSO's database and survives application releases. It does not grant
organization membership, service permissions or device access.

HTTP callbacks are accepted only for literal `localhost` and `127.0.0.1`, with
an exact, active client-and-URL registration. Other HTTP hosts, credentials in
the URL, fragments, and wildcard hosts are rejected. The legacy global redirect
setting cannot authorize an HTTP callback for another client.

Use `S256` PKCE for these callbacks. The application generates a random verifier,
challenge and state, starts SSO at `/login/`, validates returned state at its
callback, and exchanges the one-time code server-side at
`/api/auth/sso/token/` with the same client ID, exact redirect URI and verifier.
The token exchange requires no client secret. Authorization codes remain
short-lived, one-time, and bound to the client, callback and verifier.

The production SSO service remains in `DEBUG=False`; production applications
continue using registered HTTPS callbacks. Local applications must implement
their callback and session handling; the registration alone does not implement
that application-side code. Opaque central app sessions remain restricted to
the separately configured `APP_CLIENTS` in `authentication/app_sessions.py`.
