# OLS gift identity registration

Status: production API and n8n integration active since 2026-10-09, after explicit user rollout approval. The form is live at https://ourlilstudio.com/claim-gift. No customer identities were created by testing, and no real WhatsApp test messages were sent. See `SSO_MANAGER_RELEASE.md` and `OLS_GIFT_RELEASE.yaml` for artifacts, rollout evidence and remaining operator checks.

## API contract

`POST /api/v1/registrations/whatsapp/` with a short-lived RS256 bearer service token.
Audience: `arna-sso-registration`; exact scope: `sso.whatsapp.register`.
The caller must obtain the phone from an authenticated inbound WAHA message, resolve LID mapping, validate the OLS business session and record the gift first. Never accept a phone typed by a browser as WhatsApp ownership evidence.

```json
{
  "phone": "6280000000001",
  "name": "Test Gift",
  "campaign": "synthetic-wedding",
  "message_id": "synthetic-message"
}
```

Names: 1–80 characters, Unicode letters/marks/numbers plus spaces, apostrophes, periods and hyphens. Phones are canonical international digits, 8–15 characters. Unknown fields (roles, organization, activation, etc.) are rejected.

Response: HTTP 201 on first creation; 200 for an existing phone or exact retry. Fields: `user_id`, `created`, `replayed`, `status` (`registered` / `existing`), `request_id`. Errors use `error`, `detail`, `request_id`. The same service/campaign/message identifier with different data returns 409. Phone and receipt database uniqueness plus atomic transactions protect concurrent requests.

New identities receive a placeholder email consistent with existing WA registration, an unusable password, an inactive/unverified account, and a profile with the supplied name/phone. Registration does **not** issue login tokens, trigger an OTP, activate login, verify the SSO phone, create organization membership, or grant any privileges. Existing accounts—including name, MFA, OTP and verification state—are untouched. An existing placeholder email with no matching phone is a conflict, not permission to take over that account.

Identity records are owned globally by SSO, not OLS tenant membership. Service-scoped receipts store proof/payload hashes rather than copies of customer messages. OLS retains the gift registration separately. This is not marketing opt-in or physical handover proof.

## Service enrollment and secrets

After the API has been released and migrated, enroll only `ols-wedding-gift-n8n` via `create_gift_registration_service --secret-stdin`, supplying a freshly generated secret through a restricted server process. The command prints no secret and refuses rotation/overwrite of an existing client. Do not use the legacy general provisioning command for this feature.

Store the raw secret only in n8n's encrypted `httpCustomAuth` credential `OLSGiftSsoReg01`:

```json
{"body":{"client_id":"ols-wedding-gift-n8n","client_secret":"<server-side secret only>"}}
```

The HTTP token node POSTs to `/api/v1/registrations/service-token/` with `audience=arna-sso-registration`. This registration-only credential exchange has its own 120/minute IP quota, so a wedding does not consume the shared anonymous OTP/login quota. It returns `access`, `token_type`, `expires_in` and `request_id`; this scope receives a service token valid for at most five minutes. The registration endpoint checks signature, issuer, audience, lifetime, service identity, exact scope, and current active registration. Revocation/changed scope invalidates an outstanding token immediately. The legacy `/api/auth/service-token/` response remains compatible for existing callers.

No credentials or tokens belong in Git, frontend, QR, chat, build contexts or execution logs. Do not reuse a personal token or the OTP credential. Disable the service account to revoke this integration without touching OTP or other service accounts.

## Tests and migration compatibility

`scripts/test_gift_registration.py` runs checks, migration drift detection and registration/website-service/website-proof/OTP regression tests with generated synthetic RSA keys. Full migration replay requires disposable PostgreSQL because an existing IAM migration contains PostgreSQL-only SQL. `scripts/test_gift_remote.py` stages clean archives in a private temporary folder, creates an isolated internal Docker network and disposable PostgreSQL, runs tests using the existing runtime dependencies, then removes only those test resources. It never mounts production credentials or connects to the production database.

Fresh PostgreSQL tests exposed two pre-existing migration issues: partial active-session uniqueness was checked only in `pg_constraint` rather than as an index, and the device index name disagreed with model state. The two old organization migrations now recognize the existing partial unique index; migration 0014 renames the device index without changing its columns or uniqueness. Migration 0013 only adds the service-scoped registration receipt table. These changes preserve existing data and enforcement; already-applied organization migrations are not rerun in production.

## Release gates and operational follow-up

1. Publish reviewed source and test the selected exact commit in the established SSO pipeline. Verify the image does not contain `.env`, signing keys or this test configuration as its runtime setting.
2. Resolve the immutable new image digest, capture previous API/worker service configuration, run compatible one-off migrations with the release image and existing secret/network configuration.
3. Roll existing SSO roles; verify task convergence, health and relevant public/authenticated registration paths. No live customer creation is part of a probe without explicit test authorization.
4. Enroll the narrow service and encrypted n8n credential. Expand `ols_gifts.claims` using the feature schema and replace only the **inactive** `OLSGiftClaimV1` artifact. Keep old OTP workflow and credentials unchanged.
5. Activate the user-approved gift webhook while preserving the WAHA global OTP hook, and publish `/claim-gift` through Vercel. Both are active; live operator WhatsApp validation remains outstanding.

SSO errors must never revoke a registered gift or resend its WA confirmation. n8n records sync state (`pending`, `synced`, `failed`) and the SSO user ID. A failed/uncertain sync can be repaired with the same campaign/message payload, which is idempotent; do not rerun the original gift confirmation branch.

Application rollback retains receipt data; it does not reverse migrations or delete customer accounts. Disable only this service/workflow to stop registration. Never roll back unrelated OTP workflows or WAHA sessions.
