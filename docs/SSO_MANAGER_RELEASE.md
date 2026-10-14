# SSO production release source of truth

The OLS gift release was explicitly authorized on 2026-10-09 and executed over
the approved `root@arnatech.id` manager connection, using `deploy/release.py`.
The running API plus existing qcluster roles remain in `sso_service` (2 replicas,
internal port 8001, existing `production` overlay). They were not removed and
recreated. `stop-first` is deliberate: the inspected host had only about 1.1 GiB
available, and each extra replica also starts four queue workers.

Selected application commit: `1afdb8fcff2f38ba81334e022ba449cd070351c6`.
Published and tested linux/amd64 artifact:
`ardzix/arna_sso@sha256:6f2b0cd6279cec9b523a00328d6a35fa47674575680caa9175b4371bdd54097b`.
27 tests passed inside this exact image with disposable PostgreSQL and synthetic
keys. No production customer records or WhatsApp sends were used in tests.

## Runtime configuration and recovery

Complete environment configuration is now delivered through immutable Swarm
secret `sso-ols-gift-runtime-1afdb8fcff2f`; mounted signing/verification secrets
are `sso-ols-gift-private-1afdb8fcff2f` and
`sso-ols-gift-public-1afdb8fcff2f`. `SSO_RUNTIME_SECRET_PATH` selects the loader.
The original key pair was preserved, not rotated. No runtime `.env` or PEM files
are included in the release image. Values and full previous service specification
are retained only in the protected manager release directory:
`/root/arnatech-releases/sso-ols-gift-1afdb8fcff2f/`.

The single migration task completed with exit code 0; task ID
`w2c19w294rbtf1fn5qlmcxlge`. It used the same image, complete configuration,
key mounts and production overlay as the release. Existing schema/data is
preserved. Application rollback does not reverse migrations.

The earlier candidate's migration also applied successfully, but the Docker CLI
waited for service convergence after its one-off task had already exited. That
attempt stopped before application rollout. Detaching creation and separately
inspecting task completion fixed the gate. The final monitor window is explicitly
awaited because Docker update progress can finish before UpdateStatus completes.

For recovery use the retained previous specification/digest, restore configuration
references as well as the image, and verify two replicas plus public health paths.
Never reverse migrations or delete identity/gift data as an application rollback.
Retain previous images and keys; do not broadly prune Swarm secrets.

## Jenkins source of truth

On 2026-10-14, the live `production/arna_sso` job was switched through the existing
authenticated Jenkins admin browser session to **Pipeline script from SCM**:
`https://github.com/ardzix/arna_sso.git`, branch `*/main`, script `Jenkinsfile`.
The saved UI and on-disk `CpsScmFlowDefinition` were both verified. No credential,
permission, or trigger was added. The pipeline uses the existing
`stag-arnatech-sa-01` identity, preserves secret mounts, runs a separate migration
gate, and defaults `DEPLOY=false`.

The old inline pipeline must not be restored: it removed/recreated the service
and omitted the JWT secret mounts. Jenkins build 152 reported success while the
resulting runtime returned HTTP 500. The October 14 recovery was executed through
the authorized manager connection, not through a new Jenkins build. Source
configuration verification does not claim a successful run of the new pipeline.

### Manager SSH trust on Jenkins agents

All release SSH/SCP commands use the versioned public host keys in
`deploy/ssh_known_hosts`, with strict verification, a bounded connection timeout
and the existing Jenkins SSH identity. They do not rely on the executing agent's
home-directory known_hosts. The ED25519 and ECDSA keys were retrieved on
2026-10-14 over the existing trusted ECDSA connection to `172.105.124.43` and the
ECDSA key matched the previously trusted entry for `arnatech.id,172.105.124.43`.
DNS resolved the manager domain to that same address. These are public server
host keys, not the application's JWT keys or a login private key.

If the manager host key changes, verify its fingerprint through a trusted
administration channel and review an update to this file. Never accept an
unverified `ssh-keyscan` result or disable strict checking to bypass the error.

## Production recovery on 2026-10-14

Both replicas of the legacy deployment were running, but Django failed to load
because `/usr/src/app/private.pem` and `public.pem` were absent. Five migrations
were also pending. The active image's 178 tracked files matched application commit
`cb338d36c3abb2dca18be886799fdd058643743b`; 75 contract/concurrency tests passed
inside that exact image using disposable PostgreSQL and synthetic keys.

Recovered runtime digest:
`ardzix/arna_sso@sha256:971ac0befe4e722c5e72a0e3a630ba850facf0c0c5ab72b81b0a9f7d20657e83`.
The original private/public secrets were reused, and their public-key fingerprint
and key-pair consistency were verified. Current complete service configuration
was preserved in immutable secret `sso-recovery-runtime-cb338d36-20261014`, with
JWT paths pointing to the mounted keys and a bounded database connection timeout.
No signing key or database credential was rotated.

A private database backup completed before migration. One migration task using
the same digest, secrets and production overlay completed with exit code 0:
`w11njcegbeync4quq3gpvmpf2`. It applied `authentication.0015`/`0016`,
`organization.0005`, and `iam.0011`/`0012`. As designed, `0015` invalidates legacy
device pairings; those devices require explicit approval and pairing again.

The existing service was rolled one replica at a time, without removal/recreation.
Both replicas became healthy and the update completed. Public `/health/live`,
`/health/ready` and `/login/` returned 200; unauthenticated device context returned
401 and empty login input returned 400. Both replicas passed migration drift and
local readiness checks; API and queue processes were running. A successful human
sign-in was not claimed from these probes.

Private recovery specification, database backup, task logs and detailed record
are retained under `/root/arnatech-releases/sso-recovery-20261014/`. The sanitized
[recovery record](../deploy/records/sso-recovery-20261014.yaml) contains references
and outcomes only. Database backup/configuration contents must remain off Git.
