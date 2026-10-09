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

## Jenkins reconciliation boundary

The inspected legacy `production/arna_sso` job still has an inline pipeline that
copies PEM/environment into a build and removes/recreates the service. It has no
automatic triggers and **was not run for this release**. Do not run that legacy
job against this deployment. The safe versioned replacement is `Jenkinsfile`,
using the existing `stag-arnatech-sa-01` credential and strict trusted-host SSH.
It calls the same bounded manager release gates and defaults DEPLOY=false.

Switching the live Jenkins job to this versioned file requires an authenticated
Jenkins administrator to apply/reload its job configuration. Manager SSH access
is not used to forge a Jenkins login or mint an API token. This live job switch
has not been performed; the durable source for the deployed release is the
versioned manager entrypoint plus immutable Swarm runtime configuration. This is
an explicit manual-manager release, not a claimed green Jenkins build.
