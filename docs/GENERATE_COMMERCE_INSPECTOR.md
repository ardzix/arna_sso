# Generate Commerce's SSO introspection credentials

Run this once inside the configured **SSO** runtime. It creates a backend service
account with only `audiences=["arna-sso-devices"]` and
`scopes=["sso.device.introspect"]`. It does not grant device roles or payment
settlement permissions. The inspector serves Commerce across organizations;
each inspected device keeps its own verified org/tenant assignment.

Download `generate_commerce_inspector.py` and upload it to the server running an
SSO API replica. From that Linux server, in the directory containing the script:

```bash
SSO_CONTAINER=$(docker ps --filter label=com.docker.swarm.service.name=sso_service --format '{{.ID}}' | head -n 1)
test -n "$SSO_CONTAINER" || { echo "No SSO API replica on this node" >&2; exit 1; }
docker exec -i "$SSO_CONTAINER" python - --output /tmp/commerce-sso-inspector.env < generate_commerce_inspector.py
```

The container's existing working directory and Django runtime configuration are
used. The script does not need a new SSO image or migration. Use an account able
to access Docker on that host. For a checked-out SSO project with its configured
Python runtime, the equivalent command is:

```bash
python scripts/generate_commerce_inspector.py --output /secure/commerce-sso-inspector.env
```

The output parent directory must already exist. Credentials are written only to
the specified file with Unix mode `0600`; the SSO database stores a hashed
secret. The console prints the account ID, audience, scope and output path only.
Do not run with shell tracing enabled or print the file in Jenkins build logs.

Retrieve the file from the container using a private host directory:

```bash
umask 077
PRIVATE_DIR=$(mktemp -d)
docker cp "$SSO_CONTAINER":/tmp/commerce-sso-inspector.env "$PRIVATE_DIR/commerce-sso-inspector.env"
chmod 600 "$PRIVATE_DIR/commerce-sso-inspector.env"
printf 'Credential file: %s\n' "$PRIVATE_DIR/commerce-sso-inspector.env"
```

It contains just these two keys with generated values:

```env
SSO_DEVICE_INTROSPECTION_CLIENT_ID=arna-commerce-device-inspector
SSO_DEVICE_INTROSPECTION_CLIENT_SECRET=<generated secret>
```

Merge both entries into the **existing complete** Jenkins credential file
`arna-commerce-env`. Preserve the DB, SSO key, Xendit and all other settings;
do not replace that complete file with this two-line snippet. Then release
Commerce with its migration/rollout gates. Never send this file to the kiosk.

After storing it securely, remove the temporary copies:

```bash
docker exec "$SSO_CONTAINER" rm -- /tmp/commerce-sso-inspector.env
rm -- "$PRIVATE_DIR/commerce-sso-inspector.env"
rmdir -- "$PRIVATE_DIR"
```

Rerunning the generator stops if the client ID or output file already exists.
It does not rotate or reactivate an existing account, overwrite a file, or modify
runtime configuration. If the secret was lost, deliberately choose a different
client ID with `--client-id arna-commerce-device-inspector-v2`, update Commerce,
verify it, then deactivate the previous account through SSO administration.

Validation: `python scripts/test_generate_commerce_inspector.py` uses an in-memory
database and synthetic credentials. It checks exact privileges, secret hashing,
duplicate prevention, preserved files, failure rollback and console redaction.
