# Photobooth permissions and device assignment

An organization is automatically seeded with these nine permissions:

- `commerce.orders.read`, `commerce.orders.write`, `commerce.payments.create`
- `storage.files.read`, `storage.files.create`, `storage.files.update`
- `storage.files.delete`, `storage.files.share`, `storage.folders.create`

An owner/admin should list and reuse the permission IDs belonging to the active
organization. Do not create a new copy of these names. A repeated name now returns
HTTP 400 with a `name` error instead of a database error / HTTP 500. The same name
can still exist independently in a different organization. New custom permissions
can be created normally; resource tokens include only supported resource grants.

1. Sign in as the organization owner/admin. Select the intended organization and
   tenant. A device cannot create its own permissions or grant itself a role.
2. GET `/api/iam/permissions/` and select IDs whose `organization` matches the
   intended organization. Follow pagination where necessary.
3. POST `/api/iam/roles/` with `name`, `description` and `permission_ids` (UUIDs).
4. Pair the device using `/api/v1/devices/authorize/`, owner review/verification,
   and `/api/v1/devices/token/`. The approval binds the organization and tenant.
5. As the owner/admin, PUT
   `/api/v1/devices/registrations/<device_id>/access/`:

   ```json
   {"role_ids": ["<role UUID>"], "permission_ids": []}
   ```

   This replaces all assignments. Include any existing roles/direct grants that
   should remain. Direct `permission_ids` are permission UUIDs, not name strings.
   Device assignment does not use `organization_member` or the human
   `/api/iam/user-roles/` endpoint.
6. Verify effective permissions by GET on the same device access URL.
7. Exchange the base device token at `/api/v1/devices/resource-token/`, requesting
   audience `arna-commerce` or `storage`. Keep each token separate.
8. Commerce requests require the Commerce token plus stable `Idempotency-Key`
   values for order creation, submit and payment creation. The resource service
   still needs its deployed device authentication and SSO introspection setup.

The existence of a permission is separate from granting it. An owner can manage
the catalog, but a device without assigned grants must still be denied. Assigning
grants cannot make an older resource-service image accept device tokens.
