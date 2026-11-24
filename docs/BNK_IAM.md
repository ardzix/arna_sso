# BNK Roles & Permissions

BNK manages its organization roles through `/api/v1/bnk/iam/`. The BNK server resolves an existing `arnasite-dashboard` app session and exchanges the resulting subject token at `POST /api/v1/devices/resource-token/` with `{"audience":"arna-bnk-iam"}`. The subject is bound to the BNK dashboard and the resource token stays server-side. The API verifies the signature, issuer, audience, type and organization on the token, then checks the current active organization and role in the SSO database.

Only the organization's owner and members assigned its existing exact `Full Admin` role can manage BNK roles. Full Admin appears as a locked row. The member's owner, Full Admin, self, and inactive rows are also locked. BNK role assignments do not change existing platform roles or direct permissions. An organization can revoke an assignment by submitting a role list that omits it.

| Method and path under `/api/v1/bnk/iam/` | Contract |
| --- | --- |
| `GET context/` | `{subject, organization_id, can_manage, is_owner}` for an authorized actor. |
| `GET permissions/` | `{results: [{code, module}]}` with assignable BNK grants. |
| `GET roles/` | `{results: [{id, name, description, permission_codes, locked, member_count}]}`. |
| `POST roles/` | Create with `{name, description?, permission_codes}`. Returns the role row with status 201. |
| `PATCH roles/{id}/` | Update with one or more of the same fields. Returns the role row. |
| `DELETE roles/{id}/` | Delete an unassigned BNK role. An in-use role returns 409 with `role_in_use`. |
| `GET members/?page=1` | Fifty members per page. `{count, next, previous, results: [{id, user_id, name, email, role_ids, locked}]}`. Page pointers are numbers or null. |
| `PUT members/{id}/roles/` | Replace the member's BNK assignments with `{role_ids: [...]}`. Returns the member row. Replaying the same set leaves assignments and audit history unchanged. |

Role writes accept up to 120 characters for the name and 500 for the description. Each organization can create up to 100 BNK roles. Write requests use JSON and UUIDs for record identifiers. Errors return `{error, detail, request_id}` and may include `fields` for validation errors. Unknown role IDs, organizations and roles outside BNK scope share the same 404 response.

The catalog contains CMS, CRM, Operations and LevelUp grants that their respective APIs enforce. `arnasite.cms.manage` covers the CMS editor, templates, and tenant metadata. Its enforcement requires the matching ArnaSite release that checks the active tenant's organization. A granted permission still requires the target module's existing workspace and entitlement checks, where applicable. Accounting, shared File Manager, billing, device access and central role administration are outside this catalog.

Changes record the acting SSO user and organization in `AuditLog`. The endpoint reuses the organization-bound IAM models and does not migrate, rewrite, or assign existing roles. Legacy IAM write protections reserve Full Admin changes for the organization owner and route BNK role changes through this API.
