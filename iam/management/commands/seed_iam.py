import uuid
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from organization.models import Organization, OrganizationMember
from iam.models import Role, Permission, UserRole, UserPermission

User = get_user_model()

class Command(BaseCommand):
    help = 'Seeds the database with Alphabetical Multi-Tenant IAM data (Asep, Budi, Cecep...)'

    def handle(self, *args, **kwargs):
        self.stdout.write("🌱 Starting Alphabetical IAM Seeding...")
        
        # 1. CLEANUP (Wipe everything)
        self.stdout.write("⚠️ Wiping old data...")
        Organization.objects.all().delete()
        User.objects.exclude(is_superuser=True).delete()
        Permission.objects.all().delete() 
        
        # 2. CREATE SUPERADMIN
        admin, _ = User.objects.get_or_create(email='admin@arnatech.id')
        admin.set_password('admin')
        admin.is_staff = True
        admin.is_superuser = True
        admin.is_active = True
        admin.save()
        
        # 3. DEFINE PERMISSIONS
        perms = {
            'view': Permission.objects.create(name='ems.view_dashboard', description='Can view dashboard'),
            'edit': Permission.objects.create(name='ems.edit_data', description='Can edit data'),
            'm_org': Permission.objects.create(name='organization.manage_members', description='Can invite/remove members'),
            'm_role': Permission.objects.create(name='organization.manage_roles', description='Can create and assign roles'),
        }

        # 4. DEFINE ORGANIZATIONS & OWNERS (Usage of Helper)
        def create_org_hero(org_name, owner_name, email_prefix):
            email = f"{email_prefix}@{org_name.lower().replace(' ', '-')}.com"
            u = User.objects.create_user(email=email, password='password123')
            u.first_name = owner_name # Just in case we use it
            u.is_active = True
            u.save()
            
            # Pass owner in .create() to satisfy NOT NULL constraint
            org = Organization.objects.create(
                name=org_name, 
                owner=u,
                package_type='Pro' if 'A' in org_name else 'Basic'
            )
            return org, u

        # A - ASEP
        org_a, u_asep = create_org_hero("Company A", "Asep", "asep")
        # B - BUDI
        org_b, u_budi = create_org_hero("Company B", "Budi", "budi")
        # C - CECEP
        org_c, u_cecep = create_org_hero("Company C", "Cecep", "cecep")
        # D - DONO
        org_d, u_dono = create_org_hero("Company D", "Dono", "dono")
        # E - ERWIN
        org_e, u_erwin = create_org_hero("Company E", "Erwin", "erwin")

        # 5. DEFINE STAFF/EXTRAS
        # Agus (Staff A)
        u_agus = User.objects.create_user(email="agus@company-a.com", password="password123")
        u_agus.is_active = True
        u_agus.save()

        # 6. MEMBERSHIPS & ROLES Helper
        def add_member(org, user, role_name=None, role_permissions=[], direct_permissions=[]):
            mem = OrganizationMember.objects.create(user=user, organization=org, is_session_active=True)
            
            # 1. Assign Role if provided
            if role_name:
                role, _ = Role.objects.get_or_create(name=role_name, organization=org)
                if role_permissions:
                    role.permissions.add(*role_permissions)
                UserRole.objects.create(organization_member=mem, role=role)
            
            # 2. Assign Direct Permissions if provided
            if direct_permissions:
                # Create UserPermission container
                up = UserPermission.objects.create(organization_member=mem)
                up.permissions.add(*direct_permissions)

            return mem

        # --- ORG A: The Home Base ---
        add_member(org_a, u_asep, "CEO", [perms['view'], perms['edit'], perms['m_org'], perms['m_role']])
        add_member(org_a, u_agus, "Staff IT", [perms['view']]) # Starts low access

        # --- ORG B: Asep is Member ONLY (No Role) ---
        # Owner Budi is full power
        add_member(org_b, u_budi, "Direktur", [perms['view'], perms['edit'], perms['m_org'], perms['m_role']])
        # Asep is Member Only
        add_member(org_b, u_asep, role_name=None) 

        # --- ORG C: Asep is HR (Manage Members, View Only) ---
        add_member(org_c, u_cecep, "Founder", [perms['view'], perms['edit'], perms['m_org'], perms['m_role']])
        # Asep is HR
        add_member(org_c, u_asep, "HRD", [perms['view'], perms['m_org']])

        # --- ORG D: Asep is Admin (DIRECT Permissions, No Role) ---
        add_member(org_d, u_dono, "Juragan", [perms['view'], perms['edit'], perms['m_org'], perms['m_role']])
        # Asep has Direct Permissions (View, Edit, Manage Roles) but NO Role
        add_member(org_d, u_asep, role_name=None, direct_permissions=[perms['view'], perms['edit'], perms['m_role']])

        # --- ORG E: Isolation ---
        add_member(org_e, u_erwin, "Bos Besar", [perms['view']])
        # Asep has NO access here.

        self.stdout.write("\n🎉 ALPHABET SEEDING COMPLETE!")
        self.stdout.write("==================================================")
        self.stdout.write(f"PROTAGONIST: Asep (asep@company-a.com)")
        self.stdout.write("--------------------------------------------------")
        self.stdout.write(f"1. @ Company A (Owner) -> CEO (Full Access)")
        self.stdout.write(f"2. @ Company B (Owner: Budi) -> Member (NO ROLE - 0 Perms)")
        self.stdout.write(f"3. @ Company C (Owner: Cecep) -> HRD (View + Invite)")
        self.stdout.write(f"4. @ Company D (Owner: Dono) -> DIRECT PERMS (Edit + Manage Roles)")
        self.stdout.write(f"5. @ Company E (Owner: Erwin) -> OUTSIDER (No Access)")
        self.stdout.write("==================================================")
        self.stdout.write(f"TEST SUBJECT: Agus (agus@company-a.com)")
        self.stdout.write(f"Role: Staff IT @ Company A")
        self.stdout.write("==================================================")
