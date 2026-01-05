import os
import django
from django.contrib.auth import get_user_model

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sso_service.settings')
django.setup()

from organization.models import Organization, OrganizationMember
from iam.models import Permission, Role, UserRole

User = get_user_model()

def create_admin():
    email = 'admin@arnatech.id'
    password = 'admin'
    org_name = 'Arnatech HQ'
    role_name = 'Super Admin'
    
    try:
        # 1. Create/Get User
        if not User.objects.filter(email=email).exists():
            print(f"Creating superuser: {email}")
            user = User.objects.create_superuser(email=email, password=password, is_active=True)
            print("✅ Superuser created successfully.")
        else:
            print(f"ℹ️ Superuser {email} already exists. Resetting password & activating...")
            user = User.objects.get(email=email)
            user.set_password(password)
            user.is_active = True
            user.save()
            print("✅ Password updated & Account Activated.")

        # 2. Create/Get Organization
        org, created = Organization.objects.get_or_create(
            name=org_name,
            defaults={'owner': user, 'package_type': 'Enterprise'}
        )
        if created:
            print(f"✅ Organization '{org_name}' created.")
        else:
            print(f"ℹ️ Organization '{org_name}' already exists.")

        # 3. Create Membership & Set Session Active
        member, created = OrganizationMember.objects.get_or_create(
            user=user,
            organization=org,
            defaults={'is_session_active': True}
        )
        # Ensure session is active
        if not member.is_session_active:
            member.is_session_active = True
            member.save()
            print("✅ Active session set.")
        else:
            print("ℹ️ Session already active.")

        # 4. Create Permissions
        # Granular Permissions based on Use Cases
        permissions_data = [
            # Dashboard
            {'name': 'dashboard.view_admin', 'description': 'Access Admin Dashboard Analytics'},
            
            # Employees Management
            {'name': 'employees.view_list', 'description': 'View list of employees'},
            {'name': 'employees.create', 'description': 'Create new employee'},
            {'name': 'employees.edit', 'description': 'Edit employee details'},
            {'name': 'employees.delete', 'description': 'Delete employee'},
            {'name': 'employees.view_detail', 'description': 'View detailed employee profile'},
            
            # Company Management
            {'name': 'companies.view_list', 'description': 'View list of companies'},
            {'name': 'companies.manage', 'description': 'Create, edit, delete companies'},
            
            # Activitity monitoring
            {'name': 'activities.view_all', 'description': 'View all employee activities'},
        ]
        
        created_perms = []
        for p_data in permissions_data:
            perm, created = Permission.objects.get_or_create(
                name=p_data['name'],
                defaults={'description': p_data['description']}
            )
            created_perms.append(perm)
            if created:
                print(f"✅ Permission '{p_data['name']}' created.")

        # 5. Create Role & Assign Permissions
        role, created = Role.objects.get_or_create(
            name=role_name,
            organization=org,
            defaults={'description': 'Full access to everything'}
        )
        
        # Add permissions to role
        role.permissions.add(*created_perms)
        print(f"✅ Permissions assigned to Role '{role_name}'.")

        # 6. Assign Role to Member
        UserRole.objects.get_or_create(organization_member=member, role=role)
        print(f"✅ Role '{role_name}' assigned to {email}.")

        print("--------------------------------------------------")
        print(f"Credentials:\nUser: {email}\nPass: {password}")
        print("--------------------------------------------------")
        
    except Exception as e:
        print(f"❌ Failed: {e}")

if __name__ == '__main__':
    create_admin()
