import os
import django
from django.db.models import Q

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sso_service.settings')
django.setup()

from authentication.models import User
from organization.models import OrganizationMember
from iam.models import Role, Permission

def run():
    print("--- DEBUG VISIBILITY ---")
    
    # 1. Check User
    try:
        user = User.objects.get(email='owner@company-a.com')
        print(f"✅ User Found: {user.email} (ID: {user.id})")
    except User.DoesNotExist:
        print("❌ User 'owner@company-a.com' NOT FOUND!")
        return

    # 2. Check Membership
    memberships = OrganizationMember.objects.filter(user=user)
    print(f"📋 Memberships: {[m.organization.name for m in memberships]}")
    
    if not memberships.exists():
        print("❌ User has NO memberships!")

    # 3. Check Roles in DB
    all_roles = Role.objects.count()
    print(f"📊 Total Roles in DB: {all_roles}")
    
    roles_org_a = Role.objects.filter(organization__name='Company A')
    print(f"   - Roles for Company A: {[r.name for r in roles_org_a]}")

    # 4. Simulate RoleViewSet Logic
    print("\n--- SIMULATING RoleViewSet.get_queryset() ---")
    qs = Role.objects.filter(
        Q(organization__isnull=True) | 
        Q(organization__members__user=user)
    ).distinct()
    
    print(f"🔍 QuerySet Query: {qs.query}")
    print(f"🔢 Count: {qs.count()}")
    for r in qs:
        print(f"   - Found Role: {r.name} (Org: {r.organization.name if r.organization else 'Global'})")

    # 5. Check Permissions
    print("\n--- PERMISSIONS ---")
    all_perms = Permission.objects.count()
    print(f"Total Permissions: {all_perms}")
    qs_perms = Permission.objects.all()
    print(f"Visible to User: {qs_perms.count()} (Since we removed IsAdminUser)")

if __name__ == '__main__':
    run()
