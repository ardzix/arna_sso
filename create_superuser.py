import os
import django
from django.contrib.auth import get_user_model

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'sso_service.settings')
django.setup()

User = get_user_model()

def create_admin():
    email = 'admin@arnatech.id'
    password = 'admin'
    
    try:
        if not User.objects.filter(email=email).exists():
            print(f"Creating superuser: {email}")
            User.objects.create_superuser(email=email, password=password, is_active=True)
            print("✅ Superuser created successfully.")
        else:
            print(f"ℹ️ Superuser {email} already exists. Resetting password & activating...")
            u = User.objects.get(email=email)
            u.set_password(password)
            u.is_active = True
            u.save()
            print("✅ Password updated & Account Activated.")
            
        print(f"Credentials:\nUser: {email}\nPass: {password}")
        
    except Exception as e:
        print(f"❌ Failed: {e}")

if __name__ == '__main__':
    create_admin()
