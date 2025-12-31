import requests
import jwt # PyJWT
import sys
import json

# CONFIG
BASE_URL = "http://localhost:8001"
# Trying to use a user that likely exists from seeding or previous context.
# 'asep@company-a.com' was used in verify_session_flow.py, so I'll try that.
EMAIL = "asep@company-a.com"
PASSWORD = "password123"

def print_step(msg):
    print(f"\n{'='*50}\n{msg}\n{'='*50}")

def login():
    print_step("1. LOGGING IN to get Token")
    try:
        resp = requests.post(f"{BASE_URL}/api/auth/login/", json={"email": EMAIL, "password": PASSWORD})
        if resp.status_code == 200:
            print("✅ Login Successful")
            return resp.json()['access']
        else:
            print(f"❌ Login Failed: {resp.status_code} {resp.text}")
            # Try to register if login fails? No, better to fail loud.
            sys.exit(1)
    except requests.exceptions.ConnectionError:
        print("❌ Connection Refused. Is the server running?")
        sys.exit(1)

def verify_token(token):
    print_step("2. DECODING TOKEN")
    # We decode without verification just to see the payload content
    # In a real verification we would verify the signature.
    decoded = jwt.decode(token, options={"verify_signature": False})
    
    print(json.dumps(decoded, indent=2))
    
    print_step("3. VERIFYING CLAIMS")
    
    missing = []
    
    if 'org_id' not in decoded:
        missing.append('org_id')
    else:
        print(f"✅ org_id found: {decoded['org_id']}")
        
    if 'roles' not in decoded:
        missing.append('roles')
    else:
        print(f"✅ roles found: {decoded['roles']}")
        
    if 'permissions' not in decoded:
        missing.append('permissions')
    else:
        print(f"✅ permissions found: {decoded['permissions']}")
        
    if missing:
        print(f"❌ MISSING CLAIMS: {missing}")
        sys.exit(1)
    else:
        print("\n✅ SUCCESS: All custom RBAC claims are present in the JWT.")

if __name__ == "__main__":
    token = login()
    verify_token(token)
