import requests
import sys
import time

# CONFIG
BASE_URL = "http://localhost:8001"

# PERSONAS
USERS = [
    {"firstName": "Asep", "lastName": "Surasep", "email": "asep@company-a.com", "password": "password123"},
    {"firstName": "Budi", "lastName": "Budiman", "email": "budi@company-b.com", "password": "password123"},
    {"firstName": "Cecep", "lastName": "Gorbacep", "email": "cecep@company-c.com", "password": "password123"},
    {"firstName": "Dono", "lastName": "Kasino", "email": "dono@company-d.com", "password": "password123"},
    {"firstName": "Erwin", "lastName": "Erwin", "email": "erwin@company-e.com", "password": "password123"},
    {"firstName": "Agus", "lastName": "Agustus", "email": "agus@company-a.com", "password": "password123"},
]

def print_step(msg):
    print(f"\n{'='*50}\n{msg}\n{'='*50}")

def register_user(u):
    print(f"🔹 Registering {u['firstName']} ({u['email']})...")
    resp = requests.post(f"{BASE_URL}/api/auth/register/", json={
        "email": u["email"],
        "password": u["password"],
        "first_name": u["firstName"],
        "last_name": u["lastName"]
    })
    if resp.status_code == 201:
        print("✅ Registered.")
        return True
    elif resp.status_code == 400 and "already exists" in resp.text:
         print("⚠️ User already exists.")
         return True
    else:
        print(f"❌ Registration Failed: {resp.text}")
        return False

def login(email, password):
    resp = requests.post(f"{BASE_URL}/api/auth/login/", json={"email": email, "password": password})
    if resp.status_code == 200:
        return resp.json()['access']
    print(f"❌ Login Failed for {email}: {resp.text}")
    sys.exit(1)

def get_my_id(token):
    headers = {"Authorization": f"Bearer {token}"}
    resp = requests.get(f"{BASE_URL}/api/auth/me/", headers=headers)
    if resp.status_code == 200:
        return resp.json()['id']
    print(f"❌ Failed to get Profile: {resp.text}")
    sys.exit(1)

def create_org(token, name):
    print(f"🔹 Creating Org '{name}'...")
    headers = {"Authorization": f"Bearer {token}"}
    data = {"name": name}
    resp = requests.post(f"{BASE_URL}/api/org/organizations/", json=data, headers=headers)
    
    if resp.status_code == 201:
        org_data = resp.json()
        print(f"✅ Created {name} (ID: {org_data['id']})")
        return org_data
    elif resp.status_code == 400 and "already exists" in resp.text:
         print(f"⚠️ {name} likely already exists.")
         return None # Need to search for it if we want to add members?
    else:
        print(f"❌ Failed to create org: {resp.text}")
        return None

def add_member_api(owner_token, org_id, user_id):
    print(f"🔹 Adding Member (ID: {user_id}) to Org (ID: {org_id})...")
    headers = {"Authorization": f"Bearer {owner_token}"}
    data = {
        "organization": org_id,
        "user": user_id
    }
    resp = requests.post(f"{BASE_URL}/api/org/members/", json=data, headers=headers)
    if resp.status_code == 201:
        print("✅ Member Added.")
        return resp.json()
    else:
         print(f"❌ Failed to Add Member: {resp.text}")
         return None

def run_seeder():
    # 1. REGISTER ALL USERS
    print_step("1. REGISTERING USERS")
    for u in USERS:
        register_user(u)

    # 2. CAPTURE TOKENS & IDS
    print_step("2. CAPTURING CREDENTIALS (IDs via /me/)")
    tokens = {} # email -> token
    ids = {} # email -> user_id
    
    for u in USERS:
        email = u['email']
        tokens[email] = login(email, u['password'])
        ids[email] = get_my_id(tokens[email])
        print(f"User {u['firstName']} ID: {ids[email]}")

    # 3. CREATE ORGANIZATIONS
    print_step("3. CREATING ORGANIZATIONS (A-E)")
    # Asep -> Org A
    org_a = create_org(tokens["asep@company-a.com"], "Company A")
    # Budi -> Org B
    org_b = create_org(tokens["budi@company-b.com"], "Company B")
    # Cecep -> Org C
    org_c = create_org(tokens["cecep@company-c.com"], "Company C")
    # Dono -> Org D
    org_d = create_org(tokens["dono@company-d.com"], "Company D")
    # Erwin -> Org E
    org_e = create_org(tokens["erwin@company-e.com"], "Company E")

    # 4. CROSS SEEDING (The "Tour")
    print_step("4. SIMULATING 'ASEP'S JOURNEY' (Adding Asep to B, C, D)")
    
    asep_id = ids["asep@company-a.com"]
    
    # Budi adds Asep to Org B
    if org_b: add_member_api(tokens["budi@company-b.com"], org_b['id'], asep_id)
    
    # Cecep adds Asep to Org C
    if org_c: add_member_api(tokens["cecep@company-c.com"], org_c['id'], asep_id)
    
    # Dono adds Asep to Org D
    if org_d: add_member_api(tokens["dono@company-d.com"], org_d['id'], asep_id)
    
    # 5. AGUS JOINING COMPANY A
    print_step("5. ADDING STAFF (Agus) to Company A")
    if org_a:
         agus_id = ids["agus@company-a.com"]
         add_member_api(tokens["asep@company-a.com"], org_a['id'], agus_id)

    print("\n✅ API SEEDING COMPLETED SUCCESSFULLY")
    print("Run 'python verify_session_flow.py' to test the session switching!")

if __name__ == "__main__":
    run_seeder()
