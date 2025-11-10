# WhatsApp OTP Authentication

Fitur autentikasi via WhatsApp OTP menggunakan WAHA (WhatsApp HTTP API) terintegrasi seamless dengan SSO yang ada.

## Konfigurasi

### Environment Variables

#### WAHA Configuration (untuk Push Method)
```bash
WAHA_API_URL=https://waha.arnatech.id  # Default
WAHA_API_KEY=<your-api-key>
```

#### N8N Webhook Configuration (untuk Reverse Method)
```bash
N8N_WEBHOOK_URL=http://n8d.arnatech.id/webhook/  # Default
N8N_WEBHOOK_ID=<your-webhook-uuid>  # UUID webhook ID dari n8n
N8N_WEBHOOK_AUTH_TOKEN=<your-auth-token>  # Token autentikasi untuk n8n webhook
```

**Catatan:** 
- Push method: Mengirim OTP langsung via WAHA API (user menerima pesan otomatis)
- Reverse method: Mengirim data OTP ke n8n webhook (user harus initiate chat terlebih dahulu)

### Database Schema
Field baru di `User` model:
- `phone_number`: CharField(20), unique, nullable - Nomor HP terverifikasi (format E.164)
- `phone_verified`: Boolean - Status verifikasi nomor HP
- `pending_phone`: CharField(20), nullable - Nomor HP yang menunggu verifikasi

## Endpoints

### Metode Autentikasi

Sistem mendukung **2 metode** untuk WhatsApp OTP:

1. **Push Method** (Original): OTP dikirim langsung via WAHA API
   - Endpoint: `/api/auth/wa/*`
   - User menerima pesan WhatsApp otomatis
   - Memerlukan: `WAHA_API_URL` dan `WAHA_API_KEY`

2. **Reverse Method** (Baru): OTP data dikirim ke n8n webhook
   - Endpoint: `/api/auth/wa/reverse/*`
   - User harus initiate chat terlebih dahulu
   - n8n mencocokan OTP saat user chat
   - Memerlukan: `N8N_WEBHOOK_URL`, `N8N_WEBHOOK_ID`, dan `N8N_WEBHOOK_AUTH_TOKEN`

---

### 1. Link WhatsApp ke Akun Existing (Authenticated)

#### Push Method

#### Send OTP untuk Link
```
POST /api/auth/wa/send-link-otp/
Authorization: Bearer <access_token>

Body:
{
  "phone": "0858 111 444 21"  // Format apapun (akan dinormalisasi)
}

Response 200:
{
  "message": "OTP sent to WhatsApp",
  "phone": "6285811144421"
}
```

#### Verifikasi OTP Link
```
POST /api/auth/wa/verify-link/
Authorization: Bearer <access_token>

Body:
{
  "otp": "123456"
}

Response 200:
{
  "message": "Phone number linked successfully",
  "phone": "6285811144421"
}
```

#### Reverse Method
```
POST /api/auth/wa/reverse/send-link-otp/
Authorization: Bearer <access_token>

Body:
{
  "phone": "0858 111 444 21"
}

Response 200:
{
  "message": "OTP data sent to n8n. Please initiate chat via WhatsApp link.",
  "phone": "6285811144421",
  "method": "reverse"
}
```

**Catatan:** Verify endpoint sama untuk kedua metode: `POST /api/auth/wa/verify-link/`

---

### 2. Registrasi via WhatsApp (Public)

#### Push Method

#### Request Registrasi
```
POST /api/auth/wa/register-request/

Body:
{
  "phone": "0858-111-444-21",
  "email": "user@example.com"  // Optional
}

Response 200:
{
  "message": "OTP sent to WhatsApp",
  "phone": "6285811144421"
}
```

Catatan:
- Jika `email` kosong/tidak diberikan, sistem akan membuat placeholder email: `wa_<phone>@arnatech.local`
- Placeholder email **tidak** akan menerima verifikasi email otomatis

#### Verifikasi Registrasi
```
POST /api/auth/wa/register-verify/

Body:
{
  "phone": "6285811144421",
  "otp": "123456"
}

Response 200:
{
  "message": "Account activated successfully",
  "refresh": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Reverse Method
```
POST /api/auth/wa/reverse/register-request/

Body:
{
  "phone": "0858-111-444-21",
  "email": "user@example.com"  // Optional
}

Response 200:
{
  "message": "OTP data sent to n8n. Please initiate chat via WhatsApp link.",
  "phone": "6285811144421",
  "method": "reverse"
}
```

**Catatan:** Verify endpoint sama untuk kedua metode: `POST /api/auth/wa/register-verify/`

---

### 3. Login via WhatsApp (Public)

#### Push Method

#### Send OTP untuk Login
```
POST /api/auth/wa/send-otp/

Body:
{
  "phone": "0858 111 444 21"
}

Response 200:
{
  "message": "If the phone number is registered, OTP has been sent."
}
```

Catatan: Response selalu sama (anti-enumeration)

#### Verifikasi OTP Login
```
POST /api/auth/wa/verify-otp/

Body:
{
  "phone": "6285811144421",
  "otp": "123456"
}

Response 200:
{
  "refresh": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "access": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

#### Reverse Method
```
POST /api/auth/wa/reverse/send-otp/

Body:
{
  "phone": "0858 111 444 21"
}

Response 200:
{
  "message": "If the phone number is registered, OTP data has been sent to n8n."
}
```

**Catatan:** Verify endpoint sama untuk kedua metode: `POST /api/auth/wa/verify-otp/`

---

## Perbedaan Push vs Reverse Method

### Push Method (Original)
- ✅ OTP dikirim langsung via WAHA API
- ✅ User menerima pesan WhatsApp otomatis
- ⚠️ Potensi nomor/IP terblokir jika terlalu banyak push message
- 🔧 Memerlukan: WAHA API configuration

### Reverse Method (Baru)
- ✅ Mengurangi risiko nomor/IP terblokir
- ✅ User initiate chat (lebih natural)
- ✅ Lebih aman (tidak ada push message yang terdeteksi sebagai spam)
- 🔧 Memerlukan: n8n webhook configuration
- 📋 Flow: Data OTP dikirim ke n8n → User chat ke WAHA via n8n → n8n mencocokan OTP

**Rekomendasi:** Gunakan Reverse Method untuk production untuk menghindari risiko blocking.

---

## Normalisasi Nomor HP

Sistem otomatis menormalisasi nomor HP ke format E.164 Indonesia:
- Hapus karakter non-digit: `+`, `-`, spasi
- Prefix `0` diubah ke `62`: `0858` → `6285`
- Hasil akhir: `6285811144421`

Contoh input yang valid:
- `0858 111 444 21` → `6285811144421`
- `+62 858-111-444-21` → `6285811144421`
- `62858111444421` → `6285811144421`

## Keamanan

### Rate Limiting
- Cooldown 5 menit antar pengiriman OTP
- OTP berlaku 10 menit
- Response 429 jika terlalu cepat mengirim ulang

### Anti-Enumeration
- Endpoint login WA selalu return response yang sama, tidak membocorkan apakah nomor terdaftar atau tidak

### Uniqueness
- Nomor HP harus unik di sistem
- Tidak bisa link nomor yang sudah digunakan user lain
- Validasi di level database (unique constraint)

## Skenario Penggunaan

### Skenario 1: User Existing Menambahkan WhatsApp
1. User login dengan email/password
2. POST `/api/auth/wa/send-link-otp/` dengan nomor HP
3. Terima OTP via WhatsApp
4. POST `/api/auth/wa/verify-link/` dengan OTP
5. Nomor HP ter-link, bisa digunakan untuk login selanjutnya

### Skenario 2: Registrasi Phone-Only
1. POST `/api/auth/wa/register-request/` dengan nomor HP (tanpa email)
2. Sistem buat user dengan email placeholder: `wa_6285811144421@arnatech.local`
3. Terima OTP via WhatsApp
4. POST `/api/auth/wa/register-verify/` dengan OTP
5. Akun aktif, dapat JWT token

### Skenario 3: Registrasi Phone + Email
1. POST `/api/auth/wa/register-request/` dengan nomor HP dan email
2. Sistem buat user dengan email asli
3. Terima OTP via WhatsApp untuk verifikasi nomor
4. POST `/api/auth/wa/register-verify/` dengan OTP
5. Akun aktif, dapat JWT token
6. (Opsional) User bisa verify email lewat endpoint email verification nanti

### Skenario 4: Login via WhatsApp
1. POST `/api/auth/wa/send-otp/` dengan nomor HP
2. Terima OTP via WhatsApp
3. POST `/api/auth/wa/verify-otp/` dengan OTP
4. Dapat JWT token

### Skenario 5: Login via WhatsApp (Reverse Method)
1. POST `/api/auth/wa/reverse/send-otp/` dengan nomor HP
2. Sistem kirim data OTP ke n8n webhook
3. FE tampilkan wa.me link untuk user
4. User initiate chat ke WAHA via n8n
5. n8n mencocokan nomor HP dan OTP dari database
6. User dapat OTP dari n8n
7. POST `/api/auth/wa/verify-otp/` dengan OTP
8. Dapat JWT token

## Integrasi dengan Flow Existing

### Multi-Channel Authentication
User sekarang bisa login dengan:
1. **Email + Password** (existing): `POST /api/auth/login/`
2. **WhatsApp OTP Push** (new): `POST /api/auth/wa/send-otp/` → `verify-otp/`
3. **WhatsApp OTP Reverse** (new): `POST /api/auth/wa/reverse/send-otp/` → `verify-otp/`
4. **Google OAuth** (planned): (belum diimplementasi)

### Token Management
- Semua metode autentikasi menggunakan JWT yang sama (RS256)
- Token refresh, verify, logout tetap sama
- MFA (TOTP) bisa diaktifkan terlepas dari metode login

## Testing

### Push Method (WAHA)
```bash
# Set environment
export WAHA_API_URL="https://waha.arnatech.id"
export WAHA_API_KEY="your-api-key"

# Test register
curl -X POST http://localhost:8000/api/auth/wa/register-request/ \
  -H "Content-Type: application/json" \
  -d '{"phone": "0858111444211"}'

# Check OTP di WhatsApp, lalu verify
curl -X POST http://localhost:8000/api/auth/wa/register-verify/ \
  -H "Content-Type: application/json" \
  -d '{"phone": "6285811144211", "otp": "123456"}'
```

### Reverse Method (n8n)
```bash
# Set environment
export N8N_WEBHOOK_URL="http://n8d.arnatech.id/webhook/"
export N8N_WEBHOOK_ID="your-webhook-uuid"
export N8N_WEBHOOK_AUTH_TOKEN="your-auth-token"

# Test register
curl -X POST http://localhost:8000/api/auth/wa/reverse/register-request/ \
  -H "Content-Type: application/json" \
  -d '{"phone": "0858111444211"}'

# Data OTP akan dikirim ke n8n webhook
# User harus initiate chat via wa.me link
# n8n akan mencocokan OTP saat user chat
# Lalu verify seperti biasa
curl -X POST http://localhost:8000/api/auth/wa/register-verify/ \
  -H "Content-Type: application/json" \
  -d '{"phone": "6285811144211", "otp": "123456"}'
```

### Development Testing
- **Push Method:** Jika `WAHA_API_KEY` kosong, akan raise error. Set mock/dummy key atau check OTP di database/log
- **Reverse Method:** Jika `N8N_WEBHOOK_ID` kosong, akan raise error. Pastikan n8n webhook sudah dikonfigurasi dengan benar

## Migrasi

File migrasi sudah dibuat:
```
authentication/migrations/0005_user_pending_phone_user_phone_number_and_more.py
```

Jalankan:
```bash
python manage.py migrate
```

## Troubleshooting

### OTP tidak terkirim (Push Method)
- Cek `WAHA_API_URL` dan `WAHA_API_KEY` sudah benar
- Cek `django-q` cluster berjalan: `python manage.py qcluster`
- Cek log WAHA API response
- Pastikan WAHA service aktif dan accessible

### OTP data tidak terkirim ke n8n (Reverse Method)
- Cek `N8N_WEBHOOK_URL`, `N8N_WEBHOOK_ID`, dan `N8N_WEBHOOK_AUTH_TOKEN` sudah benar
- Cek `django-q` cluster berjalan: `python manage.py qcluster`
- Cek log n8n webhook response
- Pastikan n8n webhook aktif dan accessible
- Verify webhook URL format: `http://n8d.arnatech.id/webhook/{webhook_id}`

### Nomor tidak valid
- Pastikan nomor HP Indonesia (diawali 0 atau 62)
- Minimal 10 digit setelah normalisasi

### Cooldown error
- User harus tunggu 5 menit sejak OTP terakhir dikirim
- Atau reset `last_otp_sent` secara manual di database untuk testing

### Error saat Swagger schema generation
- Error "AnonymousUser is not a valid UUID" sudah diperbaiki
- ViewSet sekarang handle AnonymousUser dengan proper check

