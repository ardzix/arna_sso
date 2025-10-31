# WhatsApp OTP Authentication

Fitur autentikasi via WhatsApp OTP menggunakan WAHA (WhatsApp HTTP API) terintegrasi seamless dengan SSO yang ada.

## Konfigurasi

### Environment Variables
```bash
WAHA_API_URL=https://waha.arnatech.id  # Default
WAHA_API_KEY=<your-api-key>
```

### Database Schema
Field baru di `User` model:
- `phone_number`: CharField(20), unique, nullable - Nomor HP terverifikasi (format E.164)
- `phone_verified`: Boolean - Status verifikasi nomor HP
- `pending_phone`: CharField(20), nullable - Nomor HP yang menunggu verifikasi

## Endpoints

### 1. Link WhatsApp ke Akun Existing (Authenticated)

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

### 2. Registrasi via WhatsApp (Public)

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

### 3. Login via WhatsApp (Public)

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

## Integrasi dengan Flow Existing

### Multi-Channel Authentication
User sekarang bisa login dengan:
1. **Email + Password** (existing): `POST /api/auth/login/`
2. **WhatsApp OTP** (new): `POST /api/auth/wa/send-otp/` → `verify-otp/`
3. **Google OAuth** (planned): (belum diimplementasi)

### Token Management
- Semua metode autentikasi menggunakan JWT yang sama (RS256)
- Token refresh, verify, logout tetap sama
- MFA (TOTP) bisa diaktifkan terlepas dari metode login

## Testing

### Dengan WAHA Aktif
```bash
# Set environment
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

### Tanpa WAHA (Development)
Jika `WAHA_API_KEY` kosong, `send_otp_whatsapp` akan raise error. Untuk testing lokal:
1. Set mock/dummy WAHA_API_KEY
2. Atau check OTP langsung di database/log

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

### OTP tidak terkirim
- Cek `WAHA_API_URL` dan `WAHA_API_KEY` sudah benar
- Cek `django-q` cluster berjalan: `python manage.py qcluster`
- Cek log WAHA API response

### Nomor tidak valid
- Pastikan nomor HP Indonesia (diawali 0 atau 62)
- Minimal 10 digit setelah normalisasi

### Cooldown error
- User harus tunggu 5 menit sejak OTP terakhir dikirim
- Atau reset `last_otp_sent` secara manual di database untuk testing

