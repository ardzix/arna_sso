# Login terpusat Arna

Semua form login berada di `https://sso.arnatech.id/login/`. Aplikasi memulai
Authorization Code + S256 PKCE; SSO yang sudah memiliki session langsung
mengembalikan kode tanpa meminta kredensial lagi. Redirect ini bekerja antar-domain
tanpa iframe atau third-party cookies.

| Aplikasi | Client ID | Callback produksi |
|---|---|---|
| Account | `arna-account` | `https://account.arnatech.id/api/auth/callback` |
| Bisnis Naik Kelas | `arnasite-dashboard` | `https://www.bisnisnaikkelas.com/api/auth/callback` |
| BNK apex | `arnasite-dashboard` | `https://bisnisnaikkelas.com/api/auth/callback` |
| Company | `arnaos` | `https://company.arnatech.id/api/auth/callback` |
| Clockin | `arna-clockin` | `https://clockin.arnatech.id/api/auth/callback` |

Callback terdaftar tepat per client di SSO; wildcard tidak digunakan.
Migration SSO `0018_app_browser_sessions` harus diterapkan sebelum client baru dirilis.
Implementasi ini memakai kontrak PKCE Arna yang ada, bukan klaim bahwa SSO sudah
menyediakan seluruh discovery/ID-token endpoint OpenID Connect.

## Session dan API

- SSO menyimpan session utama selama delapan jam, menggunakan cookie
  `__Host-arna_sso` yang Secure, HttpOnly, SameSite=Lax, host-only.
- SSO menyimpan hash credential session aplikasi yang terikat ke session utama
  dan client ID. Credential hanya berada dalam cookie HttpOnly aplikasi.
- Next.js BFF memakai cookie `__Host-arna_app`. Clockin menggunakan session Django
  database melalui cookie `__Host-arna_clockin`; tidak memakai signed-cookie berisi JWT.
- Backend menukar kode pada `POST /api/auth/sso/app-session/`, lalu meminta token
  API singkat melalui `POST /api/auth/sso/app-session/resolve/`. Refresh token tidak
  dikirim ke browser. Credential session dikirim sebagai Bearer oleh backend saja.
- Endpoint browser `/api/auth/session` mengembalikan profil tanpa token API.
- Browser Next.js memanggil `/api/gateway/{service}/...`; BFF memasang token ke
  tujuan yang ditetapkan server. Storage dan Commerce memakai audience masing-masing.
- Mutasi BFF memerlukan Origin yang sama. Django Clockin menggunakan CSRF middleware.
- Pergantian org/tenant tetap divalidasi SSO dan backend pemilik resource.
  Cookie dan localStorage workspace hanya menjadi petunjuk UI.
- Pendaftaran passkey tetap mempertahankan challenge sementara dalam cookie
  HttpOnly. Pendaftaran harus dilakukan pada origin yang sesuai RP WebAuthn;
  passkey Arna dapat dikelola melalui Account, lalu dipakai login melalui SSO.

## Keluar

`GET /api/auth/logout` menampilkan pilihan keluar aplikasi ini atau semua aplikasi.
`POST /api/auth/logout` mencabut session aplikasi; payload `{ "all": true }`
sekaligus mengakhiri session SSO sumbernya. Session aplikasi lain yang terikat
ke session SSO tersebut langsung ditolak pada request berikutnya.
Ini berlaku untuk session browser yang sama; bukan perintah mengeluarkan seluruh
perangkat pengguna atau mencabut semua API credential mandiri.
Clockin menyediakan pilihan yang sama di `/auth/logout/` dengan CSRF form.

## Konfigurasi dan rollout

Tidak memerlukan client secret baru. Gunakan endpoint backend yang sudah tersedia.
Untuk reverse proxy atau preview HTTPS yang disetujui, `SSO_APP_ORIGIN` adalah
konfigurasi server-only; callback origin itu juga harus didaftarkan tepat di SSO.
Company dapat memakai `ARNAOS_PUBLIC_URL` yang sudah tersedia, dan
`ARNAOS_API_INTERNAL_URL` untuk backend. Token Company memiliki issuer
`https://sso.arnatech.id` dan audience `arnaos`; PIC perlu mencocokkan verifier
backend (`SSO_ISSUER`, `SSO_AUDIENCE`, public key) dengan kontrak ini.

1. Rilis dan migrate SSO dahulu, pertahankan signing key dan konfigurasi SMTP/WAHA.
2. Rilis client satu per satu. Login sekali melalui halaman SSO setelah migrasi
   dari cookie SPA lama; session lama di Account belum membuktikan adanya session SSO.
3. Di browser/profil yang sama, buka aplikasi lain: form login tidak muncul lagi.
4. Uji logout lokal (aplikasi lain tetap aktif), lalu logout semua aplikasi
   (request aplikasi lain ditolak dan meminta login SSO).
5. Pastikan API tetap menolak tenant/permission yang tidak dimiliki pengguna.

Untuk Company, perubahan disiapkan di branch review PIC. Jangan menerapkan branch
ini ke Home1 atau mengganti container Company tanpa proses rilis PIC.
