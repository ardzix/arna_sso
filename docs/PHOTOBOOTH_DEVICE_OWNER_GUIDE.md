# Panduan Device Photobooth untuk Owner Tenant

Alur: **kiosk mulai pairing â†’ owner tenant menyetujui â†’ owner assign role â†’ device memakai Drive tenant dan checkout photobooth.**

Panduan ini berlaku setelah perubahan SSO, File Manager, dan frontend selesai di-deploy serta database dimigrasikan.

Base URL SSO: `https://sso.arnatech.id`. Semua path API di bawah menggunakan base URL ini, kecuali endpoint File Manager.

## 1. Owner login dan pilih tenant

Login ke SSO sebagai owner organisasi. Pilih organisasi aktif, lalu workspace tenant.

Jika hanya ada satu tenant aktif, sistem memilihnya otomatis. Jika beberapa, pilih melalui dropdown workspace. `org_id` dan `tenant_id` saat approval mengikuti workspace terverifikasi tersebut.

Alternatif melalui API menggunakan token owner:

```http
GET /api/v1/devices/context/
Authorization: Bearer <owner_access_token>
```

Untuk memilih satu tenant dari daftar yang dikembalikan:

```http
POST /api/v1/devices/context/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "tenant_id": "<UUID tenant dari daftar workspace>"
}
```

## 2. Kiosk membuat permintaan pairing

Panggil tanpa token owner:

```http
POST /api/v1/devices/authorize/
Content-Type: application/json
```

```json
{
  "client_id": "photobooth-tenant-001",
  "device_name": "Photobooth Lobby",
  "audience": "photobooth-api",
  "scopes": ["photobooth.session", "photobooth.session.write"]
}
```

`client_id` harus unik untuk setiap mesin. Tidak perlu mengirim `organization_id` atau `tenant_id` pada langkah ini.

Dari respons, tampilkan QR menggunakan `verification_uri_complete` dan tampilkan `user_code`. Simpan `device_code` hanya di kiosk untuk mengambil token; jangan tampilkan atau masukkan ke QR.

## 3. Owner menyetujui device

Owner scan QR, periksa nama device dan workspace, lalu klik **Setujui perangkat**.

Alternatif API menggunakan token owner:

```http
POST /api/v1/devices/review/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "user_code": "<user_code dari authorize>"
}
```

Setelah memeriksa respons review, approve:

```http
POST /api/v1/devices/verification/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "user_code": "<user_code dari authorize>",
  "action": "approve"
}
```

Kiosk mengambil token dengan polling sesuai `interval` yang dikembalikan authorize:

```http
POST /api/v1/devices/token/
Content-Type: application/json
```

```json
{
  "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
  "device_code": "<device_code dari authorize>"
}
```

`authorization_pending` berarti belum disetujui. Jika menerima `slow_down`, gunakan interval baru. Setelah berhasil, simpan `device_id`, `access_token`, dan `refresh_token` di penyimpanan aman kiosk.

## 4. Owner membuat role Photobooth Device

Di menu **IAM â†’ Roles**, buat role **Photobooth Device** dengan permission berikut:

| Permission | Kebutuhan |
| --- | --- |
| `storage.files.read` | Membaca atau mengunduh frame dan file tenant |
| `storage.files.create` | Mengunggah hasil foto |
| `storage.files.share` | Membuat link hasil foto untuk dibagikan melalui QR |
| `storage.folders.create` | Opsional, jika kiosk membuat folder |
| `commerce.orders.read` | Membaca status order/invoice milik device |
| `commerce.orders.write` | Membuat dan submit order photobooth |
| `commerce.payments.create` | Meminta link pembayaran order |

Tambahkan `storage.files.update` dan `storage.files.delete` hanya jika aplikasi membutuhkannya. Permission storage tersedia dari migrasi; pilih permission milik organisasi aktif.

Alternatif API: ambil katalog permission device menggunakan token owner:

```http
GET /api/v1/devices/registrations/<device_id>/access/
Authorization: Bearer <owner_access_token>
```

Ambil UUID dari `permission_catalog` untuk nama permission yang diperlukan, lalu buat role:

```http
POST /api/iam/roles/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "name": "Photobooth Device",
  "description": "Akses file tenant untuk kiosk photobooth",
  "permission_ids": [
    "<UUID storage.files.read>",
    "<UUID storage.files.create>",
    "<UUID storage.files.share>",
    "<UUID commerce.orders.read>",
    "<UUID commerce.orders.write>",
    "<UUID commerce.payments.create>"
  ]
}
```

Simpan `id` role dari respons untuk langkah berikutnya. Jika role sudah tersedia di organisasi yang sama, gunakan role tersebut.

## 5. Owner assign role ke device

Buka **Devices â†’ pilih workspace â†’ Kelola akses** pada device, pilih role **Photobooth Device**, lalu simpan.

Alternatif API menggunakan token owner:

```http
PUT /api/v1/devices/registrations/<device_id>/access/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "role_ids": ["<UUID role Photobooth Device>"],
  "permission_ids": []
}
```

Endpoint ini mengganti seluruh assignment device. Sertakan seluruh role dan direct permission yang ingin dipertahankan. `permission_ids: []` berarti tidak ada direct permission; permission dari role tetap berlaku.

Device menggunakan `device_id` dan tidak membutuhkan `organization_member`. Role maupun permission harus berasal dari organisasi device yang sama.

## 6. Device meminta token File Manager

Gunakan token device yang masih berlaku:

```http
POST /api/v1/devices/resource-token/
Authorization: Bearer <device_access_token>
Content-Type: application/json
```

```json
{
  "audience": "storage"
}
```

Gunakan `access_token` hasil exchange untuk memanggil File Manager:

```http
GET https://storage.arnatech.id/api/v1/files?owner_scope=org
Authorization: Bearer <storage_access_token>
```

Saat memulai upload, gunakan `owner_scope: "org"`. Kepemilikan organisasi dan tenant diambil dari token. File tetap milik tenant, sedangkan device dicatat sebagai pembuat melalui `created_by_device_id`.

Token storage berlaku paling lama 300 detik dan tidak melebihi masa berlaku token device asal. Mint token storage baru saat diperlukan menggunakan token device yang valid.

Contoh di panduan ini memakai device Bearer tanpa key binding. Jika device menggunakan DPoP, gunakan `Authorization: DPoP <token>` dan proof baru pada exchange maupun setiap request File Manager; ikuti [kontrak DPoP](https://github.com/ardzix/arna_sso/blob/main/docs/DEVICE_AUTHORIZATION.md#optional-device-key-binding-dpop).

## 7. Refresh dan revoke

Kiosk melakukan refresh sebelum token device kedaluwarsa:

```http
POST /api/v1/devices/refresh/
Content-Type: application/json
```

```json
{
  "refresh_token": "<refresh_token terakhir>"
}
```

Simpan access dan refresh token pengganti secara atomik. Refresh token lama tidak boleh dipakai ulang. Token storage berikutnya tetap diminta melalui `resource-token/`.

Owner dapat mencabut device dari menu **Devices**, atau melalui API:

```http
POST /api/v1/devices/revoke/
Authorization: Bearer <owner_access_token>
Content-Type: application/json
```

```json
{
  "device_id": "<UUID device>"
}
```

## Pembagian akses

- Scope `photobooth.session` dan `photobooth.session.write` adalah akses API photobooth saat pairing; backend photobooth harus memeriksanya.
- Role IAM di atas memberi akses Drive tenant. Device baru belum mendapatkan izin Drive sampai owner melakukan assignment.
- `device_code` dan `user_code` bukan `device_id`, role ID, atau membership ID.
- Device tidak perlu permission administrasi seperti `device.activate` atau `organization.manage_roles`. Approval dan assignment dilakukan oleh owner.
- Device memakai token resource `arna-commerce` untuk checkout. Device tidak memperoleh `commerce.payments.process`; status paid hanya diproses backend pembayaran tepercaya.
- Simpan token di penyimpanan aman kiosk. Jangan masukkan token ke QR, URL, log, atau layar publik.


## 8. Device create order dan request payment

**Aktivasi production membutuhkan migrasi dan konfigurasi Commerce serta produk photobooth yang benar.** Scope pairing tetap dua scope photobooth; tiga permission Commerce dipilih pada role IAM, bukan dikirim saat authorize.

Exchange token device seperti langkah File Manager, tetapi kirim:

```http
POST https://sso.arnatech.id/api/v1/devices/resource-token/
Authorization: Bearer <device_access_token>
Content-Type: application/json

{"audience":"arna-commerce"}
```

Gunakan token hasil exchange pada semua request berikut. Base URL Commerce adalah `https://product.arnatech.id`.

1. Ambil product/plan/price photobooth dari `/api/v1/products/`, `/api/v1/plans/?product=<UUID>`, dan `/api/v1/prices/?plan=<UUID>`.
2. `POST /api/v1/orders/` dengan header `Idempotency-Key: <checkout_uuid>:order`:

```json
{"product":"<UUID>","plan":"<UUID>","price":"<UUID>","quantity":1,"payment_method":"pg"}
```

3. `POST /api/v1/orders/<order_uuid>/submit/`, body `{}`, key `<checkout_uuid>:submit`.
4. `POST /api/v1/orders/<order_uuid>/create-payment/`, body `{}`, key `<checkout_uuid>:payment`.
5. Jadikan `invoice_url` dari respons sebagai QR untuk membuka halaman pembayaran. Endpoint ini menghasilkan hosted checkout URL, bukan payload QRIS langsung.
6. Poll `GET /api/v1/orders/<order_uuid>/` untuk status paid. Kiosk tidak mengubah status pembayaran sendiri.

Pada setiap POST sertakan `Authorization` dan `Content-Type: application/json`. Organization, tenant, device dan harga ditentukan server. Device hanya dapat melihat order/invoice miliknya sendiri.

Simpan key dan body yang sama untuk retry. Key dengan body berbeda menghasilkan 409. Jika 503 menyatakan `payment_reconciliation_required`, cek status atau hubungi support; jangan membuat pembayaran kedua saat hasil gateway belum jelas. Token/proof DPoP, bila digunakan, harus baru untuk setiap retry. Jangan menyimpan token dalam QR.

Migrasi tambahan: SSO `iam.0013`; Commerce `common.0002`, `billing.0004`, `billing.0005`. Operator menyiapkan credential introspeksi SSO khusus backend Commerce. Produk/plan/price dipilih dinamis dari katalog Commerce yang aktif untuk pembelian one-time; tidak perlu daftar kode produk di env. SKU baru atau perubahan kode tidak memerlukan deploy atau pairing ulang. `PHOTOBOOTH_PRODUCT_CODES` sudah tidak digunakan pada versi Commerce yang dinamis. Migrasi tidak membuat harga/produk atau memberi akses otomatis.
