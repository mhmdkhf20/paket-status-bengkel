# Memasang penyimpanan server (sekali saja)

Isi paket ini:

- `public/index.html` : aplikasinya (halaman yang dibuka pelanggan dan pemilik)
- `netlify/functions/api.mjs` : server kecil yang menyimpan data terenkripsi
- `netlify.toml` dan `package.json` : pengaturan untuk Netlify

Server ini hanya berfungsi bila Netlify **membangun** folder ini. Menurut dokumentasi Netlify,
functions dipasang lewat **Git** atau **Netlify CLI**. Mengunggah satu file `index.html`
(drag-and-drop) tidak akan memasang server. Jika begitu, aplikasi tetap jalan seperti versi
sebelumnya (data di peramban, tanpa server), jadi salah pasang tidak merusak apa pun.

## Cara A: lewat GitHub (disarankan)

1. Buat repository baru di GitHub, lalu unggah **seluruh isi** folder ini
   (`public`, `netlify`, `netlify.toml`, `package.json`).
2. Di Netlify: Add new site > Import an existing project > pilih repository tadi.
   Kolom build command dan publish directory biarkan kosong; Netlify membacanya dari `netlify.toml`.
3. Klik Deploy. Setiap kali Anda mengubah berkas di GitHub, Netlify memasang ulang otomatis.

Untuk memakai situs yang sudah ada (`status-bengkel.netlify.app`), hubungkan repository itu
ke situs tersebut lewat Site configuration > Build & deploy > Link repository.

## Cara B: lewat Netlify CLI

Di komputer yang sudah ada Node.js, buka terminal di folder ini:

```
npm install
npm install -g netlify-cli
netlify login
netlify link        # pilih situs yang sudah ada, atau: netlify init
netlify deploy --prod
```

## Memeriksa apakah server sudah terpasang

Buka `https://alamat-situs-anda/api/state`. Hasil yang benar berupa teks JSON yang memuat `"srv":1`.
Jika yang muncul halaman "Page not found", server belum terpasang (lihat langkah di atas).

## Sebelum pindah: amankan data lama

Jika sekarang Anda sudah memakai situs ini dan punya pesanan:

1. Di versi lama, tekan **Unduh file terbaru** (spanduk kuning) dan simpan berkasnya. Ini cadangan.
2. Pasang paket ini, lalu buka situs dari **peramban yang sama** seperti sebelumnya.
3. Di halaman awal akan muncul kotak **Data lama ditemukan**. Isi kata sandi lama Anda, tekan
   **Pindahkan ke server**. Akun, pesanan, dan foto pindah, dan tautan pelanggan lama tetap berfungsi.
4. Bila kotak itu tidak muncul (misalnya peramban berbeda), pilih **Buat akun baru**, buka
   **Sudah punya cadangan atau file lama? Pulihkan di sini**, lalu pilih berkas dari langkah 1.

## Cara kerja dan batasnya

- Isi pesanan, nama pelanggan, dan foto dienkripsi di peramban sebelum dikirim. Server hanya
  menyimpan data terenkripsi dan tidak pernah menerima kata sandi Anda.
- Kata sandi salah 5 kali dari satu alamat membuat login dikunci 15 menit.
- Foto disimpan satu per satu, jadi batas 16 MB lama tidak berlaku. Batas sebenarnya mengikuti
  kuota Netlify Blobs di paket Netlify Anda; angkanya belum saya periksa.
- Pengaturan > **Unduh cadangan** menyimpan semua pesanan dan foto ke satu berkas (tetap terenkripsi).
  Lakukan secara berkala dan simpan di tempat aman. Kata sandi yang lupa tidak bisa dipulihkan.
- `package.json` memakai `@netlify/blobs` versi terbaru. Jika suatu saat build gagal setelah
  pembaruan paket itu, kunci ke versi yang sebelumnya berhasil.
