# JACKCSALLAS Anti-Scam

Aplikasi Android lokal untuk pencatatan insiden penipuan dan pemeriksaan awal tautan.

## Fitur
- Pemeriksaan indikator URL sederhana (HTTPS, alamat IP, Punycode, subdomain, URL shortener, dan kata umpan).
- Pencatatan kronologi insiden, kontak/akun yang dilaporkan, platform, dan waktu.
- Penyimpanan lokal menggunakan SharedPreferences.
- Berbagi ringkasan laporan melalui menu berbagi Android.
- Menghapus data laporan lokal.

## Build APK
1. Ekstrak ZIP.
2. Buka folder `JACKCSALLAS_AntiScam` di Android Studio.
3. Gunakan JDK 17 dan Android SDK Platform 35.
4. Tunggu Gradle Sync.
5. Pilih **Build > Build Bundle(s) / APK(s) > Build APK(s)**.
6. APK debug ada di `app/build/outputs/apk/debug/app-debug.apk`.

Pemeriksa tautan menggunakan heuristik lokal dan tidak menjamin sebuah URL aman atau berbahaya. Aplikasi tidak mengakses pesan/kontak, tidak mengunci perangkat pihak lain, dan tidak mengirim data ke server.
