# 🔍 AsepRecon (scan and exploit)

ini adalah tool untuk scanning dan eksploit target secara otomatis. Cocok digunakan oleh pemula yang sedang belajar Cyber Security, terutama yang menggunakan Termux, Kali Linux, atau WSL.
untuk cara penggunaan lengkap seperti dibawah ini.
untuk eksploit otomatis pakai run.py ada fitur fitur lengkap seperti sqlmap, wpscan, dll. saran pengguna laptop harap memakai run.py karna dibanding up.py run.py lebih powerfull. sedangkan khusus termux hanya tersedia aseprec.py saja dan untuk setiap fitur akan terinstall otomatis ketika mau dipakai, tinggal menunggu beberapa menit tergantung kecepatan koneksi internet di hp

---

## 📁 Isi Tool

| File        | Platform         | Deskripsi                                |
|-------------|------------------|------------------------------------------|
| `aseprec.py`| Termux / Android | Versi yang disesuaikan untuk Termux      |
| `up.py`     | Kali Linux / WSL | Versi Linux (fitur lebih lengkap)        |
| `run.py`    | Kali Linux virtualbox | (fitur lebih lengkap dan powerfull) |

---

## ⚙️ Cara Install

### 🔸 Termux / Android
```bash
pkg install python git -y
apt install nmap
git clone https://github.com/AsepRizz/scan
cd scan
pip install dnspython
pip install google
pip install -r requirements.txt
python aseprec.py

```

---

## ⚙️ Cara Install
### 🔸 Kali Linux / WSL
```bash
sudo apt update && sudo apt install python3 git -y
git clone https://github.com/AsepRizz/scan
cd scan
pip3 install -r requirements.txt
python3 up.py 

```

---

---

## ⚙️ Cara Install
### 🔸 Kali Linux Virtualbox
```bash
sudo apt update && sudo apt install python3 git -y
git clone https://github.com/AsepRizz/scan
cd scan
pip3 install -r requirements.txt
sudo python3 run.py 

```

---

####🛠️ Fitur Utama

Subdomain enumeration

Port scanning

HTTP header grabber

Web tech detection (whatweb)

SQLi scanner (jika terintegrasi)

Informasi akhir dalam bentuk ringkasan

---

####🛠️ Cara Penggunaan
1. Setelah instalasi selesai pilih salah satu fitur

2. setelah memilih salah satu fitur masukan target dengan domain contoh: asep.com atau asep.ac.id atau asep.go.id jangan menyertakan url lengkap seperti https://asep.com

3. setelah memasukan domain tunggu beberapa menit sampai hasil scan keluar secara otomatis

4. setelah hasil scan keluar, klik enter untuk lanjut ke pilihan fitur lain

---

