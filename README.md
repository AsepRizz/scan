# 🔍 AsepRecon (scan)

Project ini adalah tool sederhana untuk keperluan reconnaissance dan scanning target secara otomatis. Cocok digunakan oleh pemula yang sedang belajar Cyber Security, terutama yang menggunakan Termux, Kali Linux, atau WSL.

---

## 📁 Isi Tool

| File        | Platform         | Deskripsi                            |
|-------------|------------------|--------------------------------------|
| `aseprec.py`| Termux / Android | Versi yang disesuaikan untuk Termux  |
| `up.py`     | Kali Linux / WSL | Versi Linux (fitur lebih lengkap)    |

---

## ⚙️ Cara Install

### 🔸 Termux / Android
```bash
pkg install python git -y
git clone https://github.com/AsepRizz/scan
cd scan
pip install -r requirements.txt
python aseprec.py
🔸 Kali Linux / WSL
bash
Copy
Edit
sudo apt update && sudo apt install python3 git -y
git clone https://github.com/AsepRizz/scan
cd scan
pip3 install -r requirements.txt
python3 up.py
🛠️ Fitur Utama
Subdomain enumeration

Port scanning

HTTP header grabber

Web tech detection (whatweb)

SQLi scanner (jika terintegrasi)

Informasi akhir dalam bentuk ringkasan

📌 Catatan
Gunakan di lingkungan yang legal dan etis

Script ini terus dikembangkan dan disempurnakan

Feedback dan kontribusi sangat diterima!

⚠️ Disclaimer
Tool ini dibuat hanya untuk edukasi. Penulis tidak bertanggung jawab atas penyalahgunaan di luar tujuan pembelajaran dan pengujian yang sah.

