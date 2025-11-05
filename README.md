# 🔍 AsepRecon (scan and exploit)

ini adalah tool untuk scanning dan eksploit target secara otomatis. Cocok digunakan oleh pemula yang sedang belajar Cyber Security, terutama yang menggunakan Termux, Kali Linux, atau VirutalBox.
untuk cara penggunaan dan panduan lengkap seperti dibawah ini.


---

## 📁 Isi Tool

| File        | Platform         | Deskripsi                                |
|-------------|------------------|------------------------------------------|
| `aseprec.py`| Termux / Android | Versi yang disesuaikan untuk Termux      |
| `run.py`    | Kali Linux / linux virtualbox | (fitur lebih lengkap dan powerfull) |

---

## ⚙️ Cara Install

### 🔸 Termux / Android
```bash
pkg install python git -y
pkg install nmap -y
pkg install ruby
gem install lolcat 
git clone https://github.com/AsepRizz/scan
cd scan
pip install requests bs4 rich mechanize ruby whatweb
pip install dnspython
pip install googlesearch
pip install -r requirements.txt
python aseprec.py

```

---

---

## ⚙️ Cara Install
### 🔸 Kali Linux / Linux Virtualbox
```bash
sudo apt update && sudo apt install python3 git -y
git clone https://github.com/AsepRizz/scan
cd scan
pip3 install -r requirements.txt
sudo python3 run.py 

```

---

####🛠️ Fitur Utama

1. Reconnaissance Tools
2. Scanning & Enumeration
3. Exploitation Tools
4. Post-Exploitation
5. Network & Additional Tools
6. Exit

Informasi akhir dalam bentuk ringkasan

---

####🛠️ Cara Penggunaan
1. Setelah instalasi selesai pilih salah satu fitur

2. setelah memilih salah satu fitur masukan target dengan domain contoh: asep.com atau asep.ac.id atau asep.go.id jangan menyertakan url lengkap seperti https://asep.com

3. setelah memasukan domain tunggu beberapa menit sampai hasil scan keluar secara otomatis

4. setelah hasil scan keluar, klik enter untuk lanjut ke pilihan fitur lain

---

