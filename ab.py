import os
import sys
import time
import requests
import socket
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from googlesearch import search
from rich import box

console = Console()

# Konfigurasi Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8127930072:AAHwbMBROwSrXSRFTPL4RgdNunzrKqgisHU")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5731047913")

def send_to_telegram(message):
    """Mengirim hasil scan ke Telegram"""
    url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
    payload = {
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML"
    }
    try:
        response = requests.post(url, data=payload, timeout=10)
        return response.status_code == 200
    except Exception as e:
        console.print(f"[red]Error sending to Telegram: {str(e)}[/red]")
        return False

def banner():
    ascii_art = """
    █████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████║███████╗█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ██╔══██║╚════██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║  ██║███████║███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    console.print(Panel.fit(ascii_art, title="ASEPSCAN PRO", style="cyan", box=box.DOUBLE))
    console.print(f"[bold yellow]Termux Edition v6.0 | Ultimate Recon Tool[/bold yellow]\n")
    console.print(f"[bold green]Fitur:[/bold green] DNS Recon + Email Harvester + Cloud Detector + CMS Detector + Telegram Integration\n")

def check_tool(tool_name, install_instruction):
    """Memeriksa apakah tool terinstall di sistem"""
    if os.system(f"which {tool_name} > /dev/null 2>&1") != 0:
        console.print(Panel.fit(
            f"{tool_name} tidak terinstall.\nInstall dengan: {install_instruction}",
            title="[red]Error[/red]", style="red"))
        return False
    return True

def detect_protocol(target):
    """Mendeteksi protocol website (HTTP/HTTPS)"""
    try:
        response = requests.head(f"https://{target}", timeout=5, verify=False)
        if response.status_code < 400:
            return "https"
    except:
        pass
    return "http"

def whois_lookup(target):
    """Melakukan WHOIS lookup"""
    if not check_tool("whois", "pkg install whois"):
        return
    
    console.print("[yellow]🔍 Melakukan WHOIS lookup...[/yellow]")
    result = os.popen(f"whois {target}").read()
    
    # Kirim ke Telegram
    telegram_msg = f"🔍 WHOIS Lookup untuk {target}\n\n{result[:3000]}..."
    send_to_telegram(telegram_msg)
    
    console.print(Panel.fit(result, title="[green]Hasil WHOIS[/green]", style="green"))

def dns_recon(target):
    """Melakukan DNS reconnaissance"""
    console.print(f"[yellow]🔍 Melakukan DNS recon untuk {target}...[/yellow]")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    results = []
    
    try:
        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(target, rtype)
                results.append(f"[bold]{rtype} Records:[/bold]")
                for rdata in answers:
                    results.append(f"  {rdata.to_text()}")
                results.append("")
            except:
                continue
                
        result_text = "\n".join(results)
        # Kirim ke Telegram
        telegram_msg = f"🔍 DNS Recon untuk {target}\n\n{result_text}"
        send_to_telegram(telegram_msg)
        
        console.print(Panel.fit(result_text, title="[green]Hasil DNS Recon[/green]", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def port_scanner(target):
    """Melakukan port scanning"""
    console.print(f"[yellow]🔍 Scanning port untuk {target}...[/yellow]")
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                   443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    open_ports = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Scanning...", total=len(common_ports))
        
        for port in common_ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
            progress.update(task, advance=1)
    
    if open_ports:
        result_text = "\n".join([f"Port {port} : [green]TERBUKA[/green]" for port in open_ports])
        # Kirim ke Telegram
        telegram_msg = f"🔍 Port Scan untuk {target}\n\nPort terbuka:\n{result_text}"
        send_to_telegram(telegram_msg)
        
        console.print(Panel.fit(result_text, title="[green]Port Terbuka[/green]", style="green"))
    else:
        console.print(Panel.fit("Tidak ada port terbuka", title="[yellow]Hasil Port Scan[/yellow]", style="yellow"))

def subdomain_scanner(target):
    """Memindai subdomain"""
    console.print(f"[yellow]🔍 Mencari subdomain untuk {target}...[/yellow]")
    
    subdomains = set()
    wordlist_path = "/sdcard/wordlists/subdomains.txt"
    
    if not os.path.exists(wordlist_path):
        console.print("[red]Wordlist tidak ditemukan![/red]")
        console.print(f"Letakkan wordlist di: {wordlist_path}")
        return
    
    try:
        with open(wordlist_path, "r") as f:
            subdomain_list = [line.strip() for line in f if line.strip()]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Checking subdomains...", total=len(subdomain_list))
            
            for subdomain in subdomain_list:
                test_domain = f"{subdomain}.{target}"
                try:
                    socket.gethostbyname(test_domain)
                    subdomains.add(test_domain)
                except:
                    pass
                progress.update(task, advance=1)
        
        if subdomains:
            result_text = "\n".join(subdomains)
            # Kirim ke Telegram
            telegram_msg = f"🔍 Subdomain ditemukan untuk {target}\n\n{result_text}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[green]Subdomain Ditemukan[/green]", style="green"))
        else:
            console.print(Panel.fit("Tidak ada subdomain ditemukan", title="[yellow]Hasil Subdomain[/yellow]", style="yellow"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def main_menu():
    """Menu utama"""
    banner()
    
    while True:
        table = Table(title="🛡️ ASEPSCAN PRO - MAIN MENU", box=box.ROUNDED)
        table.add_column("No", style="cyan", justify="center")
        table.add_column("Fitur", style="magenta")
        table.add_column("Deskripsi", style="green")
        
        table.add_row("1", "WHOIS Lookup", "Informasi registrasi domain")
        table.add_row("2", "DNS Recon", "Informasi DNS records")
        table.add_row("3", "Port Scanner", "Scan port terbuka")
        table.add_row("4", "Subdomain Scanner", "Cari subdomain")
        table.add_row("5", "Exit", "Keluar dari program")
        
        console.print(table)
        
        choice = console.input("[bold cyan]Pilih opsi (1-5): [/]").strip()
        
        if choice == "1":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            whois_lookup(target)
        elif choice == "2":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            dns_recon(target)
        elif choice == "3":
            target = console.input("[bold green]Masukkan IP/domain: [/]").strip()
            port_scanner(target)
        elif choice == "4":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            subdomain_scanner(target)
        elif choice == "5":
            console.print("[bold red]Keluar dari program...[/bold red]")
            sys.exit(0)
        else:
            console.print("[red]Pilihan tidak valid![/red]")
        
        console.input("\n[bold yellow]Tekan Enter untuk melanjutkan...[/]")
        console.clear()

if __name__ == "__main__":
    try:
        # Install dependencies jika belum ada
        dependencies = ["rich", "requests", "dnspython", "google"]
        for package in dependencies:
            if os.system(f"python -c 'import {package}' >/dev/null 2>&1") != 0:
                console.print(f"[yellow]Menginstall {package}...[/yellow]")
                os.system(f"pip install -q {package}")
        
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]Program diinterupsi![/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
