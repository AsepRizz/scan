import os
import time
import requests
import socket
import dns.resolver
import shutil
import re
import subprocess
import sys
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn
from rich.status import Status

console = Console()

def banner():
    ascii_art = """
     █████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████║███████╗█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ██╔══██║╚════██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║  ██║███████║███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    console.print(Panel.fit(ascii_art, title="ASEPSCAN", style="cyan"))
    console.print(f"[bold yellow]Versi 5.0 | Ultimate Recon Tool[/bold yellow]\n")
    console.print(f"[bold green]Fitur Baru:[/bold green] DNS Recon + Email Harvester + Cloud Detector + CMS Detector + Port Scanner\n")

def install_tool(tool_name, install_cmd):
    """Install tool jika belum terpasang"""
    console.print(f"[yellow]⏳ Menginstall {tool_name}...[/yellow]")
    try:
        result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        if result.returncode == 0:
            console.print(f"[green]✓ {tool_name} berhasil diinstall[/green]")
            return True
        else:
            console.print(f"[red]✗ Gagal install {tool_name}: {result.stderr}[/red]")
            return False
    except Exception as e:
        console.print(f"[red]✗ Error install {tool_name}: {str(e)}[/red]")
        return False

def check_tool(tool_name, install_cmd=None):
    """Cek apakah tool sudah terinstall, jika belum install"""
    if shutil.which(tool_name) is not None:
        return True
    
    if install_cmd:
        return install_tool(tool_name, install_cmd)
    
    return False

def detect_protocol(target):
    try:
        response = requests.head(f"https://{target}", timeout=5, verify=False, allow_redirects=True)
        if response.status_code < 400:
            return "https"
    except:
        pass
    return "http"

def whois_lookup(target):
    if not check_tool("whois", "pkg install whois -y"):
        return
    
    console.print("[yellow]⏳ Ngecek WHOIS...[/yellow]")
    try:
        result = subprocess.run(["whois", target], capture_output=True, text=True, timeout=300)
        output = result.stdout if result.returncode == 0 else result.stderr
        console.print(Panel.fit(output, title="Hasil WHOIS", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def whatweb_scan(target):
    if not check_tool("whatweb", "pkg install whatweb -y"):
        return
    
    console.print("[yellow]⏳ Ngecek WhatWeb...[/yellow]")
    try:
        result = subprocess.run(["whatweb", target], capture_output=True, text=True, timeout=300)
        output = result.stdout if result.returncode == 0 else result.stderr
        console.print(Panel.fit(output, title="Hasil WhatWeb", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def nmap_scan(target, mode="cepat"):
    if not check_tool("nmap", "pkg install nmap -y"):
        return
    
    console.print(f"[yellow]⏳ Ngecek Nmap ({mode})...[/yellow]")
    
    scan_args = ["-sV", "-T4"] if mode == "lengkap" else ["-T4", "--top-ports", "100"]
    
    try:
        with Status("[bold green]Scanning...", spinner="dots") as status:
            result = subprocess.run(["nmap"] + scan_args + [target], capture_output=True, text=True, timeout=1800)
        output = result.stdout if result.returncode == 0 else result.stderr
        console.print(Panel.fit(output, title="Hasil Nmap", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def subdomain_checker(target):
    if not check_tool("assetfinder", "go install github.com/tomnomnom/assetfinder@latest"):
        return
    
    console.print("[yellow]⏳ Nyari subdomain...[/yellow]")
    try:
        result = subprocess.run(["assetfinder", "--subs-only", target], capture_output=True, text=True, timeout=300)
        subdomains = result.stdout.splitlines()
        output = "\n".join(subdomains) if subdomains else "Gak nemu subdomain."
        console.print(Panel.fit(output, title="Subdomain", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def gobuster_scan(target):
    if not check_tool("gobuster", "go install github.com/OJ/gobuster/v3@latest"):
        return

    protocol = detect_protocol(target)
    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)
    
    wordlist_path = os.path.join(wordlist_dir, "common.txt")
    if not os.path.exists(wordlist_path):
        console.print("[blue]Downloading wordlist...[/blue]")
        subprocess.run([
            "wget", "-O", wordlist_path, 
            "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
        ], check=True)

    console.print("[yellow]⏳ Jalanin Gobuster...[/yellow]")
    command = [
        "gobuster", "dir",
        "-u", f"{protocol}://{target}",
        "-w", wordlist_path,
        "-t", "50",
        "-b", "404,403"
    ]
    
    try:
        with Status("[bold green]Scanning...", spinner="dots") as status:
            result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
        
        output = result.stdout
        if not output.strip():
            output = "Gak nemu direktori menarik"
        
        console.print(Panel.fit(output, title="Hasil Gobuster", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def cek_header(target):
    console.print("[yellow]⏳ Ngecek header HTTP...[/yellow]")
    protocol = detect_protocol(target)
    
    try:
        response = requests.head(f"{protocol}://{target}", timeout=5, allow_redirects=True)
        header_text = f"URL: {protocol}://{target}\nStatus: {response.status_code}\n"
        for key, value in response.headers.items():
            header_text += f"{key}: {value}\n"
        
        console.print(Panel.fit(header_text, title="Header HTTP", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def waf_detection(target):
    if not check_tool("wafw00f", "pip install wafw00f"):
        return
    
    console.print("[yellow]⏳ Ngecek WAF...[/yellow]")
    try:
        result = subprocess.run(["wafw00f", target], capture_output=True, text=True, timeout=300)
        output = result.stdout if result.returncode == 0 else result.stderr
        console.print(Panel.fit(output.strip(), title="Deteksi WAF", style="green"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def userrecon_scan(username):
    console.print(f"[yellow]⏳ Mencari akun [bold]{username}[/bold] di berbagai platform...[/yellow]")
    
    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
    }
    
    results = []
    
    with Progress(SpinnerColumn(), transient=True) as progress:
        task = progress.add_task("[cyan]Cek platform...", total=len(platforms))
        
        for platform, url in platforms.items():
            progress.update(task, advance=1, description=f"[cyan]Cek {platform}...")
            
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                status = response.status_code
                
                if status == 200:
                    results.append(f"[green]✓ [bold]{platform}[/bold]: Ditemukan ({url})")
                elif status == 404:
                    results.append(f"[red]✗ [bold]{platform}[/bold]: Tidak ditemukan")
                else:
                    results.append(f"[yellow]? [bold]{platform}[/bold]: Status {status} ({url})")
                
            except:
                results.append(f"[yellow]? [bold]{platform}[/bold]: Gagal koneksi")
    
    console.print(Panel.fit("\n".join(results), title=f"Hasil UserRecon: {username}", style="cyan"))

def dns_recon(target):
    console.print(f"[yellow]⏳ Melakukan DNS Recon untuk [bold]{target}[/bold]...[/yellow]")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    results = []
    
    try:
        for rtype in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.nameservers = ['8.8.8.8', '1.1.1.1']
                answers = resolver.resolve(target, rtype)
                results.append(f"[bold magenta]╔═ {rtype} Records:[/bold magenta]")
                for rdata in answers:
                    results.append(f"[bold cyan]║[/bold cyan] {rdata.to_text()}")
            except dns.resolver.NoAnswer:
                pass
            except Exception as e:
                results.append(f"[bold yellow]║ Error: {str(e)}[/bold yellow]")
    except Exception as e:
        results.append(f"[bold red]║ Error: {str(e)}[/bold red]")
    
    if results:
        console.print(Panel.fit("\n".join(results), title="Hasil DNS Recon", style="green"))
    else:
        console.print(Panel.fit("Tidak ada record DNS yang ditemukan", title="Hasil DNS Recon", style="yellow"))

def email_harvester(target):
    console.print(f"[yellow]⏳ Mencari email terkait [bold]{target}[/bold]...[/yellow]")
    
    sources = [
        "https://www.google.com/search?q=%40{}",
        "https://www.bing.com/search?q=%40{}",
        "https://search.yahoo.com/search?p=%40{}"
    ]
    
    emails = set()
    
    with Progress(SpinnerColumn(), transient=True) as progress:
        task = progress.add_task("[cyan]Mencari email...", total=len(sources))
        
        for url_template in sources:
            progress.update(task, advance=1)
            try:
                url = url_template.format(target)
                headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"}
                response = requests.get(url, headers=headers, timeout=10)
                found_emails = re.findall(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', response.text)
                
                for email in found_emails:
                    if target in email.split('@')[1]:
                        emails.add(email)
            except:
                continue
    
    if emails:
        email_list = "\n".join([f"[green]• {email}[/green]" for email in emails])
        console.print(Panel.fit(email_list, title="Email Ditemukan", style="green"))
    else:
        console.print(Panel.fit("Tidak ditemukan email terkait domain ini", title="Email Harvester", style="yellow"))

def cloud_detector(target):
    console.print(f"[yellow]⏳ Mendeteksi layanan cloud untuk [bold]{target}[/bold]...[/yellow]")
    
    cloud_indicators = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS": ["aws", "amazon web services", "x-amz-cf-id"],
        "Google Cloud": ["google cloud", "gcp", "googleusercontent"],
        "Azure": ["azure", "microsoft", "x-azure-ref"],
    }
    
    protocol = detect_protocol(target)
    results = []
    
    try:
        response = requests.get(f"{protocol}://{target}", timeout=10)
        headers = response.headers
        
        for cloud, indicators in cloud_indicators.items():
            detected = False
            for indicator in indicators:
                if indicator in response.text.lower() or any(indicator in value.lower() for value in headers.values()):
                    results.append(f"[green]✓ {cloud}[/green]")
                    detected = True
                    break
            if not detected:
                results.append(f"[red]✗ {cloud}[/red]")
    except Exception as e:
        results.append(f"[red]Error: {str(e)}[/red]")
    
    if results:
        console.print(Panel.fit("\n".join(results), title="Hasil Cloud Detector", style="cyan"))
    else:
        console.print(Panel.fit("Tidak terdeteksi layanan cloud", title="Cloud Detector", style="yellow"))

def cms_detector(target):
    console.print(f"[yellow]⏳ Mendeteksi CMS untuk [bold]{target}[/bold]...[/yellow]")
    
    cms_indicators = {
        "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
        "Joomla": ["joomla", "media/system/js", "index.php?option=com_"],
        "Drupal": ["drupal", "sites/all/", "core/assets", "Drupal.settings"],
        "Magento": ["magento", "/js/mage/", "skin/frontend/", "Magento_"],
    }
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    detected_cms = None
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        content = response.text.lower()
        
        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator.lower() in content:
                    detected_cms = cms
                    break
            if detected_cms:
                break
        
        if detected_cms:
            result = f"[green]✓ {detected_cms}[/green]"
        else:
            result = "[red]✗ Tidak terdeteksi CMS populer[/red]"
        
        console.print(Panel.fit(result, title="Hasil CMS Detector", style="green" if detected_cms else "yellow"))
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def port_scanner(target):
    console.print(f"[yellow]⏳ Scanning port untuk [bold]{target}[/bold]...[/yellow]")
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                    993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    open_ports = []
    
    with Progress(SpinnerColumn(), transient=True) as progress:
        task = progress.add_task("[cyan]Scanning port...", total=len(common_ports))
        
        for port in common_ports:
            progress.update(task, advance=1, description=f"[cyan]Scan port {port}...")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except:
                pass
    
    if open_ports:
        ports_list = "\n".join([f"[green]• Port {port} terbuka[/green]" for port in open_ports])
        console.print(Panel.fit(ports_list, title="Port Terbuka", style="green"))
    else:
        console.print(Panel.fit("Tidak ada port terbuka yang ditemukan", title="Port Scanner", style="yellow"))

def menu():
    banner()
    
    while True:
        table = Table(title="Menu Tools Recon", header_style="bold magenta", show_lines=True)
        table.add_column("No", justify="center", style="cyan")
        table.add_column("Fitur", style="yellow")
        table.add_column("Deskripsi", style="green")
        table.add_row("1", "WHOIS Lookup", "Cek informasi domain")
        table.add_row("2", "WhatWeb", "Deteksi teknologi website")
        table.add_row("3", "Nmap", "Scan port & service")
        table.add_row("4", "Subdomain", "Cari subdomain tersembunyi")
        table.add_row("5", "Gobuster", "Bruteforce direktori/file")
        table.add_row("6", "Cek Header", "Analisis header HTTP")
        table.add_row("7", "Deteksi WAF", "Identifikasi Web Application Firewall")
        table.add_row("8", "UserRecon", "Cek username di sosmed & platform")
        table.add_row("9", "DNS Recon", "Pengumpulan informasi DNS")
        table.add_row("10", "Email Harvester", "Cari email terkait domain")
        table.add_row("11", "Cloud Detector", "Deteksi layanan cloud")
        table.add_row("12", "CMS Detector", "Identifikasi Content Management System")
        table.add_row("13", "Port Scanner", "Scan port umum")
        table.add_row("0", "Keluar", "Exit program")
        console.print(table)

        choice = console.input("[bold cyan]Pilih nomor menu: [/]").strip()

        if choice == "1":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            whois_lookup(target)
        elif choice == "2":
            target = console.input("[bold green]Masukkan URL target: [/]").strip()
            whatweb_scan(target)
        elif choice == "3":
            target = console.input("[bold green]Masukkan IP/domain target: [/]").strip()
            mode = console.input("[bold green]Pilih mode (cepat/lengkap): [/]").strip().lower()
            nmap_scan(target, mode)
        elif choice == "4":
            target = console.input("[bold green]Masukkan domain utama: [/]").strip()
            subdomain_checker(target)
        elif choice == "5":
            target = console.input("[bold green]Masukkan URL target: [/]").strip()
            gobuster_scan(target)
        elif choice == "6":
            target = console.input("[bold green]Masukkan URL target: [/]").strip()
            cek_header(target)
        elif choice == "7":
            target = console.input("[bold green]Masukkan URL target: [/]").strip()
            waf_detection(target)
        elif choice == "8":
            username = console.input("[bold green]Masukkan username: [/]").strip()
            userrecon_scan(username)
        elif choice == "9":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            dns_recon(target)
        elif choice == "10":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            email_harvester(target)
        elif choice == "11":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            cloud_detector(target)
        elif choice == "12":
            target = console.input("[bold green]Masukkan URL website: [/]").strip()
            cms_detector(target)
        elif choice == "13":
            target = console.input("[bold green]Masukkan IP/domain: [/]").strip()
            port_scanner(target)
        elif choice == "0":
            console.print(Panel.fit("[bold red]Keluar dari program...", title="Sampai Jumpa", style="red"))
            break
        else:
            console.print(Panel.fit("[bold red]Pilihan gak valid! Coba lagi.", style="red"))
        
        console.input("\n[bold yellow]Tekan Enter untuk lanjut...[/]")

if __name__ == "__main__":
    try:
        # Install dependency Python
        required_modules = ["rich", "requests", "dnspython"]
        for module in required_modules:
            try:
                __import__(module)
            except ImportError:
                console.print(f"[yellow]⏳ Menginstall {module}...[/yellow]")
                subprocess.run([sys.executable, "-m", "pip", "install", module], check=True)
        
        # Setup environment
        os.makedirs(os.path.expanduser("~/.wordlists"), exist_ok=True)
        
        # Setup Go path jika belum
        go_path = os.path.expanduser("~/go/bin")
        if go_path not in os.environ["PATH"]:
            os.environ["PATH"] += os.pathsep + go_path
        
        menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]Program dihentikan paksa![/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
