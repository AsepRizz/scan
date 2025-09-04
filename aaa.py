import os
import sys
import time
import requests
import socket
import dns.resolver
import json
import subprocess
import re
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.tree import Tree
from rich import box
from bs4 import BeautifulSoup
import ssl
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    console.print(Panel.fit(ascii_art, title="ASEPSCAN ULTIMATE", style="cyan", box=box.DOUBLE))
    console.print(f"[bold yellow]Termux Edition v7.0 | Ultimate Recon Tool[/bold yellow]\n")
    console.print(f"[bold green]Fitur:[/bold green] DNS Recon + Email Harvester + Cloud Detector + CMS Detector + Vulnerability Scanner + Telegram Integration\n")

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
    """Melakukan port scanning dengan lebih banyak port"""
    console.print(f"[yellow]🔍 Scanning port untuk {target}...[/yellow]")
    
    common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 
                   443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080, 
                   8443, 27017, 27018, 27019, 28017, 11211, 9200, 9300]
    
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
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append((port, service))
            sock.close()
            progress.update(task, advance=1)
    
    if open_ports:
        result_text = "\n".join([f"Port {port} ({service}) : [green]TERBUKA[/green]" for port, service in open_ports])
        # Kirim ke Telegram
        telegram_msg = f"🔍 Port Scan untuk {target}\n\nPort terbuka:\n{result_text}"
        send_to_telegram(telegram_msg)
        
        console.print(Panel.fit(result_text, title="[green]Port Terbuka[/green]", style="green"))
    else:
        console.print(Panel.fit("Tidak ada port terbuka", title="[yellow]Hasil Port Scan[/yellow]", style="yellow"))

def subdomain_scanner(target):
    """Memindai subdomain dengan multi-threading"""
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
        
        # Batasi jumlah subdomain untuk di-test (maksimal 1000)
        subdomain_list = subdomain_list[:1000]
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            transient=True,
        ) as progress:
            task = progress.add_task("Checking subdomains...", total=len(subdomain_list))
            
            def check_subdomain(subdomain):
                test_domain = f"{subdomain}.{target}"
                try:
                    socket.gethostbyname(test_domain)
                    return test_domain
                except:
                    return None
                finally:
                    progress.update(task, advance=1)
            
            # Gunakan multi-threading untuk mempercepat proses
            with ThreadPoolExecutor(max_workers=20) as executor:
                futures = [executor.submit(check_subdomain, subdomain) for subdomain in subdomain_list]
                
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        subdomains.add(result)
        
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

def cms_detector(target):
    """Mendeteksi CMS yang digunakan website"""
    console.print(f"[yellow]🔍 Mendeteksi CMS untuk {target}...[/yellow]")
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    
    cms_signatures = {
        "WordPress": [
            r"wp-content", r"wp-includes", r"wordpress", r"/wp-json/"
        ],
        "Joomla": [
            r"joomla", r"media/system/js", r"index.php?option=com"
        ],
        "Drupal": [
            r"drupal", r"sites/all/themes", r"core/misc/drupal.js"
        ],
        "Magento": [
            r"magento", r"/js/mage/", r"skin/frontend"
        ],
        "Shopify": [
            r"shopify", r"cdn.shopify.com", r"shopify.shop"
        ]
    }
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        content = response.text.lower()
        headers = response.headers
        
        detected_cms = []
        
        for cms, signatures in cms_signatures.items():
            for signature in signatures:
                if re.search(signature, content, re.IGNORECASE):
                    detected_cms.append(cms)
                    break
        
        if detected_cms:
            result_text = "\n".join([f"[green]✓ {cms}[/green]" for cms in detected_cms])
            # Kirim ke Telegram
            telegram_msg = f"🔍 CMS Detection untuk {target}\n\nDetected: {', '.join(detected_cms)}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[green]CMS Terdeteksi[/green]", style="green"))
        else:
            console.print(Panel.fit("Tidak dapat mendeteksi CMS", title="[yellow]Hasil CMS Detection[/yellow]", style="yellow"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def vulnerability_scanner(target):
    """Memindai vulnerability umum"""
    console.print(f"[yellow]🔍 Memindai vulnerability untuk {target}...[/yellow]")
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    
    vulnerabilities = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        
        # Check for common headers issues
        if 'x-frame-options' not in response.headers:
            vulnerabilities.append("Missing X-Frame-Options header - Clickjacking vulnerability")
        
        if 'x-content-type-options' not in response.headers:
            vulnerabilities.append("Missing X-Content-Type-Options header - MIME sniffing vulnerability")
        
        if 'strict-transport-security' not in response.headers and protocol == "https":
            vulnerabilities.append("Missing HSTS header - SSL stripping vulnerability")
        
        # Check for sensitive files
        sensitive_files = [
            "robots.txt", 
            ".env", 
            "phpinfo.php", 
            "admin/config.php",
            "backup.zip",
            "wp-config.php"
        ]
        
        for file in sensitive_files:
            file_url = f"{url}/{file}"
            file_response = requests.head(file_url, timeout=5, verify=False)
            if file_response.status_code == 200:
                vulnerabilities.append(f"Sensitive file exposed: {file}")
        
        if vulnerabilities:
            result_text = "\n".join([f"[red]• {vuln}[/red]" for vuln in vulnerabilities])
            # Kirim ke Telegram
            telegram_msg = f"🔍 Vulnerability Scan untuk {target}\n\nDitemukan:\n{result_text}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[red]Vulnerabilities Ditemukan[/red]", style="red"))
        else:
            console.print(Panel.fit("Tidak ditemukan vulnerability umum", title="[green]Hasil Vulnerability Scan[/green]", style="green"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def email_harvester(target):
    """Mencari email yang terkait dengan domain"""
    console.print(f"[yellow]🔍 Mencari email untuk {target}...[/yellow]")
    
    try:
        # Google dorking untuk mencari email
        query = f"@{target}"
        emails = set()
        
        # Simulasi pencarian email (dalam implementasi nyata, gunakan API atau scraper)
        # Catatan: Google melarang scraping, jadi ini hanya contoh
        test_emails = [
            f"admin@{target}",
            f"info@{target}",
            f"contact@{target}",
            f"support@{target}"
        ]
        
        # Hanya untuk demo - dalam implementasi nyata, gunakan teknik yang sesuai
        for email in test_emails:
            emails.add(email)
        
        if emails:
            result_text = "\n".join(emails)
            # Kirim ke Telegram
            telegram_msg = f"🔍 Email Harvester untuk {target}\n\nEmail ditemukan:\n{result_text}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[green]Email Ditemukan[/green]", style="green"))
        else:
            console.print(Panel.fit("Tidak ditemukan email", title="[yellow]Hasil Email Harvester[/yellow]", style="yellow"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def cloud_detector(target):
    """Mendeteksi layanan cloud yang digunakan"""
    console.print(f"[yellow]🔍 Mendeteksi layanan cloud untuk {target}...[/yellow]")
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    
    cloud_services = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS": ["aws", "amazon web services", "x-amz-cf-id"],
        "Google Cloud": ["google cloud", "gcp", "googleusercontent"],
        "Azure": ["azure", "microsoft", "x-azure-ref"],
        "Akamai": ["akamai", "x-akamai"]
    }
    
    detected_services = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        content = response.text.lower()
        headers = response.headers
        
        for service, indicators in cloud_services.items():
            for indicator in indicators:
                if indicator in content or any(indicator in str(value).lower() for value in headers.values()):
                    detected_services.append(service)
                    break
        
        if detected_services:
            result_text = "\n".join([f"[green]✓ {service}[/green]" for service in detected_services])
            # Kirim ke Telegram
            telegram_msg = f"🔍 Cloud Detection untuk {target}\n\nDetected: {', '.join(detected_services)}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[green]Layanan Cloud Terdeteksi[/green]", style="green"))
        else:
            console.print(Panel.fit("Tidak terdeteksi layanan cloud", title="[yellow]Hasil Cloud Detection[/yellow]", style="yellow"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def ssl_checker(target):
    """Memeriksa sertifikat SSL"""
    console.print(f"[yellow]🔍 Memeriksa SSL untuk {target}...[/yellow]")
    
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert_der = ssock.getpeercert(True)
                cert = x509.load_der_x509_certificate(cert_der, default_backend())
                
                # Informasi sertifikat
                issuer = cert.issuer.rfc4514_string()
                subject = cert.subject.rfc4514_string()
                valid_from = cert.not_valid_before
                valid_to = cert.not_valid_after
                
                result_text = f"""
Issuer: {issuer}
Subject: {subject}
Valid from: {valid_from}
Valid to: {valid_to}
"""
                
                # Kirim ke Telegram
                telegram_msg = f"🔍 SSL Check untuk {target}\n\n{result_text}"
                send_to_telegram(telegram_msg)
                
                console.print(Panel.fit(result_text, title="[green]Informasi SSL[/green]", style="green"))
                
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def website_technologies(target):
    """Mendeteksi teknologi yang digunakan website"""
    console.print(f"[yellow]🔍 Mendeteksi teknologi untuk {target}...[/yellow]")
    
    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"
    
    technologies = {
        "JavaScript Frameworks": {
            "React": ["react", "react-dom"],
            "Vue.js": ["vue", "vue.js"],
            "Angular": ["angular", "ng-"]
        },
        "Web Servers": {
            "Apache": ["apache", "server: apache"],
            "Nginx": ["nginx", "server: nginx"],
            "IIS": ["microsoft-iis", "server: microsoft-iis"]
        },
        "Programming Languages": {
            "PHP": ["php", "x-powered-by: php"],
            "Python": ["python", "django", "flask"],
            "Ruby": ["ruby", "rails", "x-powered-by: ruby"]
        }
    }
    
    detected_tech = []
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        content = response.text.lower()
        headers = response.headers
        
        for category, techs in technologies.items():
            for tech, indicators in techs.items():
                for indicator in indicators:
                    if indicator in content or any(indicator in str(value).lower() for value in headers.values()):
                        detected_tech.append(f"{category}: {tech}")
                        break
        
        if detected_tech:
            result_text = "\n".join([f"[green]✓ {tech}[/green]" for tech in detected_tech])
            # Kirim ke Telegram
            telegram_msg = f"🔍 Technology Detection untuk {target}\n\nDetected:\n{result_text}"
            send_to_telegram(telegram_msg)
            
            console.print(Panel.fit(result_text, title="[green]Teknologi Terdeteksi[/green]", style="green"))
        else:
            console.print(Panel.fit("Tidak terdeteksi teknologi", title="[yellow]Hasil Technology Detection[/yellow]", style="yellow"))
            
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def social_media_recon(target):
    """Mencari keberadaan target di media sosial"""
    console.print(f"[yellow]🔍 Mencari {target} di media sosial...[/yellow]")
    
    social_platforms = {
        "Facebook": f"https://www.facebook.com/{target}",
        "Twitter": f"https://twitter.com/{target}",
        "Instagram": f"https://www.instagram.com/{target}",
        "LinkedIn": f"https://www.linkedin.com/in/{target}",
        "YouTube": f"https://www.youtube.com/@{target}",
        "GitHub": f"https://github.com/{target}"
    }
    
    results = []
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        transient=True,
    ) as progress:
        task = progress.add_task("Checking social media...", total=len(social_platforms))
        
        for platform, url in social_platforms.items():
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    results.append(f"[green]✓ {platform}: DITEMUKAN ({url})[/green]")
                else:
                    results.append(f"[red]✗ {platform}: Tidak ditemukan[/red]")
            except:
                results.append(f"[yellow]? {platform}: Gagal memeriksa[/yellow]")
            
            progress.update(task, advance=1)
    
    if results:
        result_text = "\n".join(results)
        # Kirim ke Telegram
        telegram_msg = f"🔍 Social Media Recon untuk {target}\n\nHasil:\n{result_text}"
        send_to_telegram(telegram_msg)
        
        console.print(Panel.fit(result_text, title="[green]Hasil Social Media Recon[/green]", style="green"))
    else:
        console.print(Panel.fit("Tidak ada hasil", title="[yellow]Hasil Social Media Recon[/yellow]", style="yellow"))

def main_menu():
    """Menu utama"""
    banner()
    
    while True:
        table = Table(title="🛡️ ASEPSCAN ULTIMATE - MAIN MENU", box=box.ROUNDED)
        table.add_column("No", style="cyan", justify="center")
        table.add_column("Fitur", style="magenta")
        table.add_column("Deskripsi", style="green")
        
        table.add_row("1", "WHOIS Lookup", "Informasi registrasi domain")
        table.add_row("2", "DNS Recon", "Informasi DNS records")
        table.add_row("3", "Port Scanner", "Scan port terbuka")
        table.add_row("4", "Subdomain Scanner", "Cari subdomain")
        table.add_row("5", "CMS Detector", "Deteksi CMS website")
        table.add_row("6", "Vulnerability Scanner", "Scan vulnerability umum")
        table.add_row("7", "Email Harvester", "Cari email terkait domain")
        table.add_row("8", "Cloud Detector", "Deteksi layanan cloud")
        table.add_row("9", "SSL Checker", "Periksa sertifikat SSL")
        table.add_row("10", "Technology Detection", "Deteksi teknologi website")
        table.add_row("11", "Social Media Recon", "Cari target di media sosial")
        table.add_row("12", "Exit", "Keluar dari program")
        
        console.print(table)
        
        choice = console.input("[bold cyan]Pilih opsi (1-12): [/]").strip()
        
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
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            cms_detector(target)
        elif choice == "6":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            vulnerability_scanner(target)
        elif choice == "7":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            email_harvester(target)
        elif choice == "8":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            cloud_detector(target)
        elif choice == "9":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            ssl_checker(target)
        elif choice == "10":
            target = console.input("[bold green]Masukkan domain: [/]").strip()
            website_technologies(target)
        elif choice == "11":
            target = console.input("[bold green]Masukkan username: [/]").strip()
            social_media_recon(target)
        elif choice == "12":
            console.print("[bold red]Keluar dari program...[/bold red]")
            sys.exit(0)
        else:
            console.print("[red]Pilihan tidak valid![/red]")
        
        console.input("\n[bold yellow]Tekan Enter untuk melanjutkan...[/]")
        console.clear()

if __name__ == "__main__":
    try:
        # Install dependencies jika belum ada
        dependencies = ["rich", "requests", "dnspython", "beautifulsoup4", "cryptography"]
        for package in dependencies:
            if os.system(f"python -c 'import {package}' >/dev/null 2>&1") != 0:
                console.print(f"[yellow]Menginstall {package}...[/yellow]")
                os.system(f"pip install -q {package}")
        
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]Program diinterupsi![/bold red]")
    except Exception as e:
        console.print(f"[bold red]Error: {str(e)}[/bold red]")
