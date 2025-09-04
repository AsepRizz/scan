#!/usr/bin/env python3
import os
import sys
import socket
import requests
import subprocess
import json
import dns.resolver
from urllib.parse import urlparse
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime
import telebot
from scapy.all import ICMP, IP, sr1
import time
import concurrent.futures

# Konfigurasi Telegram
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN", "8127930072:AAHwbMBROwSrXSRFTPL4RgdNunzrKqgisHU")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "5731047913")
bot = telebot.TeleBot(TELEGRAM_TOKEN)

console = Console()

def send_telegram(message):
    try:
        bot.send_message(TELEGRAM_CHAT_ID, message, parse_mode='Markdown')
    except Exception as e:
        console.print(f"[red]Error sending to Telegram: {e}[/red]")

def banner():
    console.print("""
[bold blue]
   █████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
  ███████║███████╗███████╗██████╔╝███████╗██║     ███████║██╔██╗ ██║
  ██╔══██║╚════██║╚════██║██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║  ██║███████║███████║██║     ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold blue]
[bold red]                      Advanced Reconnaissance Tool[/bold red]
[bold yellow]                         Created for Termux[/bold yellow]
    """)

def check_dependencies():
    dependencies = ['nmap', 'whatweb', 'gobuster']
    missing = []
    
    for dep in dependencies:
        try:
            subprocess.run([dep, '--version'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            missing.append(dep)
    
    if missing:
        console.print("[red]Error: The following dependencies are missing:[/red]")
        for dep in missing:
            console.print(f"[red]- {dep}[/red]")
        console.print("\n[yellow]Please install them with:[/yellow]")
        console.print("[green]pkg install nmap whatweb golang[/green]")
        console.print("[green]go install github.com/OJ/gobuster/v3@latest[/green]")
        console.print("[green]export PATH=$PATH:~/go/bin[/green]")
        return False
    return True

def whois_lookup(domain):
    try:
        console.print(f"[yellow]Performing WHOIS lookup for {domain}...[/yellow]")
        w = whois.whois(domain)
        table = Table(title="WHOIS Information")
        table.add_column("Attribute", style="cyan")
        table.add_column("Value", style="green")
        
        for key, value in w.items():
            if value:
                table.add_row(key, str(value))
        
        console.print(table)
        send_telegram(f"*WHOIS Lookup for {domain}*\n```{str(w)}```")
        return True
    except Exception as e:
        console.print(f"[red]Error in WHOIS lookup: {e}[/red]")
        return False

def whatweb_scan(target):
    try:
        console.print(f"[yellow]Performing WhatWeb scan for {target}...[/yellow]")
        result = subprocess.check_output(f"whatweb {target} -v", shell=True, text=True)
        
        table = Table(title="WhatWeb Results")
        table.add_column("Technology", style="cyan")
        table.add_column("Details", style="green")
        
        lines = result.strip().split('\n')
        for line in lines[1:]:  # Skip the first line
            if "]" in line and "[" in line:
                tech = line.split("[")[1].split("]")[0]
                details = line.split("]")[1].strip()
                table.add_row(tech, details)
        
        console.print(table)
        send_telegram(f"*WhatWeb Scan for {target}*\n```{result}```")
        return True
    except Exception as e:
        console.print(f"[red]Error in WhatWeb scan: {e}[/red]")
        return False

def nmap_scan(target):
    try:
        console.print(f"[yellow]Performing Nmap scan for {target}...[/yellow]")
        result = subprocess.check_output(f"nmap -sV -sC -O {target}", shell=True, text=True)
        
        table = Table(title="Nmap Results")
        table.add_column("Port", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Version", style="magenta")
        
        lines = result.strip().split('\n')
        for line in lines:
            if "/tcp" in line or "/udp" in line:
                parts = line.split()
                if len(parts) >= 4:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""
                    table.add_row(port, state, service, version)
        
        console.print(table)
        send_telegram(f"*Nmap Scan for {target}*\n```{result}```")
        return True
    except Exception as e:
        console.print(f"[red]Error in Nmap scan: {e}[/red]")
        return False

def subdomain_scan(domain):
    try:
        console.print(f"[yellow]Performing subdomain enumeration for {domain}...[/yellow]")
        wordlist_path = "/usr/share/wordlists/subdomains.txt"
        
        if not os.path.exists(wordlist_path):
            console.print("[red]Wordlist not found. Using common subdomains...[/red]")
            common_subdomains = ["www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk", "ns2", 
                                "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog", 
                                "pop3", "dev", "www2", "admin", "forum", "news", "vpn", "ns3", "mail2", "new", 
                                "mysql", "old", "lists", "support", "mobile", "mx", "static", "docs", "beta", 
                                "shop", "sql", "secure", "demo", "cp", "calendar", "wiki", "web", "media", 
                                "email", "images", "img", "www1", "intranet", "portal", "video", "sip", "dns2", 
                                "api", "cdn", "stats", "dns1", "ns4", "www3", "dns", "search", "staging", "server", 
                                "mx1", "chat", "wap", "my", "download", "ssh", "office", "vps", "host", "img0", 
                                "img1", "img2", "css", "js", "files", "cdn1", "cdn2", "cdn3", "cdn4", "cdn5"]
            
            with open("/tmp/subdomains.txt", "w") as f:
                for sub in common_subdomains:
                    f.write(f"{sub}\n")
            wordlist_path = "/tmp/subdomains.txt"
        
        result = subprocess.check_output(f"gobuster dns -d {domain} -w {wordlist_path} -q", shell=True, text=True)
        
        table = Table(title="Subdomain Enumeration Results")
        table.add_column("Subdomain", style="cyan")
        table.add_column("Full Domain", style="green")
        
        subdomains = []
        for line in result.strip().split('\n'):
            if "Found:" in line:
                subdomain = line.split(":")[1].strip()
                full_domain = f"{subdomain}.{domain}"
                table.add_row(subdomain, full_domain)
                subdomains.append(full_domain)
        
        console.print(table)
        send_telegram(f"*Subdomain Enumeration for {domain}*\nFound {len(subdomains)} subdomains:\n" + "\n".join(subdomains))
        return True
    except Exception as e:
        console.print(f"[red]Error in subdomain enumeration: {e}[/red]")
        return False

def userrecon(username):
    try:
        console.print(f"[yellow]Performing user reconnaissance for {username}...[/yellow]")
        sites = [
            {"url": "https://github.com/{}", "type": "GitHub"},
            {"url": "https://twitter.com/{}", "type": "Twitter"},
            {"url": "https://instagram.com/{}", "type": "Instagram"},
            {"url": "https://facebook.com/{}", "type": "Facebook"},
            {"url": "https://youtube.com/{}", "type": "YouTube"},
            {"url": "https://reddit.com/user/{}", "type": "Reddit"},
            {"url": "https://pinterest.com/{}", "type": "Pinterest"},
            {"url": "https://github.com/{}", "type": "GitHub"},
            {"url": "https://medium.com/@{}", "type": "Medium"},
            {"url": "https://{}.tumblr.com", "type": "Tumblr"},
            {"url": "https://{}.wordpress.com", "type": "WordPress"},
            {"url": "https://{}.devianart.com", "type": "DeviantArt"},
            {"url": "https://{}.slack.com", "type": "Slack"}
        ]
        
        table = Table(title="User Reconnaissance Results")
        table.add_column("Platform", style="cyan")
        table.add_column("URL", style="green")
        table.add_column("Status", style="yellow")
        
        found_profiles = []
        
        for site in sites:
            url = site["url"].format(username)
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    table.add_row(site["type"], url, "[green]Found[/green]")
                    found_profiles.append(f"{site['type']}: {url}")
                else:
                    table.add_row(site["type"], url, "[red]Not Found[/red]")
            except:
                table.add_row(site["type"], url, "[red]Error[/red]")
        
        console.print(table)
        send_telegram(f"*User Reconnaissance for {username}*\nFound profiles:\n" + "\n".join(found_profiles))
        return True
    except Exception as e:
        console.print(f"[red]Error in user reconnaissance: {e}[/red]")
        return False

def geolocation(target):
    try:
        console.print(f"[yellow]Performing geolocation lookup for {target}...[/yellow]")
        # If target is a domain, resolve to IP first
        try:
            ip = socket.gethostbyname(target)
        except:
            ip = target
        
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        
        if data["status"] == "success":
            table = Table(title="Geolocation Information")
            table.add_column("Attribute", style="cyan")
            table.add_column("Value", style="green")
            
            for key, value in data.items():
                if key != "status":
                    table.add_row(key, str(value))
            
            console.print(table)
            send_telegram(f"*Geolocation for {target}*\n```{json.dumps(data, indent=2)}```")
            return True
        else:
            console.print("[red]Geolocation lookup failed[/red]")
            return False
    except Exception as e:
        console.print(f"[red]Error in geolocation lookup: {e}[/red]")
        return False

def http_header(target):
    try:
        console.print(f"[yellow]Performing HTTP header analysis for {target}...[/yellow]")
        if not target.startswith("http"):
            target = "http://" + target
        
        response = requests.get(target)
        
        table = Table(title="HTTP Headers")
        table.add_column("Header", style="cyan")
        table.add_column("Value", style="green")
        
        for header, value in response.headers.items():
            table.add_row(header, value)
        
        console.print(table)
        send_telegram(f"*HTTP Headers for {target}*\n```{str(response.headers)}```")
        return True
    except Exception as e:
        console.print(f"[red]Error in HTTP header analysis: {e}[/red]")
        return False

def dns_lookup(domain):
    try:
        console.print(f"[yellow]Performing DNS lookup for {domain}...[/yellow]")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        table = Table(title="DNS Records")
        table.add_column("Type", style="cyan")
        table.add_column("Value", style="green")
        
        all_records = []
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                for rdata in answers:
                    table.add_row(record_type, str(rdata))
                    all_records.append(f"{record_type}: {rdata}")
            except:
                pass
        
        console.print(table)
        send_telegram(f"*DNS Lookup for {domain}*\n" + "\n".join(all_records))
        return True
    except Exception as e:
        console.print(f"[red]Error in DNS lookup: {e}[/red]")
        return False

def port_scan(target):
    try:
        console.print(f"[yellow]Performing port scan for {target}...[/yellow]")
        # Common ports to scan
        common_ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5900, 8080]
        
        table = Table(title="Port Scan Results")
        table.add_column("Port", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Service", style="yellow")
        
        open_ports = []
        
        def check_port(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex((target, port))
                    if result == 0:
                        try:
                            service = socket.getservbyport(port)
                        except:
                            service = "unknown"
                        table.add_row(str(port), "[green]Open[/green]", service)
                        open_ports.append(f"{port} ({service})")
                    else:
                        table.add_row(str(port), "[red]Closed[/red]", "N/A")
            except:
                table.add_row(str(port), "[red]Error[/red]", "N/A")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_port, common_ports)
        
        console.print(table)
        send_telegram(f"*Port Scan for {target}*\nOpen ports: " + ", ".join(open_ports))
        return True
    except Exception as e:
        console.print(f"[red]Error in port scan: {e}[/red]")
        return False

def main_menu():
    console.print("\n[bold green]AsepScan Main Menu[/bold green]")
    console.print("[bold yellow]1.[/bold yellow] WHOIS Lookup")
    console.print("[bold yellow]2.[/bold yellow] WhatWeb Scan")
    console.print("[bold yellow]3.[/bold yellow] Nmap Scan")
    console.print("[bold yellow]4.[/bold yellow] Subdomain Enumeration")
    console.print("[bold yellow]5.[/bold yellow] User Reconnaissance")
    console.print("[bold yellow]6.[/bold yellow] Geolocation Lookup")
    console.print("[bold yellow]7.[/bold yellow] HTTP Header Analysis")
    console.print("[bold yellow]8.[/bold yellow] DNS Lookup")
    console.print("[bold yellow]9.[/bold yellow] Port Scan")
    console.print("[bold yellow]10.[/bold yellow] Full Reconnaissance (All tests)")
    console.print("[bold yellow]0.[/bold yellow] Exit")
    
    choice = console.input("\n[bold green]Enter your choice: [/bold green]")
    return choice

def main():
    banner()
    
    if not check_dependencies():
        console.print("[red]Please install missing dependencies and try again.[/red]")
        return
    
    console.print(f"[green]Telegram Token: {TELEGRAM_TOKEN}[/green]")
    console.print(f"[green]Telegram Chat ID: {TELEGRAM_CHAT_ID}[/green]")
    
    while True:
        choice = main_menu()
        
        if choice == "0":
            console.print("[bold red]Exiting AsepScan. Goodbye![/bold red]")
            break
        
        target = console.input("[bold yellow]Enter target (domain/IP/username): [/bold yellow]")
        
        if choice == "1":
            whois_lookup(target)
        elif choice == "2":
            whatweb_scan(target)
        elif choice == "3":
            nmap_scan(target)
        elif choice == "4":
            subdomain_scan(target)
        elif choice == "5":
            userrecon(target)
        elif choice == "6":
            geolocation(target)
        elif choice == "7":
            http_header(target)
        elif choice == "8":
            dns_lookup(target)
        elif choice == "9":
            port_scan(target)
        elif choice == "10":
            console.print("[bold yellow]Performing full reconnaissance...[/bold yellow]")
            if "." in target:  # Likely a domain or IP
                whois_lookup(target)
                whatweb_scan(target)
                nmap_scan(target)
                subdomain_scan(target)
                geolocation(target)
                http_header(target)
                dns_lookup(target)
                port_scan(target)
            else:  # Likely a username
                userrecon(target)
        else:
            console.print("[red]Invalid choice. Please try again.[/red]")
        
        console.input("\n[bold yellow]Press Enter to continue...[/bold yellow]")

if __name__ == "__main__":
    main()
