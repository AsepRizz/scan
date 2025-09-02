#!/usr/bin/env python3
# ASEPSCAN Ultimate - Termux Edition
# Fixed version with auto-install for all dependencies
# Removed screenshot feature as requested

import os
import sys
import time
import shutil
import subprocess
import socket
import re
import requests
import dns.resolver
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn

console = Console()

# Configuration
PIP_PACKAGES = ["rich", "requests", "dnspython", "googlesearch-python"]
REQUIRED_TOOLS = {
    "whois": "pkg install whois -y",
    "whatweb": "pkg install whatweb -y", 
    "nmap": "pkg install nmap -y",
    "curl": "pkg install curl -y",
    "git": "pkg install git -y",
    "go": "pkg install golang -y",
    "python": "pkg install python -y",
    "pip": "pkg install python-pip -y",
    "wafw00f": "pip install wafw00f",
    "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
    "gobuster": "go install github.com/OJ/gobuster/v3@latest",
}

def ensure_go_path():
    """Ensure Go binaries are in PATH"""
    home = os.path.expanduser("~")
    go_bin = os.path.join(home, "go", "bin")
    if go_bin not in os.environ["PATH"].split(os.pathsep):
        os.environ["PATH"] += os.pathsep + go_bin
        
    # Add to shell profile for future sessions
    shell_profile = os.path.expanduser("~/.bashrc")
    path_entry = 'export PATH="$HOME/go/bin:$PATH"'
    try:
        if os.path.exists(shell_profile):
            with open(shell_profile, "r") as f:
                content = f.read()
            if path_entry not in content:
                with open(shell_profile, "a") as f:
                    f.write(f"\n{path_entry}\n")
        else:
            with open(shell_profile, "w") as f:
                f.write(f"{path_entry}\n")
    except Exception:
        pass

def run_cmd(cmd, timeout=300):
    """Run a command and return results"""
    try:
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 1, "", "Command timed out"
    except Exception as e:
        return 1, "", str(e)

def is_tool_available(tool_name):
    """Check if a tool is available in PATH"""
    return shutil.which(tool_name) is not None

def install_python_packages():
    """Install required Python packages"""
    for package in PIP_PACKAGES:
        try:
            # Special handling for googlesearch
            if package == "googlesearch-python":
                import googlesearch
            else:
                __import__(package.split('==')[0])
            console.print(f"[green]✓ {package} already installed[/green]")
        except ImportError:
            console.print(f"[yellow]Installing {package}...[/yellow]")
            code, out, err = run_cmd(f"pip install {package}")
            if code == 0:
                console.print(f"[green]✓ {package} installed successfully[/green]")
            else:
                console.print(f"[red]Failed to install {package}: {err}[/red]")

def install_system_tools():
    """Install required system tools"""
    for tool, install_cmd in REQUIRED_TOOLS.items():
        if is_tool_available(tool):
            console.print(f"[green]✓ {tool} already installed[/green]")
            continue
            
        console.print(f"[yellow]Installing {tool}...[/yellow]")
        
        # Handle Go tools specially
        if "go install" in install_cmd:
            if not is_tool_available("go"):
                console.print("[yellow]Installing Go first...[/yellow]")
                run_cmd(REQUIRED_TOOLS["go"])
                ensure_go_path()
                
        code, out, err = run_cmd(install_cmd)
        if code == 0:
            console.print(f"[green]✓ {tool} installed successfully[/green]")
        else:
            console.print(f"[red]Failed to install {tool}: {err}[/red]")

def bootstrap():
    """Bootstrap the environment"""
    console.print(Panel.fit("Setting up environment...", title="Bootstrapping", style="cyan"))
    
    # Update package lists
    console.print("[yellow]Updating package lists...[/yellow]")
    run_cmd("pkg update -y")
    
    # Install system tools
    install_system_tools()
    
    # Install Python packages
    install_python_packages()
    
    # Ensure Go path
    ensure_go_path()
    
    # Create wordlists directory
    wordlist_dir = os.path.expanduser("~/.wordlists")
    os.makedirs(wordlist_dir, exist_ok=True)
    
    console.print(Panel.fit("Environment setup complete!", title="Ready", style="green"))

def detect_protocol(target):
    """Detect HTTP or HTTPS protocol for a target"""
    try:
        response = requests.head(
            f"https://{target}", 
            timeout=5, 
            verify=False,
            allow_redirects=True
        )
        if response.status_code < 400:
            return "https"
    except:
        pass
    return "http"

def whois_lookup(target):
    """Perform WHOIS lookup"""
    if not is_tool_available("whois"):
        console.print("[red]WHOIS tool not available[/red]")
        return
        
    console.print("[yellow]Performing WHOIS lookup...[/yellow]")
    code, out, err = run_cmd(f"whois {target}")
    
    if code == 0:
        console.print(Panel.fit(out, title="WHOIS Results", style="green"))
    else:
        console.print(Panel.fit(err, title="WHOIS Error", style="red"))

def whatweb_scan(target):
    """Perform WhatWeb scan"""
    if not is_tool_available("whatweb"):
        console.print("[red]WhatWeb tool not available[/red]")
        return
        
    console.print("[yellow]Performing WhatWeb scan...[/yellow]")
    code, out, err = run_cmd(f"whatweb {target}")
    
    if code == 0:
        console.print(Panel.fit(out, title="WhatWeb Results", style="green"))
    else:
        console.print(Panel.fit(err, title="WhatWeb Error", style="red"))

def nmap_scan(target, mode="cepat"):
    """Perform Nmap scan"""
    if not is_tool_available("nmap"):
        console.print("[red]Nmap tool not available[/red]")
        return
        
    console.print(f"[yellow]Performing Nmap scan ({mode} mode)...[/yellow]")
    
    if mode == "lengkap":
        scan_args = "-sV -O -T4"
    else:
        scan_args = "-T4 --top-ports 100"
        
    code, out, err = run_cmd(f"nmap {scan_args} {target}")
    
    if code == 0:
        console.print(Panel.fit(out, title="Nmap Results", style="green"))
    else:
        console.print(Panel.fit(err, title="Nmap Error", style="red"))

def subdomain_checker(target, mode="cepat"):
    """Find subdomains"""
    if not is_tool_available("assetfinder"):
        console.print("[red]Assetfinder tool not available[/red]")
        return
        
    console.print("[yellow]Finding subdomains...[/yellow]")
    code, out, err = run_cmd(f"assetfinder --subs-only {target}")
    
    if code == 0 and out.strip():
        subdomains = out.strip().split('\n')
        console.print(Panel.fit("\n".join(subdomains), title="Subdomains Found", style="green"))
    else:
        console.print(Panel.fit("No subdomains found", title="Subdomain Results", style="yellow"))

def gobuster_scan(target, mode="cepat"):
    """Perform directory brute-forcing with Gobuster"""
    if not is_tool_available("gobuster"):
        console.print("[red]Gobuster tool not available[/red]")
        return
        
    protocol = detect_protocol(target)
    wordlist_dir = os.path.expanduser("~/.wordlists")
    
    # Download wordlist if not exists
    if mode == "lengkap":
        wordlist_path = os.path.join(wordlist_dir, "big.txt")
        if not os.path.exists(wordlist_path):
            console.print("[yellow]Downloading large wordlist...[/yellow]")
            run_cmd(f"curl -s -o {wordlist_path} https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-big.txt")
    else:
        wordlist_path = os.path.join(wordlist_dir, "common.txt")
        if not os.path.exists(wordlist_path):
            console.print("[yellow]Downloading common wordlist...[/yellow]")
            run_cmd(f"curl -s -o {wordlist_path} https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt")
    
    console.print("[yellow]Running Gobuster...[/yellow]")
    cmd = f"gobuster dir -u {protocol}://{target} -w {wordlist_path} -t 50 -b 404,403"
    code, out, err = run_cmd(cmd, timeout=600)
    
    if code == 0:
        console.print(Panel.fit(out, title="Gobuster Results", style="green"))
    else:
        console.print(Panel.fit(err, title="Gobuster Error", style="red"))

def cek_header(target):
    """Check HTTP headers"""
    console.print("[yellow]Checking HTTP headers...[/yellow]")
    protocol = detect_protocol(target)
    
    try:
        response = requests.head(f"{protocol}://{target}", timeout=10, allow_redirects=True)
        header_text = f"URL: {protocol}://{target}\nStatus: {response.status_code}\n\n"
        
        for key, value in response.headers.items():
            header_text += f"{key}: {value}\n"
            
        console.print(Panel.fit(header_text, title="HTTP Headers", style="green"))
    except Exception as e:
        console.print(Panel.fit(f"Error: {str(e)}", title="HTTP Header Error", style="red"))

def waf_detection(target):
    """Detect WAF"""
    if not is_tool_available("wafw00f"):
        console.print("[red]Wafw00f tool not available[/red]")
        return
        
    console.print("[yellow]Detecting WAF...[/yellow]")
    code, out, err = run_cmd(f"wafw00f {target}")
    
    if code == 0:
        console.print(Panel.fit(out, title="WAF Detection Results", style="green"))
    else:
        console.print(Panel.fit(err, title="WAF Detection Error", style="red"))

def userrecon_scan(username):
    """Find user across social platforms"""
    console.print(f"[yellow]Searching for user {username}...[/yellow]")
    
    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
    }
    
    results = []
    with Progress(transient=True) as progress:
        task = progress.add_task("Checking platforms...", total=len(platforms))
        
        for platform, url in platforms.items():
            progress.update(task, advance=1, description=f"Checking {platform}...")
            
            try:
                response = requests.head(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    results.append(f"[green]✓ {platform}: Found[/green]")
                else:
                    results.append(f"[red]✗ {platform}: Not found[/red]")
            except:
                results.append(f"[yellow]? {platform}: Connection failed[/yellow]")
    
    console.print(Panel.fit("\n".join(results), title="User Recon Results", style="cyan"))

def dns_recon(target):
    """Perform DNS reconnaissance"""
    console.print(f"[yellow]Performing DNS reconnaissance on {target}...[/yellow]")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    results = []
    
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Use Google and Cloudflare DNS
        
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                results.append(f"[bold]{rtype} Records:[/bold]")
                for rdata in answers:
                    results.append(f"  {rdata.to_text()}")
                results.append("")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                pass
            except Exception as e:
                results.append(f"[red]Error querying {rtype}: {str(e)}[/red]")
                
    except Exception as e:
        results.append(f"[red]DNS error: {str(e)}[/red]")
    
    if results:
        console.print(Panel.fit("\n".join(results), title="DNS Recon Results", style="green"))
    else:
        console.print(Panel.fit("No DNS records found", title="DNS Recon Results", style="yellow"))

def email_harvester(target):
    """Harvest emails related to a domain"""
    console.print(f"[yellow]Harvesting emails for {target}...[/yellow]")
    
    search_queries = [
        f"site:{target} @{target}",
        f"email @{target}",
        f"contact @{target}"
    ]
    
    emails = set()
    
    try:
        from googlesearch import search
        
        for query in search_queries:
            try:
                for url in search(query, num=10, stop=10, pause=2):
                    try:
                        response = requests.get(url, timeout=5)
                        found_emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', response.text)
                        for email in found_emails:
                            if target in email:
                                emails.add(email)
                    except:
                        continue
            except:
                continue
                
    except ImportError:
        console.print("[red]Googlesearch module not available[/red]")
        return
    
    if emails:
        email_list = "\n".join([f"[green]• {email}[/green]" for email in emails])
        console.print(Panel.fit(email_list, title="Emails Found", style="green"))
    else:
        console.print(Panel.fit("No emails found", title="Email Harvester Results", style="yellow"))

def cloud_detector(target):
    """Detect cloud hosting provider"""
    console.print(f"[yellow]Detecting cloud provider for {target}...[/yellow]")
    
    cloud_indicators = {
        "AWS": ["aws", "amazon", "x-amz", "s3.amazonaws.com"],
        "Google Cloud": ["google", "gcp", "googlecloud", "appspot.com"],
        "Azure": ["azure", "microsoft", "windows.net"],
        "Cloudflare": ["cloudflare", "cf-", "cf-ray"],
    }
    
    protocol = detect_protocol(target)
    results = []
    
    try:
        response = requests.get(f"{protocol}://{target}", timeout=10)
        content = response.text.lower()
        headers = response.headers
        
        for cloud, indicators in cloud_indicators.items():
            detected = False
            for indicator in indicators:
                if indicator in content or any(indicator in str(v).lower() for k, v in headers.items()):
                    results.append(f"[green]✓ {cloud}[/green]")
                    detected = True
                    break
            if not detected:
                results.append(f"[red]✗ {cloud}[/red]")
                
    except Exception as e:
        results.append(f"[red]Error: {str(e)}[/red]")
    
    console.print(Panel.fit("\n".join(results), title="Cloud Detection Results", style="cyan"))

def cms_detector(target):
    """Detect CMS"""
    console.print(f"[yellow]Detecting CMS for {target}...[/yellow]")
    
    cms_indicators = {
        "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json"],
        "Joomla": ["joomla", "media/system/js", "index.php?option=com"],
        "Drupal": ["drupal", "sites/all", "core/assets"],
        "Magento": ["magento", "/js/mage/", "skin/frontend"],
    }
    
    protocol = detect_protocol(target)
    detected = None
    
    try:
        response = requests.get(f"{protocol}://{target}", timeout=10)
        content = response.text.lower()
        
        for cms, indicators in cms_indicators.items():
            for indicator in indicators:
                if indicator in content:
                    detected = cms
                    break
            if detected:
                break
                
        if detected:
            console.print(Panel.fit(f"[green]✓ {detected}[/green]", title="CMS Detected", style="green"))
        else:
            console.print(Panel.fit("[red]✗ No known CMS detected[/red]", title="CMS Detection", style="yellow"))
            
    except Exception as e:
        console.print(Panel.fit(f"[red]Error: {str(e)}[/red]", title="CMS Detection Error", style="red"))

def port_scanner(target, mode="cepat"):
    """Scan ports"""
    console.print(f"[yellow]Scanning ports on {target}...[/yellow]")
    
    if mode == "lengkap":
        ports = range(1, 1001)  # Scan first 1000 ports for comprehensive scan
    else:
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]
    
    open_ports = []
    
    with Progress(transient=True) as progress:
        task = progress.add_task("Scanning ports...", total=len(ports))
        
        for port in ports:
            progress.update(task, advance=1)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            try:
                result = sock.connect_ex((target, port))
                if result == 0:
                    open_ports.append(port)
            except:
                pass
            finally:
                sock.close()
    
    if open_ports:
        port_list = "\n".join([f"[green]• Port {port} open[/green]" for port in open_ports])
        console.print(Panel.fit(port_list, title="Open Ports", style="green"))
    else:
        console.print(Panel.fit("No open ports found", title="Port Scan Results", style="yellow"))

def banner():
    """Display banner"""
    ascii_art = """
     █████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
    ███████║███████╗█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
    ██╔══██║╚════██║██╔══╝  ██╔═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║  ██║███████║███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    """
    console.print(Panel.fit(ascii_art, title="ASEPSCAN ULTIMATE - Termux Edition", style="bold cyan"))
    console.print("[bold yellow]Multi-purpose reconnaissance toolkit[/bold yellow]\n")

def menu():
    """Main menu"""
    banner()
    
    while True:
        table = Table(title="Main Menu", show_header=True, header_style="bold magenta")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="green")
        
        table.add_row("1", "WHOIS Lookup")
        table.add_row("2", "WhatWeb Scan")
        table.add_row("3", "Nmap Scan")
        table.add_row("4", "Subdomain Finder")
        table.add_row("5", "Gobuster Directory Scan")
        table.add_row("6", "HTTP Header Check")
        table.add_row("7", "WAF Detection")
        table.add_row("8", "User Recon")
        table.add_row("9", "DNS Recon")
        table.add_row("10", "Email Harvester")
        table.add_row("11", "Cloud Detector")
        table.add_row("12", "CMS Detector")
        table.add_row("13", "Port Scanner")
        table.add_row("0", "Exit")
        
        console.print(table)
        
        choice = console.input("\n[bold cyan]Select an option (0-13): [/]").strip()
        
        if choice == "0":
            console.print("[green]Goodbye![/green]")
            break
            
        elif choice == "1":
            target = console.input("[yellow]Enter domain: [/]").strip()
            whois_lookup(target)
            
        elif choice == "2":
            target = console.input("[yellow]Enter URL: [/]").strip()
            whatweb_scan(target)
            
        elif choice == "3":
            target = console.input("[yellow]Enter target: [/]").strip()
            mode = console.input("[yellow]Mode (cepat/lengkap): [/]").strip().lower()
            nmap_scan(target, mode)
            
        elif choice == "4":
            target = console.input("[yellow]Enter domain: [/]").strip()
            mode = console.input("[yellow]Mode (cepat/lengkap): [/]").strip().lower()
            subdomain_checker(target, mode)
            
        elif choice == "5":
            target = console.input("[yellow]Enter URL: [/]").strip()
            mode = console.input("[yellow]Mode (cepat/lengkap): [/]").strip().lower()
            gobuster_scan(target, mode)
            
        elif choice == "6":
            target = console.input("[yellow]Enter URL: [/]").strip()
            cek_header(target)
            
        elif choice == "7":
            target = console.input("[yellow]Enter URL: [/]").strip()
            waf_detection(target)
            
        elif choice == "8":
            username = console.input("[yellow]Enter username: [/]").strip()
            userrecon_scan(username)
            
        elif choice == "9":
            target = console.input("[yellow]Enter domain: [/]").strip()
            dns_recon(target)
            
        elif choice == "10":
            target = console.input("[yellow]Enter domain: [/]").strip()
            email_harvester(target)
            
        elif choice == "11":
            target = console.input("[yellow]Enter domain: [/]").strip()
            cloud_detector(target)
            
        elif choice == "12":
            target = console.input("[yellow]Enter URL: [/]").strip()
            cms_detector(target)
            
        elif choice == "13":
            target = console.input("[yellow]Enter target: [/]").strip()
            mode = console.input("[yellow]Mode (cepat/lengkap): [/]").strip().lower()
            port_scanner(target, mode)
            
        else:
            console.print("[red]Invalid option![/red]")
        
        console.input("\n[yellow]Press Enter to continue...[/]")

if __name__ == "__main__":
    try:
        # Check if we need to bootstrap
        if not all(is_tool_available(tool) for tool in ["nmap", "whatweb", "whois"]):
            console.print("[yellow]Some tools are missing. Running bootstrap...[/yellow]")
            bootstrap()
        else:
            console.print("[green]All required tools are available![/green]")
            
        # Run the main menu
        menu()
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[red]Unexpected error: {str(e)}[/red]")
