#!/usr/bin/env python3
# aseprec_fix.py
# Termux-friendly recon toolkit (fixed)
# - Automatically ensures required system tools (pkg/go/pip)
# - Ensures $HOME/go/bin is in PATH for Go-installed tools
# - Removes the screenshot feature as requested
# NOTE: This script will attempt to install packages when missing. Run in Termux with internet access.
import os
import sys
import time
import shutil
import subprocess
import socket
import re

try:
    import requests
    import dns.resolver
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress
except Exception:
    # If imports missing, we will try to install them below in bootstrap()
    pass

# --- Configuration ---
console = Console() if 'Console' in globals() else None

# Packages to ensure via pip (python packages)
PIP_PACKAGES = ["rich", "requests", "dnspython", "googlesearch-python"]

# System tools and how to install them on Termux (pkg/go/pip)
SYSTEM_TOOLS = {
    "whois": ("whois", "pkg install -y whois", "pkg"),
    "whatweb": ("whatweb", "pkg install -y whatweb", "pkg"),
    "nmap": ("nmap", "pkg install -y nmap", "pkg"),
    "assetfinder": ("assetfinder", "go install github.com/tomnomnom/assetfinder@latest", "go"),
    "gobuster": ("gobuster", "go install github.com/OJ/gobuster/v3@latest", "go"),
    "wafw00f": ("wafw00f", "pip install wafw00f", "pip"),
    "curl": ("curl", "pkg install -y curl", "pkg"),
    "git": ("git", "pkg install -y git", "pkg"),
    "go": ("go", "pkg install -y golang", "pkg"),
    "python": ("python3", "pkg install -y python", "pkg"),
    "pip": ("pip", "pkg install -y python-pip", "pkg"),
}

def ensure_go_path():
    home = os.path.expanduser("~")
    go_bin = os.path.join(home, "go", "bin")
    path = os.environ.get("PATH", "")
    if go_bin not in path.split(os.pathsep):
        os.environ["PATH"] = go_bin + os.pathsep + path
    shell_profile = os.path.expanduser("~/.profile")
    entry = 'export PATH="$HOME/go/bin:$PATH"'
    try:
        if os.path.exists(shell_profile):
            with open(shell_profile, "r", encoding="utf-8") as f:
                content = f.read()
            if entry not in content:
                with open(shell_profile, "a", encoding="utf-8") as f:
                    f.write("\n# added by aseprec_fix\n" + entry + "\n")
        else:
            with open(shell_profile, "w", encoding="utf-8") as f:
                f.write("# profile created by aseprec_fix\n" + entry + "\n")
    except Exception:
        pass

def run_cmd(cmd, timeout=600):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.SubprocessError as e:
        return 1, "", str(e)

def is_tool_available(exe_name):
    return shutil.which(exe_name) is not None

def bootstrap_install_pip(packages):
    for pkg in packages:
        try:
            # special-case: googlesearch-python provides module 'googlesearch'
            modname = "googlesearch" if pkg == "googlesearch-python" else pkg
            __import__(modname)
        except Exception:
            if console:
                console.print(f"[yellow]⏳ Menginstall Python package: {pkg}[/yellow]")
            run_cmd(f"pip install -q {pkg}")

def ensure_system_tool(tool_key):
    if tool_key not in SYSTEM_TOOLS:
        return False
    check_name, install_cmd, install_type = SYSTEM_TOOLS[tool_key]
    if is_tool_available(check_name):
        return True
    if console:
        console.print(f"[yellow]Tool '{check_name}' belum terinstall. Mencoba install via: {install_cmd}[/yellow]")
    if install_type == "go" and not is_tool_available("go"):
        if console:
            console.print("[yellow]Go runtime gak ada. Menginstall golang dulu...[/yellow]")
        run_cmd(SYSTEM_TOOLS["go"][1])
    code, out, err = run_cmd(install_cmd, timeout=1200)
    time.sleep(1)
    ensure_go_path()
    if is_tool_available(check_name):
        if console:
            console.print(f"[green]✓ {check_name} berhasil terpasang[/green]")
        return True
    else:
        if console:
            console.print(f"[red]Gagal memasang {check_name}. Periksa pesan error: {err or out}[/red]")
        return False

def bootstrap_system_tools():
    if console:
        console.print("[cyan]↻ Memeriksa dan menginstall dependencies (best-effort)...[/cyan]")
    # Try to ensure each tool (best-effort)
    for key in SYSTEM_TOOLS:
        # skip python/pip to avoid interfering with current runtime
        if SYSTEM_TOOLS[key][0] in ("python3", "pip"):
            continue
        ensure_system_tool(key)
    bootstrap_install_pip(PIP_PACKAGES)
    ensure_go_path()

def clean_ansi(text):
    return re.sub(r'\x1B[@-_][0-?]*[ -/]*[@-~]', '', text or "")

def detect_protocol(target):
    try:
        resp = requests.head(f"https://{target}", timeout=5, allow_redirects=True, verify=False)
        if resp.status_code < 400:
            return "https"
    except Exception:
        pass
    return "http"

def whois_lookup(target):
    if not is_tool_available("whois"):
        if console: console.print("[red]whois belum terpasang, skip WHOIS[/red]"); return
    if console: console.print("[yellow]⏳ Ngecek WHOIS...[/yellow]")
    code, out, err = run_cmd(f"whois {target}", timeout=300)
    if console: console.print(Panel.fit(clean_ansi(out or err), title="Hasil WHOIS", style="green"))

def whatweb_scan(target):
    if not is_tool_available("whatweb"):
        if console: console.print("[red]whatweb belum terpasang, skip WhatWeb[/red]"); return
    if console: console.print("[yellow]⏳ Ngecek WhatWeb...[/yellow]")
    code, out, err = run_cmd(f"whatweb {target}", timeout=300)
    if console: console.print(Panel.fit(clean_ansi(out or err), title="Hasil WhatWeb", style="green"))

def nmap_scan(target, mode="cepat"):
    if not is_tool_available("nmap"):
        if console: console.print("[red]nmap belum terpasang, skip Nmap[/red]"); return
    if console: console.print(f"[yellow]⏳ Ngecek Nmap ({mode})...[/yellow]")
    scan_type = "-Pn -sV -T4 -O" if mode == "lengkap" else "-Pn -T4 -F"
    code, out, err = run_cmd(f"nmap {scan_type} {target}", timeout=3600)
    if console: console.print(Panel.fit(clean_ansi(out or err), title="Hasil Nmap", style="green"))

def subdomain_checker(target, mode="cepat"):
    if not is_tool_available("assetfinder"):
        if console: console.print("[red]assetfinder belum terpasang, skip Subdomain Finder[/red]"); return
    if console: console.print("[yellow]⏳ Nyari subdomain...[/yellow]")
    code, out, err = run_cmd(f"assetfinder --subs-only {target}", timeout=300)
    subdomains = []
    if code == 0 and out.strip():
        subdomains = [s.strip() for s in out.splitlines() if s.strip()]
    if mode == "lengkap" and is_tool_available("httprobe"):
        try:
            p = subprocess.Popen(["httprobe"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            p.stdin.write("\n".join(subdomains)); p.stdin.close()
            live_out = p.stdout.read()
            subdomains = [s.strip() for s in live_out.splitlines() if s.strip()]
        except Exception:
            pass
    panel_text = "\\n".join(subdomains) if subdomains else "Gak nemu subdomain."
    if console: console.print(Panel.fit(panel_text, title="Subdomain", style="green"))

def gobuster_scan(target, mode="cepat"):
    if not is_tool_available("gobuster"):
        if console: console.print("[red]gobuster belum terpasang, skip Gobuster[/red]"); return
    protocol = detect_protocol(target)
    wordlist_dir = os.path.expanduser("~/.wordlists"); os.makedirs(wordlist_dir, exist_ok=True)
    if mode == "lengkap":
        wordlist_path = os.path.join(wordlist_dir, "directory-list-2.3-big.txt")
        if not os.path.exists(wordlist_path):
            if console: console.print("[blue]Download wordlist besar (sabar)...[/blue]")
            run_cmd(f"curl -s -o {wordlist_path} https://github.com/danielmiessler/SecLists/raw/master/Discovery/Web-Content/directory-list-2.3-big.txt", timeout=600)
    else:
        wordlist_path = os.path.join(wordlist_dir, "quickhits.txt")
        if not os.path.exists(wordlist_path):
            run_cmd(f"curl -s -o {wordlist_path} https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/quickhits.txt", timeout=300)
    command = f"gobuster dir -u {protocol}://{target} -w {wordlist_path} -t 50 -b 404,403"
    if console: console.print("[yellow]⏳ Jalanin Gobuster...[/yellow]")
    code, out, err = run_cmd(command, timeout=1800)
    if code != 0 and not out.strip():
        if console: console.print(Panel.fit(clean_ansi(err or out), title="Hasil Gobuster (error)", style="red")); return
    if console: console.print(Panel.fit(clean_ansi(out), title="Hasil Gobuster", style="green"))

def cek_header(target):
    if console: console.print("[yellow]⏳ Ngecek header HTTP...[/yellow]")
    protocol = detect_protocol(target)
    try:
        r = requests.head(f"{protocol}://{target}", timeout=6, allow_redirects=True)
        header_text = f"URL: {protocol}://{target}\\nStatus: {r.status_code}\\n"
        for k,v in r.headers.items():
            header_text += f"{k}: {v}\\n"
    except Exception as e:
        header_text = f"Error: {str(e)}"
    if console: console.print(Panel.fit(header_text, title="Header HTTP", style="green"))

def waf_detection(target):
    if not is_tool_available("wafw00f"):
        if console: console.print("[red]wafw00f belum terpasang, skip WAF detection[/red]"); return
    if console: console.print("[yellow]⏳ Ngecek WAF...[/yellow]")
    code, out, err = run_cmd(f"wafw00f {target}", timeout=300)
    if console: console.print(Panel.fit(clean_ansi(out or err), title="Deteksi WAF", style="green"))

def userrecon_scan(username, quick=True):
    if console: console.print(f"[yellow]⏳ Mencari akun [bold]{username}[/bold] di berbagai platform...[/yellow]")
    platforms = {
        "Facebook": f"https://www.facebook.com/{username}",
        "Instagram": f"https://www.instagram.com/{username}",
        "Twitter": f"https://twitter.com/{username}",
        "LinkedIn": f"https://www.linkedin.com/in/{username}",
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "YouTube": f"https://www.youtube.com/@{username}"
    }
    results = []
    with Progress() as progress:
        task = progress.add_task("[cyan]Cek platform...", total=len(platforms))
        for platform, url in platforms.items():
            progress.update(task, advance=1, description=f"[cyan]Cek {platform}...")
            try:
                r = requests.head(url, timeout=6, allow_redirects=True)
                if r.status_code == 200:
                    results.append(f"[green]✓ {platform}: {url}[/green]")
                elif r.status_code == 404:
                    results.append(f"[red]✗ {platform}: Tidak ditemukan[/red]")
                else:
                    results.append(f"[yellow]? {platform}: Status {r.status_code}[/yellow]")
            except Exception:
                results.append(f"[yellow]? {platform}: Gagal koneksi[/yellow]")
    if console: console.print(Panel.fit("\\n".join(results), title=f"Hasil UserRecon: {username}", style="cyan"))

def godorker_scan(target):
    if console: console.print(f"[yellow]⏳ Menjalankan GoDorker untuk [bold]{target}[/bold]...[/yellow]")
    dorks = [
        f"site:{target} inurl:admin",
        f"site:{target} intext:password",
        f"site:{target} ext:pdf",
        f"site:{target} ext:doc | ext:docx",
        f"site:{target} inurl:login",
        f"site:{target} intitle:index.of",
        f"site:{target} ext:sql",
        f"site:{target} filetype:env",
        f"site:{target} inurl:wp-admin",
        f"site:{target} inurl:config"
    ]
    results = []
    try:
        from googlesearch import search
        for dork in dorks:
            for url in search(dork, num_results=3):
                results.append(url)
    except Exception as e:
        results.append(f"Error menjalankan googlesearch: {str(e)}")
    if console: console.print(Panel.fit("\\n".join(results), title=f"Hasil GoDorker: {target}", style="green"))

def dns_recon(target):
    if console: console.print(f"[yellow]⏳ Melakukan DNS Recon untuk [bold]{target}[/bold]...[/yellow]")
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
    results = []
    try:
        resolver = dns.resolver.Resolver(); resolver.nameservers = ['8.8.8.8', '1.1.1.1']
        for rtype in record_types:
            try:
                answers = resolver.resolve(target, rtype)
                results.append(f"--- {rtype} ---")
                for rdata in answers:
                    results.append(rdata.to_text())
            except Exception:
                pass
    except Exception as e:
        if console: console.print(f"[red]Error DNS: {str(e)}[/red]"); return
    if console: console.print(Panel.fit("\\n".join(results), title="Hasil DNS Recon", style="green"))

def email_harvester(target):
    if console: console.print(f"[yellow]⏳ Mencari email terkait [bold]{target}[/bold]...[/yellow]")
    sources = [
        "https://www.google.com/search?q=%40{}",
        "https://www.bing.com/search?q=%40{}",
        "https://search.yahoo.com/search?p=%40{}"
    ]
    emails = set()
    for template in sources:
        try:
            url = template.format(target); headers = {"User-Agent": "Mozilla/5.0"}
            r = requests.get(url, headers=headers, timeout=10)
            found = re.findall(r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b', r.text)
            for e in found:
                if target in e: emails.add(e)
        except Exception:
            continue
    if console:
        if emails: console.print(Panel.fit("\\n".join(sorted(emails)), title="Email Ditemukan", style="green"))
        else: console.print(Panel.fit("Tidak ditemukan email terkait domain ini", title="Email Harvester", style="yellow"))

def cloud_detector(target):
    if console: console.print(f"[yellow]⏳ Mendeteksi layanan cloud untuk [bold]{target}[/bold]...[/yellow]")
    cloud_indicators = {
        "Cloudflare": ["cloudflare", "cf-ray"],
        "AWS": ["aws", "amazon web services", "x-amz-cf-id"],
        "Google Cloud": ["google cloud", "gcp", "googleusercontent"],
        "Azure": ["azure", "microsoft", "x-azure-ref"],
        "Akamai": ["akamai", "x-akamai"],
        "CloudFront": ["cloudfront", "x-amz-cf-id"],
        "Fastly": ["fastly", "x-fastly"]
    }
    protocol = detect_protocol(target)
    try:
        r = requests.get(f"{protocol}://{target}", timeout=8)
        content = r.text.lower(); headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        results = []
        for cloud, inds in cloud_indicators.items():
            found = False
            for ind in inds:
                if ind in content or any(ind in v for v in headers.values()):
                    results.append(f"[green]✓ {cloud}[/green]"); found = True; break
            if not found: results.append(f"[red]✗ {cloud}[/red]")
    except Exception as e:
        if console: console.print(f"[red]Error: {str(e)}[/red]"); return
    if console: console.print(Panel.fit("\\n".join(results), title="Hasil Cloud Detector", style="cyan"))

def cms_detector(target):
    if console: console.print(f"[yellow]⏳ Mendeteksi CMS untuk [bold]{target}[/bold]...[/yellow]")
    cms_indicators = {
        "WordPress": ["wp-content", "wp-includes", "wordpress", "wp-json", "wp-admin"],
        "Joomla": ["joomla", "media/system/js", "index.php?option=com"],
        "Drupal": ["drupal", "sites/all", "core/assets"],
        "Magento": ["magento", "/js/mage/", "skin/frontend"],
        "Shopify": ["shopify", "cdn.shopify.com"],
        "PrestaShop": ["prestashop", "modules/", "themes/"],
        "OpenCart": ["opencart", "catalog/view/theme"],
        "Laravel": ["laravel", "/vendor/laravel", "mix-manifest.json"]
    }
    protocol = detect_protocol(target)
    try:
        r = requests.get(f"{protocol}://{target}", timeout=8); content = r.text.lower()
        detected = []
        for cms, inds in cms_indicators.items():
            for ind in inds:
                if ind in content:
                    detected.append(cms); break
    except Exception as e:
        if console: console.print(f"[red]Error: {str(e)}[/red]"); return
    if detected:
        if console: console.print(Panel.fit("\\n".join([f\"[green]✓ {d}[/green]\" for d in detected]), title=\"CMS Terdeteksi\", style=\"green\"))
    else:
        if console: console.print(Panel.fit(\"Tidak terdeteksi CMS populer\", title=\"CMS Detector\", style=\"yellow\"))

def port_scanner(target, mode="cepat"):
    if console: console.print(f\"[yellow]⏳ Scanning port untuk [bold]{target}[/bold]...[/yellow]\")
    if mode == "lengkap": ports = range(1, 65536)
    else: ports = [21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443]
    open_ports = []
    with Progress() as progress:
        task = progress.add_task(\"[cyan]Scanning port...\", total=len(list(ports)))
        for p in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.settimeout(1)
                res = sock.connect_ex((target, int(p))); sock.close()
                if res == 0: open_ports.append(p)
            except Exception:
                pass
            progress.update(task, advance=1)
    if open_ports:
        if console: console.print(Panel.fit(\"\\n\".join([f\"[green]• Port {pt} terbuka[/green]\" for pt in open_ports]), title=\"Port Terbuka\", style=\"green\"))
    else:
        if console: console.print(Panel.fit(\"Tidak ada port terbuka yang ditemukan\", title=\"Port Scanner\", style=\"yellow\"))

def banner():
    art = r\"\"\"
 █████╗ ███████╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║
███████║███████╗█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║
██╔══██║╚════██║██╔══╝  ╚═══╝ ╚════██║██║     ██╔══██║██║╚██╗██║
██║  ██║███████║███████╗██║     ███████║╚██████╗██║  ██║██║ ╚████║
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝     ╚═════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
\"\"\"
    if console: console.print(Panel.fit(art, title=\"ASEPSCAN (Termux-ready)\", style=\"magenta\"))

def menu():
    banner()
    while True:
        table = Table(title=\"Menu Tools Recon (Termux)\", header_style=\"bold magenta\", show_lines=True)
        table.add_column(\"No\", justify=\"center\", style=\"cyan\")
        table.add_column(\"Fitur\", style=\"yellow\")
        table.add_column(\"Deskripsi\", style=\"green\")
        table.add_row(\"1\", \"WHOIS Lookup\", \"Cek informasi domain\")
        table.add_row(\"2\", \"WhatWeb\", \"Deteksi teknologi website\")
        table.add_row(\"3\", \"Nmap\", \"Scan port & service\")
        table.add_row(\"4\", \"Subdomain\", \"Cari subdomain tersembunyi\")
        table.add_row(\"5\", \"Gobuster\", \"Bruteforce direktori/file\")
        table.add_row(\"6\", \"Cek Header\", \"Analisis header HTTP\")
        table.add_row(\"7\", \"Deteksi WAF\", \"Identifikasi Web Application Firewall\")
        table.add_row(\"8\", \"UserRecon\", \"Cek username di sosmed & platform\")
        table.add_row(\"9\", \"GoDorker\", \"Google Dorking otomatis\")
        table.add_row(\"10\", \"DNS Recon\", \"Pengumpulan informasi DNS\")
        table.add_row(\"11\", \"Email Harvester\", \"Cari email terkait domain\")
        table.add_row(\"12\", \"Cloud Detector\", \"Deteksi layanan cloud\")
        table.add_row(\"13\", \"CMS Detector\", \"Identifikasi Content Management System\")
        table.add_row(\"14\", \"Port Scanner\", \"Scan port umum/lengkap\")
        table.add_row(\"0\", \"Keluar\", \"Exit program\")
        if console: console.print(table)
        choice = console.input(\"[bold cyan]Pilih nomor menu: [/]\").strip() if console else input(\"Pilih: \").strip()
        try:
            if choice == \"1\": target = console.input(\"[bold green]Masukkan domain: [/]\").strip(); whois_lookup(target)
            elif choice == \"2\": target = console.input(\"[bold green]Masukkan URL target: [/]\").strip(); whatweb_scan(target)
            elif choice == \"3\": target = console.input(\"[bold green]Masukkan IP/domain target: [/]\").strip(); mode = console.input(\"[bold green]Pilih mode (cepat/lengkap): [/]\").strip().lower(); nmap_scan(target, mode)
            elif choice == \"4\": target = console.input(\"[bold green]Masukkan domain utama: [/]\").strip(); mode = console.input(\"[bold green]Pilih mode (cepat/lengkap): [/]\").strip().lower(); subdomain_checker(target, mode)
            elif choice == \"5\": target = console.input(\"[bold green]Masukkan URL target: [/]\").strip(); mode = console.input(\"[bold green]Pilih mode (cepat/lengkap): [/]\").strip().lower(); gobuster_scan(target, mode)
            elif choice == \"6\": target = console.input(\"[bold green]Masukkan URL target: [/]\").strip(); cek_header(target)
            elif choice == \"7\": target = console.input(\"[bold green]Masukkan URL target: [/]\").strip(); waf_detection(target)
            elif choice == \"8\": username = console.input(\"[bold green]Masukkan username: [/]\").strip(); userrecon_scan(username)
            elif choice == \"9\": target = console.input(\"[bold green]Masukkan domain/target: [/]\").strip(); godorker_scan(target)
            elif choice == \"10\": target = console.input(\"[bold green]Masukkan domain: [/]\").strip(); dns_recon(target)
            elif choice == \"11\": target = console.input(\"[bold green]Masukkan domain: [/]\").strip(); email_harvester(target)
            elif choice == \"12\": target = console.input(\"[bold green]Masukkan domain: [/]\").strip(); cloud_detector(target)
            elif choice == \"13\": target = console.input(\"[bold green]Masukkan URL website: [/]\").strip(); cms_detector(target)
            elif choice == \"14\": target = console.input(\"[bold green]Masukkan IP/domain: [/]\").strip(); mode = console.input(\"[bold green]Pilih mode (cepat/lengkap): [/]\").strip().lower(); port_scanner(target, mode)
            elif choice == \"0\": 
                if console: console.print(Panel.fit(\"[bold red]Keluar dari program...\", title=\"Sampai Jumpa\", style=\"red\")); break
            else: 
                if console: console.print(Panel.fit(\"[bold red]Pilihan gak valid! Coba lagi.\", style=\"red\"))
        except KeyboardInterrupt:
            break
        except Exception as e:
            if console: console.print(f\"[red]Error: {str(e)}[/red]\")
        if console: console.input(\"\\n[bold yellow]Tekan Enter untuk lanjut...[/]\")
        else: input(\"Enter untuk lanjut...\")

if __name__ == \"__main__\":
    try:
        if os.environ.get(\"SKIP_BOOTSTRAP\", \"0\") != \"1\":
            if console: console.print(\"[cyan]Mulai bootstrap dependency... (bisa butuh waktu dan koneksi internet)[/cyan]\"); bootstrap_system_tools()
        menu()
    except KeyboardInterrupt:
        if console: console.print(\"\\n[bold red]Program dihentikan paksa![/bold red]\"); sys.exit(0)
    except Exception as e:
        if console: console.print(f\"[bold red]Fatal error: {str(e)}[/bold red]\"); sys.exit(1)
