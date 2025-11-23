import logging
import os
import argparse
import csv
from datetime import datetime
from scapy.all import *
from scapy.layers.http import HTTPRequest # import HTTP packet
from colorama import init, Fore

# ----------- Setup Colorama for colorized output -----------
init(autoreset=True)
GREEN = Fore.GREEN
RED = Fore.RED
YELLOW = Fore.YELLOW
CYAN = Fore.CYAN
RESET = Fore.RESET

# ----------- Logging configuration -----------
def setup_logging(debug=False):
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(levelname)s - %(message)s"
    )

# ----------- CSV writing (optional) -----------
def save_to_csv(data, filename="http_sniff_log.csv"):
    file_exists = os.path.isfile(filename)
    with open(filename, mode="a", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        if not file_exists:
            writer.writeheader()
        writer.writerow(data)

# ----------- Packet Processing -----------
def process_packet(packet):
    """
    Called for each sniffed packet. Logs and prints useful HTTP info.
    """
    if packet.haslayer(HTTPRequest):
        try:
            url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        except Exception:
            url = "<parse error>"
        ip = packet[IP].src
        method = packet[HTTPRequest].Method.decode() if packet[HTTPRequest].Method else "-"
        user_agent = packet[HTTPRequest].User_Agent.decode() if hasattr(packet[HTTPRequest], "User_Agent") and packet[HTTPRequest].User_Agent else ""
        cookies = packet[HTTPRequest].Cookie.decode() if hasattr(packet[HTTPRequest], "Cookie") and packet[HTTPRequest].Cookie else ""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        msg = (
            f"{CYAN}{timestamp}{RESET} "
            f"{GREEN}[{ip}]{RESET} "
            f"{YELLOW}{method} {url}{RESET}"
        )
        print(msg)
        logging.info(f"{ip} {method} {url} UA:{user_agent}")
        if user_agent:
            print(f"{CYAN}User-Agent: {user_agent}{RESET}")
        if cookies:
            print(f"{CYAN}Cookies: {cookies}{RESET}")

        if show_raw and packet.haslayer(Raw) and method == "POST":
            try:
                print(f"{RED}[*] Raw POST data: {packet[Raw].load}{RESET}")
            except Exception:
                print(f"{RED}[!] Raw POST parse error{RESET}")

        # Save to CSV if requested
        if save_csv:
            save_to_csv({
                "timestamp": timestamp,
                "ip": ip,
                "method": method,
                "url": url,
                "user_agent": user_agent,
                "cookies": cookies,
                "raw_post": packet[Raw].load if show_raw and packet.haslayer(Raw) and method == "POST" else ""
            }, csv_filename)

# ----------- Sniffing Function -----------
def sniff_packets(iface=None):
    """
    Sniffs HTTP traffic (TCP/80) on specified interface.
    """
    logging.info(f"Starting sniff on iface: {iface or 'default'} (CTRL+C to stop)")
    try:
        sniff(
            filter="tcp port 80",
            prn=process_packet,
            iface=iface,
            store=False
        )
    except KeyboardInterrupt:
        logging.info("Sniff stopped by user.")

# ----------- MAIN -----------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="HTTP Packet Sniffer (advanced). Suggested to run in MITM (arp spoof) context. Supports CSV log, debug, filters."
    )
    parser.add_argument("-i", "--iface", help="Interface to use (default: scapy default)")
    parser.add_argument("--debug", action="store_true", help="Active les logs DEBUG")
    parser.add_argument("--show-raw", action="store_true", help="Affiche le contenu brut POST si présent")
    parser.add_argument("--csv", help="Enregistre les résultats dans un fichier CSV (ex: --csv http_log.csv)")
    args = parser.parse_args()

    iface = args.iface
    show_raw = args.show_raw
    save_csv = True if args.csv else False
    csv_filename = args.csv if args.csv else "http_sniff_log.csv"

    setup_logging(debug=args.debug)
    logging.info("HTTP Sniffer started (improved version)")

    sniff_packets(iface)