import sys
import threading
import time
from scapy.all import ARP, Ether, srp, sniff

class ARPScanner:
    def __init__(self, subnet, timeout=2, sniff_time=30):
        self.subnet = subnet
        self.timeout = timeout
        self.sniff_time = sniff_time
        self.baseline = {}     # {ip: mac}
        self.detected = set()  # {(ip, original_mac, spoof_mac)}

    def scan_network(self):
        """
        Send ARP who-has to the subnet and build baseline IP->MAC mapping.
        """
        try:
            print(f"[+] Scanning network {self.subnet} for live hosts...")
            arp_request = ARP(pdst=self.subnet)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            answered, _ = srp(broadcast/arp_request, timeout=self.timeout, verbose=False)

            for sent, received in answered:
                ip = received.psrc
                mac = received.hwsrc
                self.baseline[ip] = mac
                print(f"    ↳ Found host {ip} at {mac}")
        except Exception as e:
            print(f"[!] Error during network scan: {e}")
            sys.exit(1)

        if not self.baseline:
            print("[!] No hosts found. Exiting.")
            sys.exit(1)

    def _process_arp(self, packet):
        """
        Callback for sniffed ARP packets. Detect IP->MAC conflicts.
        """
        if packet.haslayer(ARP) and packet[ARP].op == 2:  # ARP is-at (response)
            ip = packet[ARP].psrc
            mac = packet[ARP].hwsrc
            original_mac = self.baseline.get(ip)

            # Conflict: IP known but MAC differs
            if original_mac and mac != original_mac:
                conflict = (ip, original_mac, mac)
                if conflict not in self.detected:
                    self.detected.add(conflict)
                    print("\n[!!!] ARP Spoofing Detected!")
                    print(f"    Victim IP : {ip}")
                    print(f"    Victim MAC: {original_mac}")
                    print(f"    Attacker IP : {ip}")
                    print(f"    Attacker MAC: {mac}\n")

    def sniff_arp(self):
        """
        Sniff ARP packets for a duration and process each one.
        """
        print(f"[+] Starting ARP sniffing for {self.sniff_time} seconds...")
        try:
            sniff(filter="arp", prn=self._process_arp,
                  timeout=self.sniff_time, store=False)
        except Exception as e:
            print(f"[!] Error during ARP sniffing: {e}")

    def run(self):
        """
        Execute scan and sniffing in sequence.
        """
        self.scan_network()
        self.sniff_arp()
        if not self.detected:
            print("[+] No ARP spoofing detected during the monitoring period.")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Detect ARP spoofing in a local network."
    )
    parser.add_argument(
        "-s", "--subnet",
        required=True,
        help="Target subnet in CIDR notation (e.g., 192.168.1.0/24)"
    )
    parser.add_argument(
        "-t", "--timeout",
        type=int,
        default=2,
        help="Timeout for ARP scan (seconds)"
    )
    parser.add_argument(
        "-d", "--duration",
        type=int,
        default=30,
        help="Duration to sniff ARP packets (seconds)"
    )
    args = parser.parse_args()

    try:
        scanner = ARPScanner(args.subnet, timeout=args.timeout, sniff_time=args.duration)
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] User interrupted. Exiting.")
        sys.exit(0)