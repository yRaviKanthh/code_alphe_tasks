# Importing the required packages.
import scapy.all
import psutil
from prettytable import PrettyTable
import subprocess
import re
import time
from colorama import Fore, Style
from scapy.layers.inet import IP, TCP, UDP, ICMP

# Function to get the current MAC address of the system.
def get_current_mac(interface):
    try:
        output = subprocess.check_output(["ipconfig", "/all"]).decode()
        mac_address = re.search(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", output)
        return mac_address.group(0) if mac_address else "No MAC found"
    except Exception as e:
        print(f"Error getting MAC address: {e}")
        return None

# Function to get the current IP address of the system.
def get_current_ip(interface):
    try:
        output = subprocess.check_output(["ipconfig"]).decode()
        # Regular expression for IPv4 address
        ip = re.search(r"IPv4 Address[.\s]+:\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", output)
        return ip.group(1) if ip else "No IP found"
    except Exception as e:
        print(f"Error getting IP address: {e}")
        return None

# Function to get IP table of the system.
def ip_table():
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f"{Fore.GREEN}Interface", "MAC Address", f"IP Address{Style.RESET_ALL}"])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k, f"{Fore.YELLOW}No MAC assigned{Style.RESET_ALL}", ip])
    print(t)

# Function to sniff the packets with a timeout or packet count limit.
def sniff(interface, packet_limit=10, timeout=30):
    print(f"[*] Sniffing for {packet_limit} packets or {timeout} seconds...")
    scapy.all.sniff(iface=interface, prn=packet_callback, store=False, count=packet_limit, timeout=timeout)
    print(f"\n[***] Stopped sniffing after capturing {packet_limit} packets or {timeout} seconds. [***]")

# Packet callback function to process sniffed packets.
def packet_callback(packet):
    packet_details = f"{Fore.CYAN}Packet Details:{Style.RESET_ALL}\n"

    if IP in packet:
        packet_details += f"{Fore.GREEN}IP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source IP: {packet[IP].src} -> Destination IP: {packet[IP].dst}\n"
        packet_details += f"ID: {packet[IP].id} ; Version: {packet[IP].version} ; Length: {packet[IP].len} ; Flags: {packet[IP].flags}\n"
        packet_details += f"Protocol: {packet[IP].proto} ; TTL: {packet[IP].ttl} ; Checksum: {packet[IP].chksum}\n"

    if TCP in packet:
        packet_details += f"{Fore.YELLOW}TCP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[TCP].sport} -> Destination Port: {packet[TCP].dport}\n"
        packet_details += f"Sequence Number: {packet[TCP].seq} ; Acknowledgment Number: {packet[TCP].ack}\n"
        packet_details += f"Window: {packet[TCP].window} ; Checksum: {packet[TCP].chksum}\n"
        packet_details += f"Flags: {packet[TCP].flags} ; Options: {packet[TCP].options}\n"

    if UDP in packet:
        packet_details += f"{Fore.YELLOW}UDP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Source Port: {packet[UDP].sport}\n"
        packet_details += f"Destination Port: {packet[UDP].dport}\n"

    if ICMP in packet:
        packet_details += f"{Fore.YELLOW}ICMP Layer:{Style.RESET_ALL}\n"
        packet_details += f"Type: {packet[ICMP].type}\n"
        packet_details += f"Code: {packet[ICMP].code}\n"

    print(packet_details)

# Main function to start the packet sniffer.
def main():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start ARP Spoofer Before Using this Module [***]{Style.RESET_ALL}")
    try:
        ip_table()
        interface = input("[*] Please enter the interface name: ")
        print(f"Current IP: {get_current_ip(interface)}")
        print(f"Current MAC: {get_current_mac(interface)}")
        print("[*] Sniffing Packets...")
        sniff(interface, packet_limit=10, timeout=10)  # Adjust packet_limit and timeout as needed
        print(f"{Fore.YELLOW}\n[*] Interrupt...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Stopping the Sniffer...{Style.RESET_ALL}")
        time.sleep(3)

if __name__ == "__main__":
    main()
