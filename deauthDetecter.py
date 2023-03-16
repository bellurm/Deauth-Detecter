from scapy.all import *
from tkinter import messagebox
from datetime import datetime
import os

def deauth_packet(pkt):
    date = datetime.now()
    if pkt.haslayer(Dot11Deauth):
        warn = messagebox.showwarning("Deauth Warn", f"Deauth packets are detected and saved here:\n{os.getcwd()}/infoAboutAttacker.txt")
        if warn == "ok":
            with open(f"{os.getcwd()}/infoAboutAttacker.txt", "a", encoding='utf-8') as infoFile:
                infoFile.writelines([f"\nDate: {date}\n{pkt.show}\n{'-' * 30}"])
                exit(0)
        
sniff(prn=deauth_packet, iface="wlan0mon")
