import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import csv
import time
import socket
import dns.resolver
import subprocess
import platform
import os

def resolve_domain(domain, record_type='A', expected_ip=None, output_callback=None, done_callback=None):
    try:
        log = []
        if not domain:
            output_callback("❌ Please enter a domain.")
            if done_callback:
                done_callback()
            return

        log.append(f"\n🔍 Resolving {domain} ({record_type})...")
        start_time = time.time()
        answers = dns.resolver.resolve(domain, record_type)
        end_time = time.time()
        response_time_ms = (end_time - start_time) * 1000

        log.append(f"✅ {record_type} Records for {domain}:")
        resolved_ips = [str(answer) for answer in answers]
        for ip in resolved_ips:
            log.append(f"   → {ip}")

        log.append(f"⏱️ Response Time: {response_time_ms:.2f} ms")

        if expected_ip:
            if expected_ip in resolved_ips:
                log.append("🛡️ Security Check Passed: IP matches expected.")
            else:
                log.append("⚠️ Security Alert: Resolved IP does not match expected!")

        for ip in resolved_ips:
            hop_count = get_hop_count(ip, record_type, log)
            if hop_count is not None:
                log.append(f"📡 Estimated Hops to {ip}: {hop_count}")
            else:
                log.append(f"⚠️ Could not determine hops to {ip}.")
            log_to_csv(domain, record_type, response_time_ms, [ip], hop_count)

        if output_callback:
            output_callback("\n".join(log))

    except dns.resolver.NoAnswer:
        output_callback("❌ No answer received (record type may not exist).")
    except dns.resolver.NXDOMAIN:
        output_callback("❌ Domain does not exist.")
    except Exception as e:
        output_callback(f"❌ Error: {e}")
    finally:
        if done_callback:
            done_callback()

def get_hop_count(ip, record_type, log_list=None):
    try:
        system_platform = platform.system().lower()
        if log_list is not None:
            log_list.append(f"📡 Running traceroute to {ip} on {system_platform}...")

        if system_platform == "windows":
            cmd = ["tracert"]
            if record_type == "AAAA":
                cmd.append("-6")
            cmd.extend(["-h", "30", "-w", "100", ip])
        else:
            if record_type == "AAAA":
                cmd = ["traceroute6", "-m", "30", "-w", "1", ip]
            else:
                cmd = ["traceroute", "-m", "30", "-w", "1", ip]

        if log_list is not None:
            log_list.append(f"💻 Executing command: {' '.join(cmd)}")

        result = subprocess.run(cmd, capture_output=True, text=True)
        if log_list is not None:
            log_list.append("📥 Raw traceroute output:\n" + result.stdout)

        return parse_hop_count(result.stdout, ip)

    except Exception as e:
        if log_list is not None:
            log_list.append(f"⚠️ Error during hop count: {e}")
        return None

def parse_hop_count(traceroute_output, target_ip):
    hops = 0
    for line in traceroute_output.splitlines():
        if line.strip() and line.strip()[0].isdigit():
            hops += 1
            if target_ip in line or target_ip.replace('.', '-') in line:
                return hops
    return None

def log_to_csv(domain, record_type, response_time_ms, resolved_ips, hops=None):
    file_exists = os.path.exists("dns_query_log.csv")
    with open("dns_query_log.csv", "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(["Domain", "Record Type", "Response Time", "Resolved IPs", "Hops"])
        writer.writerow([
            domain,
            record_type,
            f"{response_time_ms:.2f} ms",
            ", ".join(resolved_ips),
            hops if hops is not None else "N/A"
        ])

# ========================= GUI Class ===========================

class DNSAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Analyzer GUI")
        self.root.geometry("700x500")

        frame = ttk.LabelFrame(root, text="DNS Query")
        frame.pack(padx=10, pady=10, fill="x")

        ttk.Label(frame, text="Domain:").grid(column=0, row=0, padx=5, pady=5, sticky='w')
        self.domain_entry = ttk.Entry(frame, width=50)
        self.domain_entry.grid(column=1, row=0, padx=5, pady=5)

        ttk.Label(frame, text="Record Type:").grid(column=0, row=1, padx=5, pady=5, sticky='w')
        self.record_combo = ttk.Combobox(frame, values=["A", "MX", "NS", "CNAME", "AAAA"], state="readonly")
        self.record_combo.current(0)
        self.record_combo.grid(column=1, row=1, padx=5, pady=5)

        ttk.Label(frame, text="Expected IP (optional):").grid(column=0, row=2, padx=5, pady=5, sticky='w')
        self.expected_entry = ttk.Entry(frame, width=50)
        self.expected_entry.grid(column=1, row=2, padx=5, pady=5)

        self.run_button = ttk.Button(frame, text="Run Analysis", command=self.run_analysis)
        self.run_button.grid(column=1, row=3, pady=10, sticky='e')

        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20)
        self.output_area.pack(padx=10, pady=10, fill="both", expand=True)

    def run_analysis(self):
        domain = self.domain_entry.get().strip()
        record_type = self.record_combo.get()
        expected_ip = self.expected_entry.get().strip()

        if not domain:
            messagebox.showerror("Input Error", "Please enter a domain.")
            return

        self.output_area.delete("1.0", tk.END)
        self.run_button.config(state=tk.DISABLED)

        thread = threading.Thread(
            target=resolve_domain,
            args=(domain, record_type, expected_ip if expected_ip else None, self.display_output, self.enable_button)
        )
        thread.start()

    def display_output(self, text):
        self.output_area.insert(tk.END, text + "\n")
        self.output_area.see(tk.END)

    def enable_button(self):
        self.run_button.config(state=tk.NORMAL)

# ========================= Run App ===========================

if __name__ == "__main__":
    root = tk.Tk()
    app = DNSAnalyzerGUI(root)
    root.mainloop()
