import tkinter as tk
from tkinter import messagebox
import nmap
import time
import json

# Function to scan a single IP address using Nmap
def scan_with_nmap(start_ip, port, timeout=30):

    scanner = nmap.PortScanner()
    results = {}
    try:
        print(f"Starting Nmap scan for {start_ip} on port {port}...")  # log
        scanner.scan(hosts=start_ip, arguments=f"-Pn -T4 -p {port}")

        # Check if the host is up and the port is open
        if start_ip in scanner.all_hosts() and scanner[start_ip].state() == "up":
            if int(port) in scanner[start_ip]["tcp"]:
                port_status = scanner[start_ip]["tcp"][int(port)]["state"]
                results[start_ip] = f"Port {port} is {port_status}"
                print(f"{start_ip}: Port {port} is {port_status}")
            else:
                results[start_ip] = f"Port {port} is closed"
                print(f"{start_ip}: Port {port} is closed")
        else:
            results[start_ip] = "Host is inactive"
            print(f"{start_ip}: Host is inactive")

        print(results)
        return None, results

    except Exception as e:
        print(f"Error during scan: {e}")
        return str(e), None

# Function to write active IPs to a JSON file
def write_to_json(active_ips):
    try:
        # Read existing data from JSON file
        try:
            with open("active_ips.json", 'r') as json_file:
                existing_data = json.load(json_file)
        except (FileNotFoundError, json.JSONDecodeError):
            existing_data = []

        # Append new active IPs
        existing_data.extend(active_ips)

        # Write updated data back to the JSON file
        with open(filename, 'w') as json_file:
            json.dump(existing_data, json_file, indent=4)

        print(f"Active IPs written to {filename}")

    except Exception as e:
        print(f"Error writing to JSON file: {e}")

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner with Nmap")
        self.create_widgets()

    def create_widgets(self):

        # Input Fields
        tk.Label(self.root, text="Start IP:").grid(row=0, column=0, padx=5, pady=5)
        self.start_ip_entry = tk.Entry(self.root, width=20)
        self.start_ip_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(self.root, text="Port:").grid(row=1, column=0, padx=5, pady=5)
        self.port_entry = tk.Entry(self.root, width=20)
        self.port_entry.grid(row=1, column=1, padx=5, pady=5)

        # Scan Button
        self.scan_button = tk.Button(self.root, text="Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=10)

        # Results Display
        self.results_text = tk.Text(self.root, width=50, height=15, state='disabled')
        self.results_text.grid(row=3, column=0, columnspan=2, padx=5, pady=5)

    def start_scan(self):
        start_ip = self.start_ip_entry.get().strip()
        port = self.port_entry.get().strip()

        # Clear previous results
        self.results_text.config(state='normal')
        #delete all text from first line to end 1.0 line.position 
        self.results_text.delete('1.0', tk.END)
        #Prevent user from typing in the text box
        self.results_text.config(state='disabled')

        # Validate input
        if not start_ip or not port.isdigit():
            messagebox.showerror("Error", "Please enter a valid IP and port.")
            return

        try:
            # Display a message during the scan process
            self.results_text.config(state='normal')
            self.results_text.insert(tk.END, "Scanning started...\n")
            self.results_text.config(state='disabled')

            # Start the scan
            error, results = scan_with_nmap(start_ip, port)
            if error:
                self.results_text.config(state='normal')
                self.results_text.insert(tk.END, f"Error: {error}\n")
                self.results_text.config(state='disabled')
                return

            # Display results and collect active IPs
            active_ips = []
            self.results_text.config(state='normal')
            for ip, status in results.items():
                self.results_text.insert(tk.END, f"{ip}: {status}\n")
                if "open" in status:
                    active_ips.append({"ip": ip, "port": port})
            self.results_text.config(state='disabled')

            # Write active IPs to JSON file
            if active_ips:
                write_to_json(active_ips)
            else:
                self.results_text.config(state='normal')
                self.results_text.insert(tk.END, "No active devices found.\n")
                self.results_text.config(state='disabled')

        except Exception as e:
            messagebox.showerror("Error", f"Unexpected error: {e}")
            print(f"Debug Error: {e}")

# Main Function
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
