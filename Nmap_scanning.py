
import nmap
import threading
import socket
import ipaddress  # Import ipaddress module for IP address validation
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter import filedialog  # Import filedialog module explicitly



def get_local_ip():
    return socket.gethostbyname(socket.gethostname())


def fill_local_ip():
    ip_entry.delete(0, tk.END)
    ip_entry.insert(0, get_local_ip())


def get_ip_version(ip):
    try:
        ipaddress.ip_address(ip)  # Validate the IP address
        if ipaddress.ip_address(ip).version == 4:
            return "IPv4"
        elif ipaddress.ip_address(ip).version == 6:
            return "IPv6"
        else:
            return None
    except ValueError:
        return None


def scan_ports(ip, port_range, scan_type, progress_var, scanning_label):
    open_ports = []

    nm = nmap.PortScanner()

    ip_version = get_ip_version(ip)

    try:
        if not port_range:  # If no port range provided, scan all ports
            port_range = "1-65535"

        if scan_type == "TCP SYN":
            if ip_version == "IPv4":
                nm.scan(ip, arguments=f"-p {port_range} -sS  -A -v -T4")
            elif ip_version == "IPv6":
                nm.scan(ip, arguments=f"-6 -p {port_range} -sS  -A -v -T4")
            else:
                nm.scan(ip, arguments=f"-p {port_range} -sS  -A -v -T4")
        elif scan_type == "UDP":
            if ip_version == "IPv4":
                nm.scan(ip, arguments=f"-p U:{port_range} -sU -sS -T4")
            elif ip_version == "IPv6":
                nm.scan(ip, arguments=f"-6 -p U:{port_range} -sU -sS -T4")
            else:
                nm.scan(ip, arguments=f"-p U:{port_range} -sU -sS -T4")
        elif scan_type == "Comprehensive":
            if ip_version == "IPv4":
                nm.scan(ip, arguments=f"-p {port_range} -sS -sV -sC -A -O ")
            elif ip_version == "IPv6":
                nm.scan(ip, arguments=f"-6 -p {port_range} -sS -sV -sC -A -O ")
            else:
                nm.scan(ip, arguments=f"-p {port_range} -sS -sV -sC -A -O ")
        else:
            messagebox.showerror("Error", "Unsupported scan type selected.")
            return open_ports

        open_ports = get_nmap_open_ports(nm)
    except Exception as e:
        print(e)
        pass

    progress_var.set(100)  # Set progress to 100% after completion
    scanning_label.config(text="Scanning complete")
    return open_ports


def get_nmap_open_ports(nm):
    open_ports = []
    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_info = {
                    "Host": host,
                    "Port": port,
                    "Protocol": proto,
                    "State": nm[host][proto][port]["state"],
                }

                # Include additional information if available
                if "name" in nm[host][proto][port]:
                    port_info["Service"] = nm[host][proto][port]["name"]
                if "version" in nm[host][proto][port]:
                    port_info["Version"] = nm[host][proto][port]["version"]
                if "product" in nm[host][proto][port]:
                    port_info["Product"] = nm[host][proto][port]["product"]
                if "extrainfo" in nm[host][proto][port]:
                    port_info["Extra Info"] = nm[host][proto][port]["extrainfo"]

                open_ports.append(port_info)
    return open_ports


def start_scan(progress_var, scanning_label):
    ip = ip_entry.get()
    port_range = port_range_entry.get()
    scan_type = scan_var.get()

    if not ip:
        messagebox.showerror("Error", "Please enter an IP address.")
        return

    result_tree.delete(*result_tree.get_children())  # Clear previous results

    progress_var.set(0)  # Reset progress to 0%
    scanning_label.config(text="Scanning in progress...")

    def scan_thread():
        for i in range(101):
            # Simulate scanning progress
            window.after(50, progress_var.set, i)
            window.update_idletasks()

        open_ports = scan_ports(ip, port_range, scan_type, progress_var, scanning_label)

        if open_ports:
            for port_info in open_ports:
                result_tree.insert("", "end", values=list(port_info.values()))
        else:
            result_tree.insert("", "end", values=("No open ports found.",))

        window.after(0, lambda: result_tree.config(selectmode="none"))
        save_button.config(state=tk.NORMAL)  # Enable the save button after scanning completes

    scan_thread = threading.Thread(target=scan_thread)
    scan_thread.start()


def save_to_file():
    try:
        file_path = tk.filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            with open(file_path, "w") as file:
                for item in result_tree.get_children():
                    values = result_tree.item(item, "values")
                    file.write("\t".join(values) + "\n")
            messagebox.showinfo("Success", "Scan results saved successfully!")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while saving the file: {str(e)}")


window = tk.Tk()
window.title("Port Scanner")

ip_label = tk.Label(window, text="Enter IP Address or Website:")
ip_label.pack()
ip_entry = tk.Entry(window)
ip_entry.pack()

# Button to get local IP
get_ip_button = tk.Button(window, text="Get My IP Address", command=fill_local_ip)
get_ip_button.pack()

port_range_label = tk.Label(window, text="Enter Port Range (e.g., 80-100):")
port_range_label.pack()
port_range_entry = tk.Entry(window)
port_range_entry.pack()

scan_var = tk.StringVar(value="TCP SYN")  # Default to TCP SYN
scan_label = tk.Label(window, text="Select Scan Type:")
scan_label.pack()
scan_menu = tk.OptionMenu(window, scan_var, "TCP SYN", "UDP", "Comprehensive")
scan_menu.pack()

scan_button = tk.Button(window, text="Scan Ports", command=lambda: start_scan(progress_var, scanning_label))
scan_button.pack()

result_tree = ttk.Treeview(window, columns=("Host", "Port", "Protocol", "State", "Service", "Version", "Product", "Extra Info"))
result_tree.heading("#0", text="Index")
result_tree.heading("Host", text="Host")
result_tree.heading("Port", text="Port")
result_tree.heading("Protocol", text="Protocol")
result_tree.heading("State", text="State")
result_tree.heading("Service", text="Service")
result_tree.heading("Version", text="Version")
result_tree.heading("Product", text="Product")
result_tree.heading("Extra Info", text="Extra Info")
result_tree.pack()

# Save button
save_button = tk.Button(window, text="Save Scan Results", command=save_to_file, state=tk.DISABLED)
save_button.pack()

# Scanning Label
scanning_label = tk.Label(window, text="Scanning Progress:")
scanning_label.pack()

# Progress Bar
progress_var = tk.DoubleVar()
progress_bar = ttk.Progressbar(window, mode="determinate", length=200, variable=progress_var)
progress_bar.pack()

window.mainloop()
