# GUI-Based Port Scanner *Minty*

This script is a **Graphical User Interface (GUI) port scanner** built using Python and the **Tkinter** library. It utilizes the **nmap** module to perform network port scanning and display results in an interactive table. The application allows users to specify an IP address (or domain), choose a port range, select a scan type, and view the results in real-time.

---

## **Features**
- **Get Local IP Address**: Fetches the user's local IP address automatically.
- **Validate IP Address**: Supports both **IPv4** and **IPv6**.
- **Port Scanning**: Uses **Nmap** to scan for open ports on a target.
- **Multiple Scan Types**:
  - **TCP SYN Scan** (Stealth Scan)
  - **UDP Scan**
  - **Comprehensive Scan** (detailed analysis with OS detection)
- **Real-Time Progress Indicator**: A progress bar updates during the scan.
- **Results Display**: Open ports are shown in a **Treeview Table**.
- **Save Scan Results**: Users can save scan reports as **.txt files**.

---

## **How It Works**
1. **Enter Target IP Address or Website**
   - Users can enter an **IP address** manually or click **"Get My IP Address"** to auto-fill their local IP.

2. **Specify Port Range**
   - Example: `80-100` (If left blank, the script scans all ports `1-65535`).

3. **Select Scan Type**
   - **TCP SYN Scan** (`-sS`)
   - **UDP Scan** (`-sU`)
   - **Comprehensive Scan** (`-sV -sC -A -O`)

4. **Start Scanning**
   - Clicking **"Scan Ports"** starts the process in a separate thread to keep the UI responsive.
   - Scan progress is displayed with a **progress bar**.
   - Results appear in a table with details like **port number, protocol, state, service, version, and additional information**.

5. **Save Results**
   - Once scanning is complete, results can be saved as a **text file** for further analysis.

---

## **Technical Details**
- **Uses `nmap`**: The script integrates with the `python-nmap` library to execute Nmap commands.
- **Multithreading for Efficiency**: Scanning runs in a background thread to prevent UI freezing.
- **GUI Built with Tkinter**: The user interface is interactive and easy to use.
- **Port Information Extraction**: Retrieves extra details like **service name, version, product info, and additional notes** from open ports.

---

## **Dependencies**
To run this script, ensure you have the following installed:

```bash
pip install python-nmap
```

Nmap must also be installed on your system. You can download it from:
[https://nmap.org/download.html](https://nmap.org/download.html)

---

## **Usage**
Run the script with Python:

```bash
python port_scanner.py
```

A window will open where you can enter details and start scanning.

---

## **Note**
- **Administrator Privileges** may be required for certain scan types.
- This tool is intended for **ethical use**. Do not scan networks without permission.

---

This port scanner provides a **simple yet powerful** way to analyze network security and discover open ports on any given host. 🚀
