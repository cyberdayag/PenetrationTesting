![Image](image/image.png)

# Penetration Testing | PROJECT: VULNER

This project was completed as part of the course "Cyber Security" (7736/37) — Information Security and Corporate Network Protection, at John Bryce College.

---

## Project Description

This script automates a penetration testing workflow:

- Checks and installs required utilities.
- Masks MAC and IP (via Nipe/TOR) and verifies anonymity.
- Allows user input: target network, scan mode (Basic/Full), output folder.
- Performs TCP/UDP scans, service detection, NSE scripts (Full mode), and weak password checks (SSH, FTP, Telnet, RDP).
- Logs and organizes results in structured folders.
- Optionally compresses results into a ZIP file.
- Restores original MAC and IP after completion.

---

## Tools and Features

- **Nmap** – Network scanning, service detection, NSE scripts
- **Hydra** – Brute-force login attempts
- **Nipe** – TOR anonymity
- **Macchanger** – Randomizes MAC address
- **Curl, Wget, FTP** – Downloads and network operations
- **Zip** – Archiving results
- **Additional utilities**: ```ssh, sshpass, rdesktop, telnet, tree, fping, perl, xsltproc, tor```

---

## Directory Structure

``` bash
user folder (scan results)/
├── 192.168.xx.xx/
│   ├── nmap_ftp_brute_*.txt
│   ├── nmap_ssh_brute_*.txt
│   ├── nmap_telnet_brute_*.txt
│   ├── protocol_for_scan.txt
│   ├── res_tcp_*.html
│   ├── res_tcp_*.txt
│   └── res_tcp_*.xml
├── 192.168.xx.x1/
├── ...
└── live_hosts.txt

```
- Each host has its own folder containing scan results and bruteforce attempts.
- live_hosts.txt contains all active hosts detected in the network.

---

## Installation

**Clone the repository:**
```bash
git clone https://github.com/cyberdayag/PenetrationTesting.git
```

---

## Usage

**Run the script in your terminal:**

```bash
cd PenetrationTesting
chmod +x TMagen773637.s21.ZX301.sh
sudo ./TMagen773637.s21.ZX301.sh
```

#### Follow the prompts to:
- Enter the target network (CIDR notation, e.g., 192.168.29.0/24)
- Choose scan mode (Basic/Full)
- Enter the output folder name
- Optionally select a custom password list

---

## Disclaimer

Do not run this script on networks you do not own or have explicit permission to test.
This project is for educational purposes only and demonstrates penetration testing concepts in a safe lab environment.

