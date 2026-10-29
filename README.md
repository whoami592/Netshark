<div align="center">

```
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⣿⠂⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣾⣿⣿⣿⣿⣿⣿⣦⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣴⣿⢿⣷⠒♥️⣾⣾⣿⣿⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣴⣿⠟⠁⠀⢿⣿⠁⣿⣿⣿⠻⣿⣄⠀⠀⠀⠀
⠀⠀⣠⡾⠟⠁⠀⠀⠀⢸⣿⣸⣿⣿⣿⣆⠙⢿⣷⡀⠀⠀
⣰⡿⠋⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⠀⠀⠉⠻⣿⡀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⣿⣿⣿⣿⣿⣿⣆⠂⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⡿⣿⣿⣿⣿⡄⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⣿⣿⠿⠟⠀⠀⠻⣿⣿⡇⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢀⣾⡿⠃⠀⠀⠀⠀⠀⠘⢿⣿⡀⠀⠀⠀
⠀⠀⠀⠀⠀⣰⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷⡀⠀⠀
⠀⠀⠀⠀⢠⣿⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠻⣿⣧⠀⠀
⠀⠀⠀⢀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⣆⠀
⠀⠀⠠⢾⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣷
```

# 🦈 Netshark

**A complete, menu-driven networking toolkit written in pure Python 3 (standard library only).**

*Coded by Mr Sabaz Ali Khan, Cyber Security Engineer*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?logo=python&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-none-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Use](https://img.shields.io/badge/use-authorized%20testing%20only-red)

</div>

---

## 📖 Overview

**Netshark** puts the everyday tools of a network engineer or security professional into a single interactive terminal menu. It needs **no third-party packages**: just Python 3 and a terminal. DNS queries are built and parsed by Netshark's own UDP resolver, and WHOIS, HTTP and TLS checks use Python's built-in `socket`, `http.client` and `ssl` modules.

Every result from a session can be exported to a structured JSON report.

## ✨ Features

| #  | Tool | Description |
|----|------|-------------|
| 1  | **Local network information** | Hostname, local IP addresses, default gateway and interface details |
| 2  | **Ping (ICMP)** | Uses the system `ping` command and shows live output |
| 3  | **TCP latency test** | Connects to a TCP port repeatedly and reports min / avg / max latency, jitter and packet loss |
| 4  | **Ping sweep** | Discovers live hosts in a CIDR range (e.g. `192.168.1.0/24`) using multiple threads |
| 5  | **TCP port scanner** | Multi-threaded scan with banner grabbing; supports common ports, 1-1024, or a custom range |
| 6  | **DNS lookup** | Custom UDP resolver for `A`, `AAAA`, `MX`, `NS`, `TXT` and `CNAME` records |
| 7  | **Reverse DNS lookup** | Resolves an IP address back to a hostname |
| 8  | **Traceroute** | Shows the network path to a target (`tracert` on Windows, `traceroute` on Linux/macOS) |
| 9  | **WHOIS lookup** | Queries IANA, follows the referral to the authoritative WHOIS server and shows the result |
| 10 | **HTTP & security header check** | Fetches response headers over HTTP/HTTPS and checks for common security headers |
| 11 | **SSL/TLS certificate inspector** | Shows subject, issuer, validity dates, days left, TLS version, cipher and SANs |
| 12 | **Subnet calculator** | Network, netmask, wildcard, broadcast, usable hosts, first/last host (IPv4 and IPv6) |
| 13 | **Save session report** | Exports all results from the current session to a timestamped JSON file |

## 🧰 Requirements

- **Python 3.8 or newer**
- A terminal with ANSI colour support (Windows 10+ Terminal, Linux and macOS terminals all work)
- System utilities for a few tools: `ping`, and `traceroute` (Linux/macOS) or `tracert` (Windows)

No `pip install` is needed.

## 🚀 Installation

```bash
git clone https://github.com/whoami592/Netshark.git
cd Netshark
```

## ▶️ Usage

```bash
python3 Netshark.py
```

On Windows:

```powershell
python Netshark.py
```

Pick an option by typing its number and pressing **Enter**. Most prompts show a default value in `[brackets]`; press **Enter** to accept it. Press `0` to exit, or `Ctrl+C` to interrupt a running task and return to the menu.

> Tip: on some systems, ICMP ping and traceroute may need elevated privileges (`sudo` on Linux/macOS, or an Administrator terminal on Windows).

### Menu preview

```
   1) Local network information
   2) Ping (ICMP)
   3) TCP latency test
   4) Ping sweep (host discovery)
   5) TCP port scanner
   6) DNS lookup (A/AAAA/CNAME/MX/NS/TXT)
   7) Reverse DNS lookup
   8) Traceroute
   9) WHOIS lookup
  10) HTTP & security header check
  11) SSL/TLS certificate inspector
  12) Subnet calculator
  13) Save session report (JSON)
   0) Exit
```

## 📝 Example Report Output

Option **13** writes a JSON file like this:

```json
{
  "tool": "Netshark",
  "author": "Mr Sabaz Ali Khan",
  "generated": "2026-10-29T12:00:00",
  "results": [
    {
      "time": "2026-10-29T11:58:12",
      "section": "port_scan",
      "data": { "target": "192.168.1.1", "open": [[22, "SSH-2.0-OpenSSH"], [80, ""]] }
    }
  ]
}
```

## 🗂️ Project Structure

```
Netshark/
├── Netshark.py    # the complete toolkit (single file)
└── README.md
```

## ⚠️ Legal Disclaimer

Netshark is intended for **network administration, education and authorized security testing only**.

- Only scan, probe or test networks and systems that **you own** or have **explicit written permission** to test.
- Unauthorized scanning may be illegal in your country.
- The author accepts **no liability** for misuse or damage caused by this tool.

## 🤝 Contributing

Contributions, bug reports and feature requests are welcome. Open an issue or submit a pull request.

## 👤 Author

**Mr Sabaz Ali Khan**, Cyber Security Engineer

---

<div align="center">

*Netshark - Networking Toolkit | Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)*

</div>
