#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Netshark- Complete Networking Toolkit (Python 3, standard library only)

Coded by Mr Sabaz Ali Khan - Cyber Security Engineer

Features:
  1.  Local network information
  2.  Ping (system ICMP)
  3.  TCP latency test (min/avg/max/jitter/loss)
  4.  Ping sweep (live host discovery)
  5.  TCP port scanner (with banner grabbing)
  6.  DNS lookup (own UDP resolver: A, AAAA, MX, NS, TXT, CNAME)
  7.  Reverse DNS lookup
  8.  Traceroute
  9.  WHOIS lookup
  10. HTTP header & security header check
  11. SSL/TLS certificate inspector
  12. Subnet calculator
  13. Save session report (JSON)

Use only on networks and systems you own or are authorized to test.
"""

import concurrent.futures as cf
import datetime
import http.client
import ipaddress
import json
import os
import platform
import random
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import time

BANNER = r"""
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
"""

CREDIT = "Netshark - Networking Toolkit | Coded by Mr Sabaz Ali Khan (Cyber Security Engineer)"

C = {
    "r": "\033[91m", "g": "\033[92m", "y": "\033[93m",
    "b": "\033[94m", "m": "\033[95m", "c": "\033[96m",
    "w": "\033[97m", "d": "\033[2m", "x": "\033[0m",
}

IS_WIN = platform.system().lower() == "windows"
REPORT = []  # session log of results


# ----------------------------------------------------------------- helpers
def col(text, color):
    return f"{C[color]}{text}{C['x']}"


def clear():
    os.system("cls" if IS_WIN else "clear")


def show_banner():
    if IS_WIN:
        os.system("")  # enable ANSI on Windows 10+
    print(col(BANNER, "c"))
    print(col("=" * 78, "b"))
    print(col(f"  {CREDIT}", "y"))
    print(col("=" * 78, "b"))
    print(col("  For authorized use only: scan only what you own or have permission to test.\n", "d"))


def ask(prompt, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(col(f"  {prompt}{suffix}: ", "g")).strip()
    return val if val else (default if default is not None else "")


def ask_int(prompt, default, lo=1, hi=10**9):
    try:
        v = int(ask(prompt, default))
    except ValueError:
        return default
    return max(lo, min(hi, v))


def pause():
    input(col("\n  Press Enter to continue...", "d"))


def log(section, data):
    REPORT.append({
        "time": datetime.datetime.now().isoformat(timespec="seconds"),
        "section": section,
        "data": data,
    })


def head(title):
    print("\n" + col(f"  [ {title} ]", "m"))
    print(col("  " + "-" * 60, "d"))


def resolve_host(host):
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        return None


def run_cmd(cmd, stream=False):
    try:
        if stream:
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT, text=True)
            out = []
            for line in p.stdout:
                print("  " + line.rstrip())
                out.append(line.rstrip())
            p.wait()
            return "\n".join(out)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return (r.stdout or "") + (r.stderr or "")
    except FileNotFoundError:
        return f"Command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return "Command timed out."
    except KeyboardInterrupt:
        return "Interrupted."


# ----------------------------------------------------------------- 1. local info
def local_info():
    head("LOCAL NETWORK INFORMATION")
    info = {"hostname": socket.gethostname(), "os": platform.platform()}
    # Determine primary local IP (UDP connect sends no packets)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        info["local_ip"] = s.getsockname()[0]
        s.close()
    except OSError:
        info["local_ip"] = "unavailable"

    try:
        info["fqdn"] = socket.getfqdn()
    except OSError:
        pass

    # Default gateway (Linux) / generic fallback
    gw = None
    if os.path.exists("/proc/net/route"):
        try:
            with open("/proc/net/route") as f:
                for line in list(f)[1:]:
                    p = line.split()
                    if p[1] == "00000000":
                        gw = socket.inet_ntoa(struct.pack("<L", int(p[2], 16)))
                        break
        except Exception:
            pass
    info["default_gateway"] = gw or "n/a (see route output below)"

    # DNS servers
    dns = []
    if os.path.exists("/etc/resolv.conf"):
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver"):
                    dns.append(line.split()[1])
    info["dns_servers"] = dns or "n/a"

    # Interfaces
    try:
        info["interfaces"] = [n for _, n in socket.if_nameindex()]
    except (AttributeError, OSError):
        info["interfaces"] = "n/a"

    for k, v in info.items():
        print(f"  {col(k.ljust(16), 'y')}: {v}")

    print()
    print(col("  Interface / route details:", "c"))
    if IS_WIN:
        print(run_cmd(["ipconfig"]))
    else:
        out = run_cmd(["ip", "-brief", "address"])
        if "not found" in out:
            out = run_cmd(["ifconfig"])
        print(out)
    log("local_info", info)


# ----------------------------------------------------------------- 2. ping
def do_ping():
    head("PING (ICMP via system ping)")
    host = ask("Host / IP", "8.8.8.8")
    count = ask_int("Packets", 4, 1, 100)
    cmd = ["ping", "-n" if IS_WIN else "-c", str(count), host]
    out = run_cmd(cmd, stream=True)
    log("ping", {"host": host, "output": out})


# ----------------------------------------------------------------- 3. tcp latency
def tcp_latency():
    head("TCP LATENCY TEST")
    host = ask("Host", "google.com")
    port = ask_int("Port", 443, 1, 65535)
    n = ask_int("Samples", 10, 1, 200)
    ip = resolve_host(host)
    if not ip:
        print(col("  Could not resolve host.", "r"))
        return
    times, lost = [], 0
    for i in range(n):
        t0 = time.perf_counter()
        try:
            with socket.create_connection((ip, port), timeout=2):
                ms = (time.perf_counter() - t0) * 1000
                times.append(ms)
                print(f"  #{i+1:<3} {ip}:{port}  {ms:8.2f} ms")
        except OSError:
            lost += 1
            print(col(f"  #{i+1:<3} {ip}:{port}  timeout/refused", "r"))
        time.sleep(0.3)
    result = {"host": host, "ip": ip, "port": port, "sent": n, "lost": lost}
    if times:
        result.update(min=round(min(times), 2), avg=round(statistics.mean(times), 2),
                      max=round(max(times), 2),
                      jitter=round(statistics.pstdev(times), 2))
        print(col(f"\n  min {result['min']} / avg {result['avg']} / max {result['max']} ms"
                  f" | jitter {result['jitter']} ms | loss {lost}/{n}", "g"))
    else:
        print(col("  All probes failed.", "r"))
    log("tcp_latency", result)


# ----------------------------------------------------------------- 4. ping sweep
def _ping_once(ip):
    if IS_WIN:
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=4)
        return r.returncode == 0
    except Exception:
        return False


def ping_sweep():
    head("PING SWEEP (live host discovery)")
    default = "192.168.1.0/24"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        default = str(ipaddress.ip_network(s.getsockname()[0] + "/24", strict=False))
        s.close()
    except Exception:
        pass
    target = ask("Network (CIDR)", default)
    try:
        net = ipaddress.ip_network(target, strict=False)
    except ValueError:
        print(col("  Invalid network.", "r"))
        return
    if net.num_addresses > 1024:
        print(col("  Limit is /22 (1024 addresses). Choose a smaller range.", "r"))
        return
    hosts = [str(h) for h in net.hosts()]
    print(f"  Sweeping {len(hosts)} hosts...\n")
    alive = []
    with cf.ThreadPoolExecutor(max_workers=64) as ex:
        futs = {ex.submit(_ping_once, h): h for h in hosts}
        for f in cf.as_completed(futs):
            h = futs[f]
            if f.result():
                try:
                    name = socket.gethostbyaddr(h)[0]
                except OSError:
                    name = "-"
                alive.append((h, name))
    alive.sort(key=lambda x: ipaddress.ip_address(x[0]))
    for h, n in alive:
        print(f"  {col('UP', 'g')}  {h.ljust(16)} {n}")
    print(col(f"\n  {len(alive)} host(s) alive of {len(hosts)}.", "y"))
    log("ping_sweep", {"network": str(net), "alive": alive})


# ----------------------------------------------------------------- 5. port scanner
def _scan_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) != 0:
            return None
        banner = ""
        try:
            if port in (80, 8080, 8000, 8888):
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            s.settimeout(1.0)
            banner = s.recv(200).decode("utf-8", "replace").strip().splitlines()[0]
        except Exception:
            pass
        return port, banner
    finally:
        s.close()


def port_scan():
    head("TCP PORT SCANNER")
    host = ask("Target host / IP", "127.0.0.1")
    ip = resolve_host(host)
    if not ip:
        print(col("  Could not resolve host.", "r"))
        return
    mode = ask("Ports: (1) top common  (2) 1-1024  (3) custom range", "1")
    if mode == "2":
        ports = list(range(1, 1025))
    elif mode == "3":
        a = ask_int("Start port", 1, 1, 65535)
        b = ask_int("End port", 1024, 1, 65535)
        ports = list(range(min(a, b), max(a, b) + 1))
    else:
        ports = [20, 21, 22, 23, 25, 53, 67, 80, 110, 111, 123, 135, 139, 143,
                 161, 389, 443, 445, 465, 587, 993, 995, 1433, 1521, 2049, 3306,
                 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9200, 27017]
    timeout = float(ask("Timeout seconds", "0.6") or 0.6)
    print(f"\n  Scanning {ip} ({len(ports)} ports)...\n")
    start = time.time()
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=200) as ex:
        for r in ex.map(lambda p: _scan_port(ip, p, timeout), ports):
            if r:
                open_ports.append(r)
    open_ports.sort()
    for port, banner in open_ports:
        try:
            svc = socket.getservbyport(port, "tcp")
        except OSError:
            svc = "unknown"
        print(f"  {col('OPEN', 'g')}  {str(port).ljust(6)} {svc.ljust(12)} {col(banner[:60], 'd')}")
    print(col(f"\n  {len(open_ports)} open port(s) in {time.time()-start:.1f}s.", "y"))
    log("port_scan", {"target": ip, "open": open_ports})


# ----------------------------------------------------------------- 6/7. DNS
QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}
QNAMES = {v: k for k, v in QTYPES.items()}


def _parse_name(data, off):
    labels, jumped, end = [], False, off
    while True:
        l = data[off]
        if l == 0:
            off += 1
            break
        if l & 0xC0 == 0xC0:
            ptr = ((l & 0x3F) << 8) | data[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            off = ptr
            continue
        off += 1
        labels.append(data[off:off + l].decode("ascii", "replace"))
        off += l
    return ".".join(labels), (end if jumped else off)


def _dns_servers():
    servers = []
    if os.path.exists("/etc/resolv.conf"):
        with open("/etc/resolv.conf") as f:
            for line in f:
                if line.startswith("nameserver") and ":" not in line:
                    servers.append(line.split()[1])
    return servers + ["1.1.1.1", "8.8.8.8"]


def dns_query(name, qtype="A", server=None, timeout=3):
    tid = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\x00"
    packet = header + q + struct.pack(">HH", QTYPES[qtype], 1)
    for srv in ([server] if server else _dns_servers()):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(packet, (srv, 53))
            data, _ = s.recvfrom(4096)
            s.close()
        except OSError:
            continue
        rid, flags, qd, an, _, _ = struct.unpack(">HHHHHH", data[:12])
        if rid != tid:
            continue
        rcode = flags & 0xF
        if rcode != 0:
            return srv, rcode, []
        off = 12
        for _ in range(qd):
            _, off = _parse_name(data, off)
            off += 4
        answers = []
        for _ in range(an):
            _, off = _parse_name(data, off)
            rtype, _, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rd = data[off:off + rdlen]
            if rtype == 1:
                val = socket.inet_ntoa(rd)
            elif rtype == 28:
                val = socket.inet_ntop(socket.AF_INET6, rd)
            elif rtype in (2, 5):
                val, _ = _parse_name(data, off)
            elif rtype == 15:
                pref = struct.unpack(">H", rd[:2])[0]
                host, _ = _parse_name(data, off + 2)
                val = f"{pref} {host}"
            elif rtype == 16:
                parts, i = [], 0
                while i < len(rd):
                    ln = rd[i]
                    parts.append(rd[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                    i += 1 + ln
                val = "".join(parts)
            else:
                val = rd.hex()
            answers.append((QNAMES.get(rtype, str(rtype)), ttl, val))
            off += rdlen
        return srv, 0, answers
    return None, -1, []


def dns_lookup():
    head("DNS LOOKUP")
    domain = ask("Domain", "example.com")
    server = ask("DNS server (blank = system/1.1.1.1/8.8.8.8)", "") or None
    results = {}
    for qt in ("A", "AAAA", "CNAME", "MX", "NS", "TXT"):
        srv, rc, ans = dns_query(domain, qt, server)
        if rc == -1:
            print(col(f"  {qt}: no response from DNS server", "r"))
            continue
        if rc == 3:
            print(col("  Domain does not exist (NXDOMAIN).", "r"))
            break
        for t, ttl, val in ans:
            print(f"  {col(t.ljust(6), 'y')} {val[:90]}  {col(f'(ttl {ttl})', 'd')}")
        results[qt] = [a[2] for a in ans]
    log("dns_lookup", {"domain": domain, "records": results})


def reverse_dns():
    head("REVERSE DNS LOOKUP")
    ip = ask("IP address", "8.8.8.8")
    try:
        name, _, _ = socket.gethostbyaddr(ip)
        print(f"  {ip} -> {col(name, 'g')}")
        log("reverse_dns", {"ip": ip, "name": name})
    except (socket.herror, socket.gaierror):
        print(col("  No PTR record found.", "r"))


# ----------------------------------------------------------------- 8. traceroute
def traceroute():
    head("TRACEROUTE")
    host = ask("Host", "8.8.8.8")
    if IS_WIN:
        cmd = ["tracert", "-d", "-h", "20", host]
    else:
        cmd = ["traceroute", "-n", "-m", "20", host]
    out = run_cmd(cmd, stream=True)
    if "not found" in out.lower() and not IS_WIN:
        print(col("  Install traceroute (e.g. sudo apt install traceroute).", "y"))
    log("traceroute", {"host": host, "output": out})


# ----------------------------------------------------------------- 9. whois
def _whois_query(server, query):
    with socket.create_connection((server, 43), timeout=8) as s:
        s.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            d = s.recv(4096)
            if not d:
                break
            chunks.append(d)
    return b"".join(chunks).decode("utf-8", "replace")


def whois_lookup():
    head("WHOIS LOOKUP")
    q = ask("Domain or IP", "example.com")
    try:
        resp = _whois_query("whois.iana.org", q)
        refer = None
        for line in resp.splitlines():
            if line.lower().startswith(("refer:", "whois:")):
                refer = line.split(":", 1)[1].strip()
                break
        if refer:
            resp = _whois_query(refer, q)
        lines = [l for l in resp.splitlines() if l.strip() and not l.startswith(("%", "#"))]
        for l in lines[:60]:
            print("  " + l)
        if len(lines) > 60:
            print(col(f"  ... {len(lines)-60} more lines truncated", "d"))
        log("whois", {"query": q, "server": refer or "whois.iana.org", "lines": lines[:200]})
    except OSError as e:
        print(col(f"  WHOIS failed: {e}", "r"))


# ----------------------------------------------------------------- 10. http headers
SEC_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]


def http_headers():
    head("HTTP HEADER & SECURITY HEADER CHECK")
    url = ask("URL or host", "https://example.com")
    if "://" not in url:
        url = "https://" + url
    scheme, rest = url.split("://", 1)
    host, _, path = rest.partition("/")
    path = "/" + path
    port = None
    if ":" in host:
        host, port = host.rsplit(":", 1)
        port = int(port)
    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port or 443, timeout=8,
                                               context=ssl.create_default_context())
        else:
            conn = http.client.HTTPConnection(host, port or 80, timeout=8)
        t0 = time.perf_counter()
        conn.request("HEAD", path, headers={"User-Agent": "NetSentinel/1.0"})
        r = conn.getresponse()
        ms = (time.perf_counter() - t0) * 1000
        print(f"  Status : {col(f'{r.status} {r.reason}', 'g')}   ({ms:.0f} ms)\n")
        headers = {k: v for k, v in r.getheaders()}
        for k, v in headers.items():
            print(f"  {col(k, 'y')}: {v[:100]}")
        print(col("\n  Security headers:", "c"))
        lower = {k.lower() for k in headers}
        missing = []
        for h in SEC_HEADERS:
            if h.lower() in lower:
                print(f"   {col('[+]', 'g')} {h}")
            else:
                print(f"   {col('[-]', 'r')} {h} (missing)")
                missing.append(h)
        if "server" in lower:
            print(col("\n  Note: Server header discloses software information.", "y"))
        log("http_headers", {"url": url, "status": r.status, "headers": headers,
                             "missing_security_headers": missing})
        conn.close()
    except Exception as e:
        print(col(f"  Request failed: {e}", "r"))


# ----------------------------------------------------------------- 11. ssl
def ssl_inspect():
    head("SSL/TLS CERTIFICATE INSPECTOR")
    host = ask("Host", "example.com")
    port = ask_int("Port", 443, 1, 65535)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                tls = s.version()
                cipher = s.cipher()
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        exp = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]))
        start = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]))
        days = (exp - datetime.datetime.now()).days
        san = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        color = "g" if days > 30 else ("y" if days > 0 else "r")
        print(f"  Subject  : {subject.get('commonName', '-')}")
        print(f"  Issuer   : {issuer.get('organizationName', '-')} ({issuer.get('commonName', '-')})")
        print(f"  Valid    : {start:%Y-%m-%d} -> {exp:%Y-%m-%d}  {col(f'({days} days left)', color)}")
        print(f"  TLS      : {tls}   Cipher: {cipher[0]} ({cipher[2]} bit)")
        print(f"  SANs     : {', '.join(san[:8])}{' ...' if len(san) > 8 else ''}")
        log("ssl", {"host": host, "port": port, "subject": subject, "issuer": issuer,
                    "expires": str(exp), "days_left": days, "tls": tls})
    except ssl.SSLCertVerificationError as e:
        print(col(f"  Certificate verification FAILED: {e.verify_message}", "r"))
    except Exception as e:
        print(col(f"  Connection failed: {e}", "r"))


# ----------------------------------------------------------------- 12. subnet calc
def subnet_calc():
    head("SUBNET CALCULATOR")
    cidr = ask("IP/CIDR or IP/netmask", "192.168.1.10/24")
    try:
        iface = ipaddress.ip_interface(cidr)
    except ValueError:
        print(col("  Invalid input.", "r"))
        return
    net = iface.network
    data = {
        "address": str(iface.ip),
        "network": str(net.network_address),
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "broadcast": str(net.broadcast_address) if net.version == 4 else "n/a",
        "prefix": net.prefixlen,
        "total_addresses": net.num_addresses,
        "usable_hosts": max(net.num_addresses - 2, 0) if net.version == 4 else net.num_addresses,
        "private": iface.ip.is_private,
        "version": f"IPv{net.version}",
    }
    hosts = list(net.hosts()) if net.num_addresses <= 65536 else []
    if hosts:
        data["first_host"], data["last_host"] = str(hosts[0]), str(hosts[-1])
    for k, v in data.items():
        print(f"  {col(k.ljust(16), 'y')}: {v}")
    log("subnet_calc", data)


# ----------------------------------------------------------------- 13. report
def save_report():
    head("SAVE SESSION REPORT")
    if not REPORT:
        print(col("  Nothing to save yet. Run some tools first.", "y"))
        return
    default = f"netsentinel_report_{datetime.datetime.now():%Y%m%d_%H%M%S}.json"
    name = ask("File name", default)
    payload = {"tool": "NetSentinel", "author": "Mr Sabaz Ali Khan",
               "generated": datetime.datetime.now().isoformat(timespec="seconds"),
               "results": REPORT}
    with open(name, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    print(col(f"  Saved {len(REPORT)} result block(s) to {name}", "g"))


# ----------------------------------------------------------------- menu
MENU = [
    ("Local network information", local_info),
    ("Ping (ICMP)", do_ping),
    ("TCP latency test", tcp_latency),
    ("Ping sweep (host discovery)", ping_sweep),
    ("TCP port scanner", port_scan),
    ("DNS lookup (A/AAAA/CNAME/MX/NS/TXT)", dns_lookup),
    ("Reverse DNS lookup", reverse_dns),
    ("Traceroute", traceroute),
    ("WHOIS lookup", whois_lookup),
    ("HTTP & security header check", http_headers),
    ("SSL/TLS certificate inspector", ssl_inspect),
    ("Subnet calculator", subnet_calc),
    ("Save session report (JSON)", save_report),
]


def main():
    while True:
        clear()
        show_banner()
        for i, (label, _) in enumerate(MENU, 1):
            print(f"   {col(str(i).rjust(2), 'y')}) {label}")
        print(f"   {col(' 0', 'r')}) Exit\n")
        choice = ask("Select option")
        if choice == "0":
            print(col("\n  Stay secure. - Mr Sabaz Ali Khan\n", "c"))
            break
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except KeyboardInterrupt:
                print(col("\n  Interrupted.", "y"))
            except Exception as e:
                print(col(f"\n  Error: {e}", "r"))
            pause()
        else:
            print(col("  Invalid option.", "r"))
            time.sleep(1)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        print(col("\n\n  Goodbye. - Mr Sabaz Ali Khan\n", "c"))
        sys.exit(0)
