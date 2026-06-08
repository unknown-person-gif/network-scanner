#!/usr/bin/env python3
import socket
import struct
import time
import argparse
import ipaddress
import concurrent.futures
import sys
import os
from datetime import datetime


GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

def c(text, colour): return f"{colour}{text}{RESET}"


COMMON_PORTS = {
    21: "FTP",    22: "SSH",    23: "Telnet",  25: "SMTP",
    53: "DNS",    80: "HTTP",   110: "POP3",   143: "IMAP",
    443: "HTTPS", 445: "SMB",  3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
    27017: "MongoDB", 9200: "Elasticsearch",
}


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Complete a full TCP three-way handshake.
    OPEN    → connection succeeds (SYN → SYN-ACK → ACK)
    CLOSED  → RST received immediately
    FILTERED→ connection times out (firewall drops packet silently)
    """
    result = {"port": port, "state": "filtered", "banner": "", "latency_ms": None}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        start = time.time()
        code = sock.connect_ex((host, port))
        result["latency_ms"] = round((time.time() - start) * 1000, 1)

        if code == 0:
            result["state"] = "open"
            result["banner"] = grab_banner(sock)
        else:
            result["state"] = "closed"
        sock.close()
    except socket.timeout:
        result["state"] = "filtered"
    except ConnectionRefusedError:
        result["state"] = "closed"
    except Exception:
        result["state"] = "filtered"
    return result


def grab_banner(sock: socket.socket) -> str:
    """
    Read the first line the service sends after connecting.
    HTTP servers need a nudge — we send a HEAD request first.
    """
    try:
        sock.settimeout(1.0)
        # Try reading; some services (SSH, FTP) speak first
        try:
            banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
            if banner:
                return banner[:80]
        except socket.timeout:
            pass
        # HTTP probe
        sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
        return banner.split("\n")[0][:80] if banner else ""
    except Exception:
        return ""

# ── SYN Scan (raw sockets, requires root/sudo) ────────────────────────────────
def syn_scan(host: str, port: int, timeout: float = 1.0) -> dict:
    """
    Half-open scan: send SYN → if SYN-ACK comes back → OPEN, then send RST.
    Never completes the handshake, so many older IDS won't log it.
    Requires root because we build raw IP packets by hand.

    Packet structure we build:
      [IP header 20 bytes][TCP header 20 bytes]
    We set the SYN flag (0x002) and compute the TCP checksum ourselves.
    """
    result = {"port": port, "state": "filtered", "banner": "", "latency_ms": None}

    if os.geteuid() != 0:
        return {"port": port, "state": "error", "banner": "Need root for SYN scan", "latency_ms": None}

    try:
        # Raw socket: IPPROTO_RAW lets us craft the IP header too
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        recv_sock.settimeout(timeout)

        src_ip  = socket.gethostbyname(socket.gethostname())
        src_port = 60000  # arbitrary source port

        packet = build_syn_packet(src_ip, host, src_port, port)
        start  = time.time()
        send_sock.sendto(packet, (host, 0))

        while time.time() - start < timeout:
            try:
                raw, addr = recv_sock.recvfrom(65535)
                if addr[0] != host:
                    continue
                flags = parse_tcp_flags(raw)
                result["latency_ms"] = round((time.time() - start) * 1000, 1)
                if flags & 0x12:          # SYN-ACK → OPEN
                    result["state"] = "open"
                    rst = build_rst_packet(src_ip, host, src_port, port)
                    send_sock.sendto(rst, (host, 0))
                elif flags & 0x04:        # RST → CLOSED
                    result["state"] = "closed"
                break
            except socket.timeout:
                break
    except PermissionError:
        result["state"] = "error"
        result["banner"] = "Run with sudo"
    finally:
        try: send_sock.close()
        except: pass
        try: recv_sock.close()
        except: pass

    return result

def checksum(data: bytes) -> int:
    """Standard internet checksum (RFC 793)."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF

def build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """
    Craft a raw IP+TCP SYN packet by hand.
    IP header: version=4, ihl=5, ttl=64, protocol=TCP(6)
    TCP header: SYN flag=0x002, window=1024, seq=0
    """
    # IP header (with checksum=0 placeholder, kernel fills it)
    ip = struct.pack('!BBHHHBBH4s4s',
        0x45,                          # version + IHL
        0,                             # DSCP + ECN
        40,                            # total length (20 IP + 20 TCP)
        54321,                         # identification
        0,                             # flags + fragment offset
        64,                            # TTL
        socket.IPPROTO_TCP,            # protocol
        0,                             # checksum (kernel fills)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )
    # TCP header
    tcp_no_chk = struct.pack('!HHLLBBHHH',
        src_port, dst_port,
        0,          # seq
        0,          # ack
        5 << 4,     # data offset (5 × 4 = 20 bytes)
        0x002,      # SYN flag
        1024,       # window size
        0,          # checksum placeholder
        0,          # urgent pointer
    )
    # Pseudo-header for TCP checksum (RFC 793)
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_no_chk),
    )
    chk = checksum(pseudo + tcp_no_chk)
    tcp = tcp_no_chk[:16] + struct.pack('!H', chk) + tcp_no_chk[18:]
    return ip + tcp

def build_rst_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int) -> bytes:
    """Same as SYN packet but RST flag (0x004) so the target closes cleanly."""
    ip = struct.pack('!BBHHHBBH4s4s',
        0x45, 0, 40, 54322, 0, 64, socket.IPPROTO_TCP, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
    )
    tcp_no_chk = struct.pack('!HHLLBBHHH',
        src_port, dst_port, 0, 0, 5 << 4, 0x004, 1024, 0, 0,
    )
    pseudo = struct.pack('!4s4sBBH',
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip),
        0, socket.IPPROTO_TCP, len(tcp_no_chk),
    )
    chk = checksum(pseudo + tcp_no_chk)
    tcp = tcp_no_chk[:16] + struct.pack('!H', chk) + tcp_no_chk[18:]
    return ip + tcp

def parse_tcp_flags(raw: bytes) -> int:
    """Extract the TCP flags byte from a raw IP packet."""
    ip_ihl = (raw[0] & 0x0F) * 4
    return raw[ip_ihl + 13]   # TCP flags are at byte 13 of the TCP header

# ── Ping Sweep ────────────────────────────────────────────────────────────────
def ping_host(host: str, timeout: float = 1.0) -> bool:
    """
    ICMP echo request (ping) using a raw socket.
    Returns True if host replies within timeout.
    Falls back to a TCP probe on port 80 if raw sockets aren't available.
    """
    try:
        if os.geteuid() == 0:
            return _icmp_ping(host, timeout)
        else:
            return _tcp_ping(host, timeout)
    except Exception:
        return _tcp_ping(host, timeout)

def _icmp_ping(host: str, timeout: float) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    sock.settimeout(timeout)
    # ICMP echo: type=8, code=0, id=1, seq=1, data='ping'
    header = struct.pack('!BBHHH', 8, 0, 0, 1, 1)
    data   = b'ping'
    chk    = checksum(header + data)
    packet = struct.pack('!BBHHH', 8, 0, chk, 1, 1) + data
    try:
        sock.sendto(packet, (host, 1))
        sock.recv(1024)
        return True
    except socket.timeout:
        return False
    finally:
        sock.close()

def _tcp_ping(host: str, timeout: float) -> bool:
    """Non-root fallback: try connecting to port 80 or 443."""
    for port in (80, 443, 22):
        try:
            s = socket.create_connection((host, port), timeout)
            s.close()
            return True
        except Exception:
            pass
    return False

def ping_sweep(network: str) -> list:
    """Scan every host in a subnet concurrently."""
    net   = ipaddress.IPv4Network(network, strict=False)
    hosts = [str(h) for h in net.hosts()]
    alive = []
    print(c(f"\nPing sweep of {network} ({len(hosts)} hosts)…", CYAN))
    with concurrent.futures.ThreadPoolExecutor(max_workers=64) as ex:
        futures = {ex.submit(ping_host, h): h for h in hosts}
        for f in concurrent.futures.as_completed(futures):
            h = futures[f]
            if f.result():
                alive.append(h)
                print(c(f"  {h} is UP", GREEN))
    return sorted(alive, key=lambda ip: ipaddress.IPv4Address(ip))

# ── OS Fingerprinting (heuristic) ────────────────────────────────────────────
OS_HINTS = {
    ("22", "OpenSSH"):        "Linux / Unix",
    ("22", "libssh"):         "Embedded Linux",
    ("3389", ""):             "Windows (RDP)",
    ("445", ""):              "Windows (SMB)",
    ("80", "Apache"):         "Linux (Apache)",
    ("80", "nginx"):          "Linux (nginx)",
    ("80", "IIS"):            "Windows (IIS)",
    ("3306", ""):             "MySQL server",
}

def guess_os(open_ports: list) -> str:
    for r in open_ports:
        for (port_s, kw), os_name in OS_HINTS.items():
            if str(r["port"]) == port_s and kw.lower() in r["banner"].lower():
                return os_name
    return "Unknown"

# ── Port range parser ─────────────────────────────────────────────────────────
def parse_ports(spec: str) -> list:
    """'80,443,1-1024' → sorted list of ints"""
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-", 1)
            ports.update(range(int(lo), int(hi) + 1))
        else:
            ports.add(int(part))
    return sorted(ports)

# ── Main ──────────────────────────────────────────────────────────────────────
def scan_host(host: str, ports: list, syn: bool, timeout: float, threads: int):
    scan_fn = syn_scan if syn else tcp_connect_scan
    scan_type = "SYN" if syn else "TCP Connect"

    print(c(f"\n{'─'*60}", CYAN))
    print(c(f"  Target  : {host}", BOLD))
    print(c(f"  Scan    : {scan_type}", BOLD))
    print(c(f"  Ports   : {len(ports)}  |  Threads: {threads}  |  Timeout: {timeout}s", BOLD))
    print(c(f"  Started : {datetime.now().strftime('%H:%M:%S')}", BOLD))
    print(c(f"{'─'*60}", CYAN))

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(scan_fn, host, p, timeout): p for p in ports}
        done = 0
        for f in concurrent.futures.as_completed(futures):
            done += 1
            r = f.result()
            results.append(r)
            # live progress (overwrite line)
            pct = int(done / len(ports) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct:3d}%  {done}/{len(ports)} ports", end="", flush=True)

    print()  # newline after progress bar

    # Print results table
    open_ports = [r for r in results if r["state"] == "open"]
    print(c(f"\n  {'PORT':<10} {'STATE':<10} {'SERVICE':<18} {'LATENCY':<10} BANNER", BOLD))
    print(c(f"  {'─'*70}", CYAN))

    for r in sorted(open_ports, key=lambda x: x["port"]):
        svc     = COMMON_PORTS.get(r["port"], "unknown")
        lat     = f"{r['latency_ms']}ms" if r["latency_ms"] else "—"
        banner  = r["banner"][:38] if r["banner"] else ""
        print(c(f"  {r['port']:<10} ", RESET) +
              c(f"{'open':<10} ", GREEN) +
              c(f"{svc:<18} ", CYAN) +
              f"{lat:<10} " +
              c(banner, YELLOW))

    # Closed / filtered summary
    closed   = sum(1 for r in results if r["state"] == "closed")
    filtered = sum(1 for r in results if r["state"] == "filtered")
    print(c(f"\n  {closed} closed, {filtered} filtered (not shown)", RESET))

    # OS guess
    os_guess = guess_os(open_ports)
    print(c(f"  OS guess : {os_guess}", BOLD))

    print(c(f"\n  Scan finished: {datetime.now().strftime('%H:%M:%S')}", CYAN))
    print(c(f"{'─'*60}\n", CYAN))

    return open_ports

def main():
    parser = argparse.ArgumentParser(
        description="nmap-like port scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target",              help="IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
    parser.add_argument("-p", "--ports",       default="common",  help="Ports: 'common', '1-1024', '80,443,22'")
    parser.add_argument("-t", "--timeout",     type=float, default=1.0, help="Timeout per port in seconds")
    parser.add_argument("-T", "--threads",     type=int,   default=100,  help="Concurrent threads")
    parser.add_argument("--syn",               action="store_true",      help="SYN scan (requires sudo)")
    parser.add_argument("--ping",              action="store_true",      help="Ping sweep a subnet instead of port scan")
    args = parser.parse_args()

    print(c("""
  ┌─────────────────────────────────────┐
  │        nmap-like Port Scanner       │
  │  for educational & authorised use   │
  └─────────────────────────────────────┘""", CYAN))

    # Ping sweep mode
    if args.ping:
        alive = ping_sweep(args.target)
        print(c(f"\n  {len(alive)} hosts up", GREEN))
        return

    # Resolve hostname → IP
    try:
        host = socket.gethostbyname(args.target)
    except socket.gaierror:
        print(c(f"Cannot resolve '{args.target}'", RED)); sys.exit(1)

    # Determine port list
    if args.ports == "common":
        ports = sorted(COMMON_PORTS.keys())
    else:
        try:
            ports = parse_ports(args.ports)
        except ValueError:
            print(c("Bad port spec — use '80,443' or '1-1024'", RED)); sys.exit(1)

    scan_host(host, ports, args.syn, args.timeout, args.threads)

if __name__ == "__main__":
    main()
