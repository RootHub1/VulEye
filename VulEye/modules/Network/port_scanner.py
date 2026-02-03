import socket
import threading
import argparse
import time
import json
import re
import sys
from queue import Queue

VULN_CHECKS = {
    21: "FTP – anonymous login possible",
    22: "SSH – check OpenSSH version (CVE-2016-0777 etc.)",
    23: "Telnet – clear text credentials",
    25: "SMTP – user enumeration possible",
    53: "DNS – check zone transfer",
    80: "HTTP – check /robots.txt, /admin",
    110: "POP3 – credentials sniffing possible",
    139: "NetBIOS – information leakage",
    443: "HTTPS – check TLS and certificate",
    445: "SMB – possible EternalBlue (MS17-010)",
    3389: "RDP – possible BlueKeep (CVE-2019-0708)",
    5900: "VNC – often misconfigured authentication",
}


def show_banner():
    print(r"""
 _______  _______           _______  _______  _______  _       
(  ____ )(  ___  )|\     /|(  ____ \(  ____ \(  ___  )( (    /|
| (    )|| (   ) |( \   / )| (    \/| (    \/| (   ) ||  \  ( |
| (____)|| (___) | \ (_) / | (_____ | |      | (___) ||   \ | |
|  _____)|  ___  |  \   /  (_____  )| |      |  ___  || (\ \) |
| (      | (   ) |   ) (         ) || |      | (   ) || | \   |
| )      | )   ( |   | |   /\____) || (____/\| )   ( || )  \  |
|/       |/     \|   \_/   \_______)(_______/|/     \||/    )_)

卩ㄖ尺ㄒ 丂匚卂几几乇尺 & ᐯㄩㄥ几乇尺卂乃丨ㄥ丨ㄒㄚ 卂几卂ㄥㄚ乙乇尺
""")


def parse_ports(port_arg):
    ports = set()
    if "," in port_arg:
        for p in port_arg.split(","):
            ports.add(int(p))
    elif "-" in port_arg:
        start, end = map(int, port_arg.split("-"))
        ports.update(range(start, end + 1))
    else:
        ports.add(int(port_arg))
    return sorted(p for p in ports if 1 <= p <= 65535)

def resolve_target(target):
    return socket.gethostbyname(target)

def extract_version(banner):
    banner = banner.lower()
    ssh = re.search(r"ssh-\d+\.\d+-([^\s]+)", banner)
    if ssh:
        return ssh.group(1)
    server = re.search(r"server:\s*([^\r\n]+)", banner)
    if server:
        return server.group(1)
    version = re.search(r"v?\d+\.\d+(\.\d+)?", banner)
    return version.group(0) if version else "unknown"

def grab_banner(sock, host, port):
    try:
        if port in (80, 8080, 8000):
            sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
        elif port == 25:
            sock.sendall(b"EHLO test\r\n")
        return sock.recv(2048).decode(errors="ignore").strip()
    except:
        return ""


def scan_port(host, port, timeout, results, lock):
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        if sock.connect_ex((host, port)) == 0:
            banner = grab_banner(sock, host, port)
            try:
                service = socket.getservbyport(port)
            except:
                service = "unknown"
            version = extract_version(banner) if banner else "no banner"
            with lock:
                results.append({
                    "port": port,
                    "service": service,
                    "version": version,
                    "banner": banner[:100].replace("\n", " ")
                })
                print(f"[+] {port}/tcp open → {service} | {version}")
        sock.close()
    except:
        pass

def worker(host, timeout, queue, results, lock):
    while not queue.empty():
        port = queue.get()
        scan_port(host, port, timeout, results, lock)
        queue.task_done()

def start_scan(target, ports, threads=100, timeout=1.5):
    ip = resolve_target(target)
    results = []
    lock = threading.Lock()
    queue = Queue()

    for p in ports:
        queue.put(p)

    for _ in range(threads):
        threading.Thread(
            target=worker,
            args=(ip, timeout, queue, results, lock),
            daemon=True
        ).start()

    queue.join()
    return ip, results


def run():
    show_banner()

    target = input("[?] Enter target (IP/domain): ").strip()
    if not target:
        print("[!] Target required")
        input("\nPress Enter to return to main menu...")
        return

    ports_input = input("[?] Ports (default 1-1000): ").strip() or "1-1000"
    threads = input("[?] Threads (default 100): ").strip() or "100"

    ports = parse_ports(ports_input)

    print("\n[+] Scanning...\n")
    start = time.time()
    ip, results = start_scan(target, ports, int(threads))
    duration = time.time() - start

    print(f"\n[✓] Scan finished in {duration:.2f}s")

    findings = [r for r in results if r["port"] in VULN_CHECKS]
    if findings:
        print("\n[!] Possible vulnerabilities:")
        for f in findings:
            print(f" → Port {f['port']}: {VULN_CHECKS[f['port']]}")

    if input("\nSave results? (y/n): ").lower() == "y":
        fname = f"scan_{target}_{int(time.time())}.json"
        with open(fname, "w") as f:
            json.dump(results, f, indent=4)
        print(f"[✓] Saved to {fname}")

    input("\nPress Enter to return to main menu...")
    return

def cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("-p", "--ports", default="1-1000")
    parser.add_argument("-t", "--threads", type=int, default=100)
    parser.add_argument("--timeout", type=float, default=1.5)
    args = parser.parse_args()

    ports = parse_ports(args.ports)
    ip, results = start_scan(args.target, ports, args.threads, args.timeout)
    print(f"\n[✓] Open ports found: {len(results)}")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        cli()
    else:
        run()
