import socket
import ssl
import requests
from urllib.parse import urlparse
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

TIMEOUT = 5

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}

results = {
    "target": None,
    "time": None,
    "ports": {},
    "services": {},
    "os_guess": None,
    "attack_vectors": [],
    "metasploit_paths": []
}


def banner(title):
    print(f"\n{Fore.CYAN}{'='*75}")
    print(f"{Fore.CYAN}{title.center(75)}")
    print(f"{Fore.CYAN}{'='*75}{Style.RESET_ALL}")

def port_open(host, port):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        ok = s.connect_ex((host, port)) == 0
        s.close()
        return ok
    except:
        return False


def scan_ports(host):
    banner("PORT SCAN")
    for port, name in COMMON_PORTS.items():
        if port_open(host, port):
            results["ports"][port] = name
            print(f"{Fore.GREEN}[✓] {port}/tcp OPEN ({name}){Style.RESET_ALL}")


def http_recon(url):
    try:
        r = requests.get(url, timeout=TIMEOUT, verify=False)
        server = r.headers.get("Server", "Unknown")
        results["services"]["http"] = server

        print(f"{Fore.GREEN}[✓] HTTP Server: {server}{Style.RESET_ALL}")

        text = r.text.lower()

        if "wordpress" in text:
            results["attack_vectors"].append("WordPress detected")
            results["metasploit_paths"].append({
                "vector": "WordPress",
                "auxiliary": "auxiliary/scanner/http/wordpress_scanner",
                "exploit": "exploit/unix/webapp/wp_admin_shell_upload"
            })

        if "struts" in text:
            results["attack_vectors"].append("Apache Struts detected")
            results["metasploit_paths"].append({
                "vector": "Apache Struts",
                "auxiliary": "auxiliary/scanner/http/struts",
                "exploit": "exploit/multi/http/struts2_content_type_ognl"
            })

    except:
        pass


def tls_recon(host, port):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                proto = s.version()
                print(f"{Fore.GREEN}[✓] TLS Version: {proto}{Style.RESET_ALL}")

                if proto in ["TLSv1", "TLSv1.1"]:
                    results["attack_vectors"].append("Weak TLS")
                    results["metasploit_paths"].append({
                        "vector": "Weak TLS",
                        "auxiliary": "auxiliary/scanner/ssl/openssl_heartbleed",
                        "exploit": None
                    })
    except:
        pass


def smb_recon(host):
    if port_open(host, 445):
        print(f"{Fore.GREEN}[✓] SMB detected on 445/tcp{Style.RESET_ALL}")
        results["services"]["smb"] = "Detected"
        results["os_guess"] = "Windows"

        results["metasploit_paths"].append({
            "vector": "SMB Service",
            "auxiliary": "auxiliary/scanner/smb/smb_version",
            "exploit": "exploit/windows/smb/ms17_010_eternalblue"
        })


def metasploit_output(host):
    banner("METASPLOIT ATTACK PATHS")

    if not results["metasploit_paths"]:
        print(f"{Fore.YELLOW}[i] No clear exploitation paths identified{Style.RESET_ALL}")
        return

    for i, p in enumerate(results["metasploit_paths"], 1):
        print(f"\n{Fore.MAGENTA}PATH #{i}: {p['vector']}{Style.RESET_ALL}")

        print(f"{Fore.CYAN}Auxiliary (run FIRST):{Style.RESET_ALL}")
        print(f"use {p['auxiliary']}")
        print(f"set RHOSTS {host}")
        print("run")

        if p["exploit"]:
            print(f"\n{Fore.RED}Exploit (ONLY IF AUX CONFIRMS):{Style.RESET_ALL}")
            print(f"use {p['exploit']}")
            print(f"set RHOSTS {host}")
            print("set PAYLOAD <choose_based_on_OS>")
            print("set LHOST <YOUR_LAB_IP>")
            print("exploit")


def run():
    banner("METASPLOIT RECON ASSISTANT — MAX EDITION")

    mode = input(f"{Fore.YELLOW}Mode (CTF / PENTEST / LAB): {Style.RESET_ALL}").strip().upper()
    target = input(f"{Fore.YELLOW}Target (IP or URL): {Style.RESET_ALL}").strip()

    if not target:
        return

    if not target.startswith("http"):
        target = f"http://{target}"

    host = urlparse(target).hostname

    results["target"] = target
    results["time"] = str(datetime.utcnow())

    scan_ports(host)

    if 80 in results["ports"]:
        http_recon(f"http://{host}")
    if 443 in results["ports"]:
        http_recon(f"https://{host}")
        tls_recon(host, 443)

    smb_recon(host)

    metasploit_output(host)

    banner("IMPORTANT NOTES")
    print(f"{Fore.YELLOW}• Always run auxiliary scanners first")
    print(f"• Never exploit without confirmation")
    print(f"• Use VPN IP for HTB/THM")
    print(f"• This tool does NOT exploit targets{Style.RESET_ALL}")

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
