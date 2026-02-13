import socket
import time
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)

TIMEOUT = 6
DELAY = 0.7  

COMMON_USERS = [
    "admin", "administrator", "root", "postmaster",
    "webmaster", "info", "support", "sales", "billing"
]

results = {
    "target": None,
    "time": None,
    "ports": {},
    "banner": "",
    "capabilities": [],
    "auth": [],
    "users": [],
    "issues": [],
    "attack_paths": []
}

def banner(title):
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}{title.center(70)}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

def connect(host, port):
    s = socket.socket()
    s.settimeout(TIMEOUT)
    s.connect((host, port))
    return s

def recv(sock):
    return sock.recv(4096).decode(errors="ignore")


def smtp_handshake(host, port):
    sock = connect(host, port)
    banner = recv(sock)
    sock.send(b"EHLO scanner\r\n")
    ehlo = recv(sock)
    return sock, banner.strip(), ehlo

def parse_capabilities(ehlo):
    caps = []
    for line in ehlo.splitlines():
        if line.startswith("250"):
            caps.append(line.replace("250-", "").replace("250 ", "").strip())
    return caps

def check_ports(host):
    ports = [25, 587, 465]
    open_ports = []
    for p in ports:
        try:
            s = socket.socket()
            s.settimeout(3)
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
            s.close()
        except Exception:
            pass
    return open_ports

def vrfy_enum(sock, user):
    sock.send(f"VRFY {user}\r\n".encode())
    r = recv(sock)
    if r.startswith("250"):
        return "VALID"
    if r.startswith("252"):
        return "AMBIGUOUS"
    if r.startswith("550"):
        return "INVALID"
    return "UNKNOWN"

def expn_test(sock):
    sock.send(b"EXPN postmaster\r\n")
    return recv(sock)

def rcpt_test(sock, user, domain):
    sock.send(b"MAIL FROM:<test@test.com>\r\n")
    recv(sock)
    sock.send(f"RCPT TO:<{user}@{domain}>\r\n".encode())
    return recv(sock)


def run():
    banner("SMTP ENUMERATION — PRO")

    target = input(f"{Fore.YELLOW}Target SMTP host: {Style.RESET_ALL}").strip()
    domain = target.split(".")[-2] + "." + target.split(".")[-1] if "." in target else target

    results["target"] = target
    results["time"] = str(datetime.utcnow())

    
    banner("PORT DISCOVERY")
    open_ports = check_ports(target)
    for p in open_ports:
        print(f"{Fore.GREEN}[✓] {p}/tcp OPEN{Style.RESET_ALL}")
        results["ports"][p] = True

    if not open_ports:
        print(f"{Fore.RED}[!] No SMTP ports reachable{Style.RESET_ALL}")
        return

    port = open_ports[0]

   
    banner("SMTP HANDSHAKE")
    sock, banner_text, ehlo = smtp_handshake(target, port)
    results["banner"] = banner_text
    print(banner_text)

    caps = parse_capabilities(ehlo)
    results["capabilities"] = caps

    for c in caps:
        print(f"{Fore.CYAN}• {c}{Style.RESET_ALL}")
        if "STARTTLS" in c:
            results["issues"].append("INFO: STARTTLS supported")
        if "AUTH" in c:
            results["auth"].append(c)

    
    banner("USER ENUMERATION (SAFE)")
    for user in COMMON_USERS:
        status = vrfy_enum(sock, user)
        time.sleep(DELAY)

        if status == "VALID":
            results["users"].append(user)
            print(f"{Fore.RED}[✓] VALID USER: {user}{Style.RESET_ALL}")
        elif status == "AMBIGUOUS":
            print(f"{Fore.YELLOW}[?] {user}: ambiguous response{Style.RESET_ALL}")

    
    banner("EXPN CHECK")
    expn = expn_test(sock)
    if expn.startswith("250"):
        results["issues"].append("HIGH: EXPN enabled")
        print(f"{Fore.RED}[!] EXPN enabled{Style.RESET_ALL}")

    
    banner("RCPT TO ENUM (SAFE)")
    for user in COMMON_USERS[:3]:
        resp = rcpt_test(sock, user, domain)
        if resp.startswith("250"):
            results["issues"].append("HIGH: RCPT TO user enumeration possible")
            print(f"{Fore.RED}[!] RCPT accepted for {user}{Style.RESET_ALL}")

    sock.close()

    
    banner("SECURITY ANALYSIS")

    if results["users"]:
        results["issues"].append("HIGH: SMTP user enumeration possible")
        results["attack_paths"].append(
            "Valid users → phishing → password spraying"
        )

    if any("PLAIN" in a or "LOGIN" in a for a in results["auth"]):
        results["issues"].append("MEDIUM: Weak SMTP authentication methods")

    for i in results["issues"]:
        color = Fore.RED if "HIGH" in i else Fore.YELLOW
        print(f"{color}• {i}{Style.RESET_ALL}")

    
    banner("WHERE TO ATTACK NEXT")
    for p in results["attack_paths"]:
        print(f"• {p}")

    banner("DONE")
    print(f"{Fore.GREEN}[✓] SMTP Recon completed{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use only with authorization{Style.RESET_ALL}")

if __name__ == "__main__":
    run()
