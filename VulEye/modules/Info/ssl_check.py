import ssl
import socket
import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


TLS_VERSIONS = {
    "TLSv1.0": ssl.TLSVersion.TLSv1,
    "TLSv1.1": ssl.TLSVersion.TLSv1_1,
    "TLSv1.2": ssl.TLSVersion.TLSv1_2,
    "TLSv1.3": ssl.TLSVersion.TLSv1_3,
}


def test_tls_version(host, port, version):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version
        ctx.maximum_version = version

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True, ssock.version(), ssock.cipher()
    except Exception:
        return False, None, None


def get_certificate(host, port):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None


def parse_cert_dates(cert):
    try:
        nb = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        na = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        return nb, na
    except Exception:
        return None, None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SSL / TLS SECURITY SCANNER                          {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Target URL or hostname: {Style.RESET_ALL}").strip()
    if not target:
        return

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.hostname
        port = 443
    else:
        host = target
        port = 443

    print(f"\n{Fore.CYAN}[+] Scanning {host}:{port}{Style.RESET_ALL}")

    supported = {}
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}TLS VERSION SUPPORT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    for name, version in TLS_VERSIONS.items():
        ok, proto, cipher = test_tls_version(host, port, version)
        if ok:
            supported[name] = cipher
            print(f"{Fore.GREEN}[✓] {name} supported ({cipher[0]}, {cipher[2]} bits){Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[✗] {name} not supported{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}CERTIFICATE INFORMATION")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    cert = get_certificate(host, port)
    issues = []
    score = 100

    if cert:
        subject = dict(x[0] for x in cert.get("subject", []))
        issuer = dict(x[0] for x in cert.get("issuer", []))

        print(f"Subject CN: {subject.get('commonName', 'N/A')}")
        print(f"Issuer CN: {issuer.get('commonName', 'N/A')}")

        nb, na = parse_cert_dates(cert)
        now = datetime.datetime.utcnow()

        if nb and na:
            days = (na - now).days
            print(f"Valid From: {nb}")
            print(f"Valid Until: {na}")

            if days < 0:
                print(f"{Fore.RED}Certificate expired{Style.RESET_ALL}")
                issues.append("Certificate expired")
                score -= 30
            elif days < 30:
                print(f"{Fore.YELLOW}Certificate expires soon ({days} days){Style.RESET_ALL}")
                issues.append("Certificate expiring soon")
                score -= 10
            else:
                print(f"{Fore.GREEN}Certificate valid ({days} days left){Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Could not parse certificate dates{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}No certificate retrieved{Style.RESET_ALL}")
        score -= 40
        issues.append("No valid certificate")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SECURITY ANALYSIS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if "TLSv1.0" in supported or "TLSv1.1" in supported:
        issues.append("Deprecated TLS versions enabled")
        score -= 20

    for _, cipher in supported.items():
        name = cipher[0].upper()
        bits = cipher[2]

        if bits < 128:
            issues.append("Weak encryption strength")
            score -= 10

        if any(x in name for x in ["RC4", "DES", "3DES", "MD5", "NULL"]):
            issues.append("Weak cipher suite")
            score -= 15

    score = max(score, 0)
    color = Fore.GREEN if score >= 80 else Fore.YELLOW if score >= 60 else Fore.RED

    print(f"\nSecurity Score: {color}{score}/100{Style.RESET_ALL}")

    if issues:
        print(f"\n{Fore.YELLOW}Issues detected:{Style.RESET_ALL}")
        for i in set(issues):
            print(f" • {i}")
    else:
        print(f"{Fore.GREEN}No major security issues detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}RECOMMENDATIONS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if score < 80:
        print(" • Disable TLS 1.0 and TLS 1.1")
        print(" • Enable only TLS 1.2 and TLS 1.3")
        print(" • Use AES-GCM or ChaCha20-Poly1305 ciphers")
        print(" • Ensure certificates are renewed on time")
        print(" • Enable HSTS")
    else:
        print(" • Configuration follows modern TLS best practices")

    print(f"\n{Fore.GREEN}[✓] Scan completed{Style.RESET_ALL}")


if __name__ == "__main__":
    run()
