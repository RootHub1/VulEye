import socket
import re
from colorama import init, Fore, Style

init(autoreset=True)


def check_smtp_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def get_smtp_banner(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner
    except:
        return None


def test_vrfy(host, port, username):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(8)
        sock.connect((host, port))
        sock.recv(1024)

        sock.send(f'HELO scanner\r\n'.encode())
        sock.recv(1024)

        sock.send(f'VRFY {username}\r\n'.encode())
        response = sock.recv(1024).decode('utf-8', errors='ignore')
        sock.close()

        if '250' in response or '252' in response:
            return True, response.strip()
        elif '550' in response or '553' in response:
            return False, response.strip()
        else:
            return None, response.strip()
    except:
        return None, None


def test_auth_methods(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        sock.recv(1024)

        sock.send(b'EHLO scanner\r\n')
        response = sock.recv(2048).decode('utf-8', errors='ignore')
        sock.close()

        auth_methods = []
        for line in response.split('\n'):
            if 'auth' in line.lower():
                auth_methods.append(line.strip())

        return auth_methods, response
    except:
        return [], None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SMTP USER ENUMERATOR                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target mail server (IP or hostname): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Starting SMTP enumeration for: {target}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SMTP PORT SCANNING")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    smtp_ports = {
        25: 'SMTP (Standard)',
        587: 'SMTP (Submission)',
        465: 'SMTPS (Legacy SSL)'
    }

    open_ports = []
    for port, desc in smtp_ports.items():
        if check_smtp_port(target, port):
            open_ports.append(port)
            print(f"{Fore.GREEN}[✓] Port {port} ({desc}): OPEN{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[i] Port {port} ({desc}): closed/filtered{Style.RESET_ALL}")

    if not open_ports:
        print(f"\n{Fore.RED}[!] No SMTP ports open. Mail service may be disabled or filtered.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    primary_port = open_ports[0]
    print(f"\n{Fore.GREEN}[✓] Using port {primary_port} for enumeration{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SMTP BANNER GRABBING")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    banner = get_smtp_banner(target, primary_port)
    if banner:
        print(f"\n{Fore.GREEN}[✓] SMTP Banner:{Style.RESET_ALL}")
        print(f"   {banner}")

        server_info = {}
        if 'microsoft' in banner.lower() or 'exchange' in banner.lower():
            server_info['type'] = 'Microsoft Exchange'
        elif 'postfix' in banner.lower():
            server_info['type'] = 'Postfix'
        elif 'exim' in banner.lower():
            server_info['type'] = 'Exim'
        elif 'sendmail' in banner.lower():
            server_info['type'] = 'Sendmail'
        elif 'qmail' in banner.lower():
            server_info['type'] = 'Qmail'

        if 'type' in server_info:
            print(f"   {Fore.CYAN}Server Type:{Style.RESET_ALL} {server_info['type']}")
    else:
        print(f"{Fore.YELLOW}[!] Could not retrieve SMTP banner{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}AUTHENTICATION METHODS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    auth_methods, ehlo_response = test_auth_methods(target, primary_port)
    if auth_methods:
        print(f"\n{Fore.YELLOW}[!] Authentication methods supported:{Style.RESET_ALL}")
        for method in auth_methods:
            print(f"   • {method}")
            if 'login' in method.lower() or 'plain' in method.lower():
                print(f"     {Fore.RED}  WEAK AUTHENTICATION - credentials sent in plaintext{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[i] No authentication methods advertised (may require TLS){Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}USER ENUMERATION (VRFY COMMAND)")
    print(f"{Fore.YELLOW}Note: Most production servers disable VRFY for security{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    common_users = ['admin', 'administrator', 'root', 'postmaster', 'webmaster', 'info', 'support', 'sales', 'billing',
                    'hostmaster']

    print(f"\n{Fore.CYAN}[→] Testing {len(common_users)} common usernames...{Style.RESET_ALL}")

    valid_users = []
    invalid_users = []

    for username in common_users:
        result, response = test_vrfy(target, primary_port, username)
        if result is True:
            valid_users.append((username, response))
            print(f"{Fore.GREEN}[✓] VALID USER: {username}{Style.RESET_ALL}")
            print(f"    Response: {response[:70]}")
        elif result is False:
            invalid_users.append(username)
        elif result is None:
            print(
                f"{Fore.YELLOW}[?] UNKNOWN: {username} (Response: {response[:50] if response else 'No response'}){Style.RESET_ALL}")

    if valid_users:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] VALID EMAIL ACCOUNTS DISCOVERED{Style.RESET_ALL}")
        print(f"\n{Fore.RED}  CRITICAL SECURITY ISSUE:{Style.RESET_ALL}")
        print(f"   VRFY command enabled - attackers can enumerate valid accounts")
        print(f"   Impact: Targeted phishing, password spraying, account takeover")

        print(f"\n{Fore.YELLOW}Discovered accounts:{Style.RESET_ALL}")
        for user, resp in valid_users:
            print(f"   • {user}@{target}")
    else:
        print(f"\n{Fore.GREEN}[✓] No valid users enumerated via VRFY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] This is expected - most secure mail servers disable VRFY/EXPN{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SECURITY ASSESSMENT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    security_issues = []

    if valid_users:
        security_issues.append({
            'severity': 'HIGH',
            'issue': 'VRFY Command Enabled',
            'impact': 'User account enumeration possible',
            'fix': 'Disable VRFY in mail server configuration'
        })

    if auth_methods and any('login' in m.lower() or 'plain' in m.lower() for m in auth_methods):
        security_issues.append({
            'severity': 'MEDIUM',
            'issue': 'Plaintext Authentication Supported',
            'impact': 'Credentials exposed on network without TLS',
            'fix': 'Enforce STARTTLS or use port 465/587 with mandatory encryption'
        })

    if banner and ('220' not in banner):
        security_issues.append({
            'severity': 'LOW',
            'issue': 'Non-standard banner',
            'impact': 'May leak version information',
            'fix': 'Configure generic SMTP banner'
        })

    if security_issues:
        print(f"\n{Fore.RED}[!] SECURITY ISSUES DETECTED{Style.RESET_ALL}")
        for issue in security_issues:
            severity_color = Fore.MAGENTA if issue['severity'] == 'CRITICAL' else (
                Fore.RED if issue['severity'] == 'HIGH' else (
                    Fore.YELLOW if issue['severity'] == 'MEDIUM' else Fore.CYAN))
            print(f"\n{severity_color}• {issue['issue']} ({issue['severity']}){Style.RESET_ALL}")
            print(f"  Impact: {issue['impact']}")
            print(f"  Fix: {issue['fix']}")
    else:
        print(f"\n{Fore.GREEN}[✓] No critical SMTP security issues detected{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}HARDENING RECOMMENDATIONS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}For Mail Server Administrators:{Style.RESET_ALL}")
    print(f"   • Disable VRFY and EXPN commands:")
    print(f"        Postfix: disable_vrfy_command = yes")
    print(f"        Exim: no_vrfy_log = true")
    print(f"   • Enforce TLS encryption for all connections")
    print(f"   • Implement rate limiting for authentication attempts")
    print(f"   • Use SPF, DKIM, and DMARC to prevent spoofing")
    print(f"   • Configure generic SMTP banners (hide version info)")
    print(f"   • Monitor logs for enumeration attempts")
    print(f"   • Implement fail2ban or similar intrusion prevention")

    print(f"\n{Fore.YELLOW}For Pentesters:{Style.RESET_ALL}")
    print(f"   • ALWAYS obtain written authorization before SMTP testing")
    print(f"   • Never use enumerated accounts for unauthorized access")
    print(f"   • Document all testing activities for legal protection")
    print(f"   • Use dedicated tools for comprehensive testing:")
    print(f"        • smtp-user-enum (specialized tool)")
    print(f"        • Metasploit auxiliary/scanner/smtp/smtp_enum")
    print(f"        • Nmap smtp-commands script")
    print(f"   • Test only during authorized assessment windows")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}LEGAL DISCLAIMER")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.RED}  SMTP ENUMERATION WITHOUT AUTHORIZATION IS ILLEGAL{Style.RESET_ALL}")
    print(f"   • Enumerating email accounts without permission = computer fraud")
    print(f"   • May violate anti-spam laws (CAN-SPAM, GDPR Article 5)")
    print(f"   • Even passive enumeration may be considered unauthorized access")
    print(f"   • Always obtain WRITTEN authorization before ANY SMTP testing")
    print(f"   • Maintain detailed logs of authorized testing activities")
    print(f"   • Test ONLY on systems you own or have explicit written permission")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] SMTP enumeration completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")