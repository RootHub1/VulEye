import socket
import sys
from colorama import init, Fore, Style

init(autoreset=True)


def check_smb_port(host, port=445):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except:
        return False


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SMB SHARE ENUMERATOR                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target IP address (e.g., 192.168.1.100): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    try:
        socket.inet_aton(target)
    except socket.error:
        print(f"\n{Fore.RED}[!] Invalid IP address format.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Starting SMB enumeration for: {target}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}PORT SCANNING")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    smb445 = check_smb_port(target, 445)
    smb139 = check_smb_port(target, 139)

    if not smb445 and not smb139:
        print(f"\n{Fore.RED}[!] No SMB ports open (445/139). SMB service may be disabled or filtered.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Common reasons:{Style.RESET_ALL}")
        print(f"   • Windows Firewall blocking SMB")
        print(f"   • SMBv1 disabled (modern Windows systems)")
        print(f"   • Network segmentation/firewall rules")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.GREEN}[✓] SMB Ports Status:{Style.RESET_ALL}")
    if smb445:
        print(f"   • Port 445 (SMB over TCP): {Fore.GREEN}OPEN{Style.RESET_ALL}")
    if smb139:
        print(f"   • Port 139 (NetBIOS): {Fore.GREEN}OPEN{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SMB SHARE ENUMERATION")
    print(f"{Fore.YELLOW}Note: Requires pysmb library (pip install pysmb){Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    try:
        from smb.SMBConnection import SMBConnection
        from smb.base import NotConnectedError, NotReadyError
        from smb.smb_structs import OperationFailure

        print(f"\n{Fore.CYAN}[→] Attempting anonymous SMB connection...{Style.RESET_ALL}")

        try:
            conn = SMBConnection('', '', 'vuleye-client', target, use_ntlm_v2=True, is_direct_tcp=True)
            connected = conn.connect(target, 445, timeout=8)

            if connected:
                print(f"{Fore.GREEN}[✓] Anonymous SMB connection successful{Style.RESET_ALL}")

                try:
                    shares = conn.listShares(timeout=10)
                    print(f"\n{Fore.GREEN}[✓] Accessible SMB Shares:{Style.RESET_ALL}")

                    sensitive_shares = []
                    for share in shares:
                        share_name = share.name
                        share_type = share.type
                        share_comments = share.comments

                        if share_type == 0:  # DISK_TREE
                            print(f"   {Fore.CYAN}• {share_name}{Style.RESET_ALL}")
                            if share_comments:
                                print(f"     Comments: {share_comments}")

                            sensitive_keywords = ['backup', 'conf', 'Config', 'admin', 'secret', 'private', 'share',
                                                  'data', 'documents', 'users', 'home']
                            if any(keyword in share_name.lower() for keyword in sensitive_keywords):
                                sensitive_shares.append(share_name)
                                print(f"     {Fore.YELLOW}  POTENTIALLY SENSITIVE SHARE{Style.RESET_ALL}")

                    if not shares:
                        print(f"   {Fore.YELLOW}No shares enumerated (may require authentication){Style.RESET_ALL}")

                    if sensitive_shares:
                        print(f"\n{Fore.YELLOW}[!] Sensitive shares detected:{Style.RESET_ALL}")
                        for share in sensitive_shares:
                            print(f"   • {share}")

                except OperationFailure as e:
                    print(f"{Fore.YELLOW}[!] Authentication required to list shares{Style.RESET_ALL}")
                    print(f"    Error: {str(e)[:80]}")
                except Exception as e:
                    print(f"{Fore.YELLOW}[?] Could not enumerate shares: {str(e)[:80]}{Style.RESET_ALL}")

                try:
                    server_info = conn.get_server_information()
                    print(f"\n{Fore.CYAN}Server Information:{Style.RESET_ALL}")
                    if hasattr(server_info, 'server_name'):
                        print(f"   Server Name: {server_info.server_name}")
                    if hasattr(server_info, 'os_version'):
                        print(f"   OS Version: {server_info.os_version}")
                    if hasattr(server_info, 'server_type'):
                        print(f"   Server Type: {server_info.server_type}")
                except:
                    pass

                conn.close()
            else:
                print(f"{Fore.YELLOW}[!] Anonymous connection failed (authentication required){Style.RESET_ALL}")

        except (NotConnectedError, NotReadyError, socket.timeout) as e:
            print(f"{Fore.YELLOW}[!] Connection failed: {str(e)[:60]}{Style.RESET_ALL}")
        except Exception as e:
            error_str = str(e).lower()
            if 'connection refused' in error_str:
                print(f"{Fore.YELLOW}[!] Connection refused (SMB service may be disabled){Style.RESET_ALL}")
            elif 'timed out' in error_str:
                print(f"{Fore.YELLOW}[!] Connection timeout (firewall may be blocking){Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[?] SMB connection error: {str(e)[:80]}{Style.RESET_ALL}")

    except ImportError:
        print(f"\n{Fore.YELLOW}[i] pysmb library not installed{Style.RESET_ALL}")
        print(f"    Install with: pip3 install pysmb")
        print(f"\n{Fore.CYAN}Basic SMB Detection (without pysmb):{Style.RESET_ALL}")
        print(f"   • Port 445: {'OPEN' if smb445 else 'CLOSED'}")
        print(f"   • Port 139: {'OPEN' if smb139 else 'CLOSED'}")
        print(f"   • OS Fingerprinting: Requires nmap or advanced tools")
        print(f"   • Share Enumeration: Requires pysmb or smbclient")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}VULNERABILITY ASSESSMENT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulns_found = []

    if smb445:
        vulns_found.append({
            'name': 'SMBv1 (EternalBlue)',
            'cve': 'CVE-2017-0144',
            'risk': 'CRITICAL',
            'check': 'Requires version detection (nmap -p445 --script smb-vuln-ms17-010)',
            'impact': 'Remote code execution without authentication'
        })

    if smb139:
        vulns_found.append({
            'name': 'NetBIOS Information Disclosure',
            'risk': 'MEDIUM',
            'check': 'nbtscan or nmap -sU -p137 --script nbstat',
            'impact': 'Hostname, workgroup, and user enumeration'
        })

    print(f"\n{Fore.YELLOW}Potential SMB Vulnerabilities:{Style.RESET_ALL}")
    for vuln in vulns_found:
        risk_color = Fore.MAGENTA if vuln['risk'] == 'CRITICAL' else Fore.YELLOW
        print(f"\n{risk_color}• {vuln['name']}{Style.RESET_ALL}")
        if 'cve' in vuln:
            print(f"  CVE: {vuln['cve']}")
        print(f"  Risk: {vuln['risk']}")
        print(f"  Check: {vuln['check']}")
        print(f"  Impact: {vuln['impact']}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SECURITY RECOMMENDATIONS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.YELLOW}For System Administrators:{Style.RESET_ALL}")
    print(f"   • Disable SMBv1 (vulnerable to EternalBlue)")
    print(f"   • Block SMB ports (445/139) at network perimeter")
    print(f"   • Require strong authentication for SMB access")
    print(f"   • Disable anonymous SMB access:")
    print(f"        Windows: Set 'Network access: Shares that can be accessed anonymously' to blank")
    print(f"        Samba: Set 'map to guest = never' in smb.conf")
    print(f"   • Implement network segmentation for file servers")
    print(f"   • Monitor SMB traffic for anomalous access patterns")
    print(f"   • Keep SMB implementations patched (MS17-010, etc.)")

    print(f"\n{Fore.YELLOW}For Pentesters:{Style.RESET_ALL}")
    print(f"   • Always obtain written authorization before SMB testing")
    print(f"   • Use dedicated tools for deeper analysis:")
    print(f"        • crackmapexec - comprehensive SMB enumeration")
    print(f"        • smbclient - manual share exploration")
    print(f"        • enum4linux - Linux SMB enumeration")
    print(f"        • nmap scripts (smb-vuln-*) - vulnerability detection")
    print(f"   • Never access or exfiltrate data without explicit permission")
    print(f"   • Document all testing activities for legal protection")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}LEGAL DISCLAIMER")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.RED}  SMB ACCESS WITHOUT AUTHORIZATION IS ILLEGAL{Style.RESET_ALL}")
    print(f"   • Accessing SMB shares without permission = computer fraud")
    print(f"   • Even anonymous enumeration may violate laws in some jurisdictions")
    print(f"   • Always obtain written authorization before ANY SMB testing")
    print(f"   • Maintain detailed logs of authorized testing activities")
    print(f"   • Test ONLY on systems you own or have explicit written permission")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] SMB enumeration completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")