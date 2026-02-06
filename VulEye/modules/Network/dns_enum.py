import socket
import dns.resolver
import dns.query
import dns.zone
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              DNS ENUMERATION TOOL                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    domain = input(f"\n{Fore.YELLOW}Enter target domain (e.g., example.com): {Style.RESET_ALL}").strip()

    if not domain:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://')[1].split('/')[0]

    print(f"\n{Fore.CYAN}[+] Starting DNS enumeration for: {domain}{Style.RESET_ALL}")

    try:
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}DNS SERVER DISCOVERY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        ns_records = []
        try:
            answers = dns.resolver.resolve(domain, 'NS', lifetime=5)
            print(f"\n{Fore.GREEN}[✓] Name Servers:{Style.RESET_ALL}")
            for rdata in answers:
                ns = str(rdata).rstrip('.')
                ns_records.append(ns)
                print(f"   • {ns}")

                try:
                    ip_answers = dns.resolver.resolve(ns, 'A', lifetime=3)
                    for ip in ip_answers:
                        print(f"     → IP: {ip}")
                except:
                    pass
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not resolve NS records: {str(e)}{Style.RESET_ALL}")

        if not ns_records:
            print(f"\n{Fore.RED}[!] No name servers found. Aborting DNS enumeration.{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ZONE TRANSFER TEST (AXFR){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Note: Successful zone transfer = critical misconfiguration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        zone_transfer_success = False
        zone_records = []

        for ns in ns_records[:3]:
            print(f"\n{Fore.CYAN}[→] Testing zone transfer on: {ns}{Style.RESET_ALL}")
            try:
                ns_ip = socket.gethostbyname(ns)
                zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=10, lifetime=15))
                zone_transfer_success = True

                print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] ZONE TRANSFER SUCCESSFUL{Style.RESET_ALL}")
                print(f"    Server: {ns} ({ns_ip})")
                print(f"    Records found: {len(zone.nodes)}")

                for name, node in zone.nodes.items():
                    for rdataset in node.rdatasets:
                        record_type = dns.rdatatype.to_text(rdataset.rdtype)
                        for rdata in rdataset:
                            record = str(rdata)
                            zone_records.append((str(name), record_type, record))
                            if len(zone_records) <= 20:
                                print(f"      {str(name)}.{domain} [{record_type}] → {record[:70]}")

                if len(zone_records) > 20:
                    print(f"      ... and {len(zone_records) - 20} more records")
                break

            except Exception as e:
                error_msg = str(e).lower()
                if 'refused' in error_msg or 'not authorized' in error_msg:
                    print(f"{Fore.GREEN}[✓] Zone transfer properly restricted{Style.RESET_ALL}")
                elif 'timeout' in error_msg:
                    print(f"{Fore.YELLOW}[?] Timeout - server may be filtering requests{Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[i] Transfer failed: {str(e)[:60]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}DNS RECORD ENUMERATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        record_types = ['A', 'AAAA', 'MX', 'TXT', 'SOA', 'CNAME']
        dns_findings = {}

        for rtype in record_types:
            print(f"\n{Fore.CYAN}[→] Querying {rtype} records...{Style.RESET_ALL}")
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                dns_findings[rtype] = []

                for rdata in answers:
                    if rtype == 'A':
                        ip = str(rdata)
                        dns_findings[rtype].append(ip)
                        print(f"{Fore.GREEN}[✓] A: {ip}{Style.RESET_ALL}")
                    elif rtype == 'AAAA':
                        ip = str(rdata)
                        dns_findings[rtype].append(ip)
                        print(f"{Fore.GREEN}[✓] AAAA: {ip}{Style.RESET_ALL}")
                    elif rtype == 'MX':
                        exchange = str(rdata.exchange).rstrip('.')
                        preference = rdata.preference
                        dns_findings[rtype].append((preference, exchange))
                        print(f"{Fore.GREEN}[✓] MX: {exchange} (Priority: {preference}){Style.RESET_ALL}")
                    elif rtype == 'TXT':
                        txt = str(rdata).strip('"')
                        dns_findings[rtype].append(txt)
                        print(f"{Fore.GREEN}[✓] TXT: {txt[:70]}{Style.RESET_ALL}")

                        if 'v=spf1' in txt.lower():
                            print(f"    {Fore.YELLOW}  SPF Record Found{Style.RESET_ALL}")
                        if 'v=dmarc1' in txt.lower() or 'dmarc' in txt.lower():
                            print(f"    {Fore.YELLOW}  DMARC Record Found{Style.RESET_ALL}")
                    elif rtype == 'SOA':
                        mname = str(rdata.mname).rstrip('.')
                        rname = str(rdata.rname).rstrip('.')
                        serial = rdata.serial
                        dns_findings[rtype].append((mname, rname, serial))
                        print(f"{Fore.GREEN}[✓] SOA: {mname}{Style.RESET_ALL}")
                        print(f"    Admin: {rname}")
                        print(f"    Serial: {serial}")
                    elif rtype == 'CNAME':
                        target = str(rdata).rstrip('.')
                        dns_findings[rtype].append(target)
                        print(f"{Fore.GREEN}[✓] CNAME: {target}{Style.RESET_ALL}")

            except dns.resolver.NoAnswer:
                print(f"{Fore.CYAN}[i] No {rtype} records found{Style.RESET_ALL}")
            except dns.resolver.NXDOMAIN:
                print(f"{Fore.RED}[!] Domain does not exist{Style.RESET_ALL}")
                input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
                return
            except Exception as e:
                print(f"{Fore.CYAN}[i] {rtype} query failed: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SECURITY ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        security_issues = []

        if zone_transfer_success:
            security_issues.append({
                'severity': 'CRITICAL',
                'issue': 'Zone Transfer Allowed (AXFR)',
                'impact': 'Full DNS zone disclosure - attackers can map entire infrastructure',
                'fix': 'Configure DNS server to allow AXFR only from authorized IPs'
            })

        if 'TXT' in dns_findings:
            spf_found = False
            dmarc_found = False

            for txt in dns_findings['TXT']:
                if 'v=spf1' in txt.lower():
                    spf_found = True
                    if '-all' not in txt and '~all' not in txt:
                        security_issues.append({
                            'severity': 'HIGH',
                            'issue': 'Weak SPF Policy',
                            'impact': 'Email spoofing possible',
                            'fix': 'Use strict SPF policy: v=spf1 ... -all'
                        })
                if 'v=dmarc1' in txt.lower() or 'dmarc' in txt.lower():
                    dmarc_found = True

            if not spf_found:
                security_issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'No SPF Record',
                    'impact': 'Domain vulnerable to email spoofing',
                    'fix': 'Implement SPF record to authorize sending IPs'
                })

            if not dmarc_found:
                security_issues.append({
                    'severity': 'MEDIUM',
                    'issue': 'No DMARC Record',
                    'impact': 'No email authentication policy enforcement',
                    'fix': 'Implement DMARC policy for email authentication'
                })

        if 'MX' in dns_findings:
            for priority, mx in dns_findings['MX']:
                if 'google.com' in mx.lower() or 'googlemail.com' in mx.lower():
                    print(f"{Fore.CYAN}[i] MX uses Google Workspace{Style.RESET_ALL}")
                elif 'outlook.com' in mx.lower() or 'office365.com' in mx.lower():
                    print(f"{Fore.CYAN}[i] MX uses Microsoft 365{Style.RESET_ALL}")
                elif 'mailgun' in mx.lower() or 'sendgrid' in mx.lower() or 'amazonses' in mx.lower():
                    print(f"{Fore.CYAN}[i] MX uses third-party email service{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUBDOMAIN BRUTE-FORCE (Limited)")
        print(f"{Fore.YELLOW}Note: Using small built-in wordlist for demonstration{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        subdomains_found = []
        common_subdomains = ['www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'imap', 'ns1', 'ns2', 'test',
                             'dev', 'admin', 'webdisk', 'cpanel']

        print(f"\n{Fore.CYAN}[→] Testing {len(common_subdomains)} common subdomains...{Style.RESET_ALL}")

        for sub in common_subdomains:
            try:
                hostname = f"{sub}.{domain}"
                ip = socket.gethostbyname(hostname)
                subdomains_found.append((sub, ip))
                print(f"{Fore.GREEN}[✓] {hostname} → {ip}{Style.RESET_ALL}")
            except socket.gaierror:
                pass
            except Exception:
                pass

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}DNS Records Found:{Style.RESET_ALL}")
        for rtype in ['A', 'AAAA', 'MX', 'TXT', 'SOA', 'CNAME']:
            if rtype in dns_findings:
                count = len(dns_findings[rtype]) if rtype != 'SOA' else 1
                print(f"   • {rtype}: {count} record(s)")

        print(f"\n{Fore.YELLOW}Subdomains Found: {len(subdomains_found)}{Style.RESET_ALL}")
        if subdomains_found:
            for sub, ip in subdomains_found[:10]:
                print(f"   • {sub}.{domain} → {ip}")
            if len(subdomains_found) > 10:
                print(f"   • ... and {len(subdomains_found) - 10} more")

        if security_issues:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] DNS SECURITY ISSUES DETECTED{Style.RESET_ALL}")

            for issue in security_issues:
                severity_color = Fore.MAGENTA if issue['severity'] == 'CRITICAL' else (
                    Fore.RED if issue['severity'] == 'HIGH' else Fore.YELLOW)
                print(f"\n{severity_color}• {issue['issue']} ({issue['severity']}){Style.RESET_ALL}")
                print(f"  Impact: {issue['impact']}")
                print(f"  Fix: {issue['fix']}")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Restrict zone transfers to authorized IPs only")
            print(f"   • Implement strict SPF policy with -all mechanism")
            print(f"   • Deploy DMARC policy with p=quarantine or p=reject")
            print(f"   • Remove unnecessary DNS records (test/dev environments)")
            print(f"   • Monitor DNS queries for suspicious activity")
            print(f"   • Use DNSSEC to prevent cache poisoning attacks")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical DNS security issues detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Best Practices:{Style.RESET_ALL}")
            print(f"   • Regularly audit DNS records for stale entries")
            print(f"   • Implement DNS monitoring and alerting")
            print(f"   • Use split-horizon DNS for internal/external separation")
            print(f"   • Keep DNS software updated")
            print(f"   • Log and review all zone transfer attempts")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] DNS enumeration completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW} LEGAL NOTE:{Style.RESET_ALL}")
        print(f"   Zone transfer attempts may be logged and considered suspicious activity.")
        print(f"   Always obtain written authorization before DNS testing.")
        print(f"   Unauthorized DNS enumeration may violate laws in some jurisdictions.")

    except dns.resolver.NXDOMAIN:
        print(f"\n{Fore.RED}[!] Domain does not exist.{Style.RESET_ALL}")
    except dns.resolver.NoNameservers:
        print(f"\n{Fore.RED}[!] No nameservers found for domain.{Style.RESET_ALL}")
    except socket.gaierror:
        print(f"\n{Fore.RED}[!] Unable to resolve domain.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")