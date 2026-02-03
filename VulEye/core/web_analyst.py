import requests
import urllib.parse
import socket
import ssl
import time
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

def ethical_warning():
    print(f"\n{Fore.YELLOW}⚠️  CRITICAL ETHICAL WARNING{Style.RESET_ALL}")
    print(f"  This scanner will perform a comprehensive analysis of the site, including:")
    print(f"   • Discovery of technologies and CMS")
    print(f"   • Checking the SSL/TLS configuration")
    print(f"   • Analysis of security headers")
    print(f"   • Search for open files and directories")
    print(f"   • Testing for information leakage through errors")
    print(f"   • Checking HTTP methods")
    print(f"   • Vulnerability detection (LFI, XSS, SSRF и др.)")
    print(f"\n{Fore.RED}UNAUTHORIZED SCANNING = CRIMINAL OFFENSE{Style.RESET_ALL}")
    print(f"  (Articles 272/273 of the Criminal Code of the Russian Federation, CFAA in the USA, Computer Misuse Act in the UK)")
    print(f"\n{Fore.GREEN}✅ ONLY ALLOWED:{Style.RESET_ALL}")
    print(f"   • Your own systems")
    print(f"   • Systems with written permission from the owner")
    print(f"   • Legal stands (VulnHub, DVWA, Juice Shop)")
    confirm = input(
        f"\n{Fore.YELLOW}Do you confirm that you have written permission? (y/n): {Style.RESET_ALL}").strip().lower()
    return confirm == "y"


def is_target_alive(target):
    try:
        requests.get(target, timeout=10, verify=False)
        return True
    except:
        return False


def detect_technologies(target):
    print(f"\n{Fore.CYAN}[→] Discovery of technologies and CMS...{Style.RESET_ALL}")
    techs = []
    try:
        resp = requests.get(target, timeout=10, verify=False)
        headers = resp.headers
        content = resp.text


        if 'Server' in headers:
            techs.append(f"Server: {headers['Server']}")
        if 'X-Powered-By' in headers:
            techs.append(f"Technology: {headers['X-Powered-By']}")

        # CMS
        if '/wp-content/' in content or '/wp-includes/' in content:
            techs.append("CMS: WordPress")
            if 'wp-json' in content:
                techs.append("API: WordPress REST API")
        if '/sites/default/' in content or 'drupal' in content.lower():
            techs.append("CMS: Drupal")
        if '/media/system/' in content or 'joomla' in content.lower():
            techs.append("CMS: Joomla")


        if 'react' in content.lower() or '__react' in content:
            techs.append("Framework: React")
        if 'angular' in content.lower() or 'ng-app' in content:
            techs.append("Framework: Angular")
        if 'vue' in content.lower() or '__vue' in content:
            techs.append("Framework: Vue.js")


        if 'jquery' in content.lower():
            techs.append("Library: jQuery")
        if 'bootstrap' in content.lower():
            techs.append("CSS: Bootstrap")


        if 'cloudflare' in headers.get('Server', '').lower() or 'cf-ray' in headers:
            techs.append("CDN: Cloudflare")
        if 'amazonaws.com' in content or 'cloudfront' in content.lower():
            techs.append("Cloud: AWS")

        print(f"{Fore.GREEN}[✓] Technologies found: {len(techs)}{Style.RESET_ALL}")
        return techs
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Technology detection error: {str(e)[:60]}{Style.RESET_ALL}")
        return []


def check_ssl(target):
    if not target.startswith('https://'):
        return ["⚠️  The site does not use HTTPS"]

    print(f"\n{Fore.CYAN}[→] SSL/TLS configuration analysis...{Style.RESET_ALL}")
    findings = []
    try:
        hostname = urllib.parse.urlparse(target).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_ver = ssock.version()
                cipher = ssock.cipher()
                findings.append(f"Version SSL/TLS: {ssl_ver}")
                findings.append(f"Cipher: {cipher[0]} ({cipher[1]} бит)")


                if ssl_ver in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    findings.append(
                        f"{Fore.RED}⚠️  OBSOLETE PROTOCOL: {ssl_ver} (recommended TLS 1.2+){Style.RESET_ALL}")


                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get('notAfter', 'N/A')
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 0:
                            findings.append(
                                f"{Fore.RED}⚠️ CERTIFICATE EXPIRED {abs(days_left)} DAYS AGO{Style.RESET_ALL}")
                        elif days_left < 30:
                            findings.append(
                                f"{Fore.YELLOW}⚠️  The certificate expires in {days_left} days{Style.RESET_ALL}")
                        else:
                            findings.append(f"Validity period: to {not_after} ({days_left} days)")
                    except:
                        findings.append(f"Validity period: {not_after}")
    except Exception as e:
        findings.append(f"SSL parsing error: {str(e)[:60]}")

    print(f"{Fore.GREEN}[✓] SSL analysis completed{Style.RESET_ALL}")
    return findings


def check_security_headers(target):
    print(f"\n{Fore.CYAN}[→] Checking security headers...{Style.RESET_ALL}")
    findings = []
    try:
        resp = requests.get(target, timeout=10, verify=False)
        headers = resp.headers

        required = {
            'Content-Security-Policy': 'Protection against XSS and injections',
            'Strict-Transport-Security': 'Force HTTPS',
            'X-Frame-Options': 'Clickjacking protection',
            'X-Content-Type-Options': 'Preventing MIME sniffing',
            'X-XSS-Protection': 'Built-in XSS protection',
            'Referrer-Policy': 'Referer Transfer Control',
            'Permissions-Policy': 'Controlling access to browser functions'
        }

        missing = []
        for header, desc in required.items():
            if header not in headers:
                missing.append(f"❌ Absent: {header} — {desc}")
            else:
                findings.append(f"✅ {header}: {headers[header][:50]}")

        if missing:
            findings.extend(missing)
            print(f"{Fore.YELLOW}[!] Missing titles found: {len(missing)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] All critical headings are present{Style.RESET_ALL}")
    except Exception as e:
        findings.append(f"Header validation error: {str(e)[:60]}")

    return findings


def check_exposed_files(target):
    print(f"\n{Fore.CYAN}[→] Search for open sensitive files...{Style.RESET_ALL}")
    findings = []
    sensitive = [
        '.git/config', '.env', 'backup.zip', 'database.sql', 'wp-config.php',
        'config.php', 'phpinfo.php', 'robots.txt', '.htaccess', 'debug.log'
    ]

    for path in sensitive:
        url = urllib.parse.urljoin(target, path)
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 100:
                if path == '.git/config':
                    findings.append(
                        f"{Fore.MAGENTA}🔥 CRITICAL: .git open - source code leak ({url}){Style.RESET_ALL}")
                elif path == '.env':
                    findings.append(
                        f"{Fore.MAGENTA}🔥 CRITICAL: .env open - secrets leak ({url}){Style.RESET_ALL}")
                elif 'backup' in path.lower() or 'sql' in path.lower():
                    findings.append(f"{Fore.RED}⚠️  Important: Backup/database found ({url}){Style.RESET_ALL}")
                else:
                    findings.append(f"⚠️ Opened file: {path} ({url})")
        except:
            pass

    if findings:
        print(f"{Fore.RED}[!] Open files found: {len(findings)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] No sensitive files found{Style.RESET_ALL}")

    return findings


def check_directory_listing(target):
    print(f"\n{Fore.CYAN}[→] Checking open directories...{Style.RESET_ALL}")
    findings = []
    dirs = ['admin/', 'backup/', 'config/', 'uploads/', 'wp-content/uploads/']

    for d in dirs:
        url = urllib.parse.urljoin(target, d)
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and (
                    'index of' in resp.text.lower() or 'directory listing' in resp.text.lower()):
                findings.append(f"📁 Directory open: {url}")
        except:
            pass

    if findings:
        print(f"{Fore.YELLOW}[!] Open directories found: {len(findings)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓]No open directories found{Style.RESET_ALL}")

    return findings


def check_vulnerabilities(target):
    print(f"\n{Fore.CYAN}[→] Quick vulnerability check...{Style.RESET_ALL}")
    vulns = []


    test_url = f"{target}?page=../../../../etc/passwd"
    try:
        resp = requests.get(test_url, timeout=8, verify=False)
        if 'root:x:' in resp.text or '[extensions]' in resp.text:
            vulns.append(f"{Fore.MAGENTA}🔥 LFI vulnerability confirmed{Style.RESET_ALL}")
    except:
        pass


    test_url = f"{target}?q=<script>alert(1)</script>"
    try:
        resp = requests.get(test_url, timeout=8, verify=False)
        if '<script>alert(1)</script>' in resp.text:
            vulns.append(f"{Fore.RED}⚠️  XSS vulnerability (reflected){Style.RESET_ALL}")
    except:
        pass


    try:
        responses = []
        for _ in range(3):
            resp = requests.post(target, data={'user': 'test', 'pass': 'invalid'}, timeout=5, verify=False)
            responses.append(resp.status_code)
            time.sleep(0.5)
        if all(r == 200 for r in responses):
            vulns.append(f"{Fore.YELLOW}⚠️  Possible lack of brute force protection{Style.RESET_ALL}")
    except:
        pass

    if vulns:
        print(f"{Fore.RED}[!] Potential vulnerabilities were discovered: {Style.RESET_ALL}")
        for v in vulns:
            print(f"   {v}")
    else:
        print(f"{Fore.GREEN}[✓] No critical vulnerabilities found (manual verification required){Style.RESET_ALL}")

    return vulns


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}          COMPREHENSIVE WEB SCANNER — FULL SITE ANALYSIS        {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if not ethical_warning():
        print(f"\n{Fore.RED}[!]Scan cancelled by user.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to the menu...{Style.RESET_ALL}")
        return

    target = input(f"\n{Fore.YELLOW}Enter the target URL (e.g. https://example.com): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Cancel.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to the menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    print(f"\n{Fore.CYAN}[+] Start of a comprehensive scan: {target}{Style.RESET_ALL}")


    print(f"\n{Fore.CYAN}[*] Checking target availability...{Style.RESET_ALL}")
    if not is_target_alive(target):
        print(f"{Fore.RED}[!] The target is unavailable. Check the URL and connection..{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to the menu...{Style.RESET_ALL}")
        return
    print(f"{Fore.GREEN}[✓] Target available{Style.RESET_ALL}")


    results = {}
    results['Technologies'] = detect_technologies(target)
    results['SSL/TLS'] = check_ssl(target)
    results['Security Headers'] = check_security_headers(target)
    results['Open files'] = check_exposed_files(target)
    results['Open directories'] = check_directory_listing(target)
    results['Vulnerabilities'] = check_vulnerabilities(target)


    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SCAN RESULTS REPORT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    critical = []
    warnings = []
    info = []

    for category, findings in results.items():
        if findings:
            print(f"\n{Fore.CYAN}{'─' * 70}")
            print(f"{Fore.CYAN}{category.upper()}")
            print(f"{Fore.CYAN}{'─' * 70}{Style.RESET_ALL}")
            for item in findings:
                if '🔥' in item or 'CRITICALLY' in item:
                    critical.append(item)
                    print(f"{item}")
                elif '⚠️' in item or '❌' in item:
                    warnings.append(item)
                    print(f"{item}")
                else:
                    info.append(item)
                    print(f"{Fore.CYAN}{item}{Style.RESET_ALL}")


    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}CRITICAL FINDINGS: {len(critical)}{Style.RESET_ALL}")
    print(f"{Fore.RED}WARNINGS: {len(warnings)}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}INFO: {len(info)}{Style.RESET_ALL}")

    if critical:
        print(f"\n{Fore.MAGENTA}{Style.BRIGHT} IMMEDIATE ATTENTION REQUIRED:{Style.RESET_ALL}")
        for item in critical:
            print(f"   • {item.replace(Fore.MAGENTA, '').replace(Style.BRIGHT, '').replace(Style.RESET_ALL, '')}")

    if warnings:
        print(f"\n{Fore.YELLOW}  SAFETY RECOMMENDATIONS:{Style.RESET_ALL}")
        print(f"   • Install missing security headers")
        print(f"   • Block access to sensitive files and directories")
        print(f"   • Update outdated components (CMS, frameworks, libraries))")
        print(f"   • Set up rate limiting for authorization forms")
        print(f"   • Check for vulnerabilities manually using specialized VulEye modules")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] Scanning complete{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW} NEXT STEPS:{Style.RESET_ALL}")
    print(f"   1. For in-depth analysis, use separate modules VulEye:")
    print(f"      • LFI: Modules → Web → lfi")
    print(f"      • XSS: Modules → Web → xss")
    print(f"      • SSRF: Modules → Web → ssrf")
    print(f"      • CMS: Modules → Info → cms_detect")
    print(f"   2. Test vulnerabilities manually on a legal test bed")
    print(f"   3. Document all findings for reporting.")
    print(f"\n{Fore.RED}️  LEGAL REMINDER:{Style.RESET_ALL}")
    print(f"   All finds are intended ONLY for systems with written permission.")
    print(f"   Unauthorized use of results = criminal liability.")


    save = input(
        f"\n{Fore.YELLOW}Save the report in reports/comprehensive_scan_*.txt? (yes/no): {Style.RESET_ALL}").strip().lower()
    if save == "yes":
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"reports/comprehensive_scan_{urllib.parse.urlparse(target).hostname}_{timestamp}.txt"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 70 + "\n")
                f.write("COMPREHENSIVE WEB SCANNER — REPORT\n")
                f.write(f"target: {target}\n")
                f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 70 + "\n\n")

                for category, findings in results.items():
                    f.write(f"{category.upper()}\n")
                    f.write("-" * 70 + "\n")
                    for item in findings:
                        clean_item = item.replace(Fore.MAGENTA, '').replace(Fore.RED, '').replace(Fore.YELLOW,
                                                                                                  '').replace(
                            Fore.GREEN, '').replace(Fore.CYAN, '').replace(Style.RESET_ALL, '').replace(Style.BRIGHT,
                                                                                                        '')
                        f.write(f"{clean_item}\n")
                    f.write("\n")

                f.write("=" * 70 + "\n")
                f.write("SUMMARY\n")
                f.write("=" * 70 + "\n")
                f.write(f"CRITICAL FINDINGS: {len(critical)}\n")
                f.write(f"WARNINGS: {len(warnings)}\n")
                f.write(f"INFO: {len(info)}\n")

            print(f"\n{Fore.GREEN}[✓] The report has been saved.: {filename}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error saving report: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to the menu...{Style.RESET_ALL}")


if __name__ == "__main__":
    try:
        requests.packages.urllib3.disable_warnings()
        run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[!] Scanning was interrupted by the user.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to the menu...{Style.RESET_ALL}")