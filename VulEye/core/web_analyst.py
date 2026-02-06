import requests
import urllib.parse
import socket
import ssl
import time
from datetime import datetime
from colorama import init, Fore, Style

init(autoreset=True)

def is_target_alive(target):
    try:
        requests.get(target, timeout=10, verify=False)
        return True
    except:
        return False


def detect_technologies(target):
    print(f"\n{Fore.CYAN}[→] Discovery of technologies and CMS...{Style.RESET_ALL}")
    techs = []
    tech_details = []
    try:
        resp = requests.get(target, timeout=10, verify=False)
        headers = resp.headers
        content = resp.text

        if 'Server' in headers:
            techs.append(f"Server: {headers['Server']}")
            tech_details.append({
                'type': 'Server',
                'value': headers['Server'],
                'details': 'Check for known server vulnerabilities',
                'next_steps': [
                    'Check for outdated server versions',
                    'Test for server misconfigurations'
                ]
            })

        if 'X-Powered-By' in headers:
            techs.append(f"Technology: {headers['X-Powered-By']}")
            tech_details.append({
                'type': 'Technology',
                'value': headers['X-Powered-By'],
                'details': 'Check for framework-specific vulnerabilities',
                'next_steps': [
                    'Search for known vulnerabilities for this framework',
                    'Test for version-specific exploits'
                ]
            })

        # CMS
        if '/wp-content/' in content or '/wp-includes/' in content:
            techs.append("CMS: WordPress")
            tech_details.append({
                'type': 'CMS',
                'value': 'WordPress',
                'details': 'Check for WordPress vulnerabilities',
                'next_steps': [
                    'Run: Modules → Web → sqli (for SQLi in WordPress)',
                    'Run: Modules → Web → xss (for XSS in WordPress)',
                    'Check for plugin vulnerabilities'
                ]
            })
            if 'wp-json' in content:
                techs.append("API: WordPress REST API")
                tech_details.append({
                    'type': 'API',
                    'value': 'WordPress REST API',
                    'details': 'Test for REST API vulnerabilities',
                    'next_steps': [
                        'Run: Modules → Web → api_security (for API testing)'
                    ]
                })

        if '/sites/default/' in content or 'drupal' in content.lower():
            techs.append("CMS: Drupal")
            tech_details.append({
                'type': 'CMS',
                'value': 'Drupal',
                'details': 'Check for Drupal vulnerabilities',
                'next_steps': [
                    'Run: Modules → Web → sqli (for SQLi in Drupal)',
                    'Run: Modules → Web → xss (for XSS in Drupal)'
                ]
            })

        if '/media/system/' in content or 'joomla' in content.lower():
            techs.append("CMS: Joomla")
            tech_details.append({
                'type': 'CMS',
                'value': 'Joomla',
                'details': 'Check for Joomla vulnerabilities',
                'next_steps': [
                    'Run: Modules → Web → sqli (for SQLi in Joomla)',
                    'Run: Modules → Web → xss (for XSS in Joomla)'
                ]
            })

        # Frameworks
        if 'react' in content.lower() or '__react' in content:
            techs.append("Framework: React")
            tech_details.append({
                'type': 'Framework',
                'value': 'React',
                'details': 'Check for React-specific vulnerabilities',
                'next_steps': [
                    'Test for client-side XSS',
                    'Check for insecure deserialization'
                ]
            })

        if 'angular' in content.lower() or 'ng-app' in content:
            techs.append("Framework: Angular")
            tech_details.append({
                'type': 'Framework',
                'value': 'Angular',
                'details': 'Check for Angular-specific vulnerabilities',
                'next_steps': [
                    'Test for client-side XSS',
                    'Check for insecure deserialization'
                ]
            })

        if 'vue' in content.lower() or '__vue' in content:
            techs.append("Framework: Vue.js")
            tech_details.append({
                'type': 'Framework',
                'value': 'Vue.js',
                'details': 'Check for Vue.js-specific vulnerabilities',
                'next_steps': [
                    'Test for client-side XSS',
                    'Check for insecure deserialization'
                ]
            })

        # Libraries
        if 'jquery' in content.lower():
            techs.append("Library: jQuery")
            tech_details.append({
                'type': 'Library',
                'value': 'jQuery',
                'details': 'Check for jQuery vulnerabilities',
                'next_steps': [
                    'Test for jQuery XSS vulnerabilities',
                    'Check for outdated jQuery versions'
                ]
            })

        if 'bootstrap' in content.lower():
            techs.append("CSS: Bootstrap")
            tech_details.append({
                'type': 'Library',
                'value': 'Bootstrap',
                'details': 'Check for Bootstrap-related issues',
                'next_steps': [
                    'Check for outdated Bootstrap versions',
                    'Test for CSS injection'
                ]
            })

        # CDN
        if 'cloudflare' in headers.get('Server', '').lower() or 'cf-ray' in headers:
            techs.append("CDN: Cloudflare")
            tech_details.append({
                'type': 'CDN',
                'value': 'Cloudflare',
                'details': 'Check for Cloudflare bypass techniques',
                'next_steps': [
                    'Test for Cloudflare bypass',
                    'Check for IP leakage'
                ]
            })

        if 'amazonaws.com' in content or 'cloudfront' in content.lower():
            techs.append("Cloud: AWS")
            tech_details.append({
                'type': 'Cloud',
                'value': 'AWS',
                'details': 'Check for AWS misconfigurations',
                'next_steps': [
                    'Test for AWS metadata access',
                    'Check for S3 bucket misconfigurations'
                ]
            })

        print(f"{Fore.GREEN}[✓] Technologies found: {len(techs)}{Style.RESET_ALL}")
        return techs, tech_details
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Technology detection error: {str(e)[:60]}{Style.RESET_ALL}")
        return [], []


def check_ssl(target):
    if not target.startswith('https://'):
        return ["⚠️  The site does not use HTTPS"], []

    print(f"\n{Fore.CYAN}[→] SSL/TLS configuration analysis...{Style.RESET_ALL}")
    findings = []
    ssl_details = []
    try:
        hostname = urllib.parse.urlparse(target).hostname
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                ssl_ver = ssock.version()
                cipher = ssock.cipher()
                findings.append(f"Version SSL/TLS: {ssl_ver}")
                findings.append(f"Cipher: {cipher[0]} ({cipher[1]} бит)")
                ssl_details.append({
                    'type': 'SSL/TLS Version',
                    'value': ssl_ver,
                    'details': 'Check for outdated protocols',
                    'next_steps': [
                        'Run: Modules → Config → ssl_check (for detailed SSL analysis)'
                    ]
                })

                if ssl_ver in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                    findings.append(
                        f"{Fore.RED}⚠️  OBSOLETE PROTOCOL: {ssl_ver} (recommended TLS 1.2+){Style.RESET_ALL}")
                    ssl_details.append({
                        'type': 'SSL/TLS Version',
                        'value': ssl_ver,
                        'details': 'Outdated protocol detected - high risk',
                        'next_steps': [
                            'Immediate: Disable outdated protocols',
                            'Check for POODLE vulnerability (CVE-2014-3566)'
                        ]
                    })

                cert = ssock.getpeercert()
                if cert:
                    not_after = cert.get('notAfter', 'N/A')
                    try:
                        expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        days_left = (expiry - datetime.utcnow()).days
                        if days_left < 0:
                            findings.append(
                                f"{Fore.RED}⚠️ CERTIFICATE EXPIRED {abs(days_left)} DAYS AGO{Style.RESET_ALL}")
                            ssl_details.append({
                                'type': 'Certificate Expiry',
                                'value': 'EXPIRED',
                                'details': 'Certificate expired - high risk',
                                'next_steps': [
                                    'Immediate: Replace expired certificate',
                                    'Check for certificate revocation'
                                ]
                            })
                        elif days_left < 30:
                            findings.append(
                                f"{Fore.YELLOW}⚠️  The certificate expires in {days_left} days{Style.RESET_ALL}")
                            ssl_details.append({
                                'type': 'Certificate Expiry',
                                'value': f'Expires in {days_left} days',
                                'details': 'Certificate expiration warning',
                                'next_steps': [
                                    'Plan certificate renewal',
                                    'Check for auto-renewal setup'
                                ]
                            })
                        else:
                            findings.append(f"Validity period: to {not_after} ({days_left} days)")
                    except:
                        findings.append(f"Validity period: {not_after}")
    except Exception as e:
        findings.append(f"SSL parsing error: {str(e)[:60]}")

    print(f"{Fore.GREEN}[✓] SSL analysis completed{Style.RESET_ALL}")
    return findings, ssl_details


def check_security_headers(target):
    print(f"\n{Fore.CYAN}[→] Checking security headers...{Style.RESET_ALL}")
    findings = []
    header_details = []
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
                header_details.append({
                    'type': 'Security Header',
                    'value': header,
                    'details': f'Missing: {desc}',
                    'next_steps': [
                        f'Add {header} header to server configuration',
                        f'Check server Config: Apache (mod_headers), Nginx, IIS'
                    ]
                })
            else:
                findings.append(f"✅ {header}: {headers[header][:50]}")

        if missing:
            findings.extend(missing)
            print(f"{Fore.YELLOW}[!] Missing titles found: {len(missing)}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] All critical headings are present{Style.RESET_ALL}")
    except Exception as e:
        findings.append(f"Header validation error: {str(e)[:60]}")

    return findings, header_details


def check_exposed_files(target):
    print(f"\n{Fore.CYAN}[→] Search for open sensitive files...{Style.RESET_ALL}")
    findings = []
    file_details = []
    sensitive = [
        '.git/Config', '.env', 'backup.zip', 'database.sql', 'wp-Config.php',
        'Config.php', 'phpinfo.php', 'robots.txt', '.htaccess', 'debug.log'
    ]

    for path in sensitive:
        url = urllib.parse.urljoin(target, path)
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and len(resp.content) > 100:
                if path == '.git/Config':
                    findings.append(
                        f"{Fore.MAGENTA}🔥 CRITICAL: .git open - source code leak ({url}){Style.RESET_ALL}")
                    file_details.append({
                        'type': 'Critical File',
                        'value': '.git/Config',
                        'details': 'Source code leak - high risk',
                        'next_steps': [
                            'Immediate: Remove .git directory from web root',
                            'Check for sensitive data in source code',
                            'Run: Modules → Config → exposed (to check for other exposed files)'
                        ]
                    })
                elif path == '.env':
                    findings.append(
                        f"{Fore.MAGENTA}🔥 CRITICAL: .env open - secrets leak ({url}){Style.RESET_ALL}")
                    file_details.append({
                        'type': 'Critical File',
                        'value': '.env',
                        'details': 'Secrets leak - high risk',
                        'next_steps': [
                            'Immediate: Remove .env from web root',
                            'Rotate all exposed credentials',
                            'Run: Modules → Config → exposed (to check for other exposed files)'
                        ]
                    })
                elif 'backup' in path.lower() or 'sql' in path.lower():
                    findings.append(f"{Fore.RED}⚠️  Important: Backup/database found ({url}){Style.RESET_ALL}")
                    file_details.append({
                        'type': 'Important File',
                        'value': path,
                        'details': 'Backup/database file exposure',
                        'next_steps': [
                            'Remove backup files from web root',
                            'Check for sensitive data in backups',
                            'Run: Modules → Config → exposed (to check for other exposed files)'
                        ]
                    })
                else:
                    findings.append(f"⚠️ Opened file: {path} ({url})")
                    file_details.append({
                        'type': 'Exposed File',
                        'value': path,
                        'details': 'Exposed file - potential information leak',
                        'next_steps': [
                            'Check file content for sensitive information',
                            'Run: Modules → Config → exposed (to check for other exposed files)'
                        ]
                    })
        except:
            pass

    if findings:
        print(f"{Fore.RED}[!] Open files found: {len(findings)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓] No sensitive files found{Style.RESET_ALL}")

    return findings, file_details


def check_directory_listing(target):
    print(f"\n{Fore.CYAN}[→] Checking open directories...{Style.RESET_ALL}")
    findings = []
    dir_details = []
    dirs = ['admin/', 'backup/', 'Config/', 'uploads/', 'wp-content/uploads/']

    for d in dirs:
        url = urllib.parse.urljoin(target, d)
        try:
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200 and (
                    'index of' in resp.text.lower() or 'directory listing' in resp.text.lower()):
                findings.append(f"📁 Directory open: {url}")
                dir_details.append({
                    'type': 'Open Directory',
                    'value': d,
                    'details': 'Directory listing enabled - information leak',
                    'next_steps': [
                        'Disable directory listing in server Config',
                        'Check for sensitive files in directory',
                        'Run: Modules → Config → dir_listing (for detailed directory analysis)'
                    ]
                })
        except:
            pass

    if findings:
        print(f"{Fore.YELLOW}[!] Open directories found: {len(findings)}{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}[✓]No open directories found{Style.RESET_ALL}")

    return findings, dir_details


def check_vulnerabilities(target):
    print(f"\n{Fore.CYAN}[→] Quick vulnerability check...{Style.RESET_ALL}")
    vulns = []
    vuln_details = []

    # LFI Check
    test_url = f"{target}?page=../../../../etc/passwd"
    try:
        resp = requests.get(test_url, timeout=8, verify=False)
        if 'root:x:' in resp.text or '[extensions]' in resp.text:
            vulns.append(f"{Fore.MAGENTA}🔥 LFI vulnerability confirmed{Style.RESET_ALL}")
            vuln_details.append({
                'type': 'LFI',
                'value': 'Confirmed',
                'details': 'Local File Inclusion vulnerability',
                'next_steps': [
                    'Run: Modules → Web → lfi (for full LFI analysis)',
                    'Test for path traversal (../, ../../)',
                    'Check for log poisoning',
                    'Test for /etc/passwd, /etc/shadow, /var/log/apache2/access.log'
                ]
            })
    except:
        pass

    # XSS Check
    test_url = f"{target}?q=<script>alert(1)</script>"
    try:
        resp = requests.get(test_url, timeout=8, verify=False)
        if '<script>alert(1)</script>' in resp.text:
            vulns.append(f"{Fore.RED}⚠️  XSS vulnerability (reflected){Style.RESET_ALL}")
            vuln_details.append({
                'type': 'XSS',
                'value': 'Reflected',
                'details': 'Cross-Site Scripting vulnerability',
                'next_steps': [
                    'Run: Modules → Web → xss (for full XSS analysis)',
                    'Test for stored XSS in comments forms',
                    'Check for DOM-based XSS',
                    'Test for different payloads (alert(1), steal cookies)'
                ]
            })
    except:
        pass

    # Brute Force Check
    try:
        responses = []
        for _ in range(3):
            resp = requests.post(target, data={'user': 'test', 'pass': 'invalid'}, timeout=5, verify=False)
            responses.append(resp.status_code)
            time.sleep(0.5)
        if all(r == 200 for r in responses):
            vulns.append(f"{Fore.YELLOW}⚠️  Possible lack of brute force protection{Style.RESET_ALL}")
            vuln_details.append({
                'type': 'Brute Force',
                'value': 'Possible lack of protection',
                'details': 'No rate limiting detected',
                'next_steps': [
                    'Run: Modules → Auth → rate_limit (for detailed analysis)',
                    'Test with 10+ login attempts',
                    'Check for account lockout',
                    'Test for CAPTCHA bypass'
                ]
            })
    except:
        pass

    if vulns:
        print(f"{Fore.RED}[!] Potential vulnerabilities were discovered: {Style.RESET_ALL}")
        for v in vulns:
            print(f"   {v}")
    else:
        print(f"{Fore.GREEN}[✓] No critical vulnerabilities found (manual verification required){Style.RESET_ALL}")

    return vulns, vuln_details


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}          COMPREHENSIVE WEB SCANNER — FULL SITE ANALYSIS        {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")


    target = input(f"\n{Fore.YELLOW}Enter the target URL (e.g. https://example.com  ): {Style.RESET_ALL}").strip()

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

    # Запускаем сканирование с детализацией
    results = {}
    techs, tech_details = detect_technologies(target)
    results['Technologies'] = techs
    results['SSL/TLS'] = check_ssl(target)[0]
    results['Security Headers'] = check_security_headers(target)[0]
    results['Open files'] = check_exposed_files(target)[0]
    results['Open directories'] = check_directory_listing(target)[0]
    vulns, vuln_details = check_vulnerabilities(target)
    results['Vulnerabilities'] = vulns

    # Собираем все детали для рекомендаций
    all_details = {
        'Technologies': tech_details,
        'SSL/TLS': check_ssl(target)[1],
        'Security Headers': check_security_headers(target)[1],
        'Open files': check_exposed_files(target)[1],
        'Open directories': check_directory_listing(target)[1],
        'Vulnerabilities': vuln_details
    }

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
    print(f"{Fore.CYAN}WHERE TO DIG DEEPER (NEXT STEPS)")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    # Генерируем рекомендации
    recommendations = []

    # Технологии
    for detail in all_details['Technologies']:
        if detail['type'] == 'CMS':
            recommendations.append(f"• {detail['value']} detected → Check for CMS-specific vulnerabilities:")
            for step in detail['next_steps']:
                recommendations.append(f"  → {step}")

    # Открытые файлы
    for detail in all_details['Open files']:
        recommendations.append(f"• {detail['value']} exposed → Critical vulnerability:")
        for step in detail['next_steps']:
            recommendations.append(f"  → {step}")

    # Уязвимости
    for detail in all_details['Vulnerabilities']:
        recommendations.append(f"• {detail['type']} vulnerability ({detail['value']}):")
        for step in detail['next_steps']:
            recommendations.append(f"  → {step}")

    # Открытые директории
    for detail in all_details['Open directories']:
        recommendations.append(f"• {detail['value']} directory listing → Information leak:")
        for step in detail['next_steps']:
            recommendations.append(f"  → {step}")

    # Заголовки безопасности
    for detail in all_details['Security Headers']:
        recommendations.append(f"• {detail['value']} missing → Security issue:")
        for step in detail['next_steps']:
            recommendations.append(f"  → {step}")

    if recommendations:
        for rec in recommendations:
            print(f"{Fore.GREEN}{rec}{Style.RESET_ALL}")
    else:
        print(f"{Fore.CYAN}[i] No specific recommendations - manual review required{Style.RESET_ALL}")

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
                f.write("WHERE TO DIG DEEPER (NEXT STEPS)\n")
                f.write("=" * 70 + "\n")
                for rec in recommendations:
                    f.write(f"{rec}\n")

                f.write("\n" + "=" * 70 + "\n")
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