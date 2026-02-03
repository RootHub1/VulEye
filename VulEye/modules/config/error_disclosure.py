import requests
from urllib.parse import urlparse, urljoin
import re
from colorama import init, Fore, Style

init(autoreset=True)


def test_error_trigger(url, payload):
    try:
        if '?' in url:
            test_url = f"{url}&{payload}"
        else:
            test_url = f"{url}?{payload}"

        response = requests.get(test_url, timeout=8, verify=False)

        return response.status_code, response.text, response.headers
    except:
        return None, None, None


def analyze_response(content, headers):
    findings = []
    severity = 'NONE'

    if not content:
        return findings, severity

    content_lower = content.lower()

    error_patterns = {
        'stack_trace': {
            'patterns': ['stack trace', 'traceback', 'at line', 'file:', 'in function', 'called from'],
            'severity': 'HIGH',
            'type': 'Stack Trace Disclosure'
        },
        'file_path': {
            'patterns': ['/var/www/', '/home/', '/usr/local/', 'c:\\\\', 'c:/', '.php on line', '.py", line'],
            'severity': 'HIGH',
            'type': 'File Path Disclosure'
        },
        'database_error': {
            'patterns': ['sql syntax', 'mysql error', 'postgresql error', 'oracle error', 'sqlite error',
                         'database error', 'query failed'],
            'severity': 'HIGH',
            'type': 'Database Error Disclosure'
        },
        'debug_info': {
            'patterns': ['debug mode', 'debug=true', 'error_reporting', 'display_errors', 'notice:', 'warning:',
                         'fatal error'],
            'severity': 'MEDIUM',
            'type': 'Debug Information Disclosure'
        },
        'server_version': {
            'patterns': ['apache/', 'nginx/', 'iis/', 'tomcat/', 'php/', 'python/', 'django/', 'flask/'],
            'severity': 'LOW',
            'type': 'Server Version Disclosure'
        },
        'memory_address': {
            'patterns': ['0x[0-9a-f]{8,}', 'memory address', 'segmentation fault'],
            'severity': 'MEDIUM',
            'type': 'Memory Address Disclosure'
        },
        'source_code': {
            'patterns': ['<?php', '<%', '<?=', 'def ', 'function ', 'class ', 'import ', 'require '],
            'severity': 'CRITICAL',
            'type': 'Source Code Disclosure'
        },
        'config_file': {
            'patterns': ['config.php', 'settings.py', 'web.config', '.env', 'database.yml'],
            'severity': 'CRITICAL',
            'type': 'Configuration File Disclosure'
        }
    }

    for error_type, config in error_patterns.items():
        for pattern in config['patterns']:
            if pattern in content_lower:
                findings.append({
                    'type': config['type'],
                    'severity': config['severity'],
                    'pattern': pattern,
                    'context': get_context(content, pattern)
                })

                if config['severity'] == 'CRITICAL':
                    severity = 'CRITICAL'
                elif config['severity'] == 'HIGH' and severity not in ['CRITICAL']:
                    severity = 'HIGH'
                elif config['severity'] == 'MEDIUM' and severity not in ['CRITICAL', 'HIGH']:
                    severity = 'MEDIUM'

    server_header = headers.get('Server', '')
    if server_header and any(keyword in server_header.lower() for keyword in ['apache', 'nginx', 'iis', 'tomcat']):
        findings.append({
            'type': 'Server Header Disclosure',
            'severity': 'LOW',
            'pattern': server_header,
            'context': f'Server: {server_header}'
        })

    x_powered_by = headers.get('X-Powered-By', '')
    if x_powered_by:
        findings.append({
            'type': 'Technology Stack Disclosure',
            'severity': 'LOW',
            'pattern': x_powered_by,
            'context': f'X-Powered-By: {x_powered_by}'
        })

    return findings, severity


def get_context(content, pattern, context_size=100):
    match = re.search(re.escape(pattern), content, re.IGNORECASE)
    if match:
        start = max(0, match.start() - context_size)
        end = min(len(content), match.end() + context_size)
        return content[start:end]
    return None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              ERROR MESSAGE DISCLOSURE SCANNER                     {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL (e.g., https://example.com/page.php?id=1): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing error message disclosure for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ERROR TRIGGERING TESTS")
        print(f"{Fore.YELLOW}Note: Testing various payloads to trigger error messages{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        test_payloads = [
            ('id', "'"),
            ('id', '"'),
            ('id', '1 OR 1=1'),
            ('id', '../../../../etc/passwd'),
            ('debug', '1'),
            ('test', '<script>alert(1)</script>'),
            ('page', 'nonexistentpage'),
            ('limit', '-1'),
            ('offset', '999999999'),
            ('sort', "'; DROP TABLE users;--"),
            ('search', "' UNION SELECT NULL,NULL,NULL--"),
            ('file', '../../../../../../etc/passwd%00'),
            ('param', '${{7*7}}'),
            ('data', '<?php system("id"); ?>'),
            ('cmd', 'cat /etc/passwd')
        ]

        all_findings = []
        total_tests = 0
        vulnerabilities_found = 0

        for param, payload in test_payloads:
            total_tests += 1
            print(f"\n{Fore.CYAN}[→] Test {total_tests}/{len(test_payloads)}: {param}={payload[:50]}{Style.RESET_ALL}")

            status, content, headers = test_error_trigger(target, f"{param}={payload}")

            if status:
                print(f"    Status: {status}")

                findings, severity = analyze_response(content, headers)

                if findings:
                    vulnerabilities_found += 1
                    severity_color = Fore.MAGENTA if severity == 'CRITICAL' else (
                        Fore.RED if severity == 'HIGH' else (Fore.YELLOW if severity == 'MEDIUM' else Fore.CYAN))
                    print(
                        f"    {severity_color}[!] {len(findings)} issue(s) found (Severity: {severity}){Style.RESET_ALL}")

                    for finding in findings[:3]:
                        print(f"      • {finding['type']} ({finding['severity']})")

                    all_findings.extend(findings)
                else:
                    print(f"    {Fore.GREEN}[✓] No sensitive information disclosed{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}[?] Request failed (timeout/error){Style.RESET_ALL}")

            import time
            time.sleep(0.5)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RESULTS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Total tests performed: {total_tests}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerabilities found: {vulnerabilities_found}{Style.RESET_ALL}")

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in all_findings:
            severity_counts[finding['severity']] += 1

        print(f"\n{Fore.MAGENTA}Critical issues: {severity_counts['CRITICAL']}{Style.RESET_ALL}")
        print(f"{Fore.RED}High severity issues: {severity_counts['HIGH']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium severity issues: {severity_counts['MEDIUM']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Low severity issues: {severity_counts['LOW']}{Style.RESET_ALL}")

        if all_findings:
            print(f"\n{Fore.RED}[!] ERROR MESSAGE DISCLOSURE VULNERABILITIES DETECTED{Style.RESET_ALL}")

            critical_findings = [f for f in all_findings if f['severity'] == 'CRITICAL']
            high_findings = [f for f in all_findings if f['severity'] == 'HIGH']

            if critical_findings:
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT} CRITICAL FINDINGS:{Style.RESET_ALL}")
                for finding in critical_findings[:5]:
                    print(f"\n{Fore.MAGENTA}• {finding['type']}{Style.RESET_ALL}")
                    print(f"  Pattern: {finding['pattern']}")
                    if finding['context']:
                        print(f"  Context: {finding['context'][:150]}...")

            if high_findings:
                print(f"\n{Fore.RED} HIGH SEVERITY FINDINGS:{Style.RESET_ALL}")
                for finding in high_findings[:10]:
                    print(f"\n{Fore.RED}• {finding['type']}{Style.RESET_ALL}")
                    print(f"  Pattern: {finding['pattern']}")
                    if finding['context']:
                        print(f"  Context: {finding['context'][:150]}...")

            print(
                f"\n{Fore.YELLOW}Risk Level: {severity_counts['CRITICAL'] > 0 and 'CRITICAL' or (severity_counts['HIGH'] > 0 and 'HIGH' or 'MEDIUM')}{Style.RESET_ALL}")
            print(f"   • Information disclosure enables targeted attacks")
            print(f"   • Stack traces reveal application structure")
            print(f"   • File paths expose server configuration")
            print(f"   • Database errors reveal schema information")
            print(f"   • Debug info facilitates exploitation")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Implement custom error pages (no technical details)")
            print(f"   • Disable debug mode in production:")
            print(f"        PHP: display_errors = Off")
            print(f"        Python: DEBUG = False")
            print(f"        Node.js: NODE_ENV=production")
            print(f"   • Use generic error messages:")
            print(f"        'An error occurred' instead of stack traces")
            print(f"   • Configure web server to hide version info:")
            print(f"        Apache: ServerTokens Prod")
            print(f"        Nginx: server_tokens off;")
            print(f"   • Remove X-Powered-By header")
            print(f"   • Implement proper error logging (not displayed to users)")
            print(f"   • Use Web Application Firewall (WAF) for error filtering")
            print(f"   • Regular security audits and penetration testing")
        else:
            print(f"\n{Fore.GREEN}[✓] No error message disclosure vulnerabilities detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue monitoring error handling")
            print(f"   • Implement centralized error logging")
            print(f"   • Use security headers (Content-Security-Policy)")
            print(f"   • Regular code reviews for error handling")
            print(f"   • Implement proper input validation")
            print(f"   • Use automated security scanning tools")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Checking server response headers...{Style.RESET_ALL}")

        try:
            response = session.get(target, timeout=8, verify=False)

            headers_to_check = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version']

            for header in headers_to_check:
                value = response.headers.get(header)
                if value:
                    print(f"{Fore.YELLOW}[!] Header disclosed: {header} = {value}{Style.RESET_ALL}")

            if 'x-debug' in response.headers or 'debug' in response.headers:
                print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] DEBUG MODE DETECTED in headers!{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.YELLOW}[?] Could not check headers: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}LEGAL & ETHICAL GUIDANCE")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}  LEGAL WARNING:{Style.RESET_ALL}")
        print(f"   • Triggering errors without authorization may violate laws")
        print(f"   • Error testing may be logged as suspicious activity")
        print(f"   • Always obtain WRITTEN authorization before testing")
        print(f"   • Document all authorized testing activities")
        print(f"   • Never test production systems without explicit permission")
        print(f"\n{Fore.GREEN} Responsible Testing:{Style.RESET_ALL}")
        print(f"   • Test in staging/development environments first")
        print(f"   • Coordinate with system administrators")
        print(f"   • Report findings responsibly to owners")
        print(f"   • Provide mitigation recommendations")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Error disclosure analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")