import requests
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def test_http_method(url, method):
    try:
        if method == 'GET':
            response = requests.get(url, timeout=8, verify=False)
        elif method == 'POST':
            response = requests.post(url, data={'test': 'data'}, timeout=8, verify=False)
        elif method == 'PUT':
            response = requests.put(url, data='TEST_CONTENT', timeout=8, verify=False)
        elif method == 'DELETE':
            response = requests.delete(url, timeout=8, verify=False)
        elif method == 'HEAD':
            response = requests.head(url, timeout=8, verify=False)
        elif method == 'OPTIONS':
            response = requests.options(url, timeout=8, verify=False)
        elif method == 'TRACE':
            response = requests.request('TRACE', url, timeout=8, verify=False)
        elif method == 'CONNECT':
            response = requests.request('CONNECT', url, timeout=8, verify=False)
        elif method == 'PATCH':
            response = requests.patch(url, data={'test': 'data'}, timeout=8, verify=False)
        else:
            return None, None

        return response.status_code, response.headers
    except requests.exceptions.Timeout:
        return 'TIMEOUT', None
    except:
        return 'ERROR', None


def analyze_method(method, status, headers):
    risk_level = 'NONE'
    issues = []

    if status in [200, 201, 202, 204, 301, 302]:
        if method == 'PUT':
            risk_level = 'CRITICAL'
            issues.append('Allows file upload - potential webshell deployment')
        elif method == 'DELETE':
            risk_level = 'HIGH'
            issues.append('Allows resource deletion without authentication')
        elif method == 'TRACE':
            risk_level = 'HIGH'
            issues.append('Vulnerable to Cross-Site Tracing (XST) attacks')
        elif method == 'OPTIONS':
            risk_level = 'INFO'
            if headers and 'allow' in headers:
                issues.append(f"Allowed methods: {headers['allow']}")
        elif method in ['CONNECT', 'PATCH']:
            risk_level = 'MEDIUM'
            issues.append('Uncommon method - verify necessity and security')
        elif method in ['HEAD', 'POST']:
            risk_level = 'LOW'
            issues.append('Standard method - verify proper authentication')

    elif status in [401, 403, 405]:
        risk_level = 'PROTECTED'
        issues.append('Properly restricted')

    return risk_level, issues


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              HTTP METHODS SCANNER                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Scanning enabled HTTP methods for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}HTTP METHODS TESTING")
        print(f"{Fore.YELLOW}Note: Testing 9 HTTP methods with safety delays{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        methods_to_test = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH']
        results = []
        dangerous_methods = []

        for method in methods_to_test:
            print(f"\n{Fore.CYAN}[→] Testing {method} method...{Style.RESET_ALL}")

            status, headers = test_http_method(target, method)

            risk_level, issues = analyze_method(method, status, headers)

            result = {
                'method': method,
                'status': status,
                'risk': risk_level,
                'issues': issues
            }
            results.append(result)

            if risk_level in ['CRITICAL', 'HIGH', 'MEDIUM']:
                dangerous_methods.append(result)

            status_color = Fore.GREEN if status in [200, 201, 202, 204] else (
                Fore.RED if status in [401, 403, 405] else Fore.YELLOW)
            risk_color = Fore.MAGENTA if risk_level == 'CRITICAL' else (Fore.RED if risk_level == 'HIGH' else (
                Fore.YELLOW if risk_level == 'MEDIUM' else (Fore.GREEN if risk_level == 'PROTECTED' else Fore.CYAN)))

            print(
                f"    Status: {status_color}{status}{Style.RESET_ALL} | Risk: {risk_color}{risk_level}{Style.RESET_ALL}")
            for issue in issues:
                print(f"    • {issue}")

            import time
            time.sleep(1.0)

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RESULTS SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Total methods tested: {len(methods_to_test)}{Style.RESET_ALL}")
        print(
            f"{Fore.MAGENTA}Critical risk methods: {sum(1 for r in results if r['risk'] == 'CRITICAL')}{Style.RESET_ALL}")
        print(f"{Fore.RED}High risk methods: {sum(1 for r in results if r['risk'] == 'HIGH')}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium risk methods: {sum(1 for r in results if r['risk'] == 'MEDIUM')}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Protected methods: {sum(1 for r in results if r['risk'] == 'PROTECTED')}{Style.RESET_ALL}")

        if dangerous_methods:
            print(f"\n{Fore.RED}[!] DANGEROUS HTTP METHODS DETECTED{Style.RESET_ALL}")

            critical_methods = [m for m in dangerous_methods if m['risk'] == 'CRITICAL']
            high_methods = [m for m in dangerous_methods if m['risk'] == 'HIGH']

            if critical_methods:
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT} CRITICAL RISK METHODS:{Style.RESET_ALL}")
                for method in critical_methods:
                    print(f"\n{Fore.MAGENTA}• {method['method']} (Status: {method['status']}){Style.RESET_ALL}")
                    for issue in method['issues']:
                        print(f"  {Fore.YELLOW}  {issue}{Style.RESET_ALL}")

            if high_methods:
                print(f"\n{Fore.RED} HIGH RISK METHODS:{Style.RESET_ALL}")
                for method in high_methods:
                    print(f"\n{Fore.RED}• {method['method']} (Status: {method['status']}){Style.RESET_ALL}")
                    for issue in method['issues']:
                        print(f"  {Fore.YELLOW}  {issue}{Style.RESET_ALL}")

            print(f"\n{Fore.YELLOW}Risk Assessment:{Style.RESET_ALL}")
            print(f"   • PUT method enabled = attackers can upload malicious files")
            print(f"   • DELETE method enabled = attackers can delete resources")
            print(f"   • TRACE method enabled = vulnerable to Cross-Site Tracing (XST)")
            print(f"   • OPTIONS method may reveal internal API structure")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Disable dangerous methods at web server level:")
            print(f"        Apache (.htaccess):")
            print(f"            <LimitExcept GET POST HEAD>")
            print(f"                deny from all")
            print(f"            </LimitExcept>")
            print(f"        Nginx (nginx.conf):")
            print(f"            if ($request_method !~ ^(GET|HEAD|POST)$) {{")
            print(f"                return 405;")
            print(f"            }}")
            print(f"   • For IIS: Use Request Filtering module to block methods")
            print(f"   • Implement proper authentication for ALL methods")
            print(f"   • Use Web Application Firewall (WAF) to block dangerous methods")
            print(f"   • Regularly audit enabled HTTP methods")
            print(f"   • Monitor logs for unusual method usage")
        else:
            print(f"\n{Fore.GREEN}[✓] No dangerous HTTP methods detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue restricting methods to minimum required")
            print(f"   • Implement method whitelisting in application code")
            print(f"   • Use security headers (Content-Security-Policy)")
            print(f"   • Regularly test for method enumeration vulnerabilities")
            print(f"   • Monitor access logs for method abuse attempts")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Checking for method override parameters...{Style.RESET_ALL}")

        override_params = ['_method', 'method', 'http_method', 'X-HTTP-Method', 'X-HTTP-Method-Override']
        found_overrides = []

        try:
            response = session.get(target, timeout=8, verify=False)
            content_lower = response.text.lower()

            for param in override_params:
                if param in content_lower:
                    found_overrides.append(param)

            if found_overrides:
                print(f"{Fore.YELLOW}[!] Method override parameters detected:{Style.RESET_ALL}")
                for param in found_overrides:
                    print(f"    • {param}")
                print(f"    {Fore.YELLOW}️  Risk: Attackers may bypass method restrictions{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}[✓] No method override parameters detected{Style.RESET_ALL}")

        except Exception as e:
            print(f"{Fore.YELLOW}[?] Could not check for override parameters: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}LEGAL & ETHICAL GUIDANCE")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}️  LEGAL WARNING:{Style.RESET_ALL}")
        print(f"   • Sending non-standard HTTP methods without authorization may violate laws")
        print(f"   • TRACE method testing may be logged as suspicious activity")
        print(f"   • Always obtain WRITTEN authorization before testing")
        print(f"   • Document all authorized testing activities")
        print(f"   • Never test production systems without explicit permission")
        print(f"\n{Fore.GREEN} Responsible Testing:{Style.RESET_ALL}")
        print(f"   • Test in staging/development environments first")
        print(f"   • Coordinate with system administrators")
        print(f"   • Report findings responsibly to owners")
        print(f"   • Provide mitigation recommendations")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] HTTP methods analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")