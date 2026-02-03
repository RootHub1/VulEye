import requests
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse, urljoin, parse_qs
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              HIDDEN PARAMETERS DISCOVERY                          {Fore.CYAN}║")
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

    print(f"\n{Fore.CYAN}[+] Discovering hidden parameters for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()
        response = session.get(target, timeout=10, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')

        print(f"\n{Fore.GREEN}[✓] Connection successful (Status: {response.status_code}){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}HIDDEN PARAMETERS DISCOVERY RESULTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        hidden_params = []
        suspicious_patterns = []

        print(f"\n{Fore.CYAN}[→] Analyzing HTML source code...{Style.RESET_ALL}")

        html_content = response.text

        comment_patterns = re.findall(r'<!--(.*?)-->', html_content, re.DOTALL)
        for comment in comment_patterns:
            comment = comment.strip()
            if comment and len(comment) > 10:
                if any(keyword in comment.lower() for keyword in
                       ['param', 'test', 'debug', 'admin', 'hidden', 'secret', 'todo', 'fixme']):
                    suspicious_patterns.append({
                        'type': 'HTML Comment',
                        'content': comment[:100] + '...' if len(comment) > 100 else comment,
                        'risk': 'MEDIUM'
                    })
                    print(f"{Fore.YELLOW}[!] Suspicious comment found:{Style.RESET_ALL}")
                    print(f"    {comment[:100]}...")

        js_patterns = re.findall(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*[:=]\s*["\']([^"\']+)["\']', html_content)
        for key, value in js_patterns:
            if len(key) > 2 and key.lower() not in ['var', 'let', 'const', 'function', 'return', 'true', 'false',
                                                    'null']:
                if any(susp in key.lower() for susp in
                       ['token', 'secret', 'key', 'password', 'admin', 'debug', 'test', 'hidden', 'internal', 'private',
                        'config', 'setting']):
                    hidden_params.append({
                        'type': 'JavaScript Variable',
                        'name': key,
                        'value': value[:50] + '...' if len(value) > 50 else value,
                        'risk': 'HIGH' if any(
                            crit in key.lower() for crit in ['password', 'secret', 'token', 'key']) else 'MEDIUM'
                    })
                    print(f"{Fore.RED}[!] Sensitive JS variable: {key} = {value[:50]}{Style.RESET_ALL}")

        hidden_inputs = soup.find_all('input', {'type': 'hidden'})
        for inp in hidden_inputs:
            name = inp.get('name', 'unknown')
            value = inp.get('value', '')
            hidden_params.append({
                'type': 'Hidden Input',
                'name': name,
                'value': value[:50] + '...' if len(value) > 50 else value,
                'risk': 'MEDIUM'
            })
            print(f"{Fore.YELLOW}[!] Hidden input field: {name} = {value[:50]}{Style.RESET_ALL}")

        links = soup.find_all('a', href=True)
        for link in links:
            href = link['href']
            parsed = urlparse(href)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param, values in params.items():
                    if any(susp in param.lower() for susp in
                           ['debug', 'test', 'admin', 'hidden', 'internal', 'secret', 'token']):
                        hidden_params.append({
                            'type': 'URL Parameter',
                            'name': param,
                            'value': values[0][:50] if values else '',
                            'risk': 'MEDIUM'
                        })
                        print(f"{Fore.YELLOW}[!] Suspicious URL parameter: {param} in link{Style.RESET_ALL}")

        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for inp in inputs:
                name = inp.get('name', '')
                if name and any(susp in name.lower() for susp in ['csrf', 'token', 'nonce', 'session', 'auth']):
                    hidden_params.append({
                        'type': 'Form Field',
                        'name': name,
                        'value': 'Present',
                        'risk': 'LOW'
                    })
                    print(f"{Fore.CYAN}[i] Security token field: {name}{Style.RESET_ALL}")

        script_tags = soup.find_all('script')
        for script in script_tags:
            if script.string:
                api_keys = re.findall(r'["\']?([A-Z0-9]{32,})["\']?', script.string)
                for key in api_keys:
                    if len(key) >= 32:
                        hidden_params.append({
                            'type': 'Potential API Key',
                            'name': 'API Key',
                            'value': key[:10] + '...' + key[-10:],
                            'risk': 'CRITICAL'
                        })
                        print(
                            f"{Fore.MAGENTA}{Style.BRIGHT}[!] POTENTIAL API KEY FOUND: {key[:10]}...{key[-10:]}{Style.RESET_ALL}")

        data_attributes = soup.find_all(attrs=re.compile('^data-'))
        for tag in data_attributes:
            for attr in tag.attrs:
                if attr.startswith('data-'):
                    value = tag[attr]
                    if len(str(value)) > 10:
                        hidden_params.append({
                            'type': 'Data Attribute',
                            'name': attr,
                            'value': str(value)[:50] + '...' if len(str(value)) > 50 else str(value),
                            'risk': 'LOW'
                        })
                        print(f"{Fore.CYAN}[i] Data attribute: {attr} = {str(value)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL DISCOVERY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        common_hidden_endpoints = [
            '/.env',
            '/config.php',
            '/settings.php',
            '/debug.php',
            '/test.php',
            '/admin/config',
            '/api/config',
            '/internal/settings'
        ]

        exposed_configs = []
        for endpoint in common_hidden_endpoints:
            test_url = urljoin(target, endpoint)
            try:
                resp = session.get(test_url, timeout=5, verify=False)
                if resp.status_code == 200 and len(resp.text) > 100:
                    exposed_configs.append(test_url)
                    print(f"{Fore.RED}[!] Exposed configuration file: {test_url}{Style.RESET_ALL}")
            except:
                pass

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SUMMARY & RISK ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        total_params = len(hidden_params)
        total_patterns = len(suspicious_patterns)
        total_configs = len(exposed_configs)

        critical_count = sum(1 for p in hidden_params if p['risk'] == 'CRITICAL')
        high_count = sum(1 for p in hidden_params if p['risk'] == 'HIGH')
        medium_count = sum(1 for p in hidden_params if p['risk'] == 'MEDIUM')

        print(f"\n{Fore.GREEN}Total hidden parameters found: {total_params}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Critical risk parameters: {critical_count}{Style.RESET_ALL}")
        print(f"{Fore.RED}High risk parameters: {high_count}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium risk parameters: {medium_count}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Suspicious patterns: {total_patterns}{Style.RESET_ALL}")
        print(f"{Fore.RED}Exposed config files: {total_configs}{Style.RESET_ALL}")

        if critical_count > 0 or high_count > 0:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL HIDDEN PARAMETERS DETECTED{Style.RESET_ALL}")

            print(f"\n{Fore.RED} High-Risk Findings:{Style.RESET_ALL}")
            for param in hidden_params:
                if param['risk'] in ['CRITICAL', 'HIGH']:
                    risk_color = Fore.MAGENTA if param['risk'] == 'CRITICAL' else Fore.RED
                    print(f"\n{risk_color}• {param['type']}: {param['name']}{Style.RESET_ALL}")
                    print(f"  Value: {param['value']}")
                    print(f"  Risk: {param['risk']}")

                    if param['risk'] == 'CRITICAL':
                        print(f"  {Fore.YELLOW} IMMEDIATE ACTION REQUIRED - API keys exposed{Style.RESET_ALL}")
                    elif 'password' in param['name'].lower() or 'secret' in param['name'].lower():
                        print(f"  {Fore.YELLOW}  Credentials or secrets may be exposed{Style.RESET_ALL}")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Remove all hardcoded secrets from source code")
            print(f"   • Use environment variables for sensitive configuration")
            print(f"   • Implement secret management (Vault, AWS Secrets Manager)")
            print(f"   • Remove debug/test parameters from production code")
            print(f"   • Block access to configuration files via web server")
            print(f"   • Implement proper access controls for admin/internal endpoints")
            print(f"   • Conduct code review to remove all TODO/FIXME comments")
            print(f"   • Use .gitignore to prevent accidental commits of sensitive files")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical hidden parameters detected{Style.RESET_ALL}")

            if medium_count > 0:
                print(f"\n{Fore.YELLOW}[i] Medium-risk parameters found (review recommended):{Style.RESET_ALL}")
                for param in hidden_params:
                    if param['risk'] == 'MEDIUM':
                        print(f"  • {param['type']}: {param['name']} = {param['value']}")

            print(f"\n{Fore.CYAN}Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Regularly audit source code for hidden parameters")
            print(f"   • Use static analysis tools (SonarQube, Semgrep)")
            print(f"   • Implement security headers (Content-Security-Policy)")
            print(f"   • Remove all debug/test code before deployment")
            print(f"   • Use automated secret detection in CI/CD pipeline")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}TESTING RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}Next Steps:{Style.RESET_ALL}")
        print(f"   1. Manually verify all discovered parameters")
        print(f"   2. Test parameter tampering (change values, test boundaries)")
        print(f"   3. Check if hidden parameters can be accessed without authentication")
        print(f"   4. Test for IDOR vulnerabilities using discovered parameters")
        print(f"   5. Verify if exposed configs contain sensitive data")
        print(f"   6. Check for parameter pollution vulnerabilities")
        print(f"   7. Test with authenticated sessions for complete coverage")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Hidden parameters discovery completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL REMINDER:{Style.RESET_ALL}")
        print(f"   Accessing hidden parameters without authorization may violate laws.")
        print(f"   Always obtain written permission before testing internal functionality.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")