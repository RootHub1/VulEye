import requests
import json
from urllib.parse import urlparse, urljoin
from colorama import init, Fore, Style

init(autoreset=True)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              API SECURITY SCANNER                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(f"\n{Fore.YELLOW}Enter API base URL (e.g., https://api.example.com/v1): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing API security for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}API DISCOVERY & ENDPOINT ANALYSIS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        common_endpoints = [
            '/api/docs',
            '/api/swagger.json',
            '/swagger.json',
            '/openapi.json',
            '/graphql',
            '/graphql/console',
            '/api/spec',
            '/api/endpoints',
            '/health',
            '/status',
            '/version',
            '/debug',
            '/admin',
            '/users',
            '/auth',
            '/login',
            '/register'
        ]

        discovered_endpoints = []
        sensitive_endpoints = []

        for endpoint in common_endpoints:
            test_url = urljoin(target, endpoint)
            try:
                response = session.get(test_url, timeout=5, verify=False)

                if response.status_code in [200, 201, 202, 204]:
                    discovered_endpoints.append({
                        'url': test_url,
                        'status': response.status_code,
                        'content_type': response.headers.get('Content-Type', 'unknown')
                    })

                    if any(sensitive in endpoint.lower() for sensitive in ['admin', 'debug', 'graphql/console']):
                        sensitive_endpoints.append(test_url)

                    print(f"{Fore.GREEN}[✓] Found: {test_url} (Status: {response.status_code}){Style.RESET_ALL}")
                elif response.status_code in [401, 403]:
                    print(f"{Fore.YELLOW}[i] Protected: {test_url} (Status: {response.status_code}){Style.RESET_ALL}")
                else:
                    print(f"{Fore.CYAN}[i] {test_url} (Status: {response.status_code}){Style.RESET_ALL}")

            except requests.exceptions.Timeout:
                continue
            except Exception:
                continue

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}AUTHENTICATION & AUTHORIZATION TESTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        auth_issues = []
        auth_headers_found = False

        if discovered_endpoints:
            test_endpoint = discovered_endpoints[0]['url']

            print(f"\n{Fore.CYAN}[→] Testing authentication bypass on: {test_endpoint}{Style.RESET_ALL}")

            auth_tests = [
                ({}, "No authentication"),
                ({'Authorization': 'Bearer '}, "Empty Bearer token"),
                ({'Authorization': 'Bearer invalid_token'}, "Invalid token"),
                ({'X-API-Key': 'test'}, "API key header"),
                ({'Cookie': 'session=invalid'}, "Session cookie"),
                ({'Authorization': 'Basic dGVzdDp0ZXN0'}, "Basic auth (test:test)")
            ]

            for headers, description in auth_tests:
                try:
                    response = session.get(test_endpoint, headers=headers, timeout=5, verify=False)

                    if response.status_code == 200:
                        auth_issues.append({
                            'severity': 'CRITICAL',
                            'endpoint': test_endpoint,
                            'test': description,
                            'issue': 'No authentication required or bypassed'
                        })
                        print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] AUTH BYPASS: {description}{Style.RESET_ALL}")
                        print(f"    Status: {response.status_code} - Access granted without valid credentials")
                    elif response.status_code in [401, 403]:
                        if not auth_headers_found and 'www-authenticate' in response.headers:
                            auth_headers_found = True
                            print(f"{Fore.GREEN}[✓] Authentication enforced: {description}{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.CYAN}[i] {description} → Status: {response.status_code}{Style.RESET_ALL}")

                except Exception:
                    continue

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}GRAPHQL INTROSPECTION TEST")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        graphql_vulnerable = False
        graphql_url = None

        for endpoint in discovered_endpoints:
            if 'graphql' in endpoint['url'].lower():
                graphql_url = endpoint['url']
                print(f"\n{Fore.CYAN}[→] Testing GraphQL introspection: {graphql_url}{Style.RESET_ALL}")

                introspection_query = {
                    "query": """
                    {
                      __schema {
                        types {
                          name
                          fields {
                            name
                            type {
                              name
                            }
                          }
                        }
                      }
                    }
                    """
                }

                try:
                    response = session.post(
                        graphql_url,
                        json=introspection_query,
                        timeout=8,
                        verify=False
                    )

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if '__schema' in str(data):
                                graphql_vulnerable = True
                                print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] GRAPHQL INTROSPECTION ENABLED{Style.RESET_ALL}")
                                print(f"    Status: {response.status_code}")
                                print(f"    Impact: Full API schema disclosure - attackers can map all endpoints")

                                type_count = len(data.get('data', {}).get('__schema', {}).get('types', []))
                                print(f"    Schema details exposed: {type_count} types")
                        except:
                            print(f"{Fore.YELLOW}[?] Response received but not valid JSON{Style.RESET_ALL}")
                    else:
                        print(
                            f"{Fore.GREEN}[✓] GraphQL introspection disabled (Status: {response.status_code}){Style.RESET_ALL}")

                except Exception as e:
                    print(f"{Fore.YELLOW}[?] Error testing GraphQL: {str(e)[:50]}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}INFORMATION DISCLOSURE TESTS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        info_disclosure = []
        error_indicators = [
            'stack trace', 'exception', 'error', 'debug', 'sql', 'query',
            'file', 'line', 'path', 'traceback', 'syntax error'
        ]

        if discovered_endpoints:
            print(f"\n{Fore.CYAN}[→] Testing for error-based information disclosure{Style.RESET_ALL}")

            invalid_requests = [
                {'method': 'GET', 'url': urljoin(target, '/api/nonexistent'), 'data': None},
                {'method': 'POST', 'url': urljoin(target, '/api/users'), 'data': {'invalid': 'data'}},
                {'method': 'GET', 'url': urljoin(target, '/api/users/999999999'), 'data': None}
            ]

            for req in invalid_requests:
                try:
                    if req['method'] == 'GET':
                        response = session.get(req['url'], timeout=5, verify=False)
                    else:
                        response = session.post(req['url'], json=req['data'], timeout=5, verify=False)

                    response_text = response.text.lower()

                    found_indicators = [ind for ind in error_indicators if ind in response_text]

                    if found_indicators and response.status_code not in [404, 400]:
                        info_disclosure.append({
                            'url': req['url'],
                            'status': response.status_code,
                            'indicators': found_indicators[:3]
                        })
                        print(f"{Fore.YELLOW}[!] Info disclosure: {req['url']}{Style.RESET_ALL}")
                        print(f"    Status: {response.status_code} | Indicators: {', '.join(found_indicators[:3])}")

                except Exception:
                    continue

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RATE LIMITING & DOS PROTECTION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        rate_limiting_found = False
        rate_limit_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Retry-After']

        if discovered_endpoints:
            test_endpoint = discovered_endpoints[0]['url']
            print(f"\n{Fore.CYAN}[→] Checking for rate limiting headers{Style.RESET_ALL}")

            try:
                response = session.get(test_endpoint, timeout=5, verify=False)

                found_headers = [h for h in rate_limit_headers if h in response.headers]

                if found_headers:
                    rate_limiting_found = True
                    print(
                        f"{Fore.GREEN}[✓] Rate limiting headers detected: {', '.join(found_headers)}{Style.RESET_ALL}")
                    for header in found_headers:
                        print(f"    {header}: {response.headers.get(header)}")
                else:
                    print(f"{Fore.YELLOW}[!] No rate limiting headers found{Style.RESET_ALL}")
                    print(f"    Impact: API vulnerable to brute force and DoS attacks")

            except Exception:
                print(f"{Fore.YELLOW}[?] Could not check rate limiting{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}API SECURITY SUMMARY")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        total_issues = len(auth_issues) + len(info_disclosure) + (1 if graphql_vulnerable else 0)

        print(f"\n{Fore.GREEN}Discovered endpoints: {len(discovered_endpoints)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Sensitive endpoints: {len(sensitive_endpoints)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Authentication issues: {len(auth_issues)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Information disclosure: {len(info_disclosure)}{Style.RESET_ALL}")
        print(
            f"{Fore.MAGENTA}GraphQL introspection: {'ENABLED' if graphql_vulnerable else 'Disabled'}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Rate limiting: {'Configured' if rate_limiting_found else 'Missing'}{Style.RESET_ALL}")

        if total_issues > 0:
            print(f"\n{Fore.MAGENTA}{Style.BRIGHT}[!] CRITICAL API SECURITY ISSUES DETECTED{Style.RESET_ALL}")

            if auth_issues:
                print(f"\n{Fore.RED} Authentication Bypass Vulnerabilities:{Style.RESET_ALL}")
                for issue in auth_issues:
                    print(f"\n{Fore.RED}• {issue['endpoint']}{Style.RESET_ALL}")
                    print(f"  Test: {issue['test']}")
                    print(f"  Issue: {issue['issue']}")

            if graphql_vulnerable:
                print(f"\n{Fore.MAGENTA}  GraphQL Security Issues:{Style.RESET_ALL}")
                print(f"  • Introspection query enabled - full schema exposed")
                print(f"  • Attackers can enumerate all types, fields, and mutations")

            if info_disclosure:
                print(f"\n{Fore.YELLOW}  Information Disclosure:{Style.RESET_ALL}")
                for disclosure in info_disclosure:
                    print(f"  • {disclosure['url']} - Status {disclosure['status']}")
                    print(f"    Leaked: {', '.join(disclosure['indicators'])}")

            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Implement strong authentication (OAuth2, JWT)")
            print(f"   • Use API gateways for rate limiting and throttling")
            print(f"   • Disable GraphQL introspection in production")
            print(f"   • Implement proper error handling (no stack traces)")
            print(f"   • Use API keys with IP restrictions")
            print(f"   • Implement CORS restrictions for web clients")
            print(f"   • Add security headers (CSP, HSTS, X-Content-Type-Options)")
            print(f"   • Log and monitor all API requests")
            print(f"   • Implement API versioning and deprecation policies")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical API security issues detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue monitoring for new vulnerabilities")
            print(f"   • Implement API security testing in CI/CD pipeline")
            print(f"   • Use API security tools (OWASP ZAP, Burp Suite)")
            print(f"   • Conduct regular penetration testing")
            print(f"   • Keep API documentation up to date")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] API security analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL REMINDER:{Style.RESET_ALL}")
        print(f"   API testing without authorization violates computer fraud laws.")
        print(f"   Always obtain written permission before testing any API.")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")