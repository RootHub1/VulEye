import requests
import re
import jwt
import base64
from colorama import init, Fore, Style

init(autoreset=True)


def decode_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload, None
    except Exception as e:
        return None, None, str(e)


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              JWT SECURITY SCANNER                                 {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Choose JWT analysis method:{Style.RESET_ALL}")
    print(f"   1. Analyze existing JWT token")
    print(f"   2. Test login endpoint for JWT generation")
    choice = input(f"\n{Fore.YELLOW}Select option [1-2]: {Style.RESET_ALL}").strip()

    if choice == "1":
        jwt_token = input(f"\n{Fore.YELLOW}Enter JWT token: {Style.RESET_ALL}").strip()
        if not jwt_token:
            print(f"\n{Fore.RED}[!] Empty token. Aborting.{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return
    elif choice == "2":
        login_url = input(f"\n{Fore.YELLOW}Enter login endpoint URL: {Style.RESET_ALL}").strip()
        if not login_url.startswith(('http://', 'https://')):
            print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        username = input(f"{Fore.YELLOW}Enter username: {Style.RESET_ALL}").strip()
        password = input(f"{Fore.YELLOW}Enter password: {Style.RESET_ALL}").strip()

        try:
            data = {'username': username, 'password': password}
            response = requests.post(login_url, json=data, timeout=10, verify=False)
            jwt_token = None

            if 'Authorization' in response.headers:
                auth_header = response.headers['Authorization']
                if auth_header.startswith('Bearer '):
                    jwt_token = auth_header.split(' ')[1]
            elif 'token' in response.json():
                jwt_token = response.json()['token']

            if not jwt_token:
                print(f"\n{Fore.RED}[!] No JWT token found in response.{Style.RESET_ALL}")
                input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
                return
        except Exception as e:
            print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return
    else:
        print(f"\n{Fore.RED}[!] Invalid choice. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Analyzing JWT token...{Style.RESET_ALL}")

    header, payload, error = decode_jwt(jwt_token)

    if error:
        print(f"\n{Fore.RED}[!] Failed to decode JWT: {error}{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}JWT DECODED CONTENT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}Header:{Style.RESET_ALL}")
    for key, value in header.items():
        print(f"   {Fore.GREEN}{key}:{Style.RESET_ALL} {value}")

    print(f"\n{Fore.CYAN}Payload:{Style.RESET_ALL}")
    for key, value in payload.items():
        print(f"   {Fore.GREEN}{key}:{Style.RESET_ALL} {value}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}JWT SECURITY ANALYSIS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    vulnerabilities = []
    warnings = []
    info = []

    alg = header.get('alg', 'NONE')

    if alg == 'none':
        vulnerabilities.append({
            'severity': 'CRITICAL',
            'title': 'None Algorithm Attack',
            'description': 'Token uses "none" algorithm - signature validation bypassed',
            'impact': 'Attackers can forge tokens without signature',
            'fix': 'Disable "none" algorithm in JWT library configuration'
        })
    elif alg == 'HS256':
        info.append({
            'title': 'HS256 Algorithm',
            'description': 'Symmetric algorithm used - ensure strong secret key',
            'recommendation': 'Use minimum 32-character random secret key'
        })
    elif alg in ['RS256', 'ES256']:
        info.append({
            'title': 'Asymmetric Algorithm',
            'description': f'{alg} algorithm used - more secure than symmetric',
            'recommendation': 'Ensure public key distribution is secure'
        })
    else:
        warnings.append({
            'title': 'Unknown/Weak Algorithm',
            'description': f'Algorithm {alg} may be insecure or non-standard',
            'recommendation': 'Use RS256, ES256, or HS256 with strong key'
        })

    if 'nbf' not in payload:
        info.append({
            'title': 'No Not-Before (nbf) claim',
            'description': 'Token validity start time not enforced',
            'recommendation': 'Add "nbf" claim to prevent premature token use'
        })

    if 'exp' not in payload:
        warnings.append({
            'title': 'No Expiration (exp) claim',
            'description': 'Token has no expiration - permanent access',
            'impact': 'Compromised tokens remain valid indefinitely',
            'fix': 'Add "exp" claim with reasonable lifetime (e.g., 1 hour)'
        })
    else:
        import time
        current_time = int(time.time())
        exp = payload['exp']
        if isinstance(exp, str):
            exp = int(exp)

        if exp < current_time:
            info.append({
                'title': 'Token Expired',
                'description': f'Expiration time: {exp} (current: {current_time})',
                'recommendation': 'Token is expired - should be rejected by server'
            })
        elif exp - current_time > 86400:
            warnings.append({
                'title': 'Long Token Lifetime',
                'description': f'Token valid for {(exp - current_time) / 3600:.1f} hours',
                'recommendation': 'Use shorter lifetimes (1-2 hours) + refresh tokens'
            })

    if 'iss' not in payload:
        warnings.append({
            'title': 'No Issuer (iss) claim',
            'description': 'Token origin not verified',
            'recommendation': 'Add "iss" claim and validate on server'
        })

    if 'aud' not in payload:
        warnings.append({
            'title': 'No Audience (aud) claim',
            'description': 'Token recipient not specified',
            'recommendation': 'Add "aud" claim to prevent token reuse across services'
        })

    if 'jti' not in payload:
        info.append({
            'title': 'No JWT ID (jti) claim',
            'description': 'Token cannot be uniquely identified',
            'recommendation': 'Add "jti" for token revocation support'
        })

    sensitive_data = ['password', 'secret', 'token', 'api_key', 'private']
    for key in payload.keys():
        if any(sensitive in key.lower() for sensitive in sensitive_data):
            vulnerabilities.append({
                'severity': 'HIGH',
                'title': 'Sensitive Data in Token',
                'description': f'Field "{key}" contains sensitive information',
                'impact': 'Token leakage exposes sensitive data',
                'fix': 'Store only non-sensitive claims in JWT payload'
            })

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}FINDINGS SUMMARY")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    if vulnerabilities:
        print(f"\n{Fore.RED}[!] CRITICAL VULNERABILITIES:{Style.RESET_ALL}")
        for vuln in vulnerabilities:
            severity_color = Fore.MAGENTA if vuln['severity'] == 'CRITICAL' else Fore.RED
            print(f"\n{severity_color}• {vuln['title']}{Style.RESET_ALL}")
            print(f"  Description: {vuln['description']}")
            if 'impact' in vuln:
                print(f"  Impact: {vuln['impact']}")
            if 'fix' in vuln:
                print(f"  Fix: {vuln['fix']}")

    if warnings:
        print(f"\n{Fore.YELLOW}[!] SECURITY WARNINGS:{Style.RESET_ALL}")
        for warn in warnings:
            print(f"\n{Fore.YELLOW}• {warn['title']}{Style.RESET_ALL}")
            print(f"  {warn['description']}")
            if 'impact' in warn:
                print(f"  Impact: {warn['impact']}")
            if 'recommendation' in warn:
                print(f"  Recommendation: {warn['recommendation']}")

    if info:
        print(f"\n{Fore.CYAN}[i] INFORMATION:{Style.RESET_ALL}")
        for item in info:
            print(f"\n{Fore.CYAN}• {item['title']}{Style.RESET_ALL}")
            print(f"  {item['description']}")
            if 'recommendation' in item:
                print(f"  Recommendation: {item['recommendation']}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SECURITY RECOMMENDATIONS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n{Fore.GREEN}✅ Best Practices:{Style.RESET_ALL}")
    print(f"   • Use asymmetric algorithms (RS256, ES256) for better security")
    print(f"   • Implement short token lifetimes (1-2 hours)")
    print(f"   • Use refresh tokens for long-lived sessions")
    print(f"   • Validate all standard claims (iss, aud, exp, nbf)")
    print(f"   • Store only non-sensitive data in JWT payload")
    print(f"   • Implement token revocation mechanism (jti + denylist)")
    print(f"   • Rotate signing keys periodically")
    print(f"   • Use HTTPS for all token transmission")
    print(f"   • Implement proper error handling (don't leak token details)")

    print(f"\n{Fore.YELLOW}⚠️  Additional Testing:{Style.RESET_ALL}")
    print(f"   • Test token replay attacks")
    print(f"   • Verify signature validation on server")
    print(f"   • Test algorithm confusion attacks")
    print(f"   • Check for weak secret keys (brute force)")
    print(f"   • Verify token scope/permissions")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] JWT analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")