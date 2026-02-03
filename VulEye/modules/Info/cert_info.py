import ssl
import socket
import datetime
import hashlib
import serialization
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from colorama import init, Fore, Style

init(autoreset=True)


def get_certificate_chain(host, port=443):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(der_cert, default_backend())
                return cert, ssock.version()
    except Exception as e:
        return None, None


def analyze_certificate(cert, host):
    if not cert:
        return None

    analysis = {}

    analysis['subject'] = cert.subject.rfc4514_string()
    analysis['issuer'] = cert.issuer.rfc4514_string()

    analysis['serial_number'] = cert.serial_number
    analysis['version'] = cert.version.name

    analysis['not_valid_before'] = cert.not_valid_before
    analysis['not_valid_after'] = cert.not_valid_after

    analysis['signature_algorithm'] = cert.signature_algorithm_oid._name

    public_key = cert.public_key()
    analysis['key_type'] = type(public_key).__name__

    try:
        analysis['key_size'] = public_key.key_size
    except:
        analysis['key_size'] = 'Unknown'

    try:
        analysis['key_fingerprint_sha256'] = hashlib.sha256(public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )).hexdigest()
    except:
        analysis['key_fingerprint_sha256'] = 'N/A'

    san_extension = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    analysis['subject_alt_names'] = san_extension.value.get_values_for_type(x509.DNSName) if san_extension else []

    analysis['is_ca'] = cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    ).value.ca if cert.extensions.get_extension_for_oid(
        x509.oid.ExtensionOID.BASIC_CONSTRAINTS
    ) else False

    analysis['key_usage'] = []
    try:
        key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
        if key_usage.value.digital_signature:
            analysis['key_usage'].append('Digital Signature')
        if key_usage.value.key_encipherment:
            analysis['key_usage'].append('Key Encipherment')
        if key_usage.value.data_encipherment:
            analysis['key_usage'].append('Data Encipherment')
        if key_usage.value.key_agreement:
            analysis['key_usage'].append('Key Agreement')
        if key_usage.value.key_cert_sign:
            analysis['key_usage'].append('Certificate Sign')
        if key_usage.value.crl_sign:
            analysis['key_usage'].append('CRL Sign')
    except:
        pass

    analysis['extended_key_usage'] = []
    try:
        ext_key_usage = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.EXTENDED_KEY_USAGE)
        for usage in ext_key_usage.value:
            analysis['extended_key_usage'].append(usage._name)
    except:
        pass

    now = datetime.datetime.utcnow()
    analysis['is_valid'] = analysis['not_valid_before'] <= now <= analysis['not_valid_after']
    analysis['days_until_expiry'] = (analysis['not_valid_after'] - now).days

    analysis['self_signed'] = analysis['subject'] == analysis['issuer']

    analysis['common_name'] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COMMON_NAME:
            analysis['common_name'] = attr.value
            break

    analysis['organization'] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.ORGANIZATION_NAME:
            analysis['organization'] = attr.value
            break

    analysis['country'] = None
    for attr in cert.subject:
        if attr.oid == x509.oid.NameOID.COUNTRY_NAME:
            analysis['country'] = attr.value
            break

    return analysis


def check_certificate_issues(analysis):
    issues = []

    if not analysis['is_valid']:
        issues.append({
            'severity': 'CRITICAL',
            'issue': 'Certificate Not Valid',
            'description': 'Certificate is either not yet valid or has expired',
            'recommendation': 'Renew certificate immediately'
        })

    if analysis['days_until_expiry'] < 0:
        issues.append({
            'severity': 'CRITICAL',
            'issue': 'Certificate Expired',
            'description': f'Certificate expired {abs(analysis["days_until_expiry"])} days ago',
            'recommendation': 'Replace expired certificate immediately'
        })
    elif analysis['days_until_expiry'] < 30:
        issues.append({
            'severity': 'HIGH',
            'issue': 'Certificate Expiring Soon',
            'description': f'Certificate expires in {analysis["days_until_expiry"]} days',
            'recommendation': 'Renew certificate before expiration'
        })

    if analysis['key_size'] < 2048:
        issues.append({
            'severity': 'HIGH',
            'issue': 'Weak Key Size',
            'description': f'RSA key size is {analysis["key_size"]} bits (minimum recommended: 2048 bits)',
            'recommendation': 'Generate new certificate with 2048+ bit key'
        })

    if 'sha1' in analysis['signature_algorithm'].lower() or 'md5' in analysis['signature_algorithm'].lower():
        issues.append({
            'severity': 'HIGH',
            'issue': 'Weak Signature Algorithm',
            'description': f'Using deprecated signature algorithm: {analysis["signature_algorithm"]}',
            'recommendation': 'Use SHA-256 or stronger signature algorithm'
        })

    if analysis['self_signed']:
        issues.append({
            'severity': 'MEDIUM',
            'issue': 'Self-Signed Certificate',
            'description': 'Certificate is self-signed (not issued by trusted CA)',
            'recommendation': 'Use certificate from trusted Certificate Authority for public services'
        })

    if analysis['common_name'] and analysis['common_name'] != analysis.get('host', ''):
        if analysis['common_name'] not in analysis['subject_alt_names']:
            issues.append({
                'severity': 'MEDIUM',
                'issue': 'Common Name Mismatch',
                'description': f'Certificate CN "{analysis["common_name"]}" does not match hostname',
                'recommendation': 'Ensure CN or SAN matches the domain name'
            })

    if not analysis['subject_alt_names']:
        issues.append({
            'severity': 'LOW',
            'issue': 'No Subject Alternative Names',
            'description': 'Certificate lacks SAN extension (required for modern browsers)',
            'recommendation': 'Include SAN extension with all domain names'
        })

    return issues


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SSL CERTIFICATE ANALYZER                             {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL or hostname (e.g., https://example.com or example.com): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.netloc
        port = 443 if parsed.scheme == 'https' else 80
    else:
        host = target
        port = 443

    print(f"\n{Fore.CYAN}[+] Analyzing SSL certificate for: {host}:{port}{Style.RESET_ALL}")

    try:
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CERTIFICATE RETRIEVAL")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        cert, tls_version = get_certificate_chain(host, port)

        if not cert:
            print(f"\n{Fore.RED}[!] Failed to retrieve SSL certificate{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Possible reasons:{Style.RESET_ALL}")
            print(f"   • Target does not support HTTPS")
            print(f"   • Firewall blocking SSL connections")
            print(f"   • Invalid hostname")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        print(f"{Fore.GREEN}[✓] Certificate successfully retrieved{Style.RESET_ALL}")
        print(f"   TLS Version: {tls_version if tls_version else 'Unknown'}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CERTIFICATE DETAILS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        analysis = analyze_certificate(cert, host)

        if not analysis:
            print(f"\n{Fore.RED}[!] Failed to parse certificate details{Style.RESET_ALL}")
            input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
            return

        print(f"\n{Fore.CYAN}Subject Information:{Style.RESET_ALL}")
        print(f"   Common Name (CN): {analysis['common_name'] or 'N/A'}")
        print(f"   Organization (O): {analysis['organization'] or 'N/A'}")
        print(f"   Country (C): {analysis['country'] or 'N/A'}")
        print(f"   Full Subject: {analysis['subject']}")

        print(f"\n{Fore.CYAN}Issuer Information:{Style.RESET_ALL}")
        print(f"   Issuer: {analysis['issuer']}")
        print(f"   Self-Signed: {'Yes' if analysis['self_signed'] else 'No'}")

        print(f"\n{Fore.CYAN}Validity Period:{Style.RESET_ALL}")
        print(f"   Not Before: {analysis['not_valid_before']}")
        print(f"   Not After:  {analysis['not_valid_after']}")

        if analysis['days_until_expiry'] < 0:
            print(f"   Status: {Fore.RED}EXPIRED {abs(analysis['days_until_expiry'])} days ago{Style.RESET_ALL}")
        elif analysis['days_until_expiry'] < 30:
            print(f"   Status: {Fore.YELLOW}Expiring in {analysis['days_until_expiry']} days{Style.RESET_ALL}")
        else:
            print(f"   Status: {Fore.GREEN}Valid for {analysis['days_until_expiry']} more days{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Key Information:{Style.RESET_ALL}")
        print(f"   Key Type: {analysis['key_type']}")
        print(f"   Key Size: {analysis['key_size']} bits")
        print(f"   Signature Algorithm: {analysis['signature_algorithm']}")

        print(f"\n{Fore.CYAN}Subject Alternative Names (SAN):{Style.RESET_ALL}")
        if analysis['subject_alt_names']:
            for san in analysis['subject_alt_names']:
                print(f"   • {san}")
        else:
            print(f"   {Fore.YELLOW}None (not recommended for modern deployments){Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Key Usage:{Style.RESET_ALL}")
        if analysis['key_usage']:
            for usage in analysis['key_usage']:
                print(f"   • {usage}")
        else:
            print(f"   Not specified")

        print(f"\n{Fore.CYAN}Extended Key Usage:{Style.RESET_ALL}")
        if analysis['extended_key_usage']:
            for usage in analysis['extended_key_usage']:
                print(f"   • {usage}")
        else:
            print(f"   Not specified")

        print(f"\n{Fore.CYAN}Additional Information:{Style.RESET_ALL}")
        print(f"   Serial Number: {analysis['serial_number']}")
        print(f"   Version: {analysis['version']}")
        print(f"   Is CA Certificate: {'Yes' if analysis['is_ca'] else 'No'}")
        print(f"   SHA-256 Fingerprint: {analysis['key_fingerprint_sha256'][:64]}...")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SECURITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        issues = check_certificate_issues(analysis)

        if issues:
            print(f"\n{Fore.RED}[!] CERTIFICATE SECURITY ISSUES DETECTED{Style.RESET_ALL}")

            critical_issues = [i for i in issues if i['severity'] == 'CRITICAL']
            high_issues = [i for i in issues if i['severity'] == 'HIGH']
            medium_issues = [i for i in issues if i['severity'] == 'MEDIUM']

            if critical_issues:
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT} CRITICAL ISSUES:{Style.RESET_ALL}")
                for issue in critical_issues:
                    print(f"\n{Fore.MAGENTA}• {issue['issue']}{Style.RESET_ALL}")
                    print(f"  {issue['description']}")
                    print(f"  Recommendation: {issue['recommendation']}")

            if high_issues:
                print(f"\n{Fore.RED} HIGH SEVERITY ISSUES:{Style.RESET_ALL}")
                for issue in high_issues:
                    print(f"\n{Fore.RED}• {issue['issue']}{Style.RESET_ALL}")
                    print(f"  {issue['description']}")
                    print(f"  Recommendation: {issue['recommendation']}")

            if medium_issues:
                print(f"\n{Fore.YELLOW}️  MEDIUM SEVERITY ISSUES:{Style.RESET_ALL}")
                for issue in medium_issues:
                    print(f"\n{Fore.YELLOW}• {issue['issue']}{Style.RESET_ALL}")
                    print(f"  {issue['description']}")
                    print(f"  Recommendation: {issue['recommendation']}")
        else:
            print(f"\n{Fore.GREEN}[✓] Certificate security appears properly configured{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CERTIFICATE BEST PRACTICES")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN} Recommended Configuration:{Style.RESET_ALL}")
        print(f"   • Key Size: RSA 2048+ bits or ECDSA 256+ bits")
        print(f"   • Signature Algorithm: SHA-256 or stronger")
        print(f"   • Validity Period: Maximum 398 days (per CA/B Forum)")
        print(f"   • Include Subject Alternative Names (SAN) for all domains")
        print(f"   • Use certificates from trusted Certificate Authorities")
        print(f"   • Enable OCSP Stapling for revocation checking")
        print(f"   • Implement Certificate Transparency logging")
        print(f"   • Monitor expiration dates with automated alerts")

        print(f"\n{Fore.YELLOW}  Certificate Management Tips:{Style.RESET_ALL}")
        print(f"   • Renew certificates 30+ days before expiration")
        print(f"   • Use automated certificate management (Let's Encrypt + Certbot)")
        print(f"   • Maintain certificate inventory with expiration tracking")
        print(f"   • Test certificate deployment before production rollout")
        print(f"   • Verify certificate chain completeness")
        print(f"   • Check for certificate revocation via CRL/OCSP")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}ADDITIONAL VERIFICATION TOOLS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Online Certificate Checkers:{Style.RESET_ALL}")
        print(f"   • SSL Labs: https://www.ssllabs.com/ssltest/")
        print(f"   • crt.sh: https://crt.sh (Certificate Transparency search)")
        print(f"   • Google Transparency Report: https://transparencyreport.google.com/https/certificates")

        print(f"\n{Fore.CYAN}Command-Line Tools:{Style.RESET_ALL}")
        print(f"   • openssl s_client -connect {host}:443 -showcerts")
        print(f"   • openssl x509 -in cert.pem -text -noout")
        print(f"   • testssl.sh {host}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] Certificate analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}  LEGAL NOTE:{Style.RESET_ALL}")
        print(f"   Certificate analysis uses only publicly available information.")
        print(f"   No exploitation or active attacks are performed.")
        print(f"   Always obtain written authorization before testing any system.")

    except socket.gaierror:
        print(f"\n{Fore.RED}[!] Could not resolve hostname: {host}{Style.RESET_ALL}")
    except socket.timeout:
        print(f"\n{Fore.RED}[!] Connection timeout. Target may be unreachable.{Style.RESET_ALL}")
    except ConnectionRefusedError:
        print(f"\n{Fore.RED}[!] Connection refused. Target may not support HTTPS on port {port}.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[i] Required dependency: pip3 install cryptography{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")