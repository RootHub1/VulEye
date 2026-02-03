import ssl
import socket
import datetime
from urllib.parse import urlparse
from colorama import init, Fore, Style

init(autoreset=True)


def check_ssl_version(host, port, version_name, ssl_version):
    try:
        context = ssl.SSLContext(ssl_version)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher = ssock.cipher()
                return True, cipher[0], cipher[1]
    except (ssl.SSLError, socket.timeout, ConnectionRefusedError):
        return False, None, None
    except Exception:
        return False, None, None


def get_certificate_info(host, port):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                if not cert:
                    return None

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                not_before = cert.get('notBefore', '')
                not_after = cert.get('notAfter', '')

                serial_number = cert.get('serialNumber', 'N/A')

                subject_alt_names = []
                for ext in cert.get('subjectAltName', []):
                    if ext[0] == 'DNS':
                        subject_alt_names.append(ext[1])

                return {
                    'subject': subject,
                    'issuer': issuer,
                    'not_before': not_before,
                    'not_after': not_after,
                    'serial_number': serial_number,
                    'subject_alt_names': subject_alt_names,
                    'version': cert.get('version', 'N/A')
                }
    except Exception as e:
        return None


def check_vulnerabilities(host, port):
    vulnerabilities = []

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version()
                cipher = ssock.cipher()

                if protocol in ['SSLv2', 'SSLv3']:
                    vulnerabilities.append({
                        'name': 'SSLv2/SSLv3 Enabled',
                        'severity': 'CRITICAL',
                        'description': f'Using deprecated and insecure protocol: {protocol}',
                        'cve': 'CVE-2014-3566 (POODLE)',
                        'fix': 'Disable SSLv2/SSLv3, use TLS 1.2 or higher'
                    })

                if protocol == 'TLSv1' or protocol == 'TLSv1.1':
                    vulnerabilities.append({
                        'name': 'TLS 1.0/1.1 Enabled',
                        'severity': 'HIGH',
                        'description': f'Using outdated protocol: {protocol}',
                        'cve': 'N/A',
                        'fix': 'Disable TLS 1.0/1.1, use TLS 1.2 or TLS 1.3'
                    })

                weak_ciphers = [
                    'NULL', 'EXPORT', 'DES', 'RC4', 'MD5', 'CBC',
                    'anon', 'DH_anon', 'ECDH_anon'
                ]

                cipher_name = cipher[0].upper()
                if any(weak in cipher_name for weak in weak_ciphers):
                    vulnerabilities.append({
                        'name': 'Weak Cipher Suite',
                        'severity': 'HIGH',
                        'description': f'Using weak cipher: {cipher_name}',
                        'cve': 'N/A',
                        'fix': 'Configure strong ciphers (AES-GCM, ChaCha20-Poly1305)'
                    })

                if cipher[1] < 128:
                    vulnerabilities.append({
                        'name': 'Weak Encryption Key Length',
                        'severity': 'MEDIUM',
                        'description': f'Key length: {cipher[1]} bits (recommended: 128+)',
                        'cve': 'N/A',
                        'fix': 'Use ciphers with 128-bit or stronger encryption'
                    })

    except Exception as e:
        pass

    return vulnerabilities


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN}              SSL/TLS SECURITY CHECKER                             {Fore.CYAN}║")
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

    print(f"\n{Fore.CYAN}[+] Analyzing SSL/TLS configuration for: {host}:{port}{Style.RESET_ALL}")

    try:
        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SSL/TLS VERSION CHECK")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        ssl_versions = [
            ('SSLv2', ssl.PROTOCOL_SSLv2 if hasattr(ssl, 'PROTOCOL_SSLv2') else None),
            ('SSLv3', ssl.PROTOCOL_SSLv3 if hasattr(ssl, 'PROTOCOL_SSLv3') else None),
            ('TLSv1.0', ssl.PROTOCOL_TLSv1 if hasattr(ssl, 'PROTOCOL_TLSv1') else None),
            ('TLSv1.1', ssl.PROTOCOL_TLSv1_1 if hasattr(ssl, 'PROTOCOL_TLSv1_1') else None),
            ('TLSv1.2', ssl.PROTOCOL_TLSv1_2 if hasattr(ssl, 'PROTOCOL_TLSv1_2') else None),
            ('TLSv1.3', ssl.PROTOCOL_TLS_CLIENT)
        ]

        supported_versions = []

        for version_name, ssl_version in ssl_versions:
            if ssl_version is None:
                print(f"{Fore.CYAN}[i] {version_name}: Not available in this Python version{Style.RESET_ALL}")
                continue

            supported, cipher, bits = check_ssl_version(host, port, version_name, ssl_version)

            if supported:
                supported_versions.append(version_name)
                cipher_info = f" ({cipher}, {bits} bits)" if cipher else ""
                print(f"{Fore.GREEN}[✓] {version_name}: SUPPORTED{cipher_info}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[✗] {version_name}: NOT SUPPORTED{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}CERTIFICATE INFORMATION")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        cert_info = get_certificate_info(host, port)

        if cert_info:
            print(f"\n{Fore.GREEN}[✓] SSL Certificate Found{Style.RESET_ALL}")

            subject_cn = cert_info['subject'].get('commonName', 'N/A')
            issuer_cn = cert_info['issuer'].get('commonName', 'N/A')

            print(f"\n{Fore.CYAN}Subject:{Style.RESET_ALL}")
            for key, value in cert_info['subject'].items():
                print(f"   {key}: {value}")

            print(f"\n{Fore.CYAN}Issuer:{Style.RESET_ALL}")
            for key, value in cert_info['issuer'].items():
                print(f"   {key}: {value}")

            print(f"\n{Fore.CYAN}Validity:{Style.RESET_ALL}")
            print(f"   Not Before: {cert_info['not_before']}")
            print(f"   Not After: {cert_info['not_after']}")

            try:
                not_after_dt = datetime.datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after_dt - datetime.datetime.now()).days

                if days_until_expiry < 0:
                    print(f"   {Fore.RED}  CERTIFICATE EXPIRED ({abs(days_until_expiry)} days ago){Style.RESET_ALL}")
                elif days_until_expiry < 30:
                    print(f"   {Fore.YELLOW}  Certificate expires in {days_until_expiry} days{Style.RESET_ALL}")
                else:
                    print(f"   {Fore.GREEN}[✓] Valid for {days_until_expiry} more days{Style.RESET_ALL}")
            except:
                print(f"   {Fore.YELLOW}[?] Could not parse expiration date{Style.RESET_ALL}")

            if cert_info['subject_alt_names']:
                print(f"\n{Fore.CYAN}Subject Alternative Names:{Style.RESET_ALL}")
                for san in cert_info['subject_alt_names']:
                    print(f"   • {san}")

            print(f"\n{Fore.CYAN}Serial Number:{Style.RESET_ALL} {cert_info['serial_number']}")
            print(f"{Fore.CYAN}Version:{Style.RESET_ALL} {cert_info['version']}")
        else:
            print(f"\n{Fore.RED}[!] No SSL certificate found or connection failed{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[i] Target may not support HTTPS or is unreachable{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}VULNERABILITY SCAN")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        vulnerabilities = check_vulnerabilities(host, port)

        if vulnerabilities:
            print(f"\n{Fore.RED}[!] SSL/TLS VULNERABILITIES DETECTED{Style.RESET_ALL}")

            for vuln in vulnerabilities:
                severity_color = Fore.MAGENTA if vuln['severity'] == 'CRITICAL' else (
                    Fore.RED if vuln['severity'] == 'HIGH' else Fore.YELLOW)
                print(f"\n{severity_color}• {vuln['name']} ({vuln['severity']}){Style.RESET_ALL}")
                print(f"  Description: {vuln['description']}")
                if vuln.get('cve'):
                    print(f"  CVE: {vuln['cve']}")
                print(f"  Fix: {vuln['fix']}")
        else:
            print(f"\n{Fore.GREEN}[✓] No critical SSL/TLS vulnerabilities detected{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}SECURITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        security_score = 100
        issues = []

        if 'SSLv2' in supported_versions or 'SSLv3' in supported_versions:
            security_score -= 40
            issues.append('SSLv2/SSLv3 enabled (CRITICAL)')

        if 'TLSv1.0' in supported_versions or 'TLSv1.1' in supported_versions:
            security_score -= 20
            issues.append('TLS 1.0/1.1 enabled (HIGH)')

        if cert_info:
            try:
                not_after_dt = datetime.datetime.strptime(cert_info['not_after'], '%b %d %H:%M:%S %Y %Z')
                days_until_expiry = (not_after_dt - datetime.datetime.now()).days
                if days_until_expiry < 0:
                    security_score -= 30
                    issues.append('Certificate expired')
                elif days_until_expiry < 30:
                    security_score -= 10
                    issues.append('Certificate expiring soon')
            except:
                pass

        if vulnerabilities:
            security_score -= len([v for v in vulnerabilities if v['severity'] in ['CRITICAL', 'HIGH']]) * 15

        score_color = Fore.RED if security_score < 60 else (Fore.YELLOW if security_score < 80 else Fore.GREEN)

        print(f"\n{Fore.CYAN}Security Score: {score_color}{security_score}/100{Style.RESET_ALL}")

        if issues:
            print(f"\n{Fore.YELLOW}Identified Issues:{Style.RESET_ALL}")
            for issue in issues:
                print(f"   • {issue}")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}RECOMMENDATIONS")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        if security_score < 80:
            print(f"\n{Fore.YELLOW}Critical Recommendations:{Style.RESET_ALL}")
            print(f"   • Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1")
            print(f"   • Enable only TLS 1.2 and TLS 1.3")
            print(f"   • Use strong cipher suites:")
            print(f"        - TLS_AES_256_GCM_SHA384 (TLS 1.3)")
            print(f"        - TLS_CHACHA20_POLY1305_SHA256 (TLS 1.3)")
            print(f"        - ECDHE-RSA-AES256-GCM-SHA384 (TLS 1.2)")
            print(f"   • Implement HSTS (HTTP Strict Transport Security):")
            print(f"        Strict-Transport-Security: max-age=31536000; includeSubDomains")
            print(f"   • Use certificates from trusted Certificate Authorities (CA)")
            print(f"   • Enable OCSP Stapling for certificate revocation checking")
            print(f"   • Implement Certificate Transparency logging")
            print(f"   • Regularly update SSL/TLS libraries and configurations")
        else:
            print(f"\n{Fore.GREEN}[✓] SSL/TLS configuration appears secure{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Best Practices:{Style.RESET_ALL}")
            print(f"   • Continue monitoring for new vulnerabilities")
            print(f"   • Regularly update certificates before expiration")
            print(f"   • Implement HSTS preload for maximum security")
            print(f"   • Use automated SSL monitoring tools")
            print(f"   • Conduct periodic SSL security audits")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.CYAN}COMMON SSL VULNERABILITIES")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}Known SSL/TLS Vulnerabilities:{Style.RESET_ALL}")
        print(f"   • Heartbleed (CVE-2014-0160) - OpenSSL memory disclosure")
        print(f"   • POODLE (CVE-2014-3566) - SSLv3 padding oracle")
        print(f"   • BEAST (CVE-2011-3389) - TLS 1.0 CBC vulnerability")
        print(f"   • CRIME (CVE-2012-4929) - SSL compression information leak")
        print(f"   • FREAK (CVE-2015-0204) - Export-grade RSA downgrade")
        print(f"   • Logjam (CVE-2015-4000) - Diffie-Hellman downgrade")
        print(f"   • DROWN (CVE-2016-0800) - SSLv2 cross-protocol attack")

        print(f"\n{Fore.YELLOW}[i] Note: This scanner checks for configuration issues.")
        print(f"    For comprehensive vulnerability testing, use dedicated tools:")
        print(f"        • testssl.sh")
        print(f"        • SSL Labs (https://www.ssllabs.com/ssltest/)")
        print(f"        • nmap ssl-enum-ciphers script")

        print(f"\n{Fore.CYAN}{'=' * 70}")
        print(f"{Fore.GREEN}[✓] SSL/TLS security analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    except socket.gaierror:
        print(f"\n{Fore.RED}[!] Could not resolve hostname: {host}{Style.RESET_ALL}")
    except socket.timeout:
        print(
            f"\n{Fore.RED}[!] Connection timeout. Target may be unreachable or blocking SSL connections.{Style.RESET_ALL}")
    except ConnectionRefusedError:
        print(f"\n{Fore.RED}[!] Connection refused. Target may not support HTTPS on port {port}.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")