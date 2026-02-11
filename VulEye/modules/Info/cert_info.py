import ssl
import socket
import datetime
import hashlib
import json
import argparse
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from colorama import init, Fore, Style, Back
import nmap
import requests

init(autoreset=True)

class SSLTLSUltimateAnalyzer:
    def __init__(self, target: str, port: int = 443, aggressive: bool = False):
        self.target = target
        self.port = port
        self.aggressive = aggressive
        self.results = {
            'target': target,
            'port': port,
            'timestamp': datetime.datetime.now().isoformat(),
            'certificate': {},
            'tls_versions': [],
            'ciphers': [],
            'vulnerabilities': [],
            'security_score': 0,
            'risk_level': 'UNKNOWN',
            'recommendations': [],
            'msf_modules': []
        }
        self.known_vulns = self.load_vulnerability_db()

    def load_vulnerability_db(self):
        """📚 База известных SSL уязвимостей"""
        return {
            'heartbleed': {'cve': 'CVE-2014-0160', 'msf': 'auxiliary/scanner/ssl/openssl_heartbleed'},
            'poodle': {'cve': 'CVE-2014-3566', 'test': 'SSLv3 fallback'},
            'beast': {'cve': 'CVE-2011-3389', 'ciphers': ['CBC']},
            'crime': {'cve': 'CVE-2012-4929', 'ciphers': ['RC4']},
            'sweet32': {'cve': 'CVE-2016-2183', 'ciphers': ['3DES']},
            'ticketbleed': {'cve': 'CVE-2016-9244', 'openssl': '1.0.2-1.1.0'},
            'robo': {'cve': 'CVE-2017-20005', 'test': 'ROBOCERT'}
        }

    def get_certificate(self):
        """📜 Получение и парсинг сертификата"""
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        try:
            with socket.create_connection((self.target, self.port), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())
                    return cert, ssock.version()
        except Exception as e:
            print(f"{Fore.RED}❌ Certificate fetch failed: {e}{Style.RESET_ALL}")
            return None, None

    def analyze_certificate(self, cert):
        """🔬 Глубокий анализ сертификата"""
        if not cert:
            return {}
            
        analysis = {
            'subject': cert.subject.rfc4514_string(),
            'issuer': cert.issuer.rfc4514_string(),
            'serial': str(cert.serial_number),
            'version': cert.version.name,
            'not_before': cert.not_valid_before.isoformat(),
            'not_after': cert.not_valid_after.isoformat(),
            'signature_algo': cert.signature_algorithm_oid._name,
            'public_key_type': 'RSA' if 'RSAPublicKey' in str(type(cert.public_key())) else 'ECDSA',
        }
        
        
        try:
            analysis['key_size'] = cert.public_key().key_size
        except:
            analysis['key_size'] = 0
            
        
        try:
            pub_bytes = cert.public_key().public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            analysis['sha256_fingerprint'] = hashlib.sha256(pub_bytes).hexdigest()
        except:
            pass
            
        
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            analysis['san'] = [str(name) for name in san_ext.value.get_values_for_type(x509.DNSName)]
        except:
            analysis['san'] = []
            
        
        now = datetime.datetime.utcnow()
        analysis['valid'] = cert.not_valid_before <= now <= cert.not_valid_after
        analysis['days_left'] = (cert.not_valid_after - now).days
        analysis['self_signed'] = analysis['subject'] == analysis['issuer']
        
       
        for attr in cert.subject:
            if attr.oid._name == 'commonName':
                analysis['cn'] = attr.value
            elif attr.oid._name == 'organizationName':
                analysis['org'] = attr.value
            elif attr.oid._name == 'countryName':
                analysis['country'] = attr.value
                
        self.results['certificate'] = analysis
        return analysis

    def test_tls_versions(self):
        """🔍 Тест всех TLS версий"""
        versions = {
            ssl.TLSVersion.TLSv1: 'TLS 1.0',
            ssl.TLSVersion.TLSv1_1: 'TLS 1.1', 
            ssl.TLSVersion.TLSv1_2: 'TLS 1.2',
            ssl.TLSVersion.TLSv1_3: 'TLS 1.3'
        }
        
        supported = []
        for proto, name in versions.items():
            context = ssl.create_default_context()
            context.options |= ssl.OP_NO_TLSv1_3
            context.options |= ssl.OP_NO_TLSv1_2
            context.options |= ssl.OP_NO_TLSv1_1
            context.set_ciphers('DEFAULT')
            context.minimum_version = proto
            context.maximum_version = proto
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                with socket.create_connection((self.target, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        supported.append(name)
            except:
                continue
                
        self.results['tls_versions'] = supported
        return supported

    def test_ssl_vulnerabilities(self):
        """💥 Тест известных SSL уязвимостей"""
        vulns = []
        
        
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, str(self.port), 'ssl-heartbleed')
            if nm[self.target]['tcp'][self.port].get('script', {}).get('ssl-heartbleed'):
                vulns.append('HEARTBLEED')
                self.results['msf_modules'].append('auxiliary/scanner/ssl/openssl_heartbleed')
        except:
            pass
            
        
        tls_versions = self.results['tls_versions']
        if 'TLS 1.0' in tls_versions or 'TLS 1.1' in tls_versions:
            vulns.extend(['POODLE', 'BEAST'])
            self.results['msf_modules'].extend([
                'auxiliary/scanner/ssl/openssl_heartbleed_poodle'
            ])
            
        
        weak_ciphers = self.test_weak_ciphers()
        if weak_ciphers:
            vulns.append('WEAK_CIPHERS')
            
        self.results['vulnerabilities'] = vulns
        return vulns

    def test_weak_ciphers(self):
        """🔑 Тест слабых шифров"""
        weak = []
        ciphers = [
            'DES-CBC3-SHA', 'RC4', 'AES128-SHA', 'DHE-RSA-AES256-SHA256'
        ]
        
        for cipher in ciphers:
            context = ssl.create_default_context()
            context.set_ciphers(cipher)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            try:
                with socket.create_connection((self.target, self.port), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                        weak.append(cipher)
            except:
                pass
                
        self.results['ciphers'] = weak
        return weak

    def calculate_security_score(self):
        """📊 Расчет security score"""
        score = 100
        analysis = self.results['certificate']
        vulns = self.results['vulnerabilities']
        
        
        if not analysis.get('valid', True):
            score -= 40
        if analysis.get('days_left', 0) < 30:
            score -= 20
        if analysis.get('key_size', 0) < 2048:
            score -= 25
        if 'sha1' in analysis.get('signature_algo', '').lower():
            score -= 30
            
       
        if 'TLS 1.0' in self.results['tls_versions']:
            score -= 25
        if 'TLS 1.1' in self.results['tls_versions']:
            score -= 20
        if 'TLS 1.3' not in self.results['tls_versions']:
            score -= 15
            
        
        score -= len(vulns) * 10
        
        self.results['security_score'] = max(0, score)
        
        if score >= 80:
            self.results['risk_level'] = 'SECURE'
        elif score >= 60:
            self.results['risk_level'] = 'MEDIUM'
        elif score >= 40:
            self.results['risk_level'] = 'HIGH'
        else:
            self.results['risk_level'] = 'CRITICAL'
            
        return score

    def generate_recommendations(self):
        """💡 Рекомендации по исправлению"""
        recs = []
        score = self.results['security_score']
        
        if score < 60:
            recs.extend([
                "🚨 IMMEDIATE ACTION REQUIRED:",
                "   1. DISABLE TLS 1.0/1.1 - Only TLS 1.2+",
                "   2. Install Let's Encrypt / buy proper cert",
                "   3. Configure strong ciphers: ECDHE+AESGCM",
                "   4. RUN: nmap --script ssl-enum-ciphers"
            ])
            
        recs.extend([
            "🔧 Nginx (nginx.conf):",
            "   ssl_protocols TLSv1.2 TLSv1.3;",
            "   ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;",

            "🔧 Apache (.htaccess):",
            "   SSLProtocol all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1",
            "   SSLCipherSuite ECDHE+AESGCM",
            
            "🔧 Metasploit exploits:",
        ] + [f"   msf> use {module}" for module in self.results['msf_modules']])
        
        self.results['recommendations'] = recs
        return recs

    def save_report(self):
        """📊 Профессиональный JSON отчет"""
        filename = f"ssl_audit_{self.target}_{self.port}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        return filename

    def print_banner(self):
        """🏳️  Красивый баннер"""
        print(f"{Fore.MAGENTA}{'='*90}")
        print(f"{Fore.YELLOW}🔒 HACKERAI SSL/TLS ULTIMATE ANALYZER v3.0")
        print(f"{Fore.CYAN}Target: {self.target}:{self.port} | Mode: {'AGGRESSIVE' if self.aggressive else 'STANDARD'}")
        print(f"{Fore.MAGENTA}{'='*90}{Style.RESET_ALL}")

    def run_full_audit(self):
        """🚀 Полный аудит"""
        self.print_banner()
        
        print(f"{Fore.CYAN}📜 Fetching certificate...{Style.RESET_ALL}")
        cert, tls_version = self.get_certificate()
        self.analyze_certificate(cert)
        
        print(f"{Fore.CYAN}🔍 Testing TLS versions...{Style.RESET_ALL}")
        self.test_tls_versions()
        
        if self.aggressive:
            print(f"{Fore.CYAN}💥 Testing SSL vulnerabilities...{Style.RESET_ALL}")
            self.test_ssl_vulnerabilities()
        
        self.calculate_security_score()
        self.generate_recommendations()
        
        self.print_results()
        report = self.save_report()
        print(f"\n{Fore.GREEN}✅ Full report saved: {report}{Style.RESET_ALL}")

    def print_results(self):
        """📋 Красивый вывод результатов"""
        analysis = self.results['certificate']
        score = self.results['security_score']
        risk_color = {
            'SECURE': Fore.GREEN, 'MEDIUM': Fore.YELLOW, 
            'HIGH': Fore.RED, 'CRITICAL': Fore.MAGENTA
        }[self.results['risk_level']]
        
        print(f"\n{Fore.CYAN}{'='*90}")
        print(f"{Fore.WHITE}📊 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}🎯 Security Score: {risk_color}{score}/100 {self.results['risk_level']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📜 CN: {Fore.CYAN}{analysis.get('cn', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🏢 Org: {Fore.CYAN}{analysis.get('org', 'N/A')}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🔑 Key: {Fore.YELLOW}{analysis.get('public_key_type', 'N/A')} {analysis.get('key_size', 0)}bit{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📅 Expires: {Fore.GREEN if analysis.get('days_left', 0) > 30 else Fore.RED}{analysis.get('days_left', 0)} days{Style.RESET_ALL}")
        
        print(f"\n{Fore.WHITE}🔗 TLS Versions: {Fore.CYAN}', '.join(self.results['tls_versions'])}{Style.RESET_ALL}")
        
        vulns = self.results['vulnerabilities']
        if vulns:
            print(f"{Fore.RED}🚨 VULNERABILITIES ({len(vulns)}): {', '.join(vulns)}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💥 MSF Modules:{Style.RESET_ALL}")
            for module in self.results['msf_modules']:
                print(f"   {Fore.RED}msf> use {module}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}✅ No known vulnerabilities{Style.RESET_ALL}")
            
        print(f"\n{Fore.YELLOW}💡 Top Recommendations:{Style.RESET_ALL}")
        for rec in self.results['recommendations'][:4]:
            print(f"   {rec}")

def main():
    parser = argparse.ArgumentParser(description="🔒 HackerAI SSL/TLS Ultimate Analyzer")
    parser.add_argument("target", help="Hostname/IP (google.com or 192.168.1.1)")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Full vulnerability scan")
    
    args = parser.parse_args()
    
    analyzer = SSLTLSUltimateAnalyzer(args.target, args.port, args.aggressive)
    analyzer.run_full_audit()

if __name__ == "__main__":
    main()