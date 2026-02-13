import ssl
import socket
import datetime
import time
import json
import argparse
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style, Back
import nmap

init(autoreset=True)

class TLSUltimateScanner:
    def __init__(self, host: str, port: int = 443, aggressive: bool = False):
        self.host = host
        self.port = port
        self.aggressive = aggressive
        self.results = {
            'target': f"{host}:{port}",
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'tls_versions': {},
            'ciphers': [],
            'certificate': {},
            'vulnerabilities': [],
            'msf_modules': [],
            'nmap_scripts': [],
            'security_score': 100,
            'risk_level': 'UNKNOWN'
        }
        self.tls_versions = {
            "TLSv1": ssl.TLSVersion.TLSv1,
            "TLSv1.1": ssl.TLSVersion.TLSv1_1,
            "TLSv1.2": ssl.TLSVersion.TLSv1_2,
            "TLSv1.3": ssl.TLSVersion.TLSv1_3,
        }
        self.known_vulns = self.load_vuln_db()

    def load_vuln_db(self):
        """📚 База TLS CVE"""
        return {
            'heartbleed': {'cve': 'CVE-2014-0160', 'nmap': 'ssl-heartbleed', 'msf': 'auxiliary/scanner/ssl/openssl_heartbleed'},
            'poodle': {'cve': 'CVE-2014-3566', 'nmap': 'ssl-poodle', 'msf': 'auxiliary/scanner/ssl/openssl_poodle'},
            'poodle_sslv2': {'cve': 'CVE-2014-8720', 'nmap': 'ssl-poodle.nss'},
            'beast': {'cve': 'CVE-2011-3389', 'ciphers': ['CBC']},
            'sweet32': {'cve': 'CVE-2016-2183', 'ciphers': ['3DES']},
            'ticketbleed': {'cve': 'CVE-2016-9244', 'nmap': 'ssl-ticketbleed'},
            'ccs_injection': {'cve': 'CVE-2014-0224', 'nmap': 'ssl-ccs-injection'}
        }

    def test_tls_version(self, version):
        """🔍 TLS версия тест"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = version
            ctx.maximum_version = version

            with socket.create_connection((self.host, self.port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cipher = ssock.cipher()
                    return True, ssock.version(), (cipher[0] if cipher else 'Unknown', cipher[1] if cipher else '', cipher[2] if cipher else 0)
        except Exception:
            return False, None, None

    def scan_tls_versions(self):
        """⚡ Многопоточный TLS скан"""
        print(f"{Fore.CYAN}🔍 Scanning TLS versions...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=8) as executor:
            futures = {executor.submit(self.test_tls_version, ver): name 
                      for name, ver in self.tls_versions.items()}
            
            for future in futures:
                ok, proto, cipher = future.result()
                name = futures[future]
                if ok:
                    self.results['tls_versions'][name] = {
                        'protocol': proto,
                        'cipher': cipher
                    }
                    print(f"{Fore.GREEN}✅ {name}: {cipher[0]} ({cipher[2]} bits){Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}❌ {name}: Not supported{Style.RESET_ALL}")

    def get_certificate_info(self):
        """📜 Сертификат анализ"""
        print(f"{Fore.CYAN}📜 Fetching certificate...{Style.RESET_ALL}")
        
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.host, self.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse dates
                    nb = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                    na = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    now = datetime.datetime.utcnow()
                    
                    self.results['certificate'] = {
                        'subject_cn': dict(x[0] for x in cert.get("subject", [])).get('commonName', 'N/A'),
                        'issuer_cn': dict(x[0] for x in cert.get("issuer", [])).get('commonName', 'N/A'),
                        'not_before': nb.isoformat(),
                        'not_after': na.isoformat(),
                        'days_left': (na - now).days,
                        'valid': nb <= now <= na,
                        'serial': cert.get('serialNumber', 'N/A')
                    }
                    
                    status_color = Fore.GREEN if self.results['certificate']['valid'] else Fore.RED
                    days = self.results['certificate']['days_left']
                    days_color = Fore.RED if days < 0 else Fore.YELLOW if days < 30 else Fore.GREEN
                    print(f"{status_color}✅ Certificate: {self.results['certificate']['subject_cn']}{Style.RESET_ALL}")
                    print(f"{days_color}📅 Days left: {days}{Style.RESET_ALL}")
                    
        except Exception as e:
            print(f"{Fore.RED}❌ Certificate error: {e}{Style.RESET_ALL}")
            self.results['certificate'] = {'error': str(e)}

    def nmap_vuln_scan(self):
        """🛠️ Nmap SSL scripts"""
        if not self.aggressive:
            return
            
        print(f"{Fore.CYAN}🛠️ Running Nmap SSL vulnerability scan...{Style.RESET_ALL}")
        try:
            nm = nmap.PortScanner()
            nm.scan(self.host, str(self.port), 
                   arguments='--script ssl-cert,ssl-enum-ciphers,ssl-heartbleed,ssl-poodle,ssl-ticketbleed,ssl-ccs-injection')
            
            if self.host in nm.all_hosts():
                scripts = nm[self.host]['tcp'].get(self.port, {}).get('script', {})
                
                for script, result in scripts.items():
                    self.results['nmap_scripts'].append({'script': script, 'result': result})
                    print(f"{Fore.YELLOW}📋 {script}: {result[:100]}...{Style.RESET_ALL}")
                    
                
                for vuln_name, vuln_data in self.known_vulns.items():
                    if vuln_data.get('nmap') in str(scripts):
                        self.results['vulnerabilities'].append(vuln_data['cve'])
                        self.results['msf_modules'].append(vuln_data['msf'])
                        
        except Exception as e:
            print(f"{Fore.YELLOW}⚠️ Nmap scan skipped: {e}{Style.RESET_ALL}")

    def analyze_ciphers(self):
        """🔑 Шифры анализ"""
        weak_ciphers = []
        for tls_ver, data in self.results['tls_versions'].items():
            cipher_name = data['cipher'][0]
            bits = data['cipher'][2]
            
            
            weak_patterns = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'CBC']
            if any(pattern in cipher_name for pattern in weak_patterns):
                weak_ciphers.append(f"{tls_ver}: {cipher_name}")
                
            if bits < 128:
                weak_ciphers.append(f"{tls_ver}: {bits}-bit weak")
                
            self.results['ciphers'].append({
                'version': tls_ver,
                'cipher': cipher_name,
                'bits': bits,
                'weak': len(weak_ciphers) > 0
            })
            
        return weak_ciphers

    def calculate_security_score(self):
        """📊 Security scoring"""
        score = 100
        
        
        weak_tls = sum(1 for v in ['TLSv1', 'TLSv1.1'] if v in self.results['tls_versions'])
        score -= weak_tls * 25
        
    
        cert = self.results['certificate']
        if 'error' in cert:
            score -= 40
        elif not cert.get('valid', True):
            score -= 30
        elif cert.get('days_left', 999) < 30:
            score -= 15
            
        
        weak_ciphers = self.analyze_ciphers()
        score -= len(weak_ciphers) * 5
        
        
        score -= len(self.results['vulnerabilities']) * 10
        
        self.results['security_score'] = max(0, score)
        
        if score >= 85: self.results['risk_level'] = 'SECURE'
        elif score >= 70: self.results['risk_level'] = 'GOOD'
        elif score >= 50: self.results['risk_level'] = 'MEDIUM'
        elif score >= 30: self.results['risk_level'] = 'HIGH'
        else: self.results['risk_level'] = 'CRITICAL'

    def print_executive_summary(self):
        """📋 Executive summary"""
        score = self.results['security_score']
        risk_color = {
            'SECURE': Fore.GREEN, 'GOOD': Fore.GREEN,
            'MEDIUM': Fore.YELLOW, 'HIGH': Fore.RED, 'CRITICAL': Fore.MAGENTA
        }[self.results['risk_level']]
        
        print(f"\n{Fore.CYAN}{'='*90}")
        print(f"{Fore.WHITE}🎯 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}📊 Security Score: {risk_color}{score}/100 {self.results['risk_level']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🔗 TLS Versions: {len(self.results['tls_versions'])} supported{Style.RESET_ALL}")
        print(f"{Fore.RED}🚨 Vulnerabilities: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🔑 Cipher Suites: {len(self.results['ciphers'])}{Style.RESET_ALL}")

    def print_recommendations(self):
        """💡 Рекомендации"""
        print(f"\n{Fore.YELLOW}🎯 EXPLOITATION & FIXES:{Style.RESET_ALL}")
        
        if self.results['msf_modules']:
            print(f"{Fore.RED}💥 Metasploit Modules:{Style.RESET_ALL}")
            for module in self.results['msf_modules']:
                print(f"  {Fore.RED}msf6 > use {module}{Style.RESET_ALL}")
        
        print(f"{Fore.CYAN}🛠️  Nmap Commands:{Style.RESET_ALL}")
        print(f"  nmap -p{self.port} --script ssl-* {self.host}")
        print(f"  nmap -p{self.port} --script ssl-heartbleed,ssl-poodle {self.host}")
        
        print(f"\n{Fore.GREEN}✅ Nginx/Apache Config:{Style.RESET_ALL}")
        print(f"ssl_protocols TLSv1.2 TLSv1.3;")
        print(f"ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20;")
        print(f"ssl_prefer_server_ciphers off;")

    def save_report(self):
        """📊 JSON отчет"""
        filename = f"tls_audit_{self.host}_{self.port}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        return filename

    def run_full_audit(self):
        """🚀 Полный аудит"""
        print(f"{Fore.MAGENTA}{'='*90}")
        print(f"{Fore.YELLOW}🔒 HACKERAI TLS ULTIMATE SCANNER v5.0")
        print(f"{Fore.CYAN}Target: {self.host}:{self.port} | Mode: {'AGGRESSIVE' if self.aggressive else 'STANDARD'}")
        print(f"{Fore.MAGENTA}{'='*90}{Style.RESET_ALL}")
        
        self.scan_tls_versions()
        self.get_certificate_info()
        
        if self.aggressive:
            self.nmap_vuln_scan()
            
        self.calculate_security_score()
        self.print_executive_summary()
        self.print_recommendations()
        
        report = self.save_report()
        print(f"\n{Fore.GREEN}✅ Full report: {report}{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="🔒 HackerAI TLS Ultimate Scanner")
    parser.add_argument("target", help="Hostname/IP")
    parser.add_argument("-p", "--port", type=int, default=443, help="Port")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Nmap CVE scan")
    
    args = parser.parse_args()
    scanner = TLSUltimateScanner(args.target, args.port, args.aggressive)
    scanner.run_full_audit()

if __name__ == "__main__":
    main()
