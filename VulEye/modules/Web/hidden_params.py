import requests
from bs4 import BeautifulSoup
import re
import json
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
from collections import defaultdict, Counter
from colorama import init, Fore, Style, Back
import argparse
import base64
from pathlib import Path

init(autoreset=True)

class HiddenParamsScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []
        self.exposed_files = []
        self.wordlists_dir = Path(__file__).parent / "wordlists"
        
    def banner(self):
        print(f"{Fore.CYAN}{'═' * 90}")
        print(f"{Fore.CYAN}║{Fore.GREEN}{' ' * 24}PROFESSIONAL HIDDEN PARAMETERS DISCOVERY{Fore.GREEN}{' ' * 24}{Fore.CYAN}║")
        print(f"{Fore.CYAN}{'═' * 90}{Style.RESET_ALL}")

    def validate_target(self, target):
        """Валидация цели"""
        if not target.startswith(('http://', 'https://')):
            return False, f"{Fore.RED}[!] URL должен начинаться с http(s)://{Style.RESET_ALL}"
        
        parsed = urlparse(target)
        if not parsed.netloc:
            return False, f"{Fore.RED}[!] Некорректный URL{Style.RESET_ALL}"
        return True, ""

    def load_wordlists(self):
        """Загрузка словарей для fuzzing"""
        common_params = [
            'debug', 'admin', 'test', 'dev', 'staging', 'token', 'auth', 'session',
            'csrf', 'secret', 'key', 'password', 'api_key', 'access_token', 'id',
            'user_id', 'page', 'limit', 'offset', 'internal', 'beta', 'preview'
        ]
        
        sensitive_keywords = [
            'secret', 'token', 'password', 'key', 'pass', 'pwd', 'auth', 'session',
            'csrf', 'api_key', 'bearer', 'private', 'admin', 'root'
        ]
        
        config_files = [
            '/.env', '/.env.local', '/.env.production', '/.env.example',
            '/config.php', '/settings.php', '/debug.php', '/admin/config.php',
            '/wp-config.php', '/.htaccess', '/robots.txt', '/sitemap.xml',
            '/backup.sql', '/db.sql.gz', '/config.json', '/app.config'
        ]
        
        return common_params, sensitive_keywords, config_files

    def analyze_html_source(self, content):
        """Анализ HTML исходного кода"""
        findings = []
        
        
        comments = re.findall(r'<!--\s*(.*?)\s*-->', content, re.DOTALL | re.IGNORECASE)
        for comment in comments:
            if len(comment.strip()) > 5:
                risk = self.assess_risk(comment)
                findings.append({
                    'type': 'HTML Comment',
                    'value': comment.strip()[:100],
                    'risk': risk,
                    'snippet': self.truncate(comment, 80)
                })
        
        
        js_patterns = [
            r'var\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
            r'let\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
            r'const\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
            r'window\.([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for name, value in matches:
                if self.is_suspicious_param(name):
                    risk = 'CRITICAL' if self.is_sensitive_keyword(name) else 'HIGH'
                    findings.append({
                        'type': 'JS Variable',
                        'value': f"{name}={value[:50]}",
                        'risk': risk,
                        'snippet': f"{name}={value[:80]}"
                    })
        
        return findings

    def analyze_forms(self, soup):
        """Анализ форм и скрытых полей"""
        findings = []
        forms = soup.find_all('form')
        
        for form in forms:
            
            hidden_inputs = form.find_all('input', {'type': 'hidden'})
            for inp in hidden_inputs:
                name = inp.get('name', '')
                value = inp.get('value', '')[:50]
                if name:
                    risk = self.assess_input_risk(name, value)
                    findings.append({
                        'type': 'Hidden Input',
                        'value': f"{name}={value}",
                        'risk': risk,
                        'snippet': f"form[{name}]={value}"
                    })
            
            
            action = form.get('action', '')
            if action:
                parsed = urlparse(action)
                for param in parse_qs(parsed.query):
                    if self.is_suspicious_param(param):
                        findings.append({
                            'type': 'Form Action Param',
                            'value': param,
                            'risk': 'MEDIUM',
                            'snippet': f"action?{param}"
                        })
        
        return findings

    def analyze_dom_attributes(self, soup):
        """Анализ DOM атрибутов"""
        findings = []
        
        
        for tag in soup.find_all(attrs={'data-*': True}):
            for attr, value in tag.attrs.items():
                if attr.startswith('data-') and len(str(value)) > 8:
                    risk = 'LOW'
                    if self.is_suspicious_param(attr[5:]):  
                        risk = 'MEDIUM'
                    findings.append({
                        'type': f"Data Attribute ({attr})",
                        'value': str(value)[:50],
                        'risk': risk,
                        'snippet': f"{attr}={value[:60]}"
                    })
        
        
        suspicious_attrs = ['id', 'class']
        for tag in soup.find_all():
            for attr in suspicious_attrs:
                if attr in tag.attrs:
                    value = tag.attrs[attr]
                    if self.is_suspicious_param(value):
                        findings.append({
                            'type': f"{attr.upper()} Attribute",
                            'value': value,
                            'risk': 'MEDIUM',
                            'snippet': f"{attr}={value}"
                        })
        
        return findings

    def analyze_links_and_urls(self, soup, base_url):
        """Анализ ссылок и URL параметров"""
        findings = []
        
        for link in soup.find_all(['a', 'link', 'script'], href=True):
            href = link['href']
            full_url = urljoin(base_url, href)
            parsed = urlparse(full_url)
            
            for param in parse_qs(parsed.query):
                if self.is_suspicious_param(param):
                    findings.append({
                        'type': 'URL Parameter',
                        'value': param,
                        'risk': 'MEDIUM',
                        'snippet': f"{full_url.split('?')[0]}?{param}=..."
                    })
        
        return findings

    def brute_force_parameters(self, base_url):
        """Fuzzing скрытых параметров"""
        common_params, _, _ = self.load_wordlists()
        test_values = ['1', 'test', 'true', 'admin']
        
        findings = []
        base_parsed = urlparse(base_url)
        
        for param in common_params[:20]:  
            for value in test_values:
                test_url = f"{base_parsed.scheme}://{base_parsed.netloc}{base_parsed.path}?{param}={value}"
                
                try:
                    resp = self.session.get(test_url, timeout=8, allow_redirects=True)
                    
                    
                    if resp.status_code not in [404, 405] and len(resp.content) > 100:
                        findings.append({
                            'type': 'Brute Forced Param',
                            'value': f"{param}={value}",
                            'risk': 'HIGH',
                            'snippet': test_url,
                            'response_size': len(resp.content),
                            'status': resp.status_code
                        })
                    time.sleep(0.2)
                except Exception:
                    continue
        
        return findings

    def scan_config_files(self, base_url, config_files):
        """Сканирование конфигурационных файлов"""
        for filepath in config_files:
            test_url = urljoin(base_url, filepath)
            
            try:
                resp = self.session.get(test_url, timeout=7, allow_redirects=False)
                
                if resp.status_code == 200:
                    content_preview = resp.text[:200]
                    
                    
                    secrets_found = re.findall(r'(password|secret|key|token)[:=]\s*["\']?([^"\',\s]+)', 
                                            content_preview, re.IGNORECASE)
                    
                    risk = 'CRITICAL' if secrets_found else 'HIGH'
                    
                    self.exposed_files.append({
                        'url': test_url,
                        'size': len(resp.content),
                        'risk': risk,
                        'secrets': secrets_found,
                        'preview': content_preview[:100]
                    })
                    
            except Exception:
                continue

    def assess_risk(self, content):
        """Оценка уровня риска"""
        sensitive_keywords = ['secret', 'token', 'password', 'key', 'pass', 'auth']
        score = sum(1 for keyword in sensitive_keywords if keyword in content.lower())
        
        if score >= 2: return 'CRITICAL'
        if score == 1: return 'HIGH'
        if len(content) > 50: return 'MEDIUM'
        return 'LOW'

    def is_suspicious_param(self, param):
        """Проверка подозрительного параметра"""
        common_params, _, _ = self.load_wordlists()
        return param.lower() in [p.lower() for p in common_params]

    def is_sensitive_keyword(self, text):
        """Проверка чувствительных ключевых слов"""
        sensitive_keywords, _, _ = self.load_wordlists()
        return any(kw in text.lower() for kw in sensitive_keywords)

    def assess_input_risk(self, name, value):
        """Оценка риска input поля"""
        if self.is_sensitive_keyword(name):
            return 'HIGH'
        if len(value) > 20:
            return 'MEDIUM'
        return 'LOW'

    def scan(self, target):
        """Основной процесс сканирования"""
        self.banner()
        
        valid, error = self.validate_target(target)
        if not error:
            print(f"{Fore.RED}{error}{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[✓] Сканируем: {target}{Style.RESET_ALL}")
        
        try:
            resp = self.session.get(target, timeout=15, allow_redirects=True)
            soup = BeautifulSoup(resp.text, 'html.parser')
            
            print(f"{Fore.GREEN}[✓] HTML размер: {len(resp.content):,} байт{Style.RESET_ALL}")
            
            
            print(f"\n{Fore.CYAN}{'=' * 90}")
            print(f"{Fore.CYAN}🔍 НАЧИНАЕМ МНОГОУРОВНЕВЫЙ АНАЛИЗ{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 90}")
            
           
            html_findings = self.analyze_html_source(resp.text)
            self.findings.extend(html_findings)
            
            
            dom_findings = self.analyze_dom_attributes(soup)
            self.findings.extend(dom_findings)
            
           
            form_findings = self.analyze_forms(soup)
            self.findings.extend(form_findings)
            
           
            link_findings = self.analyze_links_and_urls(soup, resp.url)
            self.findings.extend(link_findings)
            
            
            print(f"\n{Fore.YELLOW}[⏳] Fuzzing параметров...{Style.RESET_ALL}")
            fuzz_findings = self.brute_force_parameters(resp.url)
            self.findings.extend(fuzz_findings)
            
            
            print(f"{Fore.YELLOW}[⏳] Проверка конфигов...{Style.RESET_ALL}")
            _, _, config_files = self.load_wordlists()
            self.scan_config_files(resp.url, config_files)
            
            self.print_report()
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[!] Ошибка сканирования: {e}{Style.RESET_ALL}")
            return False

    def truncate(self, text, length):
        """Умная обрезка текста"""
        if len(text) <= length:
            return text
        half = length // 2
        return f"{text[:half]}...{text[-half:]}"

    def print_report(self):
        """Детальный отчёт"""
        risk_levels = Counter(f['risk'] for f in self.findings)
        
        print(f"\n{Fore.CYAN}{'═' * 90}")
        print(f"{Fore.CYAN}{' ' * 36}📊 ПОЛНЫЙ ОТЧЁТ{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'═' * 90}")
        
        print(f"{Fore.CYAN}Статистика:{Style.RESET_ALL}")
        print(f"  {Fore.RED}🔴 Критично: {risk_levels['CRITICAL']:>2}  {Fore.RED}🟡 Высокий: {risk_levels['HIGH']:>2}")
        print(f"  {Fore.YELLOW}🟠 Средний: {risk_levels['MEDIUM']:>2}  {Fore.GREEN}🟢 Низкий: {risk_levels['LOW']:>2}")
        print(f"  📊 Всего: {len(self.findings):>2} | 📁 Конфиги: {len(self.exposed_files):>2}")
        
        print(f"\n{Fore.MAGENTA}{'═' * 90}")
        print(f"{Fore.MAGENTA}🎯 КРИТИЧЕСКИЕ НАХОДКИ (CRITICAL/HIGH){Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'═' * 90}")
        
        critical_findings = [f for f in self.findings if f['risk'] in ['CRITICAL', 'HIGH']]
        for i, finding in enumerate(critical_findings, 1):
            marker = Fore.RED + "🚨 CRITICAL" + Style.RESET_ALL if finding['risk'] == 'CRITICAL' else Fore.MAGENTA + "⚠️ HIGH" + Style.RESET_ALL
            print(f"{Fore.CYAN}{i:2d}.{Style.RESET_ALL} {marker} {finding['type']:<20} {finding['value']}")
        
        if self.exposed_files:
            print(f"\n{Fore.RED}{'═' * 90}")
            print(f"{Fore.RED}💾 ОТКРЫТЫЕ КОНФИГУРАЦИОННЫЕ ФАЙЛЫ{Style.RESET_ALL}")
            print(f"{Fore.RED}{'═' * 90}")
            for file in self.exposed_files:
                print(f"{Fore.RED}[!] {file['url']} ({file['size']:,}B) - {file['risk']}{Style.RESET_ALL}")
                if file.get('secrets'):
                    print(f"     Secrets: {file['secrets']}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description='Профессиональный сканер скрытых параметров')
    parser.add_argument('target', nargs='?', help='Целевой URL')
    parser.add_argument('-u', '--url', dest='target', help='Целевой URL')
    args = parser.parse_args()
    
    target = args.target
    if not target:
        target = input(f"{Fore.YELLOW}[+] Введите URL: {Style.RESET_ALL}").strip()
    
    scanner = HiddenParamsScanner()
    scanner.scan(target)

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    main()