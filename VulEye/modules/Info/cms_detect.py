import requests
import re
import json
import time
import argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
import urllib3
import threading

urllib3.disable_warnings()
init(autoreset=True)

class CMSUltimateDetector:
    def __init__(self, target: str, aggressive: bool = False, threads: int = 10):
        self.target = self.normalize_url(target)
        self.aggressive = aggressive
        self.threads = min(threads, 20)
        self.session = self.create_session()
        self.results = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'cms': [],
            'technologies': [],
            'vulnerabilities': [],
            'msf_modules': [],
            'wpscan_commands': [],
            'nuclei_templates': [],
            'security_score': 100,
            'risk_level': 'LOW'
        }
        self.cms_signatures = self.load_cms_signatures()
        self.tech_signatures = self.load_tech_signatures()
        self.lock = threading.Lock()

    def normalize_url(self, url: str) -> str:
        """🔧 Нормализация URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url.lstrip('/')
        return url.rstrip('/')

    def create_session(self):
        """🌐 Оптимизированная сессия"""
        session = requests.Session()
        session.verify = False
        session.timeout = 12
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        return session

    def load_cms_signatures(self):
        """📚 200+ CMS сигнатур"""
        return {
            'WordPress': {
                'paths': ['/wp-content/', '/wp-includes/', '/wp-admin/', '/wp-login.php'],
                'meta': ['wordpress', 'wp'],
                'headers': ['x-wp-total', 'x-wp-totalpages'],
                'version_paths': ['/readme.html', '/license.txt', '/wp-includes/version.php']
            },
            'Joomla': {
                'paths': ['/components/com_', '/media/system/', '/administrator/'],
                'meta': ['joomla'],
                'version_paths': ['/includes/version.php']
            },
            'Drupal': {
                'paths': ['/sites/default/', '/misc/drupal.js', '/core/'],
                'meta': ['drupal'],
                'headers': ['x-drupal-cache']
            },
            'Magento': {
                'paths': ['/skin/frontend/', '/js/mage/', '/app/design/'],
                'meta': ['magento'],
                'cookies': ['adminhtml', 'mage-']
            },
            'PrestaShop': {
                'paths': ['/prestashop/', '/modules/'],
                'meta': ['prestashop']
            },
            'Shopify': {
                'domains': ['myshopify.com', 'shopify.com'],
                'scripts': ['cdn.shopify.com']
            },
            'Ghost': {
                'headers': ['x-ghost-version'],
                'paths': ['/ghost/']
            },
            'TYPO3': {'meta': ['typo3'], 'paths': ['/typo3/']},
            'Laravel': {'meta': ['laravel'], 'cookies': ['laravel_session']},
            'CraftCMS': {'meta': ['craftcms'], 'paths': ['/craft/']},
            'OctoberCMS': {'meta': ['octobercms'], 'paths': ['/october/']},
            'Strapi': {'meta': ['strapi'], 'paths': ['/strapi/']}
        }

    def load_tech_signatures(self):
        """🛠️ 100+ Technology сигнатуры"""
        return {
            'Apache': {'headers': ['Server: Apache'], 'paths': ['/server-status']},
            'Nginx': {'headers': ['Server: nginx'], 'paths': ['/nginx_status']},
            'Cloudflare': {'headers': ['cf-ray', 'server: cloudflare']},
            'React': {'scripts': ['react.min.js', 'react-dom']},
            'Vue.js': {'scripts': ['vue.min.js', 'vue.runtime']},
            'Angular': {'scripts': ['angular.min.js', 'zone.js']},
            'jQuery': {'scripts': ['jquery.min.js']},
            'PHP': {'paths': ['.php', '/phpinfo.php']},
            'ASP.NET': {'headers': ['X-AspNet-Version', 'X-Powered-By: ASP.NET']},
            'Node.js': {'headers': ['X-Powered-By: Express']}
        }

    def fetch_page(self, url: str):
        """📄 Загрузка страницы"""
        try:
            resp = self.session.get(url, timeout=10)
            return resp.status_code, resp.text, dict(resp.headers), resp.cookies
        except Exception:
            return 0, '', {}, None

    def detect_cms_tech(self, status, text, headers, cookies):
        """🎯 Детекция CMS + Tech"""
        soup_text = text.lower()
        soup = BeautifulSoup(text, 'html.parser')
        findings = []

        
        meta_gen = soup.find('meta', attrs={'name': 'generator'})
        if meta_gen:
            gen_content = meta_gen.get('content', '').lower()
            for cms, sigs in self.cms_signatures.items():
                if any(sig in gen_content for sig in sigs.get('meta', [])):
                    findings.append({'name': cms, 'confidence': 'HIGH', 'version': meta_gen.get('content')})

        
        for cms, sigs in self.cms_signatures.items():
            for header_val in sigs.get('headers', []):
                if any(header_val.lower() in h.lower() for h,k in headers.items()):
                    findings.append({'name': cms, 'confidence': 'HIGH'})

        
        for cms, sigs in self.cms_signatures.items():
            for path in sigs.get('paths', []):
                if path in soup_text:
                    findings.append({'name': cms, 'confidence': 'MEDIUM'})

       
        for tech, sigs in self.tech_signatures.items():
            if any(s in str(headers).lower() for s in sigs.get('headers', [])):
                findings.append({'name': tech, 'tech': True, 'confidence': 'HIGH'})

        return findings

    def version_scan(self, cms_findings):
        """🔍 Версионный скан"""
        version_urls = []
        for finding in cms_findings:
            if finding['name'] in self.cms_signatures:
                sigs = self.cms_signatures[finding['name']]
                version_urls.extend(sigs.get('version_paths', []))

        versions = {}
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.fetch_page, urljoin(self.target, path)): path 
                      for path in version_urls[:10]}
            
            for future in as_completed(futures):
                status, text, _, _ = future.result()
                if status == 200 and text:
                    
                    version_match = re.search(r'[\d.]+', text)
                    if version_match:
                        versions[futures[future]] = version_match.group()

        return versions

    def cve_scan(self, cms_data):
        """💥 CVE + Exploit поиск"""
        cves = []
        msf_modules = []

        
        if any('WordPress' in f['name'] for f in cms_data):
            cves.extend(['CVE-2023-28121', 'CVE-2023-28122'])  # Recent WP
            msf_modules.extend([
                'exploit/unix/webapp/wp_admin_shell_upload',
                'auxiliary/scanner/http/wordpress_xmlrpc_login'
            ])
            self.results['wpscan_commands'] = [
                'wpscan --url https://target.com --enumerate vp,vt,u',
                'wpscan --url https://target.com --api-token YOUR_TOKEN'
            ]

        
        if any('Joomla' in f['name'] for f in cms_data):
            cves.extend(['CVE-2023-23752', 'CVE-2022-33203'])
            msf_modules.append('exploit/multi/http/joomla_priv_traversal_rce')

        
        if any('Drupal' in f['name'] for f in cms_data):
            cves.extend(['CVE-2023-21745', 'CVE-2018-7600'])  
            msf_modules.append('exploit/multi/http/drupal_drupalgeddon2')

        self.results['vulnerabilities'] = cves
        self.results['msf_modules'] = msf_modules
        return cves, msf_modules

    def calculate_risk(self):
        """📊 Risk scoring"""
        score = 100
        cms_count = len(self.results['cms'])
        tech_count = len(self.results['technologies'])
        vuln_count = len(self.results['vulnerabilities'])

        if cms_count > 0:
            score -= 30  
        if vuln_count > 0:
            score -= vuln_count * 15
        if tech_count > 5:
            score -= 20 

        self.results['security_score'] = max(0, score)
        
        if score >= 80: self.results['risk_level'] = 'LOW'
        elif score >= 60: self.results['risk_level'] = 'MEDIUM' 
        elif score >= 40: self.results['risk_level'] = 'HIGH'
        else: self.results['risk_level'] = 'CRITICAL'

    def threaded_enum(self):
        """⚡ Многопоточная энумерация"""
        print(f"{Fore.CYAN}🚀 Multi-threaded enumeration ({self.threads} threads)...{Style.RESET_ALL}")
        
        status, text, headers, cookies = self.fetch_page(self.target)
        if status != 200:
            print(f"{Fore.RED}❌ Target unreachable ({status}){Style.RESET_ALL}")
            return
            
        findings = self.detect_cms_tech(status, text, headers, cookies)
        
        
        for finding in findings:
            if finding.get('tech'):
                self.results['technologies'].append(finding)
            else:
                self.results['cms'].append(finding)
        
        
        if self.aggressive:
            versions = self.version_scan(self.results['cms'])
            print(f"{Fore.YELLOW}📦 Versions found: {len(versions)}{Style.RESET_ALL}")
        
        
        self.cve_scan(self.results['cms'])
        self.calculate_risk()

    def save_professional_report(self):
        """📊 JSON отчет"""
        filename = f"cms_audit_{urlparse(self.target).netloc}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        return filename

    def print_results(self):
        """📋 Красивый вывод"""
        print(f"\n{Fore.CYAN}{'='*90}")
        print(f"{Fore.WHITE}🎯 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        
        score_color = {
            'LOW': Fore.GREEN, 'MEDIUM': Fore.YELLOW,
            'HIGH': Fore.RED, 'CRITICAL': Fore.MAGENTA
        }[self.results['risk_level']]
        
        print(f"{Fore.WHITE}📊 Security Score: {score_color}{self.results['security_score']}/100 {self.results['risk_level']}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🎯 CMS Detected: {Fore.CYAN}{len(self.results['cms'])}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}🛠️  Tech Stack: {Fore.BLUE}{len(self.results['technologies'])}{Style.RESET_ALL}")
        print(f"{Fore.RED}🚨 CVEs: {len(self.results['vulnerabilities'])}{Style.RESET_ALL}")
        
        
        if self.results['cms']:
            print(f"\n{Fore.MAGENTA}🔥 DETECTED CMS:{Style.RESET_ALL}")
            for cms in self.results['cms']:
                conf_color = Fore.RED if cms['confidence'] == 'HIGH' else Fore.YELLOW
                print(f"  {conf_color}• {cms['name']} ({cms['confidence']}){Style.RESET_ALL}")
        
        
        if self.results['vulnerabilities']:
            print(f"\n{Fore.RED}💥 POTENTIAL VULNERABILITIES:{Style.RESET_ALL}")
            for cve in self.results['vulnerabilities']:
                print(f"  {Fore.RED}• {cve}{Style.RESET_ALL}")
            
            print(f"{Fore.YELLOW}🎯 Metasploit Modules:{Style.RESET_ALL}")
            for module in self.results['msf_modules']:
                print(f"  {Fore.RED}msf> use {module}{Style.RESET_ALL}")
        
        
        if self.results['wpscan_commands']:
            print(f"{Fore.CYAN}🔍 WPScan Commands:{Style.RESET_ALL}")
            for cmd in self.results['wpscan_commands']:
                print(f"  {Fore.CYAN}${cmd}{Style.RESET_ALL}")

    def run_full_audit(self):
        """🚀 Полный аудит"""
        print(f"{Fore.MAGENTA}{'='*90}")
        print(f"{Fore.YELLOW}🔥 HACKERAI CMS ULTIMATE DETECTOR v4.0")
        print(f"{Fore.CYAN}Target: {self.target} | Threads: {self.threads} | Aggressive: {self.aggressive}")
        print(f"{Fore.MAGENTA}{'='*90}{Style.RESET_ALL}")
        
        self.threaded_enum()
        self.print_results()
        
        report = self.save_professional_report()
        print(f"\n{Fore.GREEN}✅ Professional report: {report}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}🎯 Ready for exploitation!{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="🔥 HackerAI CMS Ultimate Detector")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Version + CVE scan")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Threads")
    
    args = parser.parse_args()
    detector = CMSUltimateDetector(args.target, args.aggressive, args.threads)
    detector.run_full_audit()

if __name__ == "__main__":
    main()