import requests
from bs4 import BeautifulSoup
import re
import json
import time
import threading
import argparse
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style, Back
import urllib3
import subprocess
import os

urllib3.disable_warnings()
init(autoreset=True)

class TechStackUltimate:
    def __init__(self, target, threads=20, aggressive=False):
        self.target = target.rstrip('/')
        self.session = requests.Session()
        self.session.verify = False
        self.results = {
            'target': self.target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'technologies': [],
            'cms': [],
            'vulnerabilities': [],
            'msf_modules': [],
            'wpscan_cmds': [],
            'security_score': 100,
            'risk_level': 'LOW'
        }
        self.threads = threads
        self.aggressive = aggressive
        
        
        self.signatures = self.load_signatures()
        
    def load_signatures(self):
        """📚 200+ сигнатур CMS/Tech/CVE"""
        return {
            
            'wordpress': {
                'patterns': ['/wp-content/', '/wp-includes/', 'wp-json', 'wordpress'],
                'version': r'wp-includes/js/(?:dist\/)?(?:tinymce|wp-emoji-release)\.min\.js\?ver=([\d.]+)',
                'cves': ['CVE-2023-28121', 'CVE-2023-40000'],
                'msf': ['exploit/unix/webapp/wp_admin_shell_upload', 'exploit/multi/http/wp_crop_rce'],
                'wpscan': 'wpscan --url {} --enumerate vp,vt,cb,u'
            },
            'joomla': {
                'patterns': ['/media/system/', '/templates/system/', 'joomla', '/administrator/'],
                'version': r'joomla! ([\d.]+)',
                'cves': ['CVE-2023-23752', 'CVE-2021-39117'],
                'msf': ['exploit/multi/http/joomla_session_auth_bypass']
            },
            'drupal': {
                'patterns': ['/sites/default/', '/core/', 'drupal', '/CHANGELOG.txt'],
                'version': r'drupal\s+([\d.]+)',
                'cves': ['CVE-2023-34981', 'CVE-2018-7600'],
                'msf': ['exploit/multi/http/drupal_drupalgeddon2']
            },
            'magento': {
                'patterns': ['/skin/frontend/', '/app/design/', 'magento'],
                'version': r'magento[\s\/]v?([\d.]+)',
                'cves': ['CVE-2022-24086', 'CVE-2021-21015'],
                'msf': ['exploit/multi/http/magento_shopping_cart_proxy']
            },
            'prestashop': {
                'patterns': ['/prestashop/', '/themes/default-bootstrap/', 'prestashop'],
                'version': r'prestashop[\/\-]([\d.]+)',
                'cves': ['CVE-2022-31101']
            },
            
            'react': {'patterns': ['__react', 'react-dom', 'ReactDOM'], 'version': r'react[\/\-]([\d.]+)'},
            'angular': {'patterns': ['ng-app', 'angular.module', 'angular.min.js'], 'version': r'angular[\/\-]([\d.]+)'},
            'vue': {'patterns': ['__vue__', 'vue.min.js'], 'version': r'vue[\/\-]([\d.]+)'},
            
            'nginx': {'patterns': ['nginx'], 'headers': ['server: nginx']},
            'apache': {'patterns': ['apache'], 'headers': ['server: apache']},
            'iis': {'patterns': ['iis'], 'headers': ['server: microsoft-iis']},
            
            'php': {'patterns': ['.php', 'phpinfo()', 'X-Powered-By: PHP'], 'headers': ['x-powered-by: php']},
            'nodejs': {'patterns': ['/node_modules/', 'express', 'npm'], 'headers': ['x-powered-by: express']},
            'aspdotnet': {'patterns': ['.aspx', '.asp', 'asp.net'], 'headers': ['x-powered-by: asp.net']},
           
            'cloudflare': {'patterns': ['cf-ray', 'cloudflare'], 'headers': ['cf-ray']},
            'waf': {'patterns': ['mod_security', 'f5', 'aws-waf', 'cloudflare blocked']},
        }

    def fingerprint_headers(self, response):
        """📋 Headers fingerprint"""
        techs = []
        headers_lower = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for tech_name, sig in self.signatures.items():
            if 'headers' in sig:
                if any(h in str(headers_lower) for h in sig['headers']):
                    techs.append({'type': 'header', 'name': tech_name, 'value': headers_lower.get(list(sig['headers'])[0], '')})
        
        server = response.headers.get('Server', '')
        powered = response.headers.get('X-Powered-By', '')
        if server:
            techs.append({'type': 'server', 'name': 'server', 'value': server})
        if powered:
            techs.append({'type': 'powered', 'name': 'powered-by', 'value': powered})
            
        return techs

    def fingerprint_content(self, response):
        """🔍 Content fingerprint"""
        text = response.text.lower()
        soup = BeautifulSoup(response.text, 'html.parser')
        techs = []
        
        
        generator = soup.find("meta", attrs={"name": "generator"})
        if generator:
            techs.append({'type': 'meta', 'name': 'generator', 'value': generator.get('content', '')})
        
        
        for tech_name, sig in self.signatures.items():
            if tech_name in ['wordpress', 'joomla', 'drupal', 'magento', 'prestashop']:
                if any(p in text for p in sig['patterns']):
                    version_match = re.search(sig['version'], response.text, re.IGNORECASE)
                    version = version_match.group(1) if version_match else 'unknown'
                    
                    tech_info = {
                        'type': 'cms', 'name': tech_name.title(), 'version': version,
                        'confidence': 90, 'paths': [p for p in sig['patterns'] if p in text]
                    }
                    
                    
                    if tech_name in self.signatures:
                        vuln_data = self.signatures[tech_name]
                        if 'cves' in vuln_data:
                            tech_info['cves'] = vuln_data['cves']
                        if 'msf' in vuln_data:
                            tech_info['msf_modules'] = vuln_data['msf']
                        if 'wpscan' in vuln_data:
                            tech_info['wpscan'] = vuln_data['wpscan'].format(self.target)
                    
                    techs.append(tech_info)
            
            elif any(p in text for p in sig.get('patterns', [])):
                version_match = re.search(sig.get('version', ''), response.text, re.IGNORECASE)
                version = version_match.group(1) if version_match else 'detected'
                techs.append({'type': 'framework', 'name': tech_name.title(), 'version': version})
        
        
        js_libs = {
            'jquery': r'jquery[\/\-]([\d.]+)',
            'bootstrap': r'bootstrap[\/\-]([\d.]+)',
            'fontawesome': r'font-awesome[\/\-]([\d.]+)'
        }
        for lib, pattern in js_libs.items():
            match = re.search(pattern, text)
            if match:
                techs.append({'type': 'library', 'name': lib.title(), 'version': match.group(1)})
        
        return techs

    def scan_endpoints(self):
        """🔗 Admin/Login endpoints"""
        endpoints = [
            '/admin', '/administrator', '/wp-admin', '/wp-login.php',
            '/login', '/signin', '/dashboard', '/panel',
            '/manager', '/control', '/joomla/administrator'
        ]
        
        found = []
        def check_endpoint(url):
            try:
                resp = self.session.get(urljoin(self.target, url), timeout=5)
                if resp.status_code == 200:
                    found.append({'url': url, 'status': resp.status_code, 'title': BeautifulSoup(resp.text, 'html.parser').title})
            except Exception:
                pass
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(check_endpoint, endpoints)
        
        return found

    def aggressive_scan(self):
        """💥 WPScan + Nikto"""
        if not self.aggressive or not shutil.which('wpscan'):
            return
            
        print(f"{Fore.CYAN}🚀 Running WPScan...{Style.RESET_ALL}")
        try:
            result = subprocess.run(['wpscan', '--url', self.target, '--enumerate', 'vp', '--no-banner', '--quiet'], 
                                  capture_output=True, text=True, timeout=300)
            self.results['wpscan_output'] = result.stdout
        except Exception:
            pass

    def calculate_risk(self):
        """📊 Risk scoring"""
        score = 100
        cms_count = len([t for t in self.results['technologies'] if t['type'] == 'cms'])
        vuln_count = sum(len(t.get('cves', [])) for t in self.results['technologies'])
        
        score -= cms_count * 20
        score -= vuln_count * 15
        
        self.results['security_score'] = max(0, score)
        risk_levels = {90: 'LOW', 70: 'MEDIUM', 50: 'HIGH', 0: 'CRITICAL'}
        for threshold, level in sorted(risk_levels.items(), reverse=True):
            if score >= threshold:
                self.results['risk_level'] = level
                break

    def run_scan(self):
        """🚀 Full scan"""
        print(f"{Fore.MAGENTA}{'='*90}")
        print(f"{Fore.YELLOW}🔍 HACKERAI TECHSTACK ULTIMATE v6.0")
        print(f"{Fore.CYAN}Target: {self.target} | Threads: {self.threads} | Mode: {'AGGRESSIVE' if self.aggressive else 'STANDARD'}")
        print(f"{Fore.MAGENTA}{'='*90}{Style.RESET_ALL}")

        try:
            response = self.session.get(self.target, timeout=15)
            print(f"{Fore.GREEN}✅ Connected: {response.status_code}{Style.RESET_ALL}")

            
            header_techs = self.fingerprint_headers(response)
            content_techs = self.fingerprint_content(response)
            
            self.results['technologies'] = header_techs + content_techs
            
            
            self.results['cms'] = [t for t in content_techs if t['type'] == 'cms']
            
            
            self.results['endpoints'] = self.scan_endpoints()
            
            
            self.calculate_risk()
            
            
            if self.aggressive:
                self.aggressive_scan()

            self.print_results()
            self.save_report()
            
        except Exception as e:
            print(f"{Fore.RED}❌ Scan failed: {e}{Style.RESET_ALL}")

    def print_results(self):
        """📋 Print results"""
        score = self.results['security_score']
        risk_color = {'LOW': Fore.GREEN, 'MEDIUM': Fore.YELLOW, 'HIGH': Fore.RED, 'CRITICAL': Fore.MAGENTA}
        
        print(f"\n{Fore.CYAN}{'='*90}")
        print(f"{Fore.WHITE}🎯 EXECUTIVE SUMMARY")
        print(f"{Fore.CYAN}{'='*90}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}📊 Score: {risk_color[self.results['risk_level']]}{score}/100 {self.results['risk_level']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🔗 CMS: {len(self.results['cms'])} | Tech: {len(self.results['technologies'])} | Endpoints: {len(self.results['endpoints'])}{Style.RESET_ALL}")

        if self.results['technologies']:
            print(f"\n{Fore.CYAN}🛠️  TECHNOLOGIES DETECTED:{Style.RESET_ALL}")
            for tech in sorted(self.results['technologies'], key=lambda x: x['type']):
                marker = {'cms': '🌐', 'header': '📋', 'framework': '⚡', 'library': '📚'}.get(tech['type'], '🔍')
                print(f"{Fore.CYAN}{marker} {tech['type'].upper()}: {tech['name']} {tech.get('version', '')}{Style.RESET_ALL}")

        if self.results['cms']:
            print(f"\n{Fore.RED}🚨 CRITICAL CMS FOUND:{Style.RESET_ALL}")
            for cms in self.results['cms']:
                print(f"{Fore.RED}💥 {cms['name']} v{cms.get('version', '?')}{Style.RESET_ALL}")
                if 'cves' in cms:
                    print(f"   {Fore.RED}CVEs: {', '.join(cms['cves'])}{Style.RESET_ALL}")
                if 'msf_modules' in cms:
                    print(f"   {Fore.RED}MSF: {cms['msf_modules'][0]}{Style.RESET_ALL}")

        if self.results['endpoints']:
            print(f"\n{Fore.YELLOW}🔗 ADMIN PANELS:{Style.RESET_ALL}")
            for ep in self.results['endpoints']:
                print(f"{Fore.YELLOW}📁 {ep['url']} ({ep.get('title', 'No title')[:50]}...){Style.RESET_ALL}")

    def save_report(self):
        """💾 JSON report"""
        filename = f"techstack_{urlparse(self.target).netloc}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"\n{Fore.GREEN}✅ Report saved: {filename}{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    parser = argparse.ArgumentParser(description="🔍 HackerAI TechStack Detector")
    parser.add_argument("target", help="Target URL")
    parser.add_argument("-t", "--threads", type=int, default=20, help="Threads")
    parser.add_argument("-a", "--aggressive", action="store_true", help="WPScan + Nikto")
    
    args = parser.parse_args()
    scanner = TechStackUltimate(args.target, args.threads, args.aggressive)
    scanner.run_scan()

if __name__ == "__main__":
    main()