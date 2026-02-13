import socket
import sys
import time
import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from colorama import init, Fore, Style, Back
import nmap
import requests
from urllib.parse import urlparse
import shutil

init(autoreset=True)

class UltimatePortScanner:
    def __init__(self, target, threads=500, timeout=0.5, aggressive=False):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.aggressive = aggressive
        self.results = {
            'target': target,
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'open_ports': [],
            'services': {},
            'vulnerabilities': [],
            'msf_modules': [],
            'nmap_scripts': [],
            'security_score': 100,
            'risk_assessment': [],
            'scan_duration': 0
        }
        self.port_db = self.load_port_database()
        self.version_results = {}
        
    def load_port_database(self):
        """📚 Расширенная база портов + CVE + MSF"""
        return {
            
            21: {'service': 'FTP', 'cves': ['CVE-2010-2730', 'CVE-1999-0256'], 'msf': ['exploit/unix/ftp/vsftpd_234_backdoor']},
            22: {'service': 'SSH', 'cves': ['CVE-2008-5161', 'CVE-2016-0777'], 'msf': ['auxiliary/scanner/ssh/ssh_version', 'exploit/multi/ssh/sshexec']},
            23: {'service': 'Telnet', 'cves': ['CVE-1999-0619'], 'msf': ['auxiliary/scanner/telnet/telnet_version']},
            25: {'service': 'SMTP', 'cves': ['CVE-2020-7247'], 'msf': ['auxiliary/scanner/smtp/smtp_version']},
            53: {'service': 'DNS', 'cves': ['CVE-2008-1447'], 'msf': ['auxiliary/scanner/dns/dns_version']},
            
            
            80: {'service': 'HTTP', 'cves': ['CVE-2014-6271'], 'msf': ['auxiliary/scanner/http/http_version', 'exploit/multi/http/tomcat_mgr_deploy']},
            443: {'service': 'HTTPS', 'cves': ['Heartbleed CVE-2014-0160'], 'msf': ['auxiliary/scanner/ssl/openssl_heartbleed']},
            8080: {'service': 'HTTP-Proxy', 'cves': [], 'msf': ['auxiliary/scanner/http/http_version']},
            8443: {'service': 'HTTPS-Alt', 'cves': [], 'msf': ['auxiliary/scanner/http/http_version']},
            
            
            3306: {'service': 'MySQL', 'cves': ['CVE-2012-5612'], 'msf': ['auxiliary/scanner/mysql/mysql_login']},
            5432: {'service': 'PostgreSQL', 'cves': ['CVE-2018-1058'], 'msf': ['auxiliary/scanner/postgres/postgres_login']},
            1433: {'service': 'MSSQL', 'cves': ['CVE-2017-0144'], 'msf': ['auxiliary/scanner/mssql/mssql_login']},
            1521: {'service': 'Oracle', 'cves': ['CVE-2012-1675'], 'msf': ['auxiliary/scanner/oracle/oracle_login']},
            27017: {'service': 'MongoDB', 'cves': ['CVE-2013-1892'], 'msf': ['auxiliary/scanner/mongodb/mongodb_login']},
            6379: {'service': 'Redis', 'cves': ['CVE-2022-0543'], 'msf': ['auxiliary/scanner/redis/redis_server']},
            9200: {'service': 'Elasticsearch', 'cves': ['CVE-2015-1427'], 'msf': ['exploit/multi/elasticsearch/script_mvel_rce']},
            
            
            135: {'service': 'MSRPC', 'cves': ['CVE-2017-0144'], 'msf': ['auxiliary/scanner/dcerpc/endpoint_mapper']},
            139: {'service': 'NetBIOS', 'cves': ['CVE-2017-0144'], 'msf': ['exploit/windows/smb/ms17_010_eternalblue']},
            445: {'service': 'SMB', 'cves': ['CVE-2017-0144', 'CVE-2020-0796'], 'msf': ['exploit/windows/smb/ms17_010_eternalblue']},
            3389: {'service': 'RDP', 'cves': ['CVE-2019-0708'], 'msf': ['auxiliary/scanner/rdp/rdp_scanner']},
            
            
            5900: {'service': 'VNC', 'cves': ['CVE-2019-17662'], 'msf': ['auxiliary/scanner/vnc/vnc_none_auth']},
            161: {'service': 'SNMP', 'cves': [], 'msf': ['auxiliary/scanner/snmp/snmp_enum']},
        }

    def banner_grab(self, ip, port):
        """🔍 Service version detection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, port))
            
            
            probes = {
                21: b"HELP\r\n", 22: b"SSH-2.0-Test\r\n", 23: b"\xff\xfd\x01",
                25: b"EHLO test\r\n", 53: b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
                80: b"GET / HTTP/1.0\r\n\r\n", 443: b"GET / HTTP/1.0\r\n\r\n",
                3306: b"\x0d\x00\x00\x01\x0a\x31\x2e\x30\x2e\x30",  
                11211: b"\x80\x01\x01\x00\x00\x00\x01"  
            }
            
            probe = probes.get(port, b"\r\n")
            sock.send(probe)
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                return banner[:100] 
        except:
            pass
        return None

    def nmap_service_scan(self, port):
        """🛠️ Nmap service + vuln scan"""
        if not self.aggressive:
            return None
            
        try:
            nm = nmap.PortScanner()
            nm.scan(self.target, str(port), arguments='--script=banner,vuln,version')
            if self.target in nm.all_hosts():
                host = nm[self.target]
                if str(port) in host['tcp']:
                    scripts = host['tcp'][str(port)].get('script', {})
                    return {
                        'scripts': scripts,
                        'service': host['tcp'][str(port)].get('name', 'unknown'),
                        'product': host['tcp'][str(port)].get('product', ''),
                        'version': host['tcp'][str(port)].get('version', '')
                    }
        except:
            pass
        return None

    def scan_port_advanced(self, ip, port):
        """🚀 Advanced port scan + version + CVE"""
        try:
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                port_info = self.port_db.get(port, {'service': f'Unknown-{port}', 'cves': [], 'msf': []})
                
                
                banner = self.banner_grab(ip, port)
                
                
                nmap_info = self.nmap_service_scan(port) if self.aggressive else None
                
                return {
                    'port': port,
                    'status': 'OPEN',
                    'service': port_info['service'],
                    'banner': banner,
                    'cves': port_info['cves'],
                    'msf_modules': port_info['msf'],
                    'nmap': nmap_info,
                    'risk': self.assess_port_risk(port, banner, nmap_info)
                }
        except:
            pass
        return None

    def assess_port_risk(self, port, banner, nmap_info):
        """🎯 Risk assessment + attack paths"""
        risk_score = 0
        recommendations = []
        
        
        critical_services = [21, 23, 135, 139, 445, 6379, 11211]
        if port in critical_services:
            risk_score += 80
            recommendations.append("CRITICAL SERVICE - IMMEDIATE ATTENTION REQUIRED")
        
        web_ports = [80, 443, 8080, 8443, 3000, 5000]
        if port in web_ports:
            risk_score += 60
            recommendations.append("WEB SERVICE - Run full web app scan (SQLi/XSS/LFI)")
        
        db_ports = [3306, 5432, 1433, 1521, 27017, 6379]
        if port in db_ports:
            risk_score += 70
            recommendations.append("DATABASE - Test default creds + unauthenticated access")
            
        
        if banner:
            if any(x in banner.lower() for x in ['vsftpd 2.3.4', 'openbsd ftpd', 'proftpd']):
                risk_score += 30
                recommendations.append("FTP - Known backdoor/vuln versions detected")
            if 'ssh' in banner.lower() and 'openssh' in banner.lower():
                risk_score += 20
                recommendations.append("SSH - Extract version for targeted exploits")
            if 'mysql' in banner.lower() or 'mariadb' in banner.lower():
                risk_score += 40
                recommendations.append("MySQL - Test weak root password")
            if 'redis' in banner.lower():
                risk_score += 90
                recommendations.append("REDIS - Likely unauthenticated RCE")
        
        
        risk_score += len(self.port_db.get(port, {}).get('cves', [])) * 15
        
        risk_levels = {90: 'CRITICAL', 70: 'HIGH', 50: 'MEDIUM', 20: 'LOW'}
        risk_level = next((level for threshold, level in sorted(risk_levels.items(), reverse=True) if risk_score >= threshold), 'INFO')
        
        return {'score': risk_score, 'level': risk_level, 'recommendations': recommendations}

    def run_full_scan(self, ports):
        """🚀 Complete scan"""
        print(f"{Fore.MAGENTA}{'='*100}")
        print(f"{Fore.YELLOW}🔥 HACKERAI ULTIMATE PORT SCANNER v7.0")
        print(f"{Fore.CYAN}Target: {self.target} | Ports: {len(ports)} | Threads: {self.threads} | Timeout: {self.timeout}s")
        print(f"{Fore.YELLOW}Mode: {'AGGRESSIVE (Nmap+Banner)' if self.aggressive else 'STANDARD'}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}{'='*100}{Style.RESET_ALL}")

        start_time = time.time()
        open_ports = []
        total_scanned = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.scan_port_advanced, self.target, port): port for port in ports}
            
            for future in as_completed(futures):
                result = future.result()
                total_scanned += 1
                
                if total_scanned % 1000 == 0 or total_scanned == len(ports):
                    elapsed = time.time() - start_time
                    speed = total_scanned / elapsed if elapsed > 0 else 0
                    print(f"{Fore.CYAN}⚡ Scanned {total_scanned}/{len(ports)} ({speed:.0f} p/s){Style.RESET_ALL}")
                
                if result:
                    open_ports.append(result)
                    self.print_live_result(result)

        self.results['scan_duration'] = time.time() - start_time
        self.results['open_ports'] = open_ports
        self.analyze_results()
        self.generate_report()

    def print_live_result(self, result):
        """📡 Live results"""
        port, service, banner, risk = result['port'], result['service'], result['banner'], result['risk']
        
        risk_color = {'CRITICAL': Fore.RED + Back.WHITE, 'HIGH': Fore.RED, 
                     'MEDIUM': Fore.YELLOW, 'LOW': Fore.GREEN}
        color = risk_color.get(risk['level'], Fore.CYAN)
        
        print(f"{color}🔥 [{risk['level']}] {port:5d} {service:<20} {risk['score']:3d} {Style.RESET_ALL}", end='')
        
        if banner:
            print(f"→ {banner[:50]}...", end='')
        print()
        
        
        if risk['recommendations']:
            for rec in risk['recommendations'][:1]:  
                print(f"   {Fore.WHITE}💡 {rec}{Style.RESET_ALL}")

    def analyze_results(self):
        """📊 Risk analysis"""
        critical_count = sum(1 for p in self.results['open_ports'] if p['risk']['level'] == 'CRITICAL')
        high_count = sum(1 for p in self.results['open_ports'] if p['risk']['level'] == 'HIGH')
        
        self.results['risk_summary'] = {
            'critical': critical_count,
            'high': high_count,
            'total_open': len(self.results['open_ports'])
        }
        
        
        self.results['security_score'] = max(0, 100 - (critical_count * 25 + high_count * 10))

    def generate_report(self):
        """📋 Executive report"""
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f"{Fore.WHITE}🎯 EXECUTIVE SUMMARY & ATTACK PATHS")
        print(f"{Fore.CYAN}{'='*100}{Style.RESET_ALL}")
        
        print(f"{Fore.WHITE}📊 Score: {Fore.RED if self.results['security_score'] < 50 else Fore.GREEN}{self.results['security_score']}/100{Style.RESET_ALL}")
        print(f"{Fore.RED}🚨 CRITICAL: {self.results['risk_summary']['critical']} | HIGH: {self.results['risk_summary']['high']} | Total: {len(self.results['open_ports'])}{Style.RESET_ALL}")

       
        critical_ports = [p for p in self.results['open_ports'] if p['risk']['level'] == 'CRITICAL']
        if critical_ports:
            print(f"\n{Fore.RED + Back.WHITE}{'='*100}")
            print(f"{Fore.RED + Back.WHITE}🚨 PRIORITY 1: CRITICAL SERVICES (ATTACK IMMEDIATELY)")
            print(f"{Fore.RED + Back.WHITE}{'='*100}{Style.RESET_ALL}")
            
            for port_data in critical_ports:
                self.print_attack_vector(port_data)

        
        high_ports = [p for p in self.results['open_ports'] if p['risk']['level'] == 'HIGH']
        if high_ports:
            print(f"\n{Fore.RED}{'='*100}")
            print(f"{Fore.RED}⚠️  PRIORITY 2: HIGH RISK SERVICES")
            print(f"{Fore.RED}{'='*100}{Style.RESET_ALL}")
            for port_data in high_ports[:5]:  
                self.print_attack_vector(port_data)

    def print_attack_vector(self, port_data):
        """🎯 Detailed attack paths"""
        port, service, banner, cves, msf, risk = port_data['port'], port_data['service'], port_data['banner'], port_data['cves'], port_data['msf_modules'], port_data['risk']
        
        print(f"\n{Fore.RED}🎯 TARGET: {port:5d}/{service:<20} Risk: {risk['score']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}📡 Banner: {banner or 'No banner'}{Style.RESET_ALL}")
        
        if cves:
            print(f"{Fore.RED}🔥 CVEs: {', '.join(cves)}{Style.RESET_ALL}")
            
        if msf:
            print(f"{Fore.RED}💥 MSF Modules:{Style.RESET_ALL}")
            for module in msf[:2]:
                print(f"   msf6 > use {module}")
                
        print(f"{Fore.YELLOW}🛠️  Nmap Next:{Style.RESET_ALL}")
        print(f"   nmap -p{port} --script vuln,exploit {self.target}")
        print(f"   nmap -sV -sC -p{port} {self.target}")
        
        print(f"{Fore.CYAN}🎯 Attack Vectors:{Style.RESET_ALL}")
        if port == 445:
            print("   1. EternalBlue (MS17-010) - DoublePulsar")
            print("   2. SMB Null Session Enum")
            print("   3. EternalChampion/EternalRomance")
        elif port == 22:
            print("   1. SSH UserEnum (timing attack)")
            print("   2. Weak algo negotiation")
            print("   3. Key reuse attacks")
        elif port == 6379:
            print("   1. Unauthenticated RCE (CONFIG/SCRIPT)")
            print("   2. Redis CLI shell")
        elif port in [80, 443]:
            print("   1. Web app pentest (SQLi/XSS)")
            print("   2. Dir brute + virtual hosts")
            print("   3. SSL/TLS vulns")
            
        print()

    def save_json_report(self):
        """💾 Professional JSON"""
        filename = f"portscan_{self.target.replace('.', '_')}_{int(time.time())}.json"
        os.makedirs('reports', exist_ok=True)
        with open(f'reports/{filename}', 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        print(f"{Fore.GREEN}✅ JSON Report: reports/{filename}{Style.RESET_ALL}")


def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {e}")


def main():
    print(f"{Fore.MAGENTA}{'='*100}")
    print(f"{Fore.YELLOW}🚀 HACKERAI ULTIMATE PORT SCANNER v7.0")
    print(f"{Fore.CYAN}✅ AUTHORIZED PENTEST MODE ACTIVATED")
    print(f"{Fore.MAGENTA}{'='*100}{Style.RESET_ALL}")

    target = input(f"{Fore.YELLOW}🎯 Target IP: {Style.RESET_ALL}").strip()
    
    
    print(f"\n{Fore.CYAN}⚡ Scan Speed:{Style.RESET_ALL}")
    speeds = {'1': (1000, 0.2, 'ULTRA FAST'), '2': (500, 0.5, 'FAST'), '3': (200, 1.0, 'BALANCED'), '4': (100, 2.0, 'ACCURATE')}
    speed_choice = input("1-4 [2]: ").strip() or '2'
    threads, timeout, label = speeds.get(speed_choice, speeds['2'])
    
    aggressive = input(f"{Fore.YELLOW}Aggressive Nmap scan? (y/N): {Style.RESET_ALL}").strip().lower() == 'y'
    
    
    top_ports = [21,22,23,25,53,80,110,111,135,139,143,443,993,995,1723,3306,3389,5900,8080] + list(range(1024, 5025))
    
    scanner = UltimatePortScanner(target, threads, timeout, aggressive)
    scanner.run_full_scan(top_ports)
    scanner.save_json_report()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Scan interrupted{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}❌ Error: {e}{Style.RESET_ALL}")