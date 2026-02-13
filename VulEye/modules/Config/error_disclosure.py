import requests
from urllib.parse import urlparse, urljoin
import re
from colorama import init, Fore, Style
import time
import json
import sys

init(autoreset=True)


def is_safe_to_test(target):
    """Этическая проверка перед запуском"""
    print(f"\n{Fore.RED}{'=' * 80}")
    print(f"⚠️  CRITICAL SAFETY & ETHICAL CHECK")
    print(f"{'=' * 80}{Style.RESET_ALL}")
    print(f"\n{Fore.YELLOW}This scanner will send ~35 requests to the target.{Style.RESET_ALL}")
    print(f"\n{Fore.CYAN}ETHICAL TESTING RULES:{Style.RESET_ALL}")
    print(f"   ✅ ONLY test sites where you have WRITTEN authorization")
    print(f"   ✅ ONLY test within the defined scope of bug bounty program")
    print(f"   ✅ Respect rate limits (2+ seconds between requests)")
    print(f"   ✅ STOP immediately if you see 5xx errors (server overload)")
    print(f"   ✅ Report findings responsibly through official channels")
    print(f"\n{Fore.RED}ILLEGAL ACTIVITIES (STRICTLY PROHIBITED):{Style.RESET_ALL}")
    print(f"   ❌ Testing without explicit authorization")
    print(f"   ❌ Testing production systems without permission")
    print(f"   ❌ Causing service disruption (DoS)")
    print(f"   ❌ Accessing unauthorized data")
    print(f"   ❌ Testing outside program scope")
    
    print(f"\n{Fore.YELLOW}⚠️  WARNING: Unauthorized testing may result in:{Style.RESET_ALL}")
    print(f"   • Permanent ban from bug bounty platforms")
    print(f"   • Legal action and prosecution")
    print(f"   • Financial penalties")
    print(f"   • Criminal charges in some jurisdictions")
    
    confirm = input(f"\n{Fore.YELLOW}Do you have EXPLICIT WRITTEN AUTHORIZATION to test this target? (yes/no): {Style.RESET_ALL}").strip().lower()
    
    if confirm != 'yes':
        print(f"\n{Fore.RED}[!] ABORTING: Ethical testing requires explicit authorization.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Get written permission first, then run this tool again.{Style.RESET_ALL}")
        return False
    
    # Проверка на известные крупные платформы
    major_platforms = ['google.com', 'microsoft.com', 'apple.com', 'facebook.com', 
                       'twitter.com', 'amazon.com', 'github.com', 'gitlab.com']
    if any(platform in target.lower() for platform in major_platforms):
        print(f"\n{Fore.YELLOW}⚠️  You're testing a major platform.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Have you enrolled in their official bug bounty program?{Style.RESET_ALL}")
        enrolled = input(f"{Fore.YELLOW}(yes/no): {Style.RESET_ALL}").strip().lower()
        if enrolled != 'yes':
            print(f"\n{Fore.RED}[!] ABORTING: Testing major platforms without enrollment is prohibited.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}Enroll in their program first: https://hackerone.com, https://bugcrowd.com{Style.RESET_ALL}")
            return False
    
    # Финальное подтверждение
    final_confirm = input(f"\n{Fore.RED}Type 'I ACCEPT RESPONSIBILITY' to continue: {Style.RESET_ALL}").strip()
    if final_confirm != 'I ACCEPT RESPONSIBILITY':
        print(f"\n{Fore.RED}[!] ABORTING: Safety first.{Style.RESET_ALL}")
        return False
    
    return True


def test_error_trigger(url, payload, method='GET', json_data=None, session=None):
    """Безопасная функция тестирования с защитой от перегрузки"""
    try:
        if session is None:
            session = requests.Session()
        
        if method == 'GET':
            if '?' in url:
                test_url = f"{url}&{payload}"
            else:
                test_url = f"{url}?{payload}"
            
            # Проверка здоровья сервера перед запросом
            try:
                health_resp = session.get(url, timeout=5, verify=False)
                if health_resp.status_code >= 500:
                    print(f"\n{Fore.RED}[!] SERVER RETURNING 5xx ERRORS. STOPPING TO PREVENT DoS.{Style.RESET_ALL}")
                    return "OVERLOAD", None, None
            except Exception:
                pass
            
            response = session.get(test_url, timeout=10, verify=False)
        elif method == 'POST':
            if json_data:
                response = session.post(url, json=json_data, timeout=10, verify=False)
            else:
                response = session.post(url, data=payload, timeout=10, verify=False)
        else:
            response = session.request(method, url, timeout=10, verify=False)
        
        # Критическая защита: остановка при 5xx ошибках
        if response.status_code >= 500:
            print(f"\n{Fore.RED}[!] SERVER ERROR {response.status_code} DETECTED. STOPPING SCAN.{Style.RESET_ALL}")
            return "OVERLOAD", None, None
        
        return response.status_code, response.text, response.headers
    
    except requests.exceptions.Timeout:
        return 408, None, None
    except requests.exceptions.ConnectionError:
        return 503, None, None
    except Exception as e:
        return None, None, None


def analyze_response(content, headers):
    """Анализ ответов с расширенными паттернами"""
    findings = []
    severity = 'NONE'

    if not content:
        return findings, severity

    content_lower = content.lower()

    error_patterns = {
        "cloud_secrets": {
            "patterns": [
                "sk_live_", "sk_test_", "pk_live_", "rk_live_",
                "ghp_", "gho_", "gph_", "glpat-",
                "aws_access_key_id", "aws_secret_access_key",
                "x-api-key:", "authorization: bearer",
                "firebaseio.com", "supabase.co",
                "sendgrid.net", "twilio.com", "mailgun.org",
                "cloudinary.com", "algolia.net", "pusher.com",
                "redis://", "amqp://", "s3.amazonaws.com",
                "ssh-rsa aaa", "-----begin", "private key",
                "begin rsa", "begin dsa", "begin ecdsa",
                "mongodb+srv://"
            ],
            "severity": "CRITICAL",
            "type": "Cloud Service Secret Disclosure"
        },

        "sensitive_data": {
            "patterns": [
                "db_password", "database_password", "api_key",
                "secret_key", "private_key", "password_hash",
                "password_reset_token", "session_token",
                "csrf_token", "xsrf_token", "access_token",
                "refresh_token", "oauth_token", "jwt_token",
                "bearer_token", "mongodb://", "postgres://",
                "mysql:host=", "postgresql://", "smtp_password",
                "admin_password", "root_password", "master_key",
                "encryption_key", "certificate"
            ],
            "severity": "CRITICAL",
            "type": "Sensitive Data Disclosure"
        },

        "stack_trace": {
            "patterns": [
                "traceback (most recent call last)", "stack trace:",
                "fatal error:", "uncaught exception",
                "exception in thread", "at line", "called from",
                "file \"", "line ", "in ", "throw new ",
                "at laravel.", "at illuminate.", "at symfony.",
                "at django.db", "at sqlalchemy.", "at hibernate.",
                "at sequelize.", "at mongoose.", "at prisma."
            ],
            "severity": "HIGH",
            "type": "Stack Trace Disclosure"
        },

        "file_path": {
            "patterns": [
                "/var/www/", "/home/", "/usr/local/", "/etc/",
                "/opt/", "/root/", "/tmp/", "c:\\\\", "c:/",
                "program files", "windows\\system32",
                ".php on line", ".py\", line", ".java\", line",
                ".js\", line", ".cs\", line", ".rb\", line"
            ],
            "severity": "HIGH",
            "type": "File Path Disclosure"
        },

        "database_error": {
            "patterns": [
                "sql syntax", "mysql error", "postgresql error",
                "sqlite error", "oracle error", "query failed",
                "unknown column", "syntax error near",
                "table doesn't exist", "column doesn't exist",
                "relation does not exist", "ora-", "pg_",
                "mysql_", "mysqli_", "pdo_", "sqlite_"
            ],
            "severity": "HIGH",
            "type": "Database Error Disclosure"
        },

        "modern_frameworks": {
            "patterns": [
                "nextjs", "react-dom", "hydration failed",
                "vue.runtime.esm.js", "ng0", "angular jit",
                "zone.js", "graphql error", "cannot query field",
                "aws_request_id", "lambda", "x-amzn-errortype",
                "firebase", "cloudflare", "heroku", "vercel",
                "netlify", "railway", "render", "mongodb.net"
            ],
            "severity": "HIGH",
            "type": "Modern Framework Error Disclosure"
        },

        "api_errors": {
            "patterns": [
                "json.decoder.jsondecodeerror", "invalid json",
                "unexpected token", "\"errors\": [", "\"message\": \"",
                "validation failed", "schema validation error",
                "required field missing", "invalid type for field",
                "malformed request", "bad request", "type mismatch"
            ],
            "severity": "MEDIUM",
            "type": "API Error Disclosure"
        },

        "framework_errors": {
            "patterns": [
                "illuminate\\database", "django.db.utils",
                "whitelabel error page", "server error in '/' application",
                "springframework", "flask app", "expressjs",
                "django", "flask", "express", "koa", "fastify"
            ],
            "severity": "HIGH",
            "type": "Framework Error Disclosure"
        },

        "debug_info": {
            "patterns": [
                "debug mode", "debug=true", "display_errors",
                "notice:", "warning:", "fatal error",
                "strict standards", "deprecated", "parse error",
                "syntax error", "undefined variable", "undefined index",
                "undefined offset", "call to undefined function",
                "class not found", "function not found"
            ],
            "severity": "MEDIUM",
            "type": "Debug Information Disclosure"
        }
    }

    for error_type, config in error_patterns.items():
        for pattern in config['patterns']:
            if pattern.lower() in content_lower:
                findings.append({
                    'type': config['type'],
                    'severity': config['severity'],
                    'pattern': pattern,
                    'context': get_context(content, pattern)
                })

                if config['severity'] == 'CRITICAL':
                    severity = 'CRITICAL'
                elif config['severity'] == 'HIGH' and severity not in ['CRITICAL']:
                    severity = 'HIGH'
                elif config['severity'] == 'MEDIUM' and severity not in ['CRITICAL', 'HIGH']:
                    severity = 'MEDIUM'

    server_header = headers.get('Server', '')
    if server_header and any(keyword in server_header.lower() for keyword in ['apache', 'nginx', 'iis', 'tomcat', 'gunicorn', 'uwsgi']):
        findings.append({
            'type': 'Server Header Disclosure',
            'severity': 'LOW',
            'pattern': server_header,
            'context': f'Server: {server_header}'
        })

    x_powered_by = headers.get('X-Powered-By', '')
    if x_powered_by:
        findings.append({
            'type': 'Technology Stack Disclosure',
            'severity': 'LOW',
            'pattern': x_powered_by,
            'context': f'X-Powered-By: {x_powered_by}'
        })

    sensitive_headers = {
        'X-Debug-Token': 'MEDIUM',
        'X-Runtime': 'LOW',
        'X-Version': 'LOW',
        'X-Backend-Server': 'LOW',
        'X-Cache': 'LOW',
        'X-Served-By': 'LOW',
        'X-Amzn-Trace-Id': 'LOW',
        'X-Correlation-Id': 'LOW',
        'X-Request-Id': 'LOW',
        'Server-Timing': 'LOW',
        'X-AspNet-Version': 'LOW',
        'X-AspNetMvc-Version': 'LOW'
    }

    for header, severity_level in sensitive_headers.items():
        value = headers.get(header, '')
        if value:
            findings.append({
                'type': 'Sensitive Header Disclosure',
                'severity': severity_level,
                'pattern': header,
                'context': f'{header}: {value}'
            })

    return findings, severity


def get_context(content, pattern, context_size=150):
    """Получение контекста вокруг найденного паттерна"""
    try:
        match = re.search(re.escape(pattern), content, re.IGNORECASE)
        if match:
            start = max(0, match.start() - context_size)
            end = min(len(content), match.end() + context_size)
            context = content[start:end]
            if len(context) > context_size * 2:
                lines = context.split('\n')
                if len(lines) > 3:
                    context = '\n'.join(lines[:3]) + '...'
            return context
    except Exception:
        pass
    return None


def run():
    """Основная функция запуска сканера"""
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.CYAN}║{Fore.GREEN}           ETHICAL ERROR DISCLOSURE SCANNER v2.1                    {Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.YELLOW}              Safe for Bug Bounty Programs (35 Payloads)              {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

    target = input(
        f"\n{Fore.YELLOW}Enter target URL (e.g., https://example.com/api/users?id=1): {Style.RESET_ALL}").strip()

    if not target:
        print(f"\n{Fore.RED}[!] Empty input. Aborting.{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    if not target.startswith(('http://', 'https://')):
        print(f"\n{Fore.RED}[!] URL must start with http:// or https://{Style.RESET_ALL}")
        input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
        return

    # ЭТИЧЕСКАЯ ПРОВЕРКА ПЕРЕД ЗАПУСКОМ
    if not is_safe_to_test(target):
        input(f"\n{Fore.BLUE}Press Enter to exit...{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}[+] Starting SAFE scan for: {target}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] 2.5-second delays between requests (ethical requirement){Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Scan will STOP automatically if server returns 5xx errors{Style.RESET_ALL}")

    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/json,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close'
        })

        # Проверка доступности сайта
        print(f"\n{Fore.CYAN}[→] Checking target availability...{Style.RESET_ALL}")
        try:
            resp = session.get(target, timeout=10, verify=False)
            if resp.status_code >= 500:
                print(f"{Fore.RED}[!] Target already returning errors ({resp.status_code}). Aborting.{Style.RESET_ALL}")
                input(f"\n{Fore.BLUE}Press Enter to exit...{Style.RESET_ALL}")
                return
            print(f"{Fore.GREEN}[✓] Target is healthy (status {resp.status_code}){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[?] Could not verify target: {str(e)[:50]}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Proceeding with scan anyway...{Style.RESET_ALL}")

        # ===========================================================================
        # БЕЗОПАСНЫЕ ПЕЙЛОАДЫ ДЛЯ БАГ-БАУНТИ (35 штук)
        # ===========================================================================
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}PHASE 1: GET PARAMETER ERROR TRIGGERING TESTS (25 Payloads)")
        print(f"{Fore.YELLOW}Note: All payloads are safe and non-destructive{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        test_payloads = [
            # ===== КРИТИЧЕСКИ ВАЖНЫЕ (8 пейлоадов) =====
            # 1. Простые кавычки для вызова синтаксических ошибок SQL/NoSQL
            ('id', "'"),
            ('id', '"'),
            
            # 2. NoSQL Injection (безопасные, не вызывают нагрузку)
            ('id', '{"$ne":null}'),
            ('filter', '{"$gt":""}'),
            
            # 3. SSTI (Server-Side Template Injection) - безопасные вычисления
            ('name', "{{7*7}}"),
            ('template', "<%= 7*7 %>"),
            
            # 4. GraphQL интроспекция (стандартный безопасный запрос)
            ('query', '{"query":"{__schema{types{name}}}"}'),
            
            # 5. Простой паттерн для обнаружения ошибок валидации
            ('id', '1 OR 1=1'),
            
            # ===== ВЫСОКИЕ ПРИОРИТЕТЫ (12 пейлоадов) =====
            # 6. Невалидные типы данных (часто раскрывают структуру)
            ('limit', '[]'),
            ('page', '{}'),
            ('count', 'true'),
            ('items', 'null'),
            
            # 7. Числовые аномалии
            ('timestamp', 'NaN'),
            ('price', 'Infinity'),
            ('limit', '-1'),
            ('offset', '999999999'),
            
            # 8. Несуществующие значения
            ('page', 'nonexistentpage'),
            ('sort', 'nonexistent_field'),
            
            # 9. Специальные символы
            ('test', '<>'),
            ('search', 'test&<>"\''),
            
            # ===== СРЕДНИЕ ПРИОРИТЕТЫ (10 пейлоадов) =====
            # 10. Parameter Pollution
            ('id', '1&id=2&id=3'),
            ('sort', 'name,id,created_at'),
            
            # 11. Отладочные параметры
            ('debug', '1'),
            ('verbose', 'true'),
            
            # 12. API-специфичные
            ('fields', 'id,name,nonexistent_field,created_at'),
            ('include', 'user,nonexistent_relation,comments'),
            ('version', '999999'),
            
            # 13. Токены и ключи (невалидные)
            ('token', 'Bearer invalid_jwt_token_here'),
            ('api_key', 'sk_test_invalid_1234567890'),
            
            # 14. Callback для JSONP/CORS проверок
            ('callback', 'https://example.com'),
            
            # 15. XSS-подобные (безопасные для тестирования ошибок)
            ('test', '<script>alert(1)</script>'),
            
            # 16. JSON-специфичные ошибки
            ('data', '{"malformed": "json"'),
            
            # 17. Email/URL валидация
            ('email', 'invalid_email_format'),
            ('url', 'javascript:alert(1)')
        ]

        all_findings = []
        total_tests = 0
        vulnerabilities_found = 0
        server_overloaded = False

        for param, payload in test_payloads:
            if server_overloaded:
                print(f"\n{Fore.YELLOW}[!] Skipping remaining tests due to server overload.{Style.RESET_ALL}")
                break
                
            total_tests += 1
            payload_display = payload[:45] + '...' if len(payload) > 45 else payload
            print(f"\n{Fore.CYAN}[→] Test {total_tests}/{len(test_payloads)}: {param}={payload_display}{Style.RESET_ALL}")

            status, content, headers = test_error_trigger(target, f"{param}={payload}", session=session)

            if status == "OVERLOAD":
                server_overloaded = True
                continue

            if status:
                status_color = Fore.GREEN if status < 400 else (Fore.YELLOW if status < 500 else Fore.RED)
                print(f"    Status: {status_color}{status}{Style.RESET_ALL}")

                findings, severity = analyze_response(content, headers)

                if findings:
                    vulnerabilities_found += 1
                    severity_color = Fore.MAGENTA if severity == 'CRITICAL' else (
                        Fore.RED if severity == 'HIGH' else (Fore.YELLOW if severity == 'MEDIUM' else Fore.CYAN))
                    print(
                        f"    {severity_color}[!] {len(findings)} issue(s) found (Severity: {severity}){Style.RESET_ALL}")

                    for finding in findings[:3]:
                        print(f"      • {finding['type']} ({finding['severity']})")

                    all_findings.extend(findings)
                else:
                    print(f"    {Fore.GREEN}[✓] No sensitive information disclosed{Style.RESET_ALL}")
            else:
                print(f"    {Fore.YELLOW}[?] Request failed (timeout/error){Style.RESET_ALL}")

            # БЕЗОПАСНАЯ ПАУЗА для баг-баунти
            time.sleep(2.5)

        # ===========================================================================
        # POST JSON ТЕСТЫ (10 пейлоадов)
        # ===========================================================================
        if not server_overloaded:
            print(f"\n{Fore.CYAN}{'=' * 80}")
            print(f"{Fore.CYAN}PHASE 2: POST JSON API ERROR HANDLING TESTS (10 Payloads)")
            print(f"{Fore.YELLOW}Note: Testing JSON payloads for API error disclosure{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

            json_payloads = [
                {"id": "invalid_type"},
                {"filter": {"$ne": "bypass"}},
                {"limit": "NaN"},
                {"include": ["user", "nonexistent"]},
                {"fields": "id,name,nonexistent_field"},
                {"data": "${{7*7}}"},
                {"query": "{{7*7}}"},
                {"token": "Bearer invalid_token_123"},
                {"api_key": "sk_test_invalid_key"},
                {"search": "' OR '1'='1"}
            ]

            for i, json_data in enumerate(json_payloads, 1):
                if server_overloaded:
                    break
                    
                print(f"\n{Fore.CYAN}[→] JSON Test {i}/{len(json_payloads)}: {str(json_data)[:55]}{Style.RESET_ALL}")
                
                try:
                    status, content, headers = test_error_trigger(target, None, method='POST', json_data=json_data, session=session)
                    
                    if status == "OVERLOAD":
                        server_overloaded = True
                        continue
                    
                    if status:
                        status_color = Fore.GREEN if status < 400 else (Fore.YELLOW if status < 500 else Fore.RED)
                        print(f"    Status: {status_color}{status}{Style.RESET_ALL}")

                        findings, severity = analyze_response(content, headers)

                        if findings:
                            vulnerabilities_found += 1
                            severity_color = Fore.MAGENTA if severity == 'CRITICAL' else (
                                Fore.RED if severity == 'HIGH' else (Fore.YELLOW if severity == 'MEDIUM' else Fore.CYAN))
                            print(
                                f"    {severity_color}[!] {len(findings)} issue(s) found (Severity: {severity}){Style.RESET_ALL}")

                            for finding in findings[:3]:
                                print(f"      • {finding['type']} ({finding['severity']})")

                            all_findings.extend(findings)
                        else:
                            print(f"    {Fore.GREEN}[✓] No sensitive information disclosed{Style.RESET_ALL}")
                    else:
                        print(f"    {Fore.YELLOW}[?] Request failed (timeout/error){Style.RESET_ALL}")
                        
                except Exception as e:
                    print(f"    {Fore.YELLOW}[?] Error: {str(e)[:50]}{Style.RESET_ALL}")
                
                time.sleep(2.5)

        # ===========================================================================
        # РЕЗУЛЬТАТЫ И ОТЧЕТ
        # ===========================================================================
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}RESULTS SUMMARY & SECURITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        actual_tests = total_tests
        if not server_overloaded:
            actual_tests += len(json_payloads)

        print(f"\n{Fore.GREEN}Total tests performed: {actual_tests}{Style.RESET_ALL}")
        print(f"{Fore.RED}Vulnerabilities found: {vulnerabilities_found}{Style.RESET_ALL}")

        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for finding in all_findings:
            severity_counts[finding['severity']] += 1

        print(f"\n{Fore.MAGENTA}Critical issues: {severity_counts['CRITICAL']}{Style.RESET_ALL}")
        print(f"{Fore.RED}High severity issues: {severity_counts['HIGH']}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium severity issues: {severity_counts['MEDIUM']}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Low severity issues: {severity_counts['LOW']}{Style.RESET_ALL}")

        if all_findings:
            print(f"\n{Fore.RED}[!] ERROR MESSAGE DISCLOSURE VULNERABILITIES DETECTED{Style.RESET_ALL}")

            critical_findings = [f for f in all_findings if f['severity'] == 'CRITICAL']
            high_findings = [f for f in all_findings if f['severity'] == 'HIGH']

            if critical_findings:
                print(f"\n{Fore.MAGENTA}{Style.BRIGHT}{'=' * 80}")
                print(f" CRITICAL FINDINGS (SECRET DISCLOSURE)")
                print(f"{'=' * 80}{Style.RESET_ALL}")
                for finding in critical_findings[:10]:
                    print(f"\n{Fore.MAGENTA}• {finding['type']}{Style.RESET_ALL}")
                    print(f"  Pattern: {finding['pattern']}")
                    if finding['context']:
                        context_display = finding['context'][:200] + '...' if len(finding['context']) > 200 else finding['context']
                        print(f"  Context: {context_display}")

            if high_findings:
                print(f"\n{Fore.RED}{'=' * 80}")
                print(f" HIGH SEVERITY FINDINGS")
                print(f"{'=' * 80}{Style.RESET_ALL}")
                for finding in high_findings[:15]:
                    print(f"\n{Fore.RED}• {finding['type']}{Style.RESET_ALL}")
                    print(f"  Pattern: {finding['pattern']}")
                    if finding['context']:
                        context_display = finding['context'][:200] + '...' if len(finding['context']) > 200 else finding['context']
                        print(f"  Context: {context_display}")

            print(f"\n{Fore.YELLOW}{'=' * 80}")
            print(f" RISK ASSESSMENT & BUSINESS IMPACT")
            print(f"{'=' * 80}{Style.RESET_ALL}")
            
            if severity_counts['CRITICAL'] > 0:
                risk_level = "CRITICAL"
                risk_color = Fore.MAGENTA
            elif severity_counts['HIGH'] > 0:
                risk_level = "HIGH"
                risk_color = Fore.RED
            elif severity_counts['MEDIUM'] > 0:
                risk_level = "MEDIUM"
                risk_color = Fore.YELLOW
            else:
                risk_level = "LOW"
                risk_color = Fore.CYAN

            print(f"\n{risk_color}Overall Risk Level: {risk_level}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}Business Impact:{Style.RESET_ALL}")
            print(f"   • Information disclosure enables targeted attacks")
            print(f"   • Stack traces reveal application structure and logic")
            print(f"   • File paths expose server configuration and deployment")
            print(f"   • Database errors reveal schema information")
            print(f"   • Debug info facilitates exploitation")
            print(f"   • Secret keys can lead to account takeover")
            print(f"   • API errors expose internal business logic")

            print(f"\n{Fore.GREEN}{'=' * 80}")
            print(f" CRITICAL RECOMMENDATIONS FOR DEVELOPERS")
            print(f"{'=' * 80}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}1. Implement Custom Error Pages:{Style.RESET_ALL}")
            print(f"   • Create generic error messages (no technical details)")
            print(f"   • Example: 'An error occurred. Please try again later.'")
            print(f"   • Never display stack traces to users")

            print(f"\n{Fore.YELLOW}2. Disable Debug Mode in Production:{Style.RESET_ALL}")
            print(f"   • PHP: display_errors = Off, error_reporting = 0")
            print(f"   • Python: DEBUG = False, LOG_LEVEL = 'ERROR'")
            print(f"   • Node.js: NODE_ENV=production")
            print(f"   • Java: logging.level.root=ERROR")
            print(f"   • .NET: <customErrors mode=\"On\" />")

            print(f"\n{Fore.YELLOW}3. Configure Web Server Security:{Style.RESET_ALL}")
            print(f"   • Apache: ServerTokens Prod, ServerSignature Off")
            print(f"   • Nginx: server_tokens off;")
            print(f"   • Remove X-Powered-By header")
            print(f"   • Remove Server header or set to generic value")

            print(f"\n{Fore.YELLOW}4. Implement Proper Error Logging:{Style.RESET_ALL}")
            print(f"   • Log errors to secure location (not displayed to users)")
            print(f"   • Use centralized logging (ELK, Splunk, CloudWatch)")
            print(f"   • Monitor for unusual error patterns")
            print(f"   • Set up alerts for critical errors")

            print(f"\n{Fore.YELLOW}5. API Security Best Practices:{Style.RESET_ALL}")
            print(f"   • Validate all input parameters")
            print(f"   • Use schema validation (JSON Schema, OpenAPI)")
            print(f"   • Implement rate limiting")
            print(f"   • Use Web Application Firewall (WAF)")
            print(f"   • Sanitize all error messages")

            print(f"\n{Fore.YELLOW}6. Secret Management:{Style.RESET_ALL}")
            print(f"   • Never hardcode secrets in code")
            print(f"   • Use environment variables or secret managers")
            print(f"   • Rotate keys regularly")
            print(f"   • Implement secret scanning in CI/CD")

        else:
            print(f"\n{Fore.GREEN}[✓] No error message disclosure vulnerabilities detected{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Security Best Practices (Maintain These):{Style.RESET_ALL}")
            print(f"   • Continue monitoring error handling")
            print(f"   • Implement centralized error logging")
            print(f"   • Use security headers (CSP, HSTS, X-Frame-Options)")
            print(f"   • Regular code reviews for error handling")
            print(f"   • Implement proper input validation")
            print(f"   • Use automated security scanning tools")
            print(f"   • Keep dependencies updated")
            print(f"   • Conduct regular security audits")

        # ===========================================================================
        # ДОПОЛНИТЕЛЬНЫЕ ПРОВЕРКИ
        # ===========================================================================
        if not server_overloaded:
            print(f"\n{Fore.CYAN}{'=' * 80}")
            print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
            print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

            print(f"\n{Fore.CYAN}[→] Checking server response headers...{Style.RESET_ALL}")

            try:
                response = session.get(target, timeout=10, verify=False)

                headers_to_check = [
                    'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
                    'X-Debug-Token', 'X-Runtime', 'X-Version', 'X-Backend-Server',
                    'X-Cache', 'X-Served-By', 'X-Amzn-Trace-Id', 'X-Correlation-Id',
                    'X-Request-Id', 'Server-Timing'
                ]

                disclosed_headers = 0
                for header in headers_to_check:
                    value = response.headers.get(header)
                    if value:
                        disclosed_headers += 1
                        print(f"{Fore.YELLOW}[!] Header disclosed: {header} = {value}{Style.RESET_ALL}")

                if disclosed_headers == 0:
                    print(f"{Fore.GREEN}[✓] No sensitive headers disclosed{Style.RESET_ALL}")

                if 'x-debug' in response.headers or 'debug' in response.headers:
                    print(f"{Fore.MAGENTA}{Style.BRIGHT}[!] DEBUG MODE DETECTED in headers!{Style.RESET_ALL}")

            except Exception as e:
                print(f"{Fore.YELLOW}[?] Could not check headers: {str(e)[:50]}{Style.RESET_ALL}")

        # ===========================================================================
        # ЮРИДИЧЕСКИЕ И ЭТИЧЕСКИЕ РЕКОМЕНДАЦИИ
        # ===========================================================================
        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}LEGAL & ETHICAL GUIDANCE FOR BUG BOUNTY")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}  ⚠️  LEGAL WARNING:{Style.RESET_ALL}")
        print(f"   • Unauthorized testing is ILLEGAL in most jurisdictions")
        print(f"   • Always obtain WRITTEN authorization before testing")
        print(f"   • Respect scope boundaries defined in bug bounty program")
        print(f"   • Never test production systems without explicit permission")
        print(f"   • Document all authorized testing activities")

        print(f"\n{Fore.GREEN} ✅ Responsible Testing Guidelines:{Style.RESET_ALL}")
        print(f"   • Test in staging/development environments first")
        print(f"   • Use low-frequency testing (2.5+ seconds between requests)")
        print(f"   • STOP immediately if server shows signs of overload")
        print(f"   • Report findings responsibly through official channels")
        print(f"   • Provide detailed mitigation recommendations")

        print(f"\n{Fore.CYAN} 📋 Bug Bounty Reporting Tips:{Style.RESET_ALL}")
        print(f"   • Include clear reproduction steps with curl commands")
        print(f"   • Provide screenshots with highlighted issues")
        print(f"   • Explain business impact and risk level")
        print(f"   • Suggest specific fixes")
        print(f"   • Be professional and constructive")
        print(f"   • Follow program's submission guidelines")

        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.GREEN}[✓] Error disclosure analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        # Сохранение результатов в файл
        if all_findings:
            filename = f"error_scan_{int(time.time())}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ERROR MESSAGE DISCLOSURE SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Tests: {actual_tests}\n")
                f.write(f"Vulnerabilities Found: {vulnerabilities_found}\n\n")
                
                f.write("SEVERITY BREAKDOWN:\n")
                f.write(f"  Critical: {severity_counts['CRITICAL']}\n")
                f.write(f"  High: {severity_counts['HIGH']}\n")
                f.write(f"  Medium: {severity_counts['MEDIUM']}\n")
                f.write(f"  Low: {severity_counts['LOW']}\n\n")
                
                f.write("DETAILED FINDINGS:\n")
                for i, finding in enumerate(all_findings, 1):
                    f.write(f"\n{i}. {finding['type']} ({finding['severity']})\n")
                    f.write(f"   Pattern: {finding['pattern']}\n")
                    if finding['context']:
                        f.write(f"   Context: {finding['context']}\n")
                
                f.write("\n" + "=" * 80 + "\n")
                f.write("RECOMMENDATIONS:\n")
                f.write("=" * 80 + "\n")
                f.write("1. Implement custom error pages\n")
                f.write("2. Disable debug mode in production\n")
                f.write("3. Configure web server security\n")
                f.write("4. Implement proper error logging\n")
                f.write("5. Use Web Application Firewall\n")
            
            print(f"\n{Fore.GREEN}[✓] Full report saved to: {filename}{Style.RESET_ALL}")

    except requests.exceptions.Timeout:
        print(f"\n{Fore.RED}[!] Request timeout. Target may be unreachable.{Style.RESET_ALL}")
    except requests.exceptions.ConnectionError:
        print(f"\n{Fore.RED}[!] Connection error. Check if target is accessible.{Style.RESET_ALL}")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user. No harm done.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    run()