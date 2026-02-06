import requests
import jwt
import time
from colorama import init, Fore, Style

init(autoreset=True)


def decode_jwt(token):
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        return header, payload
    except Exception:
        return None, None


def extract_jwt_from_response(resp):
    if 'Authorization' in resp.headers:
        auth = resp.headers.get('Authorization', '')
        if auth.startswith('Bearer '):
            return auth.split(' ', 1)[1]

    try:
        data = resp.json()
        for k in ['token', 'access_token', 'jwt']:
            if k in data and isinstance(data[k], str):
                return data[k]
    except Exception:
        pass

    return None


def run():
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}║{Fore.GREEN} JWT SECURITY SCANNER {Fore.CYAN}║")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\n1. Analyze existing JWT")
    print(f"2. Obtain JWT from login endpoint")
    choice = input(f"\n{Fore.YELLOW}Select [1-2]: {Style.RESET_ALL}").strip()

    token = None

    if choice == "1":
        token = input(f"\n{Fore.YELLOW}JWT token: {Style.RESET_ALL}").strip()

    elif choice == "2":
        url = input(f"\n{Fore.YELLOW}Login URL: {Style.RESET_ALL}").strip()
        user = input(f"{Fore.YELLOW}Username: {Style.RESET_ALL}").strip()
        pwd = input(f"{Fore.YELLOW}Password: {Style.RESET_ALL}").strip()

        if not url.startswith(("http://", "https://")):
            print(f"{Fore.RED}[!] Invalid URL{Style.RESET_ALL}")
            input()
            return

        try:
            r = requests.post(url, json={"username": user, "password": pwd}, timeout=10, verify=False)
            token = extract_jwt_from_response(r)
        except Exception:
            pass

    if not token:
        print(f"{Fore.RED}[!] JWT not found{Style.RESET_ALL}")
        input()
        return

    header, payload = decode_jwt(token)
    if not header or not payload:
        print(f"{Fore.RED}[!] Invalid JWT format{Style.RESET_ALL}")
        input()
        return

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}DECODED JWT")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    print(f"\nHeader:")
    for k, v in header.items():
        print(f"  {k}: {v}")

    print(f"\nPayload:")
    for k, v in payload.items():
        print(f"  {k}: {v}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}SECURITY ANALYSIS")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    alg = header.get("alg", "").lower()
    now = int(time.time())

    if alg == "none":
        print(f"{Fore.MAGENTA}[CRITICAL] alg=none (signature bypass){Style.RESET_ALL}")

    if alg.startswith("hs"):
        print(f"{Fore.YELLOW}[WARN] Symmetric algorithm used (HS*){Style.RESET_ALL}")

    if alg.startswith(("rs", "es")):
        print(f"{Fore.GREEN}[OK] Asymmetric algorithm detected{Style.RESET_ALL}")

    if "exp" not in payload:
        print(f"{Fore.RED}[HIGH] No exp claim (non-expiring token){Style.RESET_ALL}")
    else:
        exp = int(payload["exp"])
        if exp < now:
            print(f"{Fore.CYAN}[INFO] Token expired{Style.RESET_ALL}")
        elif exp - now > 86400:
            print(f"{Fore.YELLOW}[WARN] Token lifetime > 24h{Style.RESET_ALL}")

    if "nbf" not in payload:
        print(f"{Fore.CYAN}[INFO] No nbf claim{Style.RESET_ALL}")

    if "iss" not in payload:
        print(f"{Fore.YELLOW}[WARN] Missing iss claim{Style.RESET_ALL}")

    if "aud" not in payload:
        print(f"{Fore.YELLOW}[WARN] Missing aud claim{Style.RESET_ALL}")

    if "jti" not in payload:
        print(f"{Fore.CYAN}[INFO] No jti claim{Style.RESET_ALL}")

    for k in payload:
        if any(x in k.lower() for x in ["password", "secret", "key", "token"]):
            print(f"{Fore.RED}[HIGH] Sensitive data in payload: {k}{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.GREEN}[✓] JWT analysis completed{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

    input()


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    run()
