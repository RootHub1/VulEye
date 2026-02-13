import socket
from colorama import Fore, Style, init
from datetime import datetime

init(autoreset=True)


TIMEOUT = 3
SENSITIVE_KEYWORDS = [
    "admin", "backup", "conf", "config", "secret",
    "private", "data", "users", "home", "share"
]

results = {
    "target": None,
    "time": None,
    "ports": {},
    "smb": {
        "anonymous": False,
        "guest": False,
        "shares": [],
        "server_info": {},
        "issues": [],
        "attack_paths": []
    }
}


def banner(title):
    print(f"\n{Fore.CYAN}{'=' * 70}")
    print(f"{Fore.CYAN}{title.center(70)}")
    print(f"{Fore.CYAN}{'=' * 70}{Style.RESET_ALL}")

def check_port(host, port):
    try:
        s = socket.socket()
        s.settimeout(TIMEOUT)
        open_ = s.connect_ex((host, port)) == 0
        s.close()
        return open_
    except Exception:
        return False


def smb_enum(target):
    try:
        from smb.SMBConnection import SMBConnection
        from smb.smb_structs import OperationFailure
    except ImportError:
        results["smb"]["issues"].append("pysmb not installed")
        return

    try:
        conn = SMBConnection(
            username="",
            password="",
            my_name="pentest-client",
            remote_name=target,
            use_ntlm_v2=True,
            is_direct_tcp=True
        )

        if not conn.connect(target, 445, timeout=TIMEOUT):
            return

        results["smb"]["anonymous"] = True

       
        try:
            info = conn.get_server_information()
            results["smb"]["server_info"] = {
                "server_name": getattr(info, "server_name", ""),
                "os": getattr(info, "os_version", ""),
                "server_type": getattr(info, "server_type", "")
            }
        except Exception:
            pass

        
        try:
            shares = conn.listShares(timeout=TIMEOUT)
            for s in shares:
                if s.type != 0:
                    continue

                risk = "LOW"
                for kw in SENSITIVE_KEYWORDS:
                    if kw in s.name.lower():
                        risk = "HIGH"
                        break

                results["smb"]["shares"].append({
                    "name": s.name,
                    "comment": s.comments,
                    "risk": risk
                })
        except OperationFailure:
            results["smb"]["issues"].append("Auth required for share listing")

        conn.close()

    except Exception as e:
        results["smb"]["issues"].append(str(e))


def run():
    banner("SMB ENUMERATION — PRO")

    target = input(f"{Fore.YELLOW}Target IP: {Style.RESET_ALL}").strip()
    results["target"] = target
    results["time"] = str(datetime.utcnow())

   
    banner("PORT CHECK")
    smb445 = check_port(target, 445)
    smb139 = check_port(target, 139)

    results["ports"]["445"] = smb445
    results["ports"]["139"] = smb139

    if not smb445 and not smb139:
        print(f"{Fore.RED}[!] SMB not reachable{Style.RESET_ALL}")
        return

    if smb445:
        print(f"{Fore.GREEN}[✓] 445/tcp OPEN{Style.RESET_ALL}")
    if smb139:
        print(f"{Fore.GREEN}[✓] 139/tcp OPEN{Style.RESET_ALL}")

    
    banner("SMB ENUMERATION")
    smb_enum(target)

   
    banner("RESULTS")

    if results["smb"]["anonymous"]:
        print(f"{Fore.RED}[!] Anonymous SMB access enabled{Style.RESET_ALL}")
        results["smb"]["attack_paths"].append(
            "Anonymous SMB → share access → data leakage"
        )

    for share in results["smb"]["shares"]:
        color = Fore.RED if share["risk"] == "HIGH" else Fore.GREEN
        print(f"{color}• {share['name']} ({share['risk']}){Style.RESET_ALL}")

    if results["smb"]["shares"]:
        results["smb"]["attack_paths"].append(
            "SMB shares → creds/config → lateral movement"
        )

    
    banner("ATTACK PATHS")
    print("• enum4linux / crackmapexec smb")
    print("• Check SMB signing & NTLM relay")
    print("• Test MS17-010 only with permission")

    
    banner("SUMMARY")
    print(f"{Fore.GREEN}[✓] SMB Recon completed{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Use only with authorization{Style.RESET_ALL}")

if __name__ == "__main__":
    run()
