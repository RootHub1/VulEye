import os
import sys
import importlib
from datetime import datetime

if not os.path.exists('reports'):
    os.makedirs('reports')
    print(f"[+] Created reports directory at {os.path.abspath('reports')}")


def show_banner():
    print(r"""

                  _        _______           _______ 
|\     /||\     /|( \      (  ____ \|\     /|(  ____ \
| )   ( || )   ( || (      | (    \/( \   / )| (    \/
| |   | || |   | || |      | (__     \ (_) / | (__    
( (   ) )| |   | || |      |  __)     \   /  |  __)   
 \ \_/ / | |   | || |      | (         ) (   | (      
  \   /  | (___) || (____/\| (____/\   | |   | (____/\
   \_/   (_______)(_______/(_______/   \_/   (_______/

        VυʅEყҽ — Eƚԋιƈαʅ Sҽƈυɾιƚყ Sƈαɳɳҽɾ Sυιƚҽ
                      Vҽɾʂισɳ: 1.0
""")


def show_main_menu():
    print("\n" + "=" * 70)
    print(" VulEye — MAIN MENU")
    print("=" * 70)
    print(" 1. Modules")
    print(" 2. Core Tools")
    print(" 3. Exploits Database (CVE/Payloads)")
    print(" 0. Exit")
    print("=" * 70)
    return input("Select option [0-3]: ").strip()


def show_modules_menu():
    print("\n" + "=" * 70)
    print(" MODULES CATEGORIES")
    print("=" * 70)
    print(" 1. Web")
    print(" 2. Network")
    print(" 3. Auth")
    print(" 4. Config")
    print(" 5. Info")
    print(" 0. Back to main menu")
    print("=" * 70)
    return input("Select category [0-5]: ").strip()


def get_modules_in_category(category):
    modules_dir = os.path.join('modules', category)
    modules = []

    if not os.path.exists(modules_dir):
        return []

    for filename in os.listdir(modules_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            module_name = filename[:-3]
            modules.append(module_name)

    return modules


def run_module(category, module_name):
    try:

        module_path = f"modules.{category}.{module_name}"
        module = importlib.import_module(module_path)

        if hasattr(module, 'run'):
            print(f"\n[+] Running {module_name} ({category})...")
            print("-" * 70)
            module.run()
        else:
            print(f"\n[!] Error: Module {module_name} has no 'run' function.")
    except ImportError as e:
        print(f"\n[!] Module not found: {e}")
    except Exception as e:
        print(f"\n[!] Error running module: {e}")


def get_core_tools():

    core_dir = 'core'
    tools = []

    if not os.path.exists(core_dir):
        return []

    for filename in os.listdir(core_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            tool_name = filename[:-3]
            tools.append(tool_name)

    return sorted(tools)


def run_core_tool(tool_name):

    try:
        module = importlib.import_module(f'core.{tool_name}')

        if hasattr(module, 'run'):
            print(f"\n[+] Running Core Tool: {tool_name}...")
            print("-" * 70)
            module.run()
        else:
            print(f"\n[!] Core tool '{tool_name}' has no 'run' function.")
            print("    This is expected for library modules (scanner, utils, etc.)")
            print("    They are used by other modules, not run directly.")
    except Exception as e:
        print(f"\n[!] Error running core tool '{tool_name}': {e}")


def show_core_tools_menu():

    tools = get_core_tools()

    if not tools:
        print("\n[!] No tools found in core/ directory.")
        print("    Expected files: scanner.py, reporter.py, utils.py, payloads.py")
        return None

    print("\n" + "=" * 70)
    print(" CORE TOOLS (Library modules used by scanners)")
    print("=" * 70)

    for i, tool in enumerate(tools, 1):
        print(f" {i}. {tool}")

    print(f"\n 0. Back to main menu")
    print("=" * 70)

    choice = input("\nSelect tool [0-{}]: ".format(len(tools))).strip()

    if choice == "0":
        return "back"

    try:
        tool_index = int(choice) - 1
        if 0 <= tool_index < len(tools):
            return tools[tool_index]
    except ValueError:
        pass

    print("[!] Invalid choice.")
    return None



def get_payloads_list():

    payloads_dir = 'payloads'
    payloads = []

    if not os.path.exists(payloads_dir):
        return []

    for filename in os.listdir(payloads_dir):
        if filename.endswith('.py') and filename != '__init__.py':
            payload_name = filename[:-3]
            payloads.append(payload_name)

    return sorted(payloads)


def show_payloads_menu():

    payloads = get_payloads_list()

    print("\n" + "=" * 70)
    print(" EXPLOITS DATABASE — Search by CVE or Name")
    print("=" * 70)

    if payloads:

        print("\n Examples: CVE-2017-5638, log4shell, heartbleed, dirty_cow")
    else:
        print("\n[!] No exploits found in payloads/ directory.")
        print("    Create payloads with format: CVE-XXXX-XXXX.py or name.py")

    print(f"\n 0. Back to main menu")
    print("=" * 70)

    return input("\nEnter CVE or exploit name: ").strip()


def search_and_run_payload(search_term):

    payloads = get_payloads_list()

    if not payloads:
        print("\n[!] Exploits database is empty.")
        return


    search = search_term.lower().strip()


    if search.startswith('cve-'):
        search = search[4:]


    exact_match = None
    for payload in payloads:
        if payload.lower() == search_term.lower():
            exact_match = payload
            break


    if not exact_match:
        matches = []
        for payload in payloads:
            payload_lower = payload.lower()
            if search in payload_lower:
                matches.append(payload)

        if len(matches) == 1:
            exact_match = matches[0]
        elif len(matches) > 1:
            print(f"\n[!] Found {len(matches)} matches:")
            for i, match in enumerate(matches, 1):
                print(f" {i}. {match}")
            print("\n[!] Please enter exact name.")
            return
        else:

            print(f"\n[!] Exploit '{search_term}' not found in database.")
            print(f"\n Suggestions:")
            print(f"   1. Check spelling (case-sensitive)")
            print(f"   2. Available exploits: {', '.join(payloads[:5])}...")
            print(f"   3. Search online: https://www.exploit-db.com/search?q={search_term}")
            print(f"   4. Add new exploit to payloads/ folder")
            return


    if exact_match:
        run_payload(exact_match)


def run_payload(payload_name):

    try:
        module = importlib.import_module(f'payloads.{payload_name}')

        if hasattr(module, 'run'):
            print(f"\n{'=' * 70}")
            print(f" EXPLOIT: {payload_name}")
            print(f"{'=' * 70}")
            print(f"\n  WARNING: This is a potentially dangerous exploit!")
            print(f"  Use ONLY on systems you own or have written permission!")
            confirm = input(f"\nDo you confirm ethical use? (type 'I accept risk'): ").strip()

            if confirm.lower() != 'i accept risk':
                print("\n[!] Exploit aborted by user.")
                return

            print(f"\n[+] Executing {payload_name}...")
            print("-" * 70)
            module.run()
        else:
            print(f"\n[!] Exploit '{payload_name}' has no 'run' function.")
            print("    Expected structure:")
            print("    def run():")
            print("        # Your exploit code here")
    except ImportError as e:
        print(f"\n[!] Exploit module not found: {e}")
    except Exception as e:
        print(f"\n[!] Error executing exploit: {e}")


def show_payload_details(payload_name):

    try:
        module = importlib.import_module(f'payloads.{payload_name}')

        print(f"\n{'=' * 70}")
        print(f" EXPLOIT DETAILS: {payload_name}")
        print(f"{'=' * 70}")


        if hasattr(module, 'DESCRIPTION'):
            print(f"\nDescription: {module.DESCRIPTION}")
        if hasattr(module, 'CVE'):
            print(f"CVE: {module.CVE}")
        if hasattr(module, 'CVSS'):
            print(f"CVSS Score: {module.CVSS}")
        if hasattr(module, 'AFFECTED'):
            print(f"Affected: {module.AFFECTED}")
        if hasattr(module, 'REFERENCES'):
            print(f"\nReferences:")
            for ref in module.REFERENCES:
                print(f"  - {ref}")

        print(f"\n[✓] Details displayed.")
    except Exception as e:
        print(f"\n[!] Error loading exploit details: {e}")





def main():
    show_banner()

    while True:
        choice = show_main_menu()

        if choice == "0":
            print("\n[✓] Exiting VulEye. Stay ethical!")
            break

        elif choice == "1":

            while True:
                category_choice = show_modules_menu()

                if category_choice == "0":
                    break

                categories = {
                    "1": "web",
                    "2": "network",
                    "3": "auth",
                    "4": "config",
                    "5": "info"
                }

                if category_choice not in categories:
                    print("\n[!] Invalid choice. Please try again.")
                    continue

                category = categories[category_choice]
                modules = get_modules_in_category(category)

                if not modules:
                    print(f"\n[!] No modules found in {category} category.")
                    continue

                print(f"\n[+] Available modules in {category} category:")
                print("-" * 70)
                for i, module in enumerate(modules, 1):
                    print(f" {i}. {module}")
                print(f" 0. Back to categories")
                print("-" * 70)

                module_choice = input("Select module [0-{}]: ".format(len(modules))).strip()

                if module_choice == "0":
                    continue

                try:
                    module_index = int(module_choice) - 1
                    if 0 <= module_index < len(modules):
                        run_module(category, modules[module_index])
                    else:
                        print("\n[!] Invalid module number.")
                except ValueError:
                    print("\n[!] Please enter a number.")

        elif choice == "2":
            while True:
                tool = show_core_tools_menu()

                if tool == "back":
                    break

                if tool:
                    run_core_tool(tool)
                    input("\nPress Enter to continue...")


        elif choice == "3":
            while True:
                search_term = show_payloads_menu()

                if search_term == "0":
                    break

                if search_term:
                    search_and_run_payload(search_term)
                    input("\nPress Enter to continue...")


        else:
            print("\n[!] Invalid choice. Please try again.")


if __name__ == "__main__":
    try:

        if not os.path.exists('payloads'):
            os.makedirs('payloads')
            print(f"[+] Created payloads directory at {os.path.abspath('payloads')}")

        main()
    except KeyboardInterrupt:
        print("\n\n[!] Process interrupted by user. Exiting...")
        sys.exit(0)