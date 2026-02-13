# fix_run_functions.py
import os
import re

# Модули, которым нужна функция run()
MODULES_TO_FIX = {
    'Web': ['api_security.py', 'xss.py', 'SQLi.py', 'xxe.py', 'ssrf.py', 'OWASP10.py', 'lfi.py', 'csrf.py', 'hidden_params.py'],
    'Network': ['port_scanner.py'],
    'Info': ['tech_detect.py', 'ssl_check.py', 'cms_detect.py', 'cert_info.py'],
    'Auth': ['cookie_check.py', 'default_creds.py'],
    'Config': ['dir_listing.py', 'error_disclosure.py']
}

def has_run_function(content):
    """Check if file already has def run()"""
    return bool(re.search(r'^def run\(\):', content, re.MULTILINE))

def add_run_function(filepath, content):
    """Add run() function to the file"""
    
    # If already has run(), don't modify
    if has_run_function(content):
        return content
    
    # Find the main() function
    main_match = re.search(r'^def main\(\):(.*?)(?=\nif __name__|$)', content, re.MULTILINE | re.DOTALL)
    
    if not main_match:
        print(f"Warning: No main() found in {filepath}")
        return content
    
    # Create the run() function by copying main()
    main_body = main_match.group(1)
    
    # Create run function
    run_function = f"""
def run():
    '''Wrapper function for main.py integration'''
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"Error: {{e}}")
"""
    
    # Insert run() before main()
    new_content = content.replace('def main():', run_function + '\n\ndef main():')
    
    return new_content

def process_modules():
    """Process all modules and add run() function"""
    base_path = r'c:\Users\ADMIN\Documents\VulEye\VulEye\modules'
    
    for category, modules in MODULES_TO_FIX.items():
        category_path = os.path.join(base_path, category)
        
        for module_file in modules:
            filepath = os.path.join(category_path, module_file)
            
            if not os.path.exists(filepath):
                print(f"File not found: {filepath}")
                continue
            
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            if has_run_function(content):
                print(f"✓ {category}/{module_file} - already has run()")
                continue
            
            new_content = add_run_function(filepath, content)
            
            if new_content != content:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"✓ Fixed {category}/{module_file}")
            else:
                print(f"⚠ Could not fix {category}/{module_file}")

if __name__ == "__main__":
    process_modules()
    print("\n✓ All modules processed!")