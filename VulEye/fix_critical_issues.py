# fix_critical_issues.py
import os
import re

def fix_bare_except_in_file(filepath):
    """Заменяет bare except: на except Exception:"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Replace except: with except Exception:
    fixed_content = re.sub(
        r'(\s+)except:',
        r'\1except Exception:',
        content
    )
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(fixed_content)
    
    return fixed_content != content

def fix_ssl_warnings(filepath):
    """Удаляет подавление SSL предупреждений"""
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Удалить disable_warnings
    fixed_content = content.replace(
        'requests.packages.urllib3.disable_warnings()',
        '# requests SSL verification enabled by default'
    )
    
    return fixed_content, fixed_content != content

# Main execution
modules_dir = r'c:\Users\ADMIN\Documents\VulEye\VulEye\modules'

count = 0
for root, dirs, files in os.walk(modules_dir):
    for file in files:
        if file.endswith('.py'):
            filepath = os.path.join(root, file)
            if fix_bare_except_in_file(filepath):
                print(f"✓ Fixed bare except in {filepath}")
                count += 1

print(f"\n[✓] Fixed {count} files")
