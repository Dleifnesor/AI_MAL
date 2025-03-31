#!/usr/bin/env python3
"""
Fix script for python-nmap package to prevent circular import issues.
This is especially important for Python 3.13 which has stricter import rules.
"""

import os
import sys
import importlib
import importlib.util
import site
import shutil

def find_nmap_module():
    """Find the nmap module location."""
    try:
        # Try importing nmap and get its location
        spec = importlib.util.find_spec('nmap')
        if spec and spec.origin:
            # Get the directory containing __init__.py
            module_dir = os.path.dirname(spec.origin)
            return module_dir
    except ImportError:
        pass
    
    # If direct import fails, try finding it in site-packages
    try:
        site_packages = site.getsitepackages()
        for path in site_packages:
            nmap_path = os.path.join(path, 'nmap')
            if os.path.isdir(nmap_path) and os.path.exists(os.path.join(nmap_path, '__init__.py')):
                return nmap_path
    except Exception:
        pass
    
    return None

def fix_nmap_module(module_dir):
    """Fix the nmap module to prevent circular imports."""
    init_file = os.path.join(module_dir, '__init__.py')
    if not os.path.exists(init_file):
        print(f"Error: __init__.py not found in {module_dir}")
        return False
    
    # Backup the original file
    backup_file = init_file + '.bak'
    try:
        shutil.copy2(init_file, backup_file)
        print(f"Created backup: {backup_file}")
    except Exception as e:
        print(f"Warning: Could not create backup: {e}")
    
    # Read the content of __init__.py
    try:
        with open(init_file, 'r') as f:
            content = f.read()
    except Exception as e:
        print(f"Error reading {init_file}: {e}")
        return False
    
    # Create new content with circular import fix
    new_content = """import sys
# Prevent circular imports - a common issue in Python 3.13
if 'nmap.nmap' in sys.modules:
    sys.modules['nmap'] = sys.modules['nmap.nmap']

# Original content follows
""" + content
    
    # Write the modified content
    try:
        with open(init_file, 'w') as f:
            f.write(new_content)
        print(f"Successfully modified {init_file} to prevent circular imports")
        return True
    except Exception as e:
        print(f"Error writing to {init_file}: {e}")
        # Restore backup if write fails
        try:
            shutil.copy2(backup_file, init_file)
            print(f"Restored original file from backup")
        except:
            pass
        return False

def create_symlink(module_dir):
    """Create a symlink from python_nmap to nmap."""
    site_packages = os.path.dirname(module_dir)
    symlink_path = os.path.join(site_packages, 'python_nmap')
    
    # Remove existing symlink if it exists
    if os.path.exists(symlink_path):
        try:
            if os.path.islink(symlink_path):
                os.unlink(symlink_path)
            else:
                print(f"Warning: {symlink_path} exists but is not a symlink")
                return False
        except Exception as e:
            print(f"Error removing existing symlink: {e}")
            return False
    
    # Create symlink
    try:
        os.symlink(module_dir, symlink_path)
        print(f"Created symlink: {symlink_path} -> {module_dir}")
        return True
    except Exception as e:
        print(f"Error creating symlink: {e}")
        return False

def main():
    print("Python-nmap fix utility")
    print("=======================")
    print(f"Python version: {sys.version}")
    print("")
    
    # Find nmap module
    print("Looking for nmap module...")
    module_dir = find_nmap_module()
    
    if not module_dir:
        print("Error: Could not find nmap module. Please ensure python-nmap is installed.")
        return 1
    
    print(f"Found nmap module at: {module_dir}")
    
    # Fix the module
    if fix_nmap_module(module_dir):
        print("Successfully fixed nmap module.")
    else:
        print("Failed to fix nmap module.")
    
    # Create symlink
    if create_symlink(module_dir):
        print("Successfully created symlink for python_nmap.")
    else:
        print("Failed to create symlink for python_nmap.")
    
    print("\nFix completed. Please restart any running scripts that use python-nmap.")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 