#!/usr/bin/env python3
"""
Setup script for FairPlay Decryptor
Installs required dependencies and sets up the environment
"""

import subprocess
import sys
import os
import shutil
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors"""
    print(f"[+] {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"    ✓ {description} completed")
        return result
    except subprocess.CalledProcessError as e:
        print(f"    ✗ {description} failed: {e.stderr}")
        return None


def check_macos_version():
    """Check if running on supported macOS version"""
    try:
        result = subprocess.run(["sw_vers", "-productVersion"], capture_output=True, text=True)
        version = result.stdout.strip()
        version_parts = list(map(int, version.split(".")))
        
        print(f"[+] Detected macOS version: {version}")
        
        if version_parts[0] == 15 and 0 <= version_parts[1] <= 2:
            print("    ✓ macOS version is compatible with CVE-2025-24204")
            return True
        else:
            print("    ⚠ This tool is designed for macOS 15.0-15.2 (Sequoia)")
            print("    ⚠ Other versions may not have the vulnerable gcore binary")
            return False
    except Exception as e:
        print(f"    ✗ Could not detect macOS version: {e}")
        return False


def check_gcore_vulnerability():
    """Check if gcore has the vulnerable entitlement"""
    print("[+] Checking for CVE-2025-24204 vulnerability...")
    
    if not os.path.exists("/usr/bin/gcore"):
        print("    ✗ gcore binary not found")
        return False
    
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", "/usr/bin/gcore"],
            capture_output=True, text=True
        )
        
        if "com.apple.system-task-ports.read" in result.stdout:
            print("    ✓ gcore has the vulnerable entitlement (com.apple.system-task-ports.read)")
            return True
        else:
            print("    ✗ gcore does not have the required entitlement")
            print("    ✗ CVE-2025-24204 may not be exploitable on this system")
            return False
    except Exception as e:
        print(f"    ✗ Could not check gcore entitlements: {e}")
        return False


def install_python_dependencies():
    """Install required Python packages"""
    print("[+] Installing Python dependencies...")
    
    # Check if pip is available
    if not shutil.which("pip3"):
        print("    ✗ pip3 not found. Please install Python 3 with pip")
        return False
    
    # Install packages
    packages = ["lief>=0.12.0", "typer>=0.9.0"]
    for package in packages:
        result = run_command(f"pip3 install --user {package}", f"Installing {package}")
        if result is None:
            return False
    
    return True


def check_radare2():
    """Check if radare2 is installed"""
    print("[+] Checking for radare2...")
    
    if shutil.which("rabin2"):
        print("    ✓ radare2 is installed")
        return True
    else:
        print("    ✗ radare2 not found")
        print("    → Install with: brew install radare2")
        return False


def make_scripts_executable():
    """Make Python scripts executable"""
    print("[+] Making scripts executable...")
    
    script_dir = Path(__file__).parent
    scripts = ["app_scanner.py", "decrypt_fairplay.py"]
    
    for script in scripts:
        script_path = script_dir / script
        if script_path.exists():
            os.chmod(script_path, 0o755)
            print(f"    ✓ Made {script} executable")
        else:
            print(f"    ⚠ {script} not found")


def main():
    """Main setup function"""
    print("=" * 60)
    print("FairPlay Decryptor Setup")
    print("CVE-2025-24204 App Store App Decryption Tool")
    print("=" * 60)
    
    # System checks
    macos_ok = check_macos_version()
    vuln_ok = check_gcore_vulnerability()
    
    # Tool dependencies
    radare2_ok = check_radare2()
    python_ok = install_python_dependencies()
    
    # Setup scripts
    make_scripts_executable()
    
    print("\n" + "=" * 60)
    print("Setup Summary:")
    print(f"  macOS Version: {'✓' if macos_ok else '⚠'}")
    print(f"  CVE-2025-24204: {'✓' if vuln_ok else '✗'}")
    print(f"  radare2: {'✓' if radare2_ok else '✗'}")
    print(f"  Python deps: {'✓' if python_ok else '✗'}")
    
    if all([vuln_ok, radare2_ok, python_ok]):
        print("\n✓ Setup completed successfully!")
        print("\nNext steps:")
        print("1. Ensure you have Apple Developer Program membership")
        print("2. Create a development provisioning profile")
        print("3. Generate signing identity and entitlements file")
        print("4. Launch the macOS app and configure settings")
        print("\nIMPORTANT: This tool requires administrator privileges to run.")
    else:
        print("\n⚠ Setup completed with warnings/errors.")
        print("Please address the issues above before using the tool.")
    
    print("=" * 60)


if __name__ == "__main__":
    main()
