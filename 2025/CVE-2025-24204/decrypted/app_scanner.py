#!/usr/bin/env python3
"""
App Scanner for CVE-2025-24204 FairPlay Decryptor
Scans for App Store applications and detects FairPlay encryption
"""

import os
import json
import subprocess
import sys
import plistlib
from pathlib import Path
from typing import List, Dict, Optional, NamedTuple
import lief
from enum import Enum


class BinaryType(Enum):
    """Types of binary items that can be found"""
    APP = "app"
    FRAMEWORK = "framework"
    APPEX = "appex"
    UNKNOWN = "unknown"


class BinaryItem(NamedTuple):
    """Represents a binary item found during scanning"""
    binary_type: BinaryType
    executable_path: str
    bundle_path: str
    info_plist_path: str


class AppAnalyzer:
    """Enhanced app analyzer based on Decrypter's Scaner.swift"""
    
    def __init__(self):
        self.debug = False
    
    def log(self, message: str):
        """Log debug messages"""
        if self.debug:
            print(f"[DEBUG] {message}", file=sys.stderr)
    
    def obtain_binary_locations(self, search_path: str) -> List[BinaryItem]:
        """
        Recursively scan a directory for binary items (apps, frameworks, appex)
        Based on the logic from Scaner.swift
        """
        binary_items = []
        
        for root, dirs, files in os.walk(search_path):
            # Look for Info.plist files
            if "Info.plist" in files:
                info_plist_path = os.path.join(root, "Info.plist")
                binary_item = self.convert_to_binary_item(info_plist_path)
                if binary_item:
                    binary_items.append(binary_item)
        
        return binary_items
    
    def convert_to_binary_item(self, info_plist_path: str) -> Optional[BinaryItem]:
        """
        Convert an Info.plist file to a BinaryItem
        Based on convertToBinaryItem from Scaner.swift
        """
        try:
            with open(info_plist_path, 'rb') as f:
                plist_data = plistlib.load(f)
            
            executable_name = plist_data.get('CFBundleExecutable')
            if not executable_name:
                self.log(f"[-] executable not found in metadata {info_plist_path}")
                return None
            
            bundle_path = os.path.dirname(info_plist_path)
            executable_path = os.path.join(bundle_path, executable_name)
            
            # Check if the executable exists and is a regular file
            if not os.path.isfile(executable_path):
                self.log(f"[E] target executable is not a regular file: {executable_path}")
                return None
            
            # Determine binary type based on bundle extension
            bundle_name = os.path.basename(bundle_path)
            
            if bundle_name.endswith('.appex'):
                self.log(f"[AppEx] {executable_path}")
                return BinaryItem(BinaryType.APPEX, executable_path, bundle_path, info_plist_path)
            elif bundle_name.endswith('.framework'):
                self.log(f"[Framework] {executable_path}")
                return BinaryItem(BinaryType.FRAMEWORK, executable_path, bundle_path, info_plist_path)
            elif bundle_name.endswith('.app'):
                self.log(f"[App] {executable_path}")
                return BinaryItem(BinaryType.APP, executable_path, bundle_path, info_plist_path)
            else:
                return BinaryItem(BinaryType.UNKNOWN, executable_path, bundle_path, info_plist_path)
                
        except Exception as e:
            self.log(f"Error processing {info_plist_path}: {e}")
            return None


def is_process_running(app_name: str) -> bool:
    """Check if an application process is currently running"""
    try:
        result = subprocess.run(
            ["pgrep", "-x", app_name],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return result.returncode == 0
    except Exception:
        return False


def get_bundle_info(app_path: str) -> Optional[Dict]:
    """Extract bundle information from Info.plist"""
    info_plist_path = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(info_plist_path):
        return None
    
    try:
        with open(info_plist_path, 'rb') as f:
            return plistlib.load(f)
    except Exception as e:
        print(f"Error reading Info.plist for {app_path}: {e}", file=sys.stderr)
        return None


def is_ios_app(app_path: str) -> bool:
    """Check if the app is an iOS app (has Wrapper directory or is inside a Wrapper)"""
    # Check if this app has a Wrapper directory
    wrapper_path = os.path.join(app_path, "Wrapper")
    if os.path.exists(wrapper_path):
        return True
    
    # Check if this app is inside a Wrapper directory
    if "Wrapper" in app_path:
        return True
    
    # Check if parent directories contain "Wrapper"
    parent_path = os.path.dirname(app_path)
    while parent_path and parent_path != "/":
        if os.path.basename(parent_path) == "Wrapper":
            return True
        parent_path = os.path.dirname(parent_path)
    
    return False


def is_encrypted_binary(binary_path: str) -> bool:
    """Check if a binary is FairPlay encrypted"""
    try:
        binary = lief.parse(binary_path)
        if binary is None or binary.format != lief.Binary.FORMATS.MACHO:
            return False
        
        for cmd in binary.commands:
            if (cmd.command == lief.MachO.LoadCommand.TYPE.ENCRYPTION_INFO_64 and 
                cmd.crypt_id == 1):
                return True
        return False
    except Exception:
        return False


def find_encrypted_binaries(app_path: str) -> bool:
    """Find if there are any encrypted binaries in the app"""
    if not is_ios_app(app_path):
        return False
    
    for root, _, files in os.walk(app_path):
        for file in files:
            file_path = os.path.join(root, file)
            if is_encrypted_binary(file_path):
                return True
    return False


def get_app_receipt_info(app_path: str) -> Dict:
    """Check if app has App Store receipt and extract info"""
    receipt_path = os.path.join(app_path, "Contents", "_MASReceipt", "receipt")
    has_receipt = os.path.exists(receipt_path)
    
    # Check for App Store metadata
    metadata_path = os.path.join(app_path, "Contents", "Resources", "Info.plist")
    from_app_store = False
    
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, 'rb') as f:
                plist_data = plistlib.load(f)
                # Check for App Store specific keys
                from_app_store = (
                    has_receipt or
                    plist_data.get('LSUIElement') is not None or
                    'com.apple.application-identifier' in str(plist_data)
                )
        except:
            pass
    
    return {
        'hasReceipt': has_receipt,
        'fromAppStore': from_app_store
    }


def get_additional_app_directories() -> List[str]:
    """Get additional directories where apps might be installed"""
    user_home = os.path.expanduser("~")
    additional_dirs = [
        "/Applications",
    ]
    
    return [d for d in additional_dirs if os.path.exists(d)]


def analyze_binary_item(binary_item: BinaryItem) -> Optional[Dict]:
    """Analyze a binary item and extract app information"""
    try:
        # Read the Info.plist
        with open(binary_item.info_plist_path, 'rb') as f:
            bundle_info = plistlib.load(f)
        
        # Extract basic app information
        app_name = (bundle_info.get('CFBundleDisplayName') or 
                   bundle_info.get('CFBundleName') or 
                   os.path.basename(binary_item.bundle_path).replace('.app', ''))
        
        bundle_id = bundle_info.get('CFBundleIdentifier', 'unknown')
        
        # Check if it's an iOS app
        is_ios = is_ios_app(binary_item.bundle_path)
        
        # For iOS apps, check encryption
        is_encrypted = False
        if is_ios:
            is_encrypted = is_encrypted_binary(binary_item.executable_path)
            # If main executable is not encrypted, check other binaries
            if not is_encrypted:
                is_encrypted = find_encrypted_binaries(binary_item.bundle_path)
        
        # Check if app is running
        is_running = is_process_running(app_name)
        
        # Get App Store info
        receipt_info = get_app_receipt_info(binary_item.bundle_path)
        
        # Enhanced app analysis
        app_info = {
            'name': app_name,
            'path': binary_item.bundle_path,
            'executablePath': binary_item.executable_path,
            'bundleId': bundle_id,
            'isEncrypted': is_encrypted,
            'isRunning': is_running,
            'fromAppStore': receipt_info['fromAppStore'],
            'hasReceipt': receipt_info['hasReceipt'],
            'binaryType': binary_item.binary_type.value,
            'isIOS': is_ios
        }
        
        # Add version info if available
        if 'CFBundleShortVersionString' in bundle_info:
            app_info['version'] = bundle_info['CFBundleShortVersionString']
        
        # Add build number if available
        if 'CFBundleVersion' in bundle_info:
            app_info['buildNumber'] = bundle_info['CFBundleVersion']
        
        # Add minimum OS version if available
        if 'LSMinimumSystemVersion' in bundle_info:
            app_info['minimumSystemVersion'] = bundle_info['LSMinimumSystemVersion']
        
        # Check for framework dependencies and embedded content
        frameworks = []
        for root, dirs, files in os.walk(binary_item.bundle_path):
            if 'Frameworks' in root:
                for item in dirs:
                    if item.endswith('.framework'):
                        frameworks.append(item)
        
        if frameworks:
            app_info['frameworks'] = frameworks
        
        return app_info
        
    except Exception as e:
        print(f"Error analyzing binary item {binary_item.bundle_path}: {e}", file=sys.stderr)
        return None


def scan_applications() -> List[Dict]:
    """Enhanced application scanning using the improved analyzer"""
    apps = []
    scanned_bundles = set()  # Prevent duplicates
    analyzer = AppAnalyzer()
    
    # Enable debug mode if needed
    # analyzer.debug = True
    
    # Scan multiple directories
    for applications_dir in get_additional_app_directories():
        try:
            print(f"Scanning directory: {applications_dir}", file=sys.stderr)
            
            # Use the enhanced analyzer to find all binary items
            binary_items = analyzer.obtain_binary_locations(applications_dir)
            
            for binary_item in binary_items:
                # Only process .app bundles for now
                if binary_item.binary_type != BinaryType.APP:
                    continue
                
                # Skip if already scanned
                if binary_item.bundle_path in scanned_bundles:
                    continue
                scanned_bundles.add(binary_item.bundle_path)
                
                # Analyze the binary item
                app_info = analyze_binary_item(binary_item)
                if app_info:
                    # Add location information
                    app_info['location'] = applications_dir
                    
                    # Only include iOS apps for decryption
                    if app_info['isIOS']:
                        apps.append(app_info)
                    # But also include interesting macOS apps with frameworks
                    elif app_info.get('frameworks') and len(app_info['frameworks']) > 0:
                        app_info['note'] = 'macOS app with embedded frameworks'
                        apps.append(app_info)
                    
        except PermissionError:
            print(f"Permission denied accessing {applications_dir}", file=sys.stderr)
        except Exception as e:
            print(f"Error scanning {applications_dir}: {e}", file=sys.stderr)
    
    # Sort by App Store apps first, then iOS apps, then by name
    apps.sort(key=lambda x: (
        not x.get('fromAppStore', False),
        not x.get('isIOS', False),
        x['name'].lower()
    ))
    
    return apps


def get_system_info() -> Dict:
    """Get system information relevant to CVE-2025-24204"""
    try:
        # Check macOS version
        version_output = subprocess.run(
            ["sw_vers", "-productVersion"],
            stdout=subprocess.PIPE,
            text=True
        ).stdout.strip()
        
        # Check if gcore has the required entitlement
        gcore_entitlements = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", "/usr/bin/gcore"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        ).stdout
        
        has_vulnerability = "com.apple.system-task-ports.read" in gcore_entitlements
        
        return {
            'macosVersion': version_output,
            'hasVulnerability': has_vulnerability,
            'gcoreAvailable': os.path.exists('/usr/bin/gcore')
        }
    except Exception as e:
        return {
            'macosVersion': 'unknown',
            'hasVulnerability': False,
            'gcoreAvailable': False,
            'error': str(e)
        }


def main():
    """Main function to scan and output results as JSON"""
    try:
        # Scan for applications
        apps = scan_applications()
        
        # Get system info
        system_info = get_system_info()
        
        # Output results as JSON
        result = {
            'apps': apps,
            'systemInfo': system_info,
            'totalApps': len(apps),
            'encryptedApps': len([app for app in apps if app['isEncrypted']]),
            'runningApps': len([app for app in apps if app['isRunning']])
        }
        
        print(json.dumps(result, indent=2))
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'apps': [],
            'systemInfo': {},
            'totalApps': 0,
            'encryptedApps': 0,
            'runningApps': 0
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()
