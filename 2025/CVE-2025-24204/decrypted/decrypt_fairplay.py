#!/usr/bin/env python3
"""
Enhanced FairPlay Decryptor using CVE-2025-24204
Based on the original decrypt-fairplay/main.py with improvements for GUI integration
"""

import os
import sys
import shutil
import subprocess
import glob
import re
import time
import platform
import json
import argparse
import lief
from typing import Tuple, List, Optional
from pathlib import Path


CORE_DUMP_PATH = "/tmp/dumped"
CORE_DUMP_PATH_TMP = f"{CORE_DUMP_PATH}.tmp"


class DecryptionError(Exception):
    """Custom exception for decryption errors"""
    pass


class ProgressReporter:
    """Helper class to report progress to the GUI"""
    
    def __init__(self):
        self.current_step = 0
        self.total_steps = 10
    
    def report(self, message: str, step: Optional[int] = None):
        """Report progress message"""
        if step is not None:
            self.current_step = step
        else:
            self.current_step += 1
        
        progress = (self.current_step / self.total_steps) * 100
        print(f"[PROGRESS:{progress:.1f}] {message}")
        sys.stdout.flush()


def check_macos_version() -> None:
    """Check if running on supported macOS version"""
    if platform.system() != "Darwin":
        raise DecryptionError("This script only works on macOS")

    version = platform.mac_ver()[0]
    version_parts = list(map(int, version.split(".")))

    if version_parts[0] != 15 or version_parts[1] < 0 or version_parts[1] > 2:
        raise DecryptionError(f"This script requires macOS 15.0-15.2 (current version: {version})")


def check_tools() -> None:
    """Check if required tools are available"""
    if subprocess.run(["which", "rabin2"], stdout=subprocess.PIPE).returncode != 0:
        raise DecryptionError("radare2 is not installed. Please install with: brew install radare2")


def check_root() -> None:
    """Check if running as root"""
    if os.geteuid() != 0:
        raise DecryptionError("This script must be run as root")


def cleanup() -> None:
    """Clean up temporary files"""
    for file in [CORE_DUMP_PATH, CORE_DUMP_PATH_TMP]:
        if os.path.exists(file):
            os.remove(file)


def get_nonwritable_regions(pid: int) -> List[Tuple[str, int, int, str]]:
    """Get non-writable memory regions for a process"""
    vmmap_output = subprocess.run(
        ["vmmap", "--wide", str(pid)], 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE
    ).stdout.decode()
    
    pattern = re.compile(
        r'^(\S.*?\S)\s+([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+\[.*?\]\s+\S+/\S+\s+\S+(?:\s+(.*))?$'
    )

    nonwritable_regions = []
    nonwritable_region_start = False
    
    for line in vmmap_output.split("\n"):
        if line.startswith("==== Non-writable regions for process"):
            nonwritable_region_start = True
            continue

        if line.startswith("==== Writable regions for process"):
            nonwritable_region_start = False
            continue

        if nonwritable_region_start:
            match = pattern.match(line)
            if match:
                region_type, start, end, detail = match.groups()
                nonwritable_regions.append((region_type, int(start, 16), int(end, 16), (detail or "").strip()))
    
    return nonwritable_regions


def launch_process(target_process: str, progress: ProgressReporter) -> int:
    """Launch target process and return its PID"""
    progress.report(f"Launching {target_process}...")
    
    subprocess.run(["open", "-j", "-g", "-a", target_process])
    time.sleep(5)
    
    process = subprocess.Popen(["pgrep", "-x", target_process], stdout=subprocess.PIPE)
    output = process.stdout.read().decode().strip()
    
    if not output:
        raise DecryptionError(f"Failed to launch or find process: {target_process}")
    
    pid = int(output)
    progress.report(f"Process {target_process} launched with PID {pid}")
    return pid


def dump_core(pid: int, progress: ProgressReporter) -> str:
    """Dump core file for the target process"""
    progress.report("Dumping process memory...")
    
    result = subprocess.run(
        ["gcore", "-d", "-v", "-o", CORE_DUMP_PATH, "-s", str(pid)],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise DecryptionError(f"Failed to dump core: {result.stderr}")

    if os.path.exists(CORE_DUMP_PATH) and os.path.getsize(CORE_DUMP_PATH) > 0:
        progress.report(f"Core file saved to {CORE_DUMP_PATH}")
        return CORE_DUMP_PATH

    if os.path.exists(CORE_DUMP_PATH_TMP) and os.path.getsize(CORE_DUMP_PATH_TMP) > 0:
        progress.report(f"Core file saved to {CORE_DUMP_PATH_TMP}")
        return CORE_DUMP_PATH_TMP

    raise DecryptionError("Failed to create core file")


def is_encrypted_binary(binary_path: str) -> Tuple[bool, Optional[lief.Binary]]:
    """Check if binary is encrypted and return LIEF binary object"""
    try:
        binary = lief.parse(binary_path)
        if binary is None or binary.format != lief.Binary.FORMATS.MACHO:
            return False, None
        
        for cmd in binary.commands:
            if cmd.command == lief.MachO.LoadCommand.TYPE.ENCRYPTION_INFO_64 and cmd.crypt_id == 1:
                return True, binary
        return False, None
    except Exception as e:
        raise DecryptionError(f"Failed to parse binary {binary_path}: {e}")


def get_app_path(target_process: str, progress: ProgressReporter) -> str:
    """Get application bundle path"""
    progress.report("Locating application bundle...")
    
    app_path = os.path.join("/Applications", f"{target_process}.app")
    if not os.path.exists(app_path):
        raise DecryptionError(f"Application not found: {app_path}")

    if not os.path.exists(os.path.join(app_path, "Wrapper")):
        raise DecryptionError("Application is not an iOS app")
    
    progress.report(f"Found application: {app_path}")
    return app_path


def get_encrypted_binaries(app_path: str, progress: ProgressReporter) -> List[Tuple[str, lief.Binary]]:
    """Find all encrypted binaries in the app"""
    progress.report("Scanning for encrypted binaries...")
    
    encrypted_binaries = []
    for root, _, files in os.walk(app_path):
        for file in files:
            file_path = os.path.join(root, file)
            is_encrypted, binary = is_encrypted_binary(file_path)
            if is_encrypted:
                encrypted_binaries.append((file_path, binary))

    if len(encrypted_binaries) == 0:
        raise DecryptionError("No encrypted binaries found")

    progress.report(f"Found {len(encrypted_binaries)} encrypted binaries")
    return encrypted_binaries


def get_crypto_info(binary: lief.Binary) -> Tuple[int, int]:
    """Extract cryptoff and cryptsize from binary"""
    for cmd in binary.commands:
        if cmd.command == lief.MachO.LoadCommand.TYPE.ENCRYPTION_INFO_64:
            return cmd.crypt_offset, cmd.crypt_size
    
    raise DecryptionError("Failed to get cryptoff and cryptsize")


def to_ios_path(path: str) -> Optional[str]:
    """Convert macOS path to iOS path"""
    wrapper_index = path.find("/Wrapper")
    if wrapper_index != -1:
        return path[wrapper_index + len("/Wrapper"):]
    return None


def get_decrypted_content(
    encrypted_binary_path: str, 
    encrypted_binary: lief.Binary, 
    core_file: lief.Binary, 
    nonwritable_regions: List[Tuple[str, int, int, str]], 
    cryptoff: int, 
    cryptsize: int
) -> Optional[bytes]:
    """Extract decrypted content from core file"""
    ios_path = to_ios_path(encrypted_binary_path)
    if ios_path is None:
        raise DecryptionError("Failed to convert path to iOS path")

    segment_content = b""
    segment_with_encrypted_content = encrypted_binary.segment_from_offset(cryptoff)
    
    for region_type, start, _, detail in nonwritable_regions:
        if region_type == segment_with_encrypted_content.name and detail.endswith(ios_path):
            segment = core_file.segment_from_virtual_address(start)
            segment_content += bytearray(segment.content)

    if segment_content:
        return segment_content[
            cryptoff - segment_with_encrypted_content.file_offset:
            cryptoff + cryptsize - segment_with_encrypted_content.file_offset
        ]
    return None


def get_cryptid_offset(executable_path: str) -> int:
    """Get cryptid offset using rabin2"""
    # Get base address
    process = subprocess.Popen(
        ["rabin2", "-I", executable_path], 
        stdout=subprocess.PIPE
    )
    output = process.stdout.read().decode()
    baddr_match = re.search(r"baddr\s+0x([0-9a-f]+)", output)
    if not baddr_match:
        raise DecryptionError("Failed to get base address")
    baddr = int(baddr_match.group(1), 16)

    # Get cryptid virtual address
    process = subprocess.Popen(
        ["rabin2", "-H", executable_path], 
        stdout=subprocess.PIPE
    )
    output = process.stdout.read().decode()
    cryptid_match = re.search(r"0x([0-9a-f]+)\s+cryptid\s+", output)
    if not cryptid_match:
        raise DecryptionError("Failed to get cryptid address")
    cryptid_vaddr = int(cryptid_match.group(1), 16)

    return cryptid_vaddr - baddr


def create_ipa_file(
    app_path: str,
    decrypted_binaries: List[Tuple[str, str]],
    signing_identity: str,
    profile_path: str,
    entitlements_path: str,
    progress: ProgressReporter
) -> None:
    """Create IPA file with decrypted binaries"""
    progress.report("Creating IPA file...")
    
    app_exec_name = os.path.basename(app_path).split(".")[0]
    dest_app_path = f"./Payload/{os.path.basename(app_path)}"

    # Clean up previous builds
    subprocess.run(["rm", "-rf", "Payload"], check=True)
    subprocess.run(["rm", "-f", f"{app_exec_name}.ipa"], check=True)

    login_user = os.getlogin()

    # Copy original app content
    progress.report("Copying application content...")
    subprocess.run(["sudo", "-u", login_user, "mkdir", "Payload"], check=True)
    subprocess.run(["sudo", "-u", login_user, "cp", "-R", app_path, dest_app_path], check=True)

    # Copy decrypted executables
    progress.report("Installing decrypted binaries...")
    for ios_path, decrypted_executable_path in decrypted_binaries:
        target_path = os.path.join("./Payload", ios_path)
        subprocess.run(
            ["sudo", "-u", login_user, "cp", decrypted_executable_path, target_path],
            check=True
        )

    # Copy provisioning profile
    subprocess.run(
        ["sudo", "-u", login_user, "cp", profile_path, 
         os.path.join(dest_app_path, "embedded.provisionprofile")],
        check=True
    )

    # Re-sign frameworks
    progress.report("Re-signing frameworks...")
    for framework_path in glob.glob(os.path.join(dest_app_path, "Frameworks", "*")):
        subprocess.run(
            ["sudo", "-u", login_user, "codesign", "--force", "--sign", signing_identity, 
             "--entitlements", entitlements_path, framework_path],
            check=True
        )

    # Re-sign main executable
    progress.report("Re-signing main executable...")
    subprocess.run(
        ["sudo", "-u", login_user, "codesign", "--force", "--sign", signing_identity, 
         "--entitlements", entitlements_path, dest_app_path],
        check=True
    )

    # Create IPA file
    progress.report("Packaging IPA...")
    subprocess.run(
        ["sudo", "-u", login_user, "zip", "-r", f"{app_exec_name}.ipa", "Payload"],
        check=True
    )
    
    progress.report(f"IPA file created: {app_exec_name}.ipa")


def main():
    """Main decryption function"""
    parser = argparse.ArgumentParser(description="Decrypt FairPlay-protected iOS apps")
    parser.add_argument("target_process", help="Target process name")
    parser.add_argument("-s", "--signing-identity", required=True, 
                       help="Signing identity for re-signing")
    parser.add_argument("-p", "--profile", required=True, 
                       help="Path to provisioning profile")
    parser.add_argument("-e", "--entitlements", required=True, 
                       help="Path to entitlements file")
    
    args = parser.parse_args()
    
    progress = ProgressReporter()
    
    try:
        # Initial checks
        progress.report("Performing system checks...", 1)
        check_root()
        check_macos_version()
        check_tools()
        cleanup()

        # Launch and analyze target process
        pid = launch_process(args.target_process, progress)
        app_path = get_app_path(args.target_process, progress)
        nonwritable_regions = get_nonwritable_regions(pid)

        # Dump core
        core_file_path = dump_core(pid, progress)
        core_file = lief.parse(core_file_path)

        # Process encrypted binaries
        encrypted_binaries = get_encrypted_binaries(app_path, progress)
        decrypted_binaries = []
        
        for i, (binary_path, binary) in enumerate(encrypted_binaries):
            progress.report(f"Processing binary {i+1}/{len(encrypted_binaries)}: {os.path.basename(binary_path)}")
            
            cryptoff, cryptsize = get_crypto_info(binary)
            decrypted_content = get_decrypted_content(
                binary_path, binary, core_file, nonwritable_regions, cryptoff, cryptsize
            )
            
            if decrypted_content is None:
                progress.report(f"Warning: Could not decrypt {os.path.basename(binary_path)}")
                continue

            # Create decrypted binary
            output_path = f"/tmp/{os.path.basename(binary_path)}.decrypted"
            shutil.copy(binary_path, output_path)

            # Write decrypted content
            with open(output_path, "r+b") as dst:
                dst.seek(cryptoff)
                dst.write(decrypted_content)

            # Patch cryptid
            cryptid_offset = get_cryptid_offset(binary_path)
            with open(output_path, "r+b") as f:
                f.seek(cryptid_offset)
                f.write(b"\x00")

            decrypted_binaries.append((to_ios_path(binary_path)[1:], output_path))

        if not decrypted_binaries:
            raise DecryptionError("No binaries were successfully decrypted")

        # Create IPA
        wrapped_app_path = os.path.join(app_path, "Wrapper", os.path.basename(app_path))
        create_ipa_file(
            wrapped_app_path, 
            decrypted_binaries, 
            args.signing_identity, 
            args.profile, 
            args.entitlements,
            progress
        )
        
        progress.report("Decryption completed successfully!", 10)

    except DecryptionError as e:
        progress.report(f"Error: {e}")
        sys.exit(1)
    except Exception as e:
        progress.report(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
