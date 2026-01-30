#!/usr/bin/env python3
"""
Android Data Directory Monitor with APK Support
Automatically extracts package name from APK and monitors /data/data/ directory
"""

import subprocess
import os
import sys
import time
import json
import hashlib
import re
import tempfile
from pathlib import Path
import argparse
from datetime import datetime
from collections import defaultdict
import zipfile
import xml.etree.ElementTree as ET

class AndroidDataMonitor:
    def __init__(self, package_name=None, apk_path=None, output_file="data_changes.log", interval=2):
        self.apk_path = apk_path
        self.package_name = package_name
        self.output_file = output_file
        self.interval = interval
        
        # If APK is provided, extract package name
        if apk_path and not package_name:
            self.package_name = self.extract_package_from_apk(apk_path)
            if not self.package_name:
                print("[!] Failed to extract package name from APK")
                sys.exit(1)
        
        if not self.package_name:
            print("[!] Package name is required")
            sys.exit(1)
            
        self.data_path = f"/data/data/{self.package_name}"
        self.snapshot = {}
        self.history = []
        self.first_run = True
        self.known_files = set()
        self.file_hashes = {}
        self.change_count = 0
        
        # Ensure ADB is connected
        if not self.check_adb():
            print("[!] ADB not connected. Please connect a device.")
            sys.exit(1)
    
    def extract_package_from_apk(self, apk_path):
        """Extract package name from APK using multiple methods"""
        print(f"[*] Extracting package name from: {apk_path}")
        
        # Method 1: Use aapt2 (Android SDK)
        package = self.extract_with_aapt(apk_path)
        if package:
            print(f"[+] Package name found via aapt: {package}")
            return package
        
        # Method 2: Use apktool
        package = self.extract_with_apktool(apk_path)
        if package:
            print(f"[+] Package name found via apktool: {package}")
            return package
        
        # Method 3: Parse AndroidManifest.xml from APK
        package = self.extract_from_zip(apk_path)
        if package:
            print(f"[+] Package name found via zip parsing: {package}")
            return package
        
        return None
    
    def extract_with_aapt(self, apk_path):
        """Extract package name using aapt2"""
        try:
            cmd = ["aapt2", "dump", "badging", apk_path]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line.startswith('package: name='):
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            return match.group(1)
        except Exception as e:
            if self.verbose:
                print(f"[!] aapt2 failed: {e}")
        return None
    
    def extract_with_apktool(self, apk_path):
        """Extract package name using apktool"""
        try:
            # Create temp directory
            with tempfile.TemporaryDirectory() as temp_dir:
                cmd = ["apktool", "d", apk_path, "-o", temp_dir, "-f", "-s"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    manifest_path = os.path.join(temp_dir, "AndroidManifest.xml")
                    if os.path.exists(manifest_path):
                        with open(manifest_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        match = re.search(r'package=["\']([^"\']+)["\']', content)
                        if match:
                            return match.group(1)
        except Exception as e:
            if self.verbose:
                print(f"[!] apktool failed: {e}")
        return None
    
    def extract_from_zip(self, apk_path):
        """Extract package name directly from APK zip"""
        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # Look for AndroidManifest.xml
                for file_info in apk_zip.infolist():
                    if 'AndroidManifest.xml' in file_info.filename:
                        # Read and decode binary AndroidManifest
                        manifest_data = apk_zip.read(file_info.filename)
                        
                        # Try to find package in binary data
                        # AndroidManifest has package name in binary format
                        # Simple string search (might work for some APKs)
                        manifest_str = manifest_data.decode('latin-1', errors='ignore')
                        match = re.search(r'package=["\']([^"\']+)["\']', manifest_str)
                        if match:
                            return match.group(1)
                        
                        # Try another pattern
                        match = re.search(r'package=([^\s]+)', manifest_str)
                        if match:
                            return match.group(1).strip('"\'')
        except Exception as e:
            if self.verbose:
                print(f"[!] Zip parsing failed: {e}")
        return None
    
    def check_adb(self):
        """Check if ADB is connected"""
        try:
            result = subprocess.run(["adb", "devices"], capture_output=True, text=True)
            return "device" in result.stdout
        except:
            return False
    
    def install_apk_if_needed(self):
        """Install APK if not already installed"""
        print(f"[*] Checking if {self.package_name} is installed...")
        
        # Check if app is installed
        cmd = f"pm list packages | grep {self.package_name}"
        result = self.run_adb_shell(cmd)
        
        if self.package_name in result:
            print(f"[+] App already installed: {self.package_name}")
            return True
        else:
            if self.apk_path and os.path.exists(self.apk_path):
                print(f"[*] Installing APK: {self.apk_path}")
                install_result = subprocess.run(["adb", "install", "-r", self.apk_path], 
                                               capture_output=True, text=True)
                if "Success" in install_result.stdout:
                    print(f"[+] APK installed successfully")
                    return True
                else:
                    print(f"[!] Failed to install APK: {install_result.stdout}")
                    return False
            else:
                print(f"[!] APK not found: {self.apk_path}")
                return False
    
    def run_adb_shell(self, command):
        """Execute ADB shell command"""
        try:
            cmd = ["adb", "shell", command]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            return result.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""
        except Exception as e:
            return f"ERROR: {str(e)}"
    
    def get_app_info(self):
        """Get app information from device"""
        print(f"\n[*] App Information for {self.package_name}:")
        print("-" * 50)
        
        # Get app version
        version_cmd = f"dumpsys package {self.package_name} | grep versionName"
        version = self.run_adb_shell(version_cmd)
        if version:
            print(f"Version: {version}")
        
        # Get app data directory info
        dir_cmd = f"ls -la {self.data_path}"
        dir_info = self.run_adb_shell(dir_cmd)
        if dir_info and not "ERROR" in dir_info:
            print(f"Data directory exists: {self.data_path}")
        
        # Get app permissions
        perm_cmd = f"dumpsys package {self.package_name} | grep permission"
        perms = self.run_adb_shell(perm_cmd)
        if perms:
            lines = [line.strip() for line in perms.split('\n') if line.strip()]
            print(f"Permissions: {len(lines)} permissions found")
        
        print("-" * 50)
    
    def get_file_list(self):
        """Get recursive file list from app data directory"""
        # Use find command to get all files and directories
        find_cmd = f"find {self.data_path} -type f 2>/dev/null"
        output = self.run_adb_shell(find_cmd)
        
        if not output or "ERROR" in output:
            return []
        
        files = output.split('\n')
        return [f.strip() for f in files if f.strip()]
    
    def get_file_info(self, file_path):
        """Get detailed info about a file"""
        # Get file permissions, size, and modification time
        stat_cmd = f"stat -c '%a %s %Y' {file_path} 2>/dev/null"
        stat_output = self.run_adb_shell(stat_cmd)
        
        if not stat_output or "ERROR" in stat_output:
            return None
        
        try:
            perms, size, mtime = stat_output.split()
            return {
                'path': file_path,
                'permissions': perms,
                'size': int(size),
                'mtime': int(mtime),
                'exists': True
            }
        except:
            return None
    
    def get_file_content_hash(self, file_path):
        """Get hash of file content (if readable)"""
        # Try to read file content and hash it
        cat_cmd = f"cat {file_path} 2>/dev/null | md5sum"
        hash_output = self.run_adb_shell(cat_cmd)
        
        if hash_output and not "ERROR" in hash_output and hash_output.strip():
            # md5sum outputs "hash -" or "hash filename"
            hash_value = hash_output.split()[0]
            return hash_value
        
        return None
    
    def get_directory_structure(self):
        """Get full directory structure with file info"""
        files = self.get_file_list()
        structure = {}
        
        for file_path in files:
            info = self.get_file_info(file_path)
            if info:
                structure[file_path] = info
                # Get content hash for certain file types
                if file_path.endswith(('.db', '.sqlite', '.xml', '.txt', '.json', '.properties', '.prefs')):
                    content_hash = self.get_file_content_hash(file_path)
                    if content_hash:
                        info['content_hash'] = content_hash
        
        return structure
    
    def compare_snapshots(self, old_snap, new_snap):
        """Compare two snapshots and detect changes"""
        changes = {
            'created': [],
            'deleted': [],
            'modified': [],
            'permission_changed': [],
            'size_changed': []
        }
        
        old_files = set(old_snap.keys())
        new_files = set(new_snap.keys())
        
        # Find created files
        for file in new_files - old_files:
            changes['created'].append({
                'path': file,
                'info': new_snap[file]
            })
        
        # Find deleted files
        for file in old_files - new_files:
            changes['deleted'].append({
                'path': file,
                'info': old_snap[file]
            })
        
        # Find modified files
        for file in old_files & new_files:
            old_info = old_snap[file]
            new_info = new_snap[file]
            
            # Check if modified (mtime changed)
            if old_info['mtime'] != new_info['mtime']:
                change_detail = {
                    'path': file,
                    'old_mtime': old_info['mtime'],
                    'new_mtime': new_info['mtime'],
                    'old_size': old_info['size'],
                    'new_size': new_info['size']
                }
                
                # Check content hash if available
                if 'content_hash' in old_info and 'content_hash' in new_info:
                    if old_info['content_hash'] != new_info['content_hash']:
                        change_detail['content_changed'] = True
                        change_detail['old_hash'] = old_info['content_hash']
                        change_detail['new_hash'] = new_info['content_hash']
                
                # Check permission changes
                if old_info['permissions'] != new_info['permissions']:
                    changes['permission_changed'].append({
                        'path': file,
                        'old_perms': old_info['permissions'],
                        'new_perms': new_info['permissions']
                    })
                
                # Check size changes
                if old_info['size'] != new_info['size']:
                    changes['size_changed'].append({
                        'path': file,
                        'old_size': old_info['size'],
                        'new_size': new_info['size']
                    })
                
                changes['modified'].append(change_detail)
        
        return changes
    
    def analyze_file_content(self, file_path):
        """Analyze file content for sensitive data patterns"""
        patterns = {
            'password': ['password', 'passwd', 'pwd', 'secret'],
            'token': ['token', 'auth', 'access_token', 'refresh_token'],
            'key': ['key', 'api_key', 'secret_key', 'private_key'],
            'email': ['@', 'email', 'mail'],
            'phone': ['phone', 'mobile', 'tel'],
            'credit_card': ['card', 'credit', 'expiry', 'cvv'],
            'ssn': ['ssn', 'social', 'security'],
            'database': ['.db', '.sqlite', '.sqlite3']
        }
        
        # Read file content
        cat_cmd = f"cat {file_path} 2>/dev/null | head -100"
        content = self.run_adb_shell(cat_cmd)
        
        if not content or "ERROR" in content:
            return []
        
        findings = []
        content_lower = content.lower()
        
        for category, keywords in patterns.items():
            for keyword in keywords:
                if keyword in content_lower:
                    # Get some context
                    idx = content_lower.find(keyword)
                    start = max(0, idx - 20)
                    end = min(len(content), idx + len(keyword) + 20)
                    context = content[start:end].replace('\n', ' ')
                    
                    findings.append({
                        'category': category,
                        'keyword': keyword,
                        'context': context
                    })
                    break
        
        return findings
    
    def monitor_specific_files(self, file_types=None):
        """Monitor specific file types for changes"""
        if file_types is None:
            file_types = ['.db', '.sqlite', '.xml', '.txt', '.json', '.properties', '.prefs']
        
        current_files = self.get_file_list()
        
        for file_path in current_files:
            for file_type in file_types:
                if file_path.endswith(file_type):
                    self.monitor_file_content(file_path)
                    break
    
    def monitor_file_content(self, file_path):
        """Monitor specific file for content changes"""
        current_hash = self.get_file_content_hash(file_path)
        
        if file_path in self.file_hashes:
            if current_hash != self.file_hashes[file_path]:
                # Content changed
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"\n[{timestamp}] [!] Content changed in: {file_path}")
                
                # Analyze for sensitive data
                findings = self.analyze_file_content(file_path)
                if findings:
                    print(f"[!] Sensitive data found in {file_path}:")
                    for finding in findings[:3]:  # Show first 3 findings
                        print(f"    - {finding['category'].upper()}: {finding['context']}")
                
                # Update hash
                self.file_hashes[file_path] = current_hash
        else:
            # New file or first time seeing it
            if current_hash:
                timestamp = datetime.now().strftime('%H:%M:%S')
                print(f"\n[{timestamp}] [+] New file detected: {file_path}")
                
                # Analyze initial content
                findings = self.analyze_file_content(file_path)
                if findings:
                    print(f"[!] Sensitive data in new file {file_path}:")
                    for finding in findings[:3]:
                        print(f"    - {finding['category'].upper()}: {finding['context']}")
                
                # Store hash
                self.file_hashes[file_path] = current_hash
    
    def log_changes(self, changes, timestamp):
        """Log changes to file"""
        log_entry = {
            'timestamp': timestamp.isoformat(),
            'changes': changes
        }
        
        # Append to history
        self.history.append(log_entry)
        
        # Write to log file
        with open(self.output_file, 'a') as f:
            f.write(json.dumps(log_entry, indent=2) + "\n")
        
        # Also print to console
        self.print_changes(changes, timestamp)
    
    def print_changes(self, changes, timestamp):
        """Print changes to console"""
        if not any(changes[key] for key in changes):
            return
        
        print(f"\n[{timestamp.strftime('%H:%M:%S')}] Changes detected:")
        
        if changes['created']:
            print(f"  [+] {len(changes['created'])} files created:")
            for change in changes['created'][:3]:
                file_type = Path(change['path']).suffix
                print(f"      {change['path']} ({change['info']['size']} bytes)")
                
                # Check for sensitive data in new files
                findings = self.analyze_file_content(change['path'])
                if findings:
                    categories = set(f['category'] for f in findings)
                    print(f"      ! Contains: {', '.join(categories)}")
        
        if changes['deleted']:
            print(f"  [-] {len(changes['deleted'])} files deleted:")
            for change in changes['deleted'][:3]:
                print(f"      {change['path']}")
        
        if changes['modified']:
            print(f"  [*] {len(changes['modified'])} files modified:")
            for change in changes['modified'][:3]:
                print(f"      {change['path']}")
    
    def generate_report(self):
        """Generate summary report"""
        print("\n" + "="*60)
        print("DATA MONITORING REPORT")
        print("="*60)
        print(f"Package: {self.package_name}")
        print(f"APK: {self.apk_path or 'N/A'}")
        print(f"Monitoring snapshots: {len(self.history)}")
        print(f"Total changes detected: {self.change_count}")
        
        # Find files that changed most frequently
        change_counts = defaultdict(int)
        for entry in self.history:
            for change_type, changes in entry['changes'].items():
                if isinstance(changes, list):
                    for change in changes:
                        if 'path' in change:
                            change_counts[change['path']] += 1
        
        if change_counts:
            print("\nMost frequently changed files:")
            sorted_files = sorted(change_counts.items(), key=lambda x: x[1], reverse=True)[:5]
            for file_path, count in sorted_files:
                print(f"  {count:3} changes: {file_path}")
        
        # List sensitive files found
        sensitive_files = {}
        all_files = self.get_file_list()
        for file_path in all_files:
            if any(ext in file_path for ext in ['.db', '.xml', '.txt', '.prefs', '.sqlite']):
                findings = self.analyze_file_content(file_path)
                if findings:
                    sensitive_files[file_path] = [f['category'] for f in findings]
        
        if sensitive_files:
            print("\nFiles containing sensitive data:")
            for file_path, categories in sensitive_files.items():
                print(f"  - {file_path}")
                print(f"    Categories: {', '.join(set(categories))}")
        
        print("\n" + "="*60)
        print(f"[*] Log saved to: {self.output_file}")
        print(f"[*] You can analyze the log with: python3 -m json.tool {self.output_file}")
    
    def run(self, duration=None, continuous=False):
        """Main monitoring loop"""
        print(f"[*] Starting monitoring for: {self.package_name}")
        if self.apk_path:
            print(f"[*] Source APK: {self.apk_path}")
        
        # Install APK if provided and not installed
        if self.apk_path:
            if not self.install_apk_if_needed():
                print("[!] Cannot proceed without installed app")
                return
        
        # Show app info
        self.get_app_info()
        
        print(f"[*] Data directory: {self.data_path}")
        print(f"[*] Monitoring interval: {self.interval} seconds")
        print(f"[*] Output log: {self.output_file}")
        print("[*] Press Ctrl+C to stop")
        print("[*] Start interacting with the app to see changes\n")
        
        start_time = time.time()
        snapshot_count = 0
        
        try:
            # Initial snapshot
            self.snapshot = self.get_directory_structure()
            initial_count = len(self.snapshot)
            print(f"[*] Initial snapshot: {initial_count} files")
            
            # Show interesting files immediately
            interesting_files = [f for f in self.snapshot.keys() 
                                if any(ext in f for ext in ['.db', '.sqlite', '.xml', '.prefs'])]
            if interesting_files:
                print(f"[*] Found {len(interesting_files)} interesting files:")
                for f in interesting_files[:5]:
                    print(f"    - {f}")
            
            while True:
                time.sleep(self.interval)
                snapshot_count += 1
                
                # Take new snapshot
                new_snapshot = self.get_directory_structure()
                timestamp = datetime.now()
                
                # Compare with previous snapshot
                changes = self.compare_snapshots(self.snapshot, new_snapshot)
                
                # Log changes if any
                any_changes = any(changes[key] for key in changes)
                if any_changes:
                    self.log_changes(changes, timestamp)
                    self.change_count += 1
                
                # Monitor specific file content
                self.monitor_specific_files()
                
                # Update snapshot
                self.snapshot = new_snapshot
                
                # Check if duration limit reached
                if duration and (time.time() - start_time) > duration:
                    print(f"\n[*] Monitoring duration reached ({duration} seconds)")
                    break
                
                # Show status every 20 snapshots
                if snapshot_count % 20 == 0:
                    current_time = datetime.now().strftime('%H:%M:%S')
                    print(f"[{current_time}] Status: {snapshot_count} snapshots, {self.change_count} changes")
                
        except KeyboardInterrupt:
            print("\n[*] Monitoring stopped by user")
        
        finally:
            # Generate report
            self.generate_report()
            
            # Save final snapshot
            snapshot_file = f"{self.package_name}_final_snapshot.json"
            with open(snapshot_file, 'w') as f:
                json.dump(self.snapshot, f, indent=2)
            
            print(f"[*] Final snapshot saved to {snapshot_file}")

def main():
    parser = argparse.ArgumentParser(
        description='Android Data Directory Monitor - Supports APK files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -p com.example.app
  %(prog)s -a app.apk
  %(prog)s -a app.apk -i 1 -d 60
  %(prog)s -a app.apk -o custom.log
        """
    )
    
    # Package and APK options (mutually exclusive group)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-p', '--package', help='Package name to monitor')
    group.add_argument('-a', '--apk', help='Path to APK file (will extract package automatically)')
    
    parser.add_argument('-i', '--interval', type=float, default=2.0, 
                       help='Monitoring interval in seconds (default: 2)')
    parser.add_argument('-d', '--duration', type=int, 
                       help='Monitoring duration in seconds')
    parser.add_argument('-o', '--output', default="data_changes.log",
                       help='Output log file (default: data_changes.log)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Create monitor instance
    monitor = AndroidDataMonitor(
        package_name=args.package,
        apk_path=args.apk,
        output_file=args.output,
        interval=args.interval
    )
    
    # Start monitoring
    monitor.run(duration=args.duration)

if __name__ == "__main__":
    main()
