"""
PS4 Klog Crash Logger
Monitors PS4 kernel logs for crashes and saves them to files
"""

import socket
import datetime
import os
import json
import re
import sys
import time
from pathlib import Path

print("PS4 Crash Logger Starting...")

# Configuration
CONFIG_FILE = "ps4_ips.json"
PS4_PORT = 3232
LOG_DIR = "crash_logs"
BUFFER_SIZE = 8192
VERBOSE_MODE = True  # Set to True to see all klog messages, False for crashes only

# Crash-related keywords to filter
CRASH_KEYWORDS = [
    b'panic',
    b'crash',
    b'fatal',
    b'exception',
    b'segfault',
    b'SIGSEGV',
    b'SIGABRT',
    b'SIGILL',
    b'SIGFPE',
    b'kernel trap',
    b'page fault',
    b'trap',
    b'abort',
    b'core dump',
    b'signal',
]

class IPManager:
    def __init__(self, config_file):
        self.config_file = config_file
        self.ips = self.load_ips()
    
    def load_ips(self):
        """Load saved IPs from config file"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    data = json.load(f)
                    return data.get('ips', [])
            except:
                return []
        return []
    
    def save_ips(self):
        """Save IPs to config file"""
        try:
            with open(self.config_file, 'w') as f:
                json.dump({'ips': self.ips}, f, indent=2)
        except Exception as e:
            print(f"[-] Warning: Could not save IPs to config: {e}")
    
    def add_ip(self, ip):
        """Add a new IP to the list"""
        if ip not in self.ips:
            self.ips.append(ip)
            self.save_ips()
    
    def is_valid_ip(self, ip):
        """Validate IP address format"""
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if not re.match(pattern, ip):
            return False
        parts = ip.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    
    def get_ip_choice(self):
        """Interactive IP selection"""
        print("\n" + "=" * 80)
        print("PS4 IP Configuration")
        print("=" * 80)
        
        if self.ips:
            print("\nSaved PS4 IPs:")
            for idx, ip in enumerate(self.ips, 1):
                print(f"  [{idx}] {ip}")
            print(f"  [N] Enter a new IP address")
            print(f"  [Q] Quit")
            
            while True:
                choice = input("\nSelect an option: ").strip().upper()
                
                if choice == 'Q':
                    print("Exiting...")
                    sys.exit(0)
                
                if choice == 'N':
                    return self.prompt_new_ip()
                
                try:
                    idx = int(choice)
                    if 1 <= idx <= len(self.ips):
                        selected_ip = self.ips[idx - 1]
                        print(f"\n[*] Using IP: {selected_ip}")
                        return selected_ip
                    else:
                        print(f"[-] Invalid choice. Enter 1-{len(self.ips)}, N, or Q")
                except ValueError:
                    print(f"[-] Invalid choice. Enter 1-{len(self.ips)}, N, or Q")
        else:
            print("\nNo saved IPs found.")
            return self.prompt_new_ip()
    
    def prompt_new_ip(self):
        """Prompt user for a new IP address"""
        while True:
            ip = input("\nEnter PS4 IP address (or Q to quit): ").strip()
            
            if ip.upper() == 'Q':
                print("Exiting...")
                sys.exit(0)
            
            if self.is_valid_ip(ip):
                self.add_ip(ip)
                print(f"[+] IP {ip} saved!")
                return ip
            else:
                print("[-] Invalid IP address format. Please use format: 192.168.1.150")

class PS4CrashLogger:
    def __init__(self, ip, port, log_dir):
        self.ip = ip
        self.port = port
        self.log_dir = Path(log_dir)
        self.sock = None
        self.current_crash_buffer = []
        self.crash_context_lines = 30  # Increased to capture more context
        self.line_buffer = []
        self.message_count = 0
        self.last_heartbeat = datetime.datetime.now()
        
        # Crash sequence tracking
        self.in_crash_sequence = False
        self.crash_start_time = None
        self.crash_sequence_timeout = 2.0  # Wait 2 seconds after last crash line
        self.crash_buffer = []
        
        # Create log directory if it doesn't exist
        self.log_dir.mkdir(exist_ok=True)
        
    def connect(self):
        """Connect to PS4 klog socket"""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5)  # Longer timeout for connection
            print(f"\n[*] Connecting to PS4 at {self.ip}:{self.port}...")
            self.sock.connect((self.ip, self.port))
            # After connection, use shorter timeout for receiving
            self.sock.settimeout(1)
            print(f"[+] Connected successfully!")
            return True
        except socket.timeout:
            print(f"[-] Connection timeout. Is the PS4 at {self.ip}:{self.port} accessible?")
            return False
        except ConnectionRefusedError:
            print(f"[-] Connection refused. Is klog enabled on your PS4?")
            return False
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def is_crash_line(self, line):
        """Check if a line contains crash-related keywords"""
        line_lower = line.lower()
        return any(keyword.decode().lower() in line_lower for keyword in CRASH_KEYWORDS)
    
    def is_crash_start(self, line):
        """Check if this is the actual start of a crash dump"""
        stripped = line.strip()
        return "A user thread receives a fatal signal" in stripped or stripped.startswith("# signal:")
    
    def is_crash_end_marker(self, line):
        """Check if this line marks the end of a crash dump (dynamic libraries section ends)"""
        stripped = line.strip()
        # End when we see system messages after the crash dump
        return (not stripped.startswith("#") and 
                any(marker in stripped for marker in ["[Syscore App]", "[SceLncService]", "[Crash Reporter]"]))
    
    def save_crash_log(self, crash_data):
        """Save crash data to a timestamped file"""
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = self.log_dir / f"crash_{timestamp}.log"
        
        try:
            with open(filename, 'w', encoding='utf-8', errors='replace') as f:
                f.write("=" * 80 + "\n")
                f.write(f"PS4 CRASH REPORT - {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"PS4 IP: {self.ip}\n")
                f.write("=" * 80 + "\n\n")
                f.writelines(crash_data)
                f.write("\n" + "=" * 80 + "\n")
            
            print(f"[!] Crash log saved: {filename}")
            return filename
        except Exception as e:
            print(f"[-] Error saving crash log: {e}")
            return None
    
    def check_crash_sequence_timeout(self):
        """Check if crash sequence has timed out and should be saved"""
        if self.in_crash_sequence and self.crash_start_time:
            elapsed = time.time() - self.crash_start_time
            if elapsed >= self.crash_sequence_timeout:
                # Save the complete crash sequence
                print(f"[!] Complete crash sequence captured ({len(self.crash_buffer)} lines)")
                self.save_crash_log(self.crash_buffer)
                
                # Reset crash tracking
                self.in_crash_sequence = False
                self.crash_buffer = []
                self.crash_start_time = None
    
    def process_data(self, data):
        """Process incoming klog data and detect crashes"""
        try:
            # Decode data, replacing invalid characters
            text = data.decode('utf-8', errors='replace')
            lines = text.split('\n')
            
            for line in lines:
                if not line.strip():
                    continue
                
                self.message_count += 1
                
                # In verbose mode, print all messages
                if VERBOSE_MODE:
                    print(f"[{self.message_count}] {line.strip()}")
                
                # Add to circular buffer for context (lines before crash)
                self.line_buffer.append(line + '\n')
                if len(self.line_buffer) > self.crash_context_lines:
                    self.line_buffer.pop(0)
                
                # Check if this line indicates a crash
                if self.is_crash_line(line):
                    if not self.in_crash_sequence:
                        # Check if this is the actual crash start marker
                        if self.is_crash_start(line):
                            # Start of new crash sequence
                            print(f"\n[!] CRASH DETECTED - Capturing crash dump...")
                            self.in_crash_sequence = True
                            self.crash_start_time = time.time()
                            
                            # Start fresh - only include crash data
                            self.crash_buffer = ["#\n"]  # Add marker at start
                            self.crash_buffer.append(line + '\n')
                        # Ignore other crash keywords that aren't the actual start
                    else:
                        # Continue existing crash sequence
                        if line + '\n' not in self.crash_buffer:
                            self.crash_buffer.append(line + '\n')
                        # Reset timeout since we got more crash data
                        self.crash_start_time = time.time()
                
                elif self.in_crash_sequence:
                    # We're in a crash sequence
                    # Only capture lines that start with "#" (actual crash dump data)
                    stripped = line.strip()
                    if stripped.startswith("#"):
                        if line + '\n' not in self.crash_buffer:
                            self.crash_buffer.append(line + '\n')
                        # Reset timeout on each new line
                        self.crash_start_time = time.time()
                    else:
                        # Non-# line means crash dump ended, save immediately
                        print(f"[!] Complete crash dump captured ({len(self.crash_buffer)} lines)")
                        self.save_crash_log(self.crash_buffer)
                        
                        # Reset crash tracking
                        self.in_crash_sequence = False
                        self.crash_buffer = []
                        self.crash_start_time = None
                    
        except Exception as e:
            print(f"[-] Error processing data: {e}")
    
    def listen(self):
        """Main listening loop"""
        print(f"\n[*] Listening for crashes on {self.ip}:{self.port}")
        print(f"[*] Logs will be saved to: {self.log_dir.absolute()}")
        if VERBOSE_MODE:
            print("[*] VERBOSE MODE: All klog messages will be displayed")
        print("[*] Press Ctrl+C to stop\n")
        
        try:
            while True:
                try:
                    data = self.sock.recv(BUFFER_SIZE)
                    if not data:
                        print("[-] Connection closed by PS4")
                        break
                    
                    self.process_data(data)
                    
                    # Check if crash sequence has timed out
                    self.check_crash_sequence_timeout()
                    
                    # Print heartbeat every 30 seconds if not in verbose mode
                    if not VERBOSE_MODE:
                        now = datetime.datetime.now()
                        if (now - self.last_heartbeat).seconds >= 30:
                            print(f"[*] Still listening... ({self.message_count} messages received)")
                            self.last_heartbeat = now
                    
                except socket.timeout:
                    # Timeout is expected, continue listening
                    # But check for crash sequence timeout
                    self.check_crash_sequence_timeout()
                    continue
                    
        except KeyboardInterrupt:
            print(f"\n[*] Stopping crash logger... (Total messages: {self.message_count})")
        except Exception as e:
            print(f"[-] Error during listening: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Clean up resources"""
        if self.sock:
            self.sock.close()
            print("[*] Connection closed")
    
    def run(self):
        """Main entry point"""
        if self.connect():
            self.listen()
        else:
            print("\n[!] Failed to connect. Make sure:")
            print("    1. Your PS4 is jailbroken and klog is enabled")
            print("    2. The IP address is correct")
            print("    3. The port is correct (currently set to {})".format(self.port))
            print("    4. Your firewall isn't blocking the connection")
            print("\nTry selecting a different IP or checking your PS4 settings.")

def main():
    print("=" * 80)
    print("PS4 Klog Crash Logger")
    print("=" * 80)
    
    # IP Management
    ip_manager = IPManager(CONFIG_FILE)
    selected_ip = ip_manager.get_ip_choice()
    
    # Start logger
    logger = PS4CrashLogger(selected_ip, PS4_PORT, LOG_DIR)
    logger.run()

if __name__ == "__main__":
    main()
