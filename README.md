# PS4 Klog Crash Logger

A Python-based tool that monitors PS4 kernel logs (klog) in real-time and automatically captures detailed crash reports for debugging homebrew applications and analyzing game crashes.

## Features

- 🔍 **Real-time Crash Detection** - Monitors kernel logs and automatically detects crashes
- 💾 **Detailed Crash Reports** - Captures complete crash information including:
  - Signal type and error codes
  - Full register dumps (RAX, RBX, RCX, etc.)
  - Complete backtrace/call stack
  - All loaded libraries and plugins
  - Memory addresses and execution context
- 📝 **Automatic Logging** - Saves each crash to a timestamped file
- 🌐 **IP Management** - Save and manage multiple PS4 IP addresses
- ⚡ **Lightweight** - Minimal resource usage, runs in the background
- 🎯 **Context Capture** - Includes surrounding log lines for better debugging

## Prerequisites

- **Jailbroken PS4** with kernel log (klog) enabled
- **Python 3.7+** installed on your PC
- **GoldHEN** or similar homebrew enabler with klog support
- PS4 and PC on the same network

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/ps4-crash-logger.git
cd ps4-crash-logger
```

2. **No additional dependencies required!** The script uses only Python standard library.

## Usage

### Quick Start

1. **Run the script:**
```bash
python ps4_crash_logger.py
```

2. **Configure your PS4 IP:**
   - On first run, enter your PS4's IP address
   - The IP will be saved for future use
   - You can manage multiple PS4 IPs

3. **Monitor crashes:**
   - The script connects to your PS4 and monitors for crashes
   - When a crash occurs, it's automatically logged
   - Crash reports are saved in the `crash_logs/` directory

### IP Management

The script provides an interactive menu for managing PS4 IP addresses:

```
PS4 IP Configuration
====================
Saved PS4 IPs:
  [1] 192.168.1.150
  [2] 192.168.1.200
  [N] Enter a new IP address
  [Q] Quit

Select an option:
```

- Press **1, 2, etc.** to use a saved IP
- Press **N** to add a new IP address
- Press **Q** to quit

IPs are automatically saved to `ps4_ips.json` for future use.

## Configuration

Edit the script to customize behavior:

```python
# Line 12-16: Configuration options
PS4_PORT = 3232           # Klog port (try 9081 if 3232 doesn't work)
LOG_DIR = "crash_logs"    # Directory for crash logs
BUFFER_SIZE = 8192        # Network buffer size
VERBOSE_MODE = False      # Set to True to see all klog messages
```

### Verbose Mode

Enable verbose mode to see all kernel log messages in real-time:

```python
VERBOSE_MODE = True  # Shows every klog message
```

This is useful for:
- Verifying the connection is working
- Debugging klog connectivity issues
- Monitoring general PS4 system activity

## Crash Log Format

Crash logs are saved with timestamps: `crash_YYYYMMDD_HHMMSS.log`

Each log contains:
```
================================================================================
PS4 CRASH REPORT - 2025-12-10 23:10:03
PS4 IP: 192.168.1.150
================================================================================

# signal: 10 (SIGBUS)
# thread ID: 100926
# thread name: eboot.bin
# proc ID: 78
# proc name: eboot.bin
# reason: general protection fault

# registers:
# rax: 0000000003384660  rbx: 000000026c61cab8
# rcx: 0000000000000000  rdx: 0000000000000000
...

# backtrace:
# 0x000000000282BF0E </app0/eboot.bin> + 0x242BF0E
# 0x000000000226C467 </app0/eboot.bin> + 0x1E6C467
...

# dynamic libraries:
# /app0/eboot.bin
# /Pa0WVI44qW/common/lib/libkernel.sprx
...
```

## Troubleshooting

### Connection Issues

**"Connection refused"**
- Ensure klog is enabled on your PS4 (usually through GoldHEN settings)
- Check that your PS4 is jailbroken and running homebrew

**"Connection timeout"**
- Verify the IP address is correct
- Ensure PS4 and PC are on the same network
- Check firewall settings on your PC

**"No data received"**
- Try changing the port from 3232 to 9081 (common alternative)
- Verify klog is actively running on the PS4
- Enable verbose mode to see if any data is coming through

### Wrong Port

If port 3232 doesn't work, try these common alternatives:
- **9081** (most common klog port)
- **9998**

Change the port in the script:
```python
PS4_PORT = 9081  # Line 12
```

## Common Use Cases

### Homebrew Development
- Debug crashes in your homebrew applications
- Identify memory access violations
- Track down segmentation faults
- Analyze call stacks for error paths

### Game Analysis
- Monitor game stability
- Capture crash reports for bug reporting
- Analyze plugin compatibility issues
- Debug game patches

### System Monitoring
- Track system stability
- Monitor for kernel panics
- Log unexpected crashes for analysis

## Technical Details

### Crash Detection Keywords

The logger monitors for these crash indicators:
- `panic`, `crash`, `fatal`
- `exception`, `segfault`
- `SIGSEGV`, `SIGABRT`, `SIGILL`, `SIGFPE`, `SIGBUS`
- `kernel trap`, `page fault`
- `abort`, `core dump`

### How It Works

1. Connects to PS4's klog socket via TCP
2. Receives kernel log stream in real-time
3. Buffers recent log lines for context
4. Detects crash-related keywords
5. Captures surrounding context (10 lines before/after)
6. Saves complete crash report to file

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

### Ideas for Contributions
- Crash report parsing and analysis tools
- GUI interface
- Multiple PS4 simultaneous monitoring
- Crash statistics and trending
- Integration with debugging tools
- Automatic symbol resolution

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for legitimate homebrew development and debugging purposes only. Users are responsible for complying with all applicable laws and terms of service.

## Acknowledgments

- PS4 homebrew community
- GoldHEN developers
- OpenOrbis SDK contributors

## Support

If you encounter issues:
1. Check the [Troubleshooting](#troubleshooting) section
2. Enable verbose mode to diagnose connectivity
3. Open an issue with:
   - Python version
   - PS4 firmware version
   - Error messages or logs
   - Steps to reproduce

---

**Made with ❤️ for the PS4 homebrew community**
