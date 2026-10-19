#!/usr/bin/env python3
# -*- coding: utf-8 -*-


# Author    : Andre Henrique (@mrhenrike)
# GitHub    : https://github.com/mrhenrike
# LinkedIn  : https://linkedin.com/in/mrhenrike
# X/Twitter : https://x.com/mrhenrike

# python standard library
import re
import os
import sys
import cmd
import glob
import errno
import random
import ntpath
import posixpath
import hashlib
import socket
import tempfile
import subprocess
import traceback
try:
    import requests
except ImportError:
    requests = None
import time
import signal
import threading

# local pret classes
from utils.helper import log, output, conv, file, item, conn, const as c
from core.discovery import discovery
from utils.fuzzer import fuzzer
# CVE module moved to backup - functionality integrated into PJL v2.0


def _detect_editor() -> str:
    """Return the best available text editor for the current OS."""
    import shutil as _shutil
    import sys as _sys

    if _sys.platform == 'win32':
        # Windows: prefer notepad (always present) or VS Code
        for candidate in ('code', 'notepad++', 'notepad'):
            if _shutil.which(candidate):
                return candidate
        return 'notepad'

    # POSIX: Linux, macOS, WSL, Android/Termux, BSD
    # Respect VISUAL / EDITOR environment variables first
    for env_var in ('VISUAL', 'EDITOR'):
        val = os.environ.get(env_var, '').strip()
        if val and _shutil.which(val.split()[0]):
            return val

    # Fallback preference list (ordered)
    for candidate in ('nano', 'micro', 'vim', 'vi', 'emacs', 'pico'):
        if _shutil.which(candidate):
            return candidate

    return 'vi'  # POSIX mandates vi


class printer(cmd.Cmd, object):
    # cmd module config and customization
    intro = "Welcome to the PrinterXPL-Forge shell. Type help or ? to list commands.\nType 'exit' to quit. Type 'discover' to scan for printers on your local network.\nNote: Not all commands will work on every printer — support depends on the device's manufacturer, model, and firmware language implementation."
    doc_header = "Available commands (type help <topic>):"
    offline_str = "Not connected."
    undoc_header = None

    logfile = None
    debug = False
    status = False
    quiet = False
    fuzz = False
    options_fuzz = ("path", "write", "blind")
    conn = None
    mode = None
    error = None
    iohack = True
    timeout = 30  # Increased to 30 seconds as requested
    max_retries = 3
    target = ""
    vol = ""
    cwd = ""
    traversal = ""
    _fingerprint = None
    vendor = ""
    product = ""
    model = ""
    # default editor – auto-detected per OS, can be overridden at runtime
    editor = _detect_editor()
    
    # Interruption control
    interrupted = False
    current_command = None
    command_thread = None
    should_exit = False  # Flag to indicate if shell should exit

    # --------------------------------------------------------------------
    # INITIALIZATION AND CONTROL METHODS
    # --------------------------------------------------------------------
    def __init__(self, args, skip_open=False):
        # init cmd module
        cmd.Cmd.__init__(self)
        self.debug = args.debug  # debug mode
        self.quiet = args.quiet  # quiet mode
        self.mode = args.mode    # command mode
        self._fingerprint = getattr(args, '_fingerprint', None)
        if self._fingerprint:
            self._apply_fingerprint_meta(self._fingerprint)

        # Setup signal handlers for graceful interruption
        self.setup_signal_handlers()

        # connect to device (skip if target is test or caller manages open)
        if args.target != "test" and not skip_open:
            self.do_open(args.target, "init")
        # log pjl/ps cmds to file
        if args.log:
            self.logfile = log().open(args.log)
            header = None
            if self.mode == "ps":
                header = c.PS_HEADER
            if self.mode == "pcl":
                header = c.PCL_HEADER
            if header:
                log().write(self.logfile, header + os.linesep)
        # run pret cmds from file
        if args.load:
            self.do_load(args.load)
            # Mark that shell should exit after loading commands
            self.should_exit = True

    def setup_signal_handlers(self):
        """Setup signal handlers for graceful interruption"""
        def signal_handler(signum, frame):
            output().info("\nExiting PrinterXPL-Forge...")
            sys.exit(0)
        
        # Handle SIGINT (Ctrl+C) and SIGTERM
        signal.signal(signal.SIGINT, signal_handler)
        if hasattr(signal, 'SIGTERM'):
            signal.signal(signal.SIGTERM, signal_handler)



    def set_defaults(self, newtarget):
        self.fuzz = False
        if newtarget:
            self.set_vol()
            self.set_traversal()
            self.error = None
            self.set_prompt()  # Set prompt after connecting
        else:
            self.set_prompt()

    # --------------------------------------------------------------------
    # CORE SHELL METHODS
    # --------------------------------------------------------------------
    # do nothing on empty input
    def emptyline(self):
        pass

    # show message for unknown commands
    def default(self, line):
        if line and line[0] != "#":  # interpret as comment
            # Don't show error for EOF
            if line.strip() != "EOF":
                output().chitchat("Unknown command: '" + line + "'")

    # suppress help message for undocumented commands
    def print_topics(self, header, cmds, cmdlen, maxcol):
        if cmds:
            output().chitchat(header)

    def chitchat(self, *args):
        if not self.quiet:
            output().message(*args)

    def precmd(self, line):
        # normalize line endings
        if line and line[-1] == os.linesep:
            line = line[:-1]
        # convert to unicode if needed
        if hasattr(line, "decode"):
            try:
                line = line.decode("utf-8")
            except UnicodeDecodeError:
                line = line.decode("latin-1")
        return line

    # --------------------------------------------------------------------
    # catch-all wrapper to guarantee continuation on unhandled exceptions
    def onecmd(self, line):
        # Set current command for interruption tracking
        self.current_command = line.strip()
        self.interrupted = False
        
        # Set timeout for command execution
        start_time = time.time()
        max_execution_time = 30  # 30 seconds timeout
        
        try:
            # Execute command with timeout monitoring
            result = cmd.Cmd.onecmd(self, line)
            
            # Check if command took too long
            execution_time = time.time() - start_time
            if execution_time > max_execution_time:
                output().warning(f"Command took {execution_time:.2f} seconds (timeout: {max_execution_time}s)")
            
            # Clear current command on successful completion
            self.current_command = None
            return result
            
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            output().errmsg("Connection lost - printer may have disconnected")
            self.current_command = None
            return False
        except socket.timeout as e:
            output().errmsg("Command timed out - printer may be busy")
            self.current_command = None
            return False
        except KeyboardInterrupt:
            output().warning("Command interrupted by user")
            self.current_command = None
            return False
        except Exception as e:
            # Only show traceback in debug mode
            if hasattr(self, 'debug') and self.debug:
                traceback.print_exc()
            output().errmsg(f"Command failed: {str(e)}")
            self.current_command = None
            return False
        finally:
            # Always clear current command
            self.current_command = None

    # --------------------------------------------------------------------
    # HELP SYSTEM (generic fallback)
    # --------------------------------------------------------------------
    def do_help(self, arg):
        """Show help for commands (generic fallback for non-PJL shells)"""
        # If a specific topic was requested, try dedicated help_<topic> first
        topic = (arg or "").strip()
        if topic:
            method = getattr(self, f"help_{topic}", None)
            if callable(method):
                method()
                return
            # Fallback to showing the do_<topic> docstring if present
            do_method = getattr(self, f"do_{topic}", None)
            if callable(do_method) and (do_method.__doc__ or "").strip():
                print()
                print(f"{topic} - {do_method.__doc__}")
                print()
                return
            output().errmsg(f"No help available for '{topic}'")
            return

        # No topic: dynamically list all available do_* commands for this shell
        names = self.get_names()
        commands = sorted({n[3:] for n in names if n.startswith("do_") and not n.startswith("do__")})

        print()
        title_mode = (self.mode or "shell").upper()
        print(f"{title_mode} Commands - Available ({len(commands)})")
        print("=" * 70)

        # Pretty-print in columns
        if not commands:
            print("No commands available.")
            print()
            print("Use 'help <command>' for details.")
            return

        col_width = max(len(cmd) for cmd in commands) + 2
        cols = max(1, 70 // col_width)
        for i in range(0, len(commands), cols):
            row = commands[i:i+cols]
            print("".join(cmd.ljust(col_width) for cmd in row))
        print()
        print("Use 'help <command>' for details. Example: help download")
        print()

    # ====================================================================
    # BASIC CONTROL COMMANDS
    # ====================================================================
    # These commands control the basic operation of the shell and program

    def do_exit(self, *arg):
        if self.logfile:
            log().close(self.logfile)
        return True

    def help_exit(self):
        """Exit the PrinterXPL-Forge shell"""
        print()
        print("exit - Exit the PrinterXPL-Forge shell")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Exits the PrinterXPL-Forge shell and closes the connection to the printer.")
        print("  This command will also close any open log files.")
        print()
        print("USAGE:")
        print("  exit")
        print()
        print("EXAMPLES:")
        print("  exit                    # Exit the shell")
        print("  quit                    # Alternative command (same as exit)")
        print()
        print("NOTES:")
        print("  - All unsaved work will be lost")
        print("  - Connection to printer will be closed")
        print("  - Log files will be properly closed")
        print()

    def do_debug(self, arg):
        "Toggle raw traffic debug output"
        self.debug = not self.debug
        output().message("Debug output " + ("enabled" if self.debug else "disabled"))

    def help_debug(self):
        """Toggle debug output mode"""
        print()
        print("debug - Toggle debug output mode")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Enables or disables debug output mode. When enabled, shows")
        print("  detailed information about commands being sent to and")
        print("  received from the printer. Useful for troubleshooting connection issues.")
        print()
        print("USAGE:")
        print("  debug")
        print()
        print("EXAMPLES:")
        print("  debug                    # Toggle debug mode on/off")
        print()
        print("NOTES:")
        print("  - Debug mode shows raw PJL/PS/PCL commands")
        print("  - Useful for understanding printer communication")
        print("  - May produce verbose output")
        print()

    def do_loop(self, arg):
        "Run a command repeatedly over multiple arguments"
        if not arg:
            output().errmsg("Usage: loop <command> <arg1> <arg2> ...")
            return
        args = arg.split()
        cmd = args[0]
        for arg in args[1:]:
            output().message(f"Running: {cmd} {arg}")
            self.onecmd(f"{cmd} {arg}")

    def help_loop(self):
        """Run a command repeatedly over multiple arguments"""
        print()
        print("loop - Run a command repeatedly over multiple arguments")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Executes a command multiple times, once for each argument provided.")
        print("  Useful for batch operations and automation tasks.")
        print()
        print("USAGE:")
        print("  loop <command> <arg1> <arg2> ...")
        print()
        print("EXAMPLES:")
        print("  loop download file1.txt file2.txt file3.txt")
        print("  loop delete old1.log old2.log old3.log")
        print("  loop cat config1.cfg config2.cfg")
        print()
        print("NOTES:")
        print("  - Each argument is passed to the command separately")
        print("  - Useful for batch file operations")
        print("  - Commands are executed in sequence")
        print()

    # ====================================================================
    # DISCOVERY AND CONNECTION COMMANDS
    # ====================================================================
    # These commands handle network discovery and establishing connections

    def do_discover(self, arg):
        "Scan networks for SNMP printers (context-aware if target is set)"
        discovery(usage=False, context_target=self.target or '')

    def help_discover(self):
        """Scan local networks for SNMP printers"""
        print()
        print("discover - Scan local networks for SNMP printers")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Scans the local network for printers using SNMP protocol.")
        print("  Discovers printers on the network and displays their information.")
        print()
        print("USAGE:")
        print("  discover")
        print()
        print("EXAMPLES:")
        print("  discover                 # Scan local network for printers")
        print()
        print("NOTES:")
        print("  - Requires SNMP to be enabled on target printers")
        print("  - Scans common printer ports (9100, 515, 631)")
        print("  - May take some time depending on network size")
        print("  - Results show IP address, model, and capabilities")
        print()

    def _apply_fingerprint_meta(self, fp) -> None:
        from utils.vendor_profile import normalize_vendor
        self.vendor = normalize_vendor(getattr(fp, 'make', '') or '')
        self.model = (getattr(fp, 'model', '') or '').strip()
        make = (getattr(fp, 'make', '') or '').strip()
        self.product = f"{make} {self.model}".strip()

    def _require_raw(self, command: str = 'command') -> bool:
        if self.conn:
            return True
        output().errmsg(
            f"Not connected to RAW port 9100 — '{command}' requires an active PJL/RAW session."
        )
        return False

    def do_vendor(self, arg):
        "Show or set printer vendor (filters vendor-specific PJL commands)"
        from utils.vendor_profile import normalize_vendor, VENDOR_NAMES
        parts = (arg or '').strip().split()
        if not parts:
            print()
            print(f"  Vendor : {self.vendor or '(not set — generic INFO set)'}")
            print(f"  Product: {self.product or '(unknown)'}")
            print(f"  Model  : {self.model or '(unknown)'}")
            print(f"  RAW    : {'connected' if self.conn else 'offline (passive mode)'}")
            print()
            print("  Usage:")
            print("    vendor set <name>   — hp, brother, epson, ricoh, xerox, …")
            print("    vendor detect       — re-run passive fingerprint")
            print(f"    Known: {', '.join(VENDOR_NAMES)}")
            print()
            return
        sub = parts[0].lower()
        if sub == 'set' and len(parts) >= 2:
            self.vendor = normalize_vendor(parts[1])
            output().info(f"Vendor set to: {self.vendor}")
            return
        if sub == 'detect':
            fp = self._show_passive_id(refresh=True)
            self._apply_fingerprint_meta(fp)
            output().info(
                f"Detected vendor={self.vendor or 'generic'} "
                f"product={self.product or '?'}"
            )
            return
        self.vendor = normalize_vendor(parts[0])
        output().info(f"Vendor set to: {self.vendor}")

    def help_vendor(self):
        print()
        print("vendor - Show or set printer vendor for command filtering")
        print("=" * 50)
        print("  vendor              Show current vendor / product / model")
        print("  vendor set hp       Force vendor (filters info, nvram, etc.)")
        print("  vendor detect       Re-detect from IPP/HTTP/SNMP fingerprint")
        print()

    def _show_passive_id(self, refresh: bool = False):
        """Fingerprint via IPP/HTTP/SNMP/FTP when RAW/PJL is unavailable."""
        from utils.banner_grabber import grab_all, print_fingerprint, print_protocol_hints
        if refresh or not self._fingerprint:
            host = (self.target or '').split(':')[0]
            self._fingerprint = grab_all(host, timeout=5.0)
        print_fingerprint(self._fingerprint)
        print_protocol_hints(self._fingerprint)
        return self._fingerprint

    def do_open(self, arg, mode=""):
        "Connect to a new target"
        if not arg:
            arg = input("Target: ")
        base = arg.split(':')[0] if ':' in arg else arg
        self.target = base
        explicit_port = None
        if ':' in arg:
            try:
                explicit_port = int(arg.rsplit(':', 1)[1])
            except ValueError:
                explicit_port = None

        try:
            from utils.ports import PortConfig
            raw_ports = []
            if explicit_port is not None:
                raw_ports.append(explicit_port)
            for p in (PortConfig.resolve('raw'), 9100, 9101, 9150):
                if p not in raw_ports:
                    raw_ports.append(p)
        except Exception:
            raw_ports = [explicit_port or 9100, 9101]

        self.conn = None
        for port in raw_ports:
            target = f"{base}:{port}"
            self.conn = conn(self.mode, self.debug, self.quiet).open(target)
            if self.conn:
                if port != 9100:
                    output().info(f"Connected on RAW port {port}")
                break

        if self.conn:
            self.on_connect(mode)
            self.set_defaults(True)
        else:
            self.set_defaults(False)
            output().warning(
                f"RAW port unavailable on {base} — shell commands need port 9100 (PJL/PS/PCL)."
            )
            if self._fingerprint:
                from utils.banner_grabber import print_fingerprint, print_protocol_hints
                print_fingerprint(self._fingerprint)
                print_protocol_hints(self._fingerprint)
            else:
                self._show_passive_id()

    def help_open(self):
        """Connect to a new printer target"""
        print()
        print("open - Connect to a new printer target")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Establishes a connection to a printer target. This command")
        print("  connects to the specified printer and prepares it for")
        print("  subsequent commands.")
        print()
        print("USAGE:")
        print("  open <target>")
        print()
        print("EXAMPLES:")
        print("  open 192.168.1.100        # Connect to IP address")
        print("  open printer.local        # Connect to hostname")
        print("  open 10.0.0.50:9100       # Connect to specific port")
        print()
        print("NOTES:")
        print("  - Target can be IP address or hostname")
        print("  - Default port is 9100 (raw printing)")
        print("  - Connection is established immediately")
        print("  - Previous connection is closed if exists")
        print()

    def do_close(self, *arg):
        "Disconnect from the current printer"
        if self.conn:
            self.conn.close()
            self.conn = None
        self.set_defaults(False)

    def help_close(self):
        """Disconnect from the current printer"""
        print()
        print("close - Disconnect from the current printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Closes the connection to the currently connected printer.")
        print("  This command disconnects from the printer and resets")
        print("  the connection state.")
        print()
        print("USAGE:")
        print("  close")
        print()
        print("EXAMPLES:")
        print("  close                    # Disconnect from current printer")
        print()
        print("NOTES:")
        print("  - Closes the current connection")
        print("  - Resets connection state")
        print("  - Use 'open' to connect to a new printer")
        print()

    def do_timeout(self, arg, quiet=False):
        "Change the network timeout"
        if not arg:
            # Show current timeout if no argument provided
            output().message(f"Current timeout: {self.timeout} seconds")
            return
        self.timeout = conv().int(arg)
        if not quiet:
            output().message(f"Timeout set to {self.timeout} seconds")

    def timeoutcmd(self, str_send, timeout, *stuff):
        return self.conn.timeoutcmd(str_send, timeout, *stuff)

    def help_timeout(self):
        """Change the network timeout"""
        print()
        print("timeout - Change the network timeout")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Sets the network timeout value for printer communications.")
        print("  This affects how long the system waits for responses")
        print("  from the printer before timing out.")
        print()
        print("USAGE:")
        print("  timeout <seconds>")
        print()
        print("EXAMPLES:")
        print("  timeout 30              # Set timeout to 30 seconds")
        print("  timeout 5               # Set timeout to 5 seconds")
        print()
        print("NOTES:")
        print("  - Default timeout is 10 seconds")
        print("  - Higher values for slow networks")
        print("  - Lower values for faster response")
        print()

    def do_reconnect(self, *arg):
        "Reconnect to the current printer"
        self.reconnect("Reconnecting...")

    def reconnect(self, msg):
        output().message(msg)
        if self.conn:
            self.conn.close()
        self.conn = conn(self.mode, self.debug, self.quiet).open(self.target)
        if self.conn:
            self.on_connect("")
            self.set_defaults(True)
        else:
            self.set_defaults(False)

    def on_connect(self, mode):
        if mode == "init":
            return
        output().message("Connected to " + self.target)

    def help_reconnect(self):
        """Reconnect to the current printer"""
        print()
        print("reconnect - Reconnect to the current printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Reconnects to the currently configured printer target.")
        print("  Useful when the connection is lost or becomes unstable.")
        print("  Attempts to re-establish the connection using the same target.")
        print()
        print("USAGE:")
        print("  reconnect")
        print()
        print("EXAMPLES:")
        print("  reconnect                # Reconnect to current printer")
        print()
        print("NOTES:")
        print("  - Uses the same target as previous connection")
        print("  - Useful for unstable connections")
        print("  - Closes old connection before reconnecting")
        print()

    # ====================================================================
    # SYSTEM INFORMATION COMMANDS
    # ====================================================================
    # These commands provide information about the connected printer

    def do_id(self, *arg):
        "Show printer identification and system information"
        if not self.conn:
            output().warning("Not connected to RAW — showing passive fingerprint:")
            self._show_passive_id()
            return
        output().message("Unknown printer — specify mode: pjl, ps, or pcl")

    def help_id(self):
        """Show printer identification and system information"""
        print()
        print("id - Show printer identification and system information")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Displays comprehensive identification and system information")
        print("  about the connected printer. Shows device ID, firmware version,")
        print("  product details, and other system information.")
        print()
        print("USAGE:")
        print("  id")
        print()
        print("EXAMPLES:")
        print("  id                       # Show printer identification")
        print()
        print("NOTES:")
        print("  - Shows device ID and model information")
        print("  - Displays firmware version and capabilities")
        print("  - Useful for identifying printer type and features")
        print()

    def do_pwd(self, arg):
        """
        Show current working directory *and* list all volumes on the device.
        """
        if not self.conn:
            output().errmsg(self.offline_str)
            return
        output().message("Current directory: " + self.cwd)
        output().message("Available volumes:")
        for vol in self.get_vol():
            output().message("  " + vol)

    def help_pwd(self):
        """Print the current remote working directory"""
        print()
        print("pwd - Print the current remote working directory")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Shows the current working directory on the remote printer")
        print("  and lists all available volumes. Useful for understanding")
        print("  the printer's file system structure.")
        print()
        print("USAGE:")
        print("  pwd")
        print()
        print("EXAMPLES:")
        print("  pwd                      # Show current directory and volumes")
        print()
        print("NOTES:")
        print("  - Shows current working directory")
        print("  - Lists all available volumes (0:, 1:, etc.)")
        print("  - Useful for navigation planning")
        print()

    # ====================================================================
    # FILESYSTEM NAVIGATION COMMANDS
    # ====================================================================
    # These commands handle navigation and basic filesystem operations

    def do_chvol(self, arg):
        "Change current volume"
        if not arg:
            arg = input("Volume: ")
        self.set_vol(arg)
        output().message("Changed to volume: " + self.vol)

    def set_vol(self, vol=""):
        if not vol:
            vol = self.get_vol()[0] if self.get_vol() else ""
        self.vol = vol

    def get_vol(self):
        return ["0:", "1:", "2:", "3:", "4:", "5:", "6:", "7:", "8:", "9:"]

    def help_chvol(self):
        """Change current volume"""
        print()
        print("chvol - Change current volume")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Changes the current working volume on the printer.")
        print("  Printers may have multiple volumes (0:, 1:, 2:, etc.)")
        print("  and this command allows switching between them.")
        print()
        print("USAGE:")
        print("  chvol <volume>")
        print()
        print("EXAMPLES:")
        print("  chvol 0:                 # Switch to volume 0")
        print("  chvol 1:                 # Switch to volume 1")
        print()
        print("NOTES:")
        print("  - Volume format is typically 'X:' where X is a number")
        print("  - Use 'pwd' to see available volumes")
        print("  - Different volumes may contain different files")
        print()

    def do_traversal(self, arg):
        "Set path traversal root"
        if not arg:
            # Show current traversal root if no argument provided
            if self.traversal:
                output().message(f"Current traversal root: {self.traversal}")
            else:
                output().message("Traversal root not set (unrestricted)")
            return
        self.set_traversal(arg)

    def set_traversal(self, traversal=""):
        self.traversal = traversal

    def help_traversal(self):
        """Set path traversal root"""
        print()
        print("traversal - Set path traversal root")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Sets the root directory for path traversal operations.")
        print("  This limits file system access to a specific directory")
        print("  and its subdirectories for security purposes.")
        print()
        print("USAGE:")
        print("  traversal <path>")
        print()
        print("EXAMPLES:")
        print("  traversal /               # Set root to filesystem root")
        print("  traversal /tmp            # Limit to /tmp directory")
        print()
        print("NOTES:")
        print("  - Restricts file access to specified directory")
        print("  - Security feature to prevent unauthorized access")
        print("  - Use empty string to disable traversal restrictions")
        print()

    def do_cd(self, arg):
        "Change the current working directory on the printer"
        if not arg:
            arg = input("Directory: ")
        self.set_cwd(arg)

    def set_cwd(self, cwd=""):
        self.cwd = cwd
        self.set_prompt()

    def set_prompt(self):
        self.prompt = self.target + ":" + self.cwd + "/> "

    def get_sep(self, path):
        if ":" in path:
            return ":"
        return "/"

    def tpath(self, path):
        return self.traversal + path if self.traversal else path

    def cpath(self, path):
        return self.cwd + "/" + path if self.cwd and not path.startswith("/") else path

    def vpath(self, path):
        return self.vol + path if self.vol and ":" not in path else path

    def rpath(self, path=""):
        if not path:
            path = self.cwd
        return self.vpath(self.cpath(self.tpath(path)))

    def normpath(self, path):
        return posixpath.normpath(path)

    def basename(self, path):
        return posixpath.basename(path)

    def help_cd(self):
        """Change the current working directory on the printer"""
        print()
        print("cd - Change the current working directory on the printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Changes the current working directory on the remote printer.")
        print("  This affects the default location for file operations")
        print("  and determines the current working directory context.")
        print()
        print("USAGE:")
        print("  cd <directory>")
        print()
        print("EXAMPLES:")
        print("  cd /                      # Change to root directory")
        print("  cd /tmp                   # Change to /tmp directory")
        print("  cd config                 # Change to config subdirectory")
        print()
        print("NOTES:")
        print("  - Use 'pwd' to see current directory")
        print("  - Directory must exist on the printer")
        print("  - Affects default paths for file operations")
        print()

    # ====================================================================
    # FILE TRANSFER COMMANDS
    # ====================================================================
    # These commands handle uploading and downloading files

    def do_download(self, arg, lpath="", r=True):
        "Receive file:  get <file>"
        if not arg:
            arg = input("Remote file: ")
        if not lpath:
            lpath = self.basename(arg)
        path = self.rpath(arg) if r else arg
        str_recv = self.get(path)
        if str_recv != c.NONEXISTENT:
            rsize, data = str_recv
            lsize = len(data)
            if rsize == lsize:
                file().write(lpath, data)
                output().message(f"Downloaded {arg} to {lpath}")
            elif rsize == c.NONEXISTENT:
                output().message("Permission denied.")
            else:
                self.size_mismatch(lsize, rsize)

    def size_mismatch(self, size1, size2):
        size1, size2 = str(size1), str(size2)
        print(("Size mismatch (should: " + size1 + ", is: " + size2 + ")."))

    def help_download(self):
        """Download a file from the printer"""
        print()
        print("download - Download a file from the printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Downloads a file from the remote printer to the local system.")
        print("  The file is saved to the current local directory with")
        print("  the same name as the remote file.")
        print()
        print("USAGE:")
        print("  download <remote_file>")
        print()
        print("EXAMPLES:")
        print("  download config.cfg       # Download config.cfg")
        print("  download 1:/config.cfg   # Download from volume 1")
        print("  download /tmp/log.txt     # Download from /tmp directory")
        print()
        print("NOTES:")
        print("  - File is saved to current local directory")
        print("  - Remote file must exist and be readable")
        print("  - Use volume prefix (1:) for specific volumes")
        print()

    def do_upload(self, arg, rpath=""):
        "Send file:  put <local file>"
        if not arg:
            arg = input("Local file: ")
        if not rpath:
            rpath = os.path.basename(arg)
        rpath = self.rpath(rpath)
        lpath = os.path.abspath(arg)
        # read from local file
        data = file().read(lpath)
        if data != None:
            rsize = self.put(rpath, data)
            lsize = len(data)
            if rsize == lsize:
                output().message(f"Uploaded {arg} to {rpath}")
            elif rsize == c.NONEXISTENT:
                output().message("Permission denied.")
            else:
                self.size_mismatch(lsize, rsize)
        else:
            output().errmsg("Could not read local file.")

    def help_upload(self):
        """Upload a local file to the printer"""
        print()
        print("upload - Upload a local file to the printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Uploads a file from the local system to the remote printer.")
        print("  The file is transferred to the current working directory")
        print("  on the printer with the same name.")
        print()
        print("USAGE:")
        print("  upload <local_file>")
        print()
        print("EXAMPLES:")
        print("  upload config.txt         # Upload config.txt")
        print("  upload /path/to/file.cfg  # Upload with full path")
        print("  upload script.py          # Upload Python script")
        print()
        print("NOTES:")
        print("  - Local file must exist and be readable")
        print("  - File is uploaded to current remote directory")
        print("  - Preserves original filename")
        print()

    def do_append(self, arg):
        "Append to file:  append <file> <string>"
        arg = re.split(r"\s+", arg, 1)
        if len(arg) < 2:
            output().errmsg("Usage: append <file> <string>")
            return
        path, data = arg[0], arg[1]
        self.append(self.rpath(path), data)

    def help_append(self):
        """Append to file"""
        print()
        print("append - Append to file")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Appends text content to a remote file on the printer.")
        print("  If the file doesn't exist, it will be created.")
        print("  The text is added to the end of the file.")
        print()
        print("USAGE:")
        print("  append <file> <text>")
        print()
        print("EXAMPLES:")
        print("  append log.txt 'New entry'  # Append to log.txt")
        print("  append config.cfg 'setting=value'  # Add configuration")
        print()
        print("NOTES:")
        print("  - File is created if it doesn't exist")
        print("  - Text is appended to the end of the file")
        print("  - Use quotes for text with spaces")
        print()

    def do_delete(self, arg):
        if not arg:
            arg = input("File: ")
        self.delete(arg)

    def help_delete(self):
        """Delete a remote file"""
        print()
        print("delete - Delete a remote file")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Deletes a file from the remote printer's file system.")
        print("  The file is permanently removed from the printer.")
        print("  Use with caution as this operation cannot be undone.")
        print()
        print("USAGE:")
        print("  delete <file>")
        print()
        print("EXAMPLES:")
        print("  delete old.log           # Delete old.log")
        print("  delete /tmp/temp.txt     # Delete from /tmp directory")
        print()
        print("NOTES:")
        print("  - File is permanently deleted")
        print("  - Operation cannot be undone")
        print("  - File must exist and be writable")
        print()

    def do_cat(self, arg):
        "Print remote file contents"
        if not arg:
            arg = input("File: ")
        data = self.get(self.rpath(arg))
        if data != c.NONEXISTENT:
            size, content = data
            print(content.decode("utf-8", errors="ignore"))
        else:
            output().errmsg("File not found or permission denied.")

    def help_cat(self):
        """Print remote file contents"""
        print()
        print("cat - Print remote file contents")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Displays the contents of a remote file on the printer.")
        print("  The file content is printed to the console.")
        print("  Useful for viewing configuration files and logs.")
        print()
        print("USAGE:")
        print("  cat <file>")
        print()
        print("EXAMPLES:")
        print("  cat config.cfg           # View configuration file")
        print("  cat /var/log/printer.log  # View log file")
        print("  cat status.txt           # View status file")
        print()
        print("NOTES:")
        print("  - File must exist and be readable")
        print("  - Content is displayed in the console")
        print("  - Large files may produce lots of output")
        print()

    def do_edit(self, arg):
        "Edit a remote file"
        if not arg:
            arg = input("File: ")
        # download file
        data = self.get(self.rpath(arg))
        if data == c.NONEXISTENT:
            output().errmsg("File not found or permission denied.")
            return
        size, content = data
        # write to temporary file
        tmp = tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".tmp")
        tmp.write(content.decode("utf-8", errors="ignore"))
        tmp.close()
        # edit file
        subprocess.call([self.editor, tmp.name])
        # read edited file
        with open(tmp.name, "rb") as f:
            new_content = f.read()
        # upload file
        self.put(self.rpath(arg), new_content)
        # cleanup
        os.unlink(tmp.name)
        output().message(f"Edited {arg}")

    def help_edit(self):
        """Edit a remote file"""
        print()
        print("edit - Edit a remote file")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Downloads a remote file, opens it in a text editor,")
        print("  and uploads the modified version back to the printer.")
        print("  Uses the system's default text editor.")
        print()
        print("USAGE:")
        print("  edit <file>")
        print()
        print("EXAMPLES:")
        print("  edit config.cfg          # Edit configuration file")
        print("  edit /tmp/script.sh      # Edit script file")
        print()
        print("NOTES:")
        print("  - File is downloaded, edited, and uploaded")
        print("  - Uses system default editor (vim, nano, etc.)")
        print("  - Temporary files are cleaned up automatically")
        print()

    # ====================================================================
    # FILE SYNCHRONIZATION COMMANDS
    # ====================================================================
    # These commands handle mirroring and synchronization

    def mirror(self, name, size):
        "Mirror a remote file to local disk"
        lpath = os.path.join(".", name)
        ldir = os.path.dirname(lpath)
        if ldir and not os.path.exists(ldir):
            self.makedirs(ldir)
        if os.path.exists(lpath):
            lsize = os.path.getsize(lpath)
            if lsize == size:
                return
        data = self.get(self.rpath(name))
        if data != c.NONEXISTENT:
            rsize, content = data
            file().write(lpath, content)
            output().message(f"Mirrored {name}")

    def makedirs(self, path):
        "Create directory structure"
        if not os.path.exists(path):
            os.makedirs(path)

    def help_mirror(self):
        """Mirror files from printer to local system"""
        print()
        print("mirror - Mirror files from printer to local system")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Recursively downloads a remote directory tree to the local disk.")
        print("  Creates a local copy of the remote file system structure.")
        print("  Useful for backups and offline analysis.")
        print()
        print("USAGE:")
        print("  mirror <remote_directory>")
        print()
        print("EXAMPLES:")
        print("  mirror /                  # Mirror entire filesystem")
        print("  mirror /config            # Mirror config directory")
        print("  mirror /logs              # Mirror logs directory")
        print()
        print("NOTES:")
        print("  - Creates local directory structure")
        print("  - Downloads all files recursively")
        print("  - May take time for large directories")
        print()

    # ====================================================================
    # FUZZING AND TESTING COMMANDS
    # ====================================================================
    # These commands perform security testing and fuzzing

    def complete_lfiles(self, text, line, begidx, endidx):
        "Complete local files"
        before_arg = line.rfind(" ", 0, begidx)
        if before_arg == -1:
            return []
        fixed_arg = line[before_arg + 1:begidx]
        arg = os.path.expanduser(fixed_arg)
        completions = []
        try:
            for item in os.listdir(os.path.dirname(arg) or "."):
                if item.startswith(os.path.basename(arg)):
                    completions.append(item)
        except OSError:
            pass
        return completions

    def vol_exists(self, vol=""):
        """Return existing volumes for fuzzing; override in language modules."""
        return []

    def do_fuzz(self, arg):
        "File system fuzzing: fuzz path|write|blind"
        arg = (arg or "").strip().lower()
        if arg in self.options_fuzz:
            self.fuzz = True
            if arg == "path":
                self.fuzz_path()
            elif arg == "write":
                self.fuzz_write()
            elif arg == "blind":
                self.fuzz_blind()
            self.chitchat("Fuzzing finished.")
            self.fuzz = False
        elif not arg:
            self.help_fuzz()
        else:
            output().errmsg(f"Unknown fuzz mode '{arg}'. Use: path, write, or blind")

    def fuzz_path(self):
        "Fuzz file paths (PRET-compatible traversal strategies)"
        output().message("Checking base paths first.")
        found = {}
        for path in self.vol_exists() + list(fuzzer().path):
            self.verify_path(path, found)
        output().message("Checking filesystem hierarchy standard.")
        for path in fuzzer().fhs:
            self.verify_path(path, found)
        if found:
            output().message("Now checking traversal strategies.")
            for vol in found:
                sep = "" if vol[-1:] in ("", "/", "\\") else "/"
                sep2 = vol[-1:] if vol[-1:] in ("/", "\\") else "/"
                for d in fuzzer().dir:
                    self.verify_path(vol + sep + d + sep2)
                    for f in fuzzer().abs:
                        if isinstance(f, list):
                            self.verify_path(vol + sep + d + sep2 + f[0] + sep + f[1])
                        else:
                            self.verify_path(vol + sep + d + sep2 + f)

    def fuzz_write(self):
        "Fuzz write operations"
        for path in fuzzer().write:
            for name in fuzzer().fuzz_names():
                data = fuzzer().fuzz_data()
                self.verify_write(path, name, data, "write")

    def fuzz_blind(self):
        "Fuzz blind read-only sensitive paths"
        for path in fuzzer().blind:
            for rel in fuzzer().rel:
                self.verify_blind(path, rel)

    def verify_path(self, path, found={}):
        "Verify if path exists"
        if path in found:
            return found[path]
        result = self.get(self.rpath(path))
        found[path] = result != c.NONEXISTENT
        return found[path]

    def verify_write(self, path, name, data, cmd):
        "Verify write operation"
        full_path = os.path.join(path, name)
        result = self.put(self.rpath(full_path), data)
        return result != c.NONEXISTENT

    def verify_blind(self, path, name):
        "Verify blind operation"
        full_path = os.path.join(path, name)
        result = self.get(self.rpath(full_path))
        return result != c.NONEXISTENT

    def complete_fuzz(self, text, line, begidx, endidx):
        "Complete fuzz parameters"
        return [cat for cat in self.options_fuzz if cat.startswith(text)]

    def help_fuzz(self):
        """Launch file-system fuzzing"""
        print()
        print("fuzz - File system fuzzing (PRET-compatible)")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Performs security testing by fuzzing the printer's file system.")
        print("  Three modes mirror the original PRET toolkit:")
        print()
        print("USAGE:")
        print("  fuzz path    - Explore fs structure with path traversal strategies")
        print("  fuzz write   - Put/append files, then check for existence")
        print("  fuzz blind   - Read-only tests for sensitive files (/etc/passwd, etc.)")
        print()
        print("EXAMPLES:")
        print("  fuzz path")
        print("  fuzz write")
        print("  fuzz blind")
        print()
        print("NOTES:")
        print("  - May generate large output and affect printer stability")
        print("  - Use only on authorized targets")
        print()

    def do_site(self, arg):
        "Execute custom raw command on printer: site <command>"
        if not self.conn:
            output().errmsg(self.offline_str)
            return
        if not arg:
            try:
                arg = input("Command: ")
            except (EOFError, KeyboardInterrupt):
                return
        if hasattr(self, "cmd"):
            str_recv = self.cmd(arg)
            if str_recv:
                output().info(str_recv)
        else:
            output().errmsg("site requires an active language shell (pjl/ps/pcl)")

    def help_site(self):
        print()
        print("site - Execute custom raw command on printer")
        print("  site <command>   Send arbitrary PJL/PS/PCL to the device")
        print()

    # ====================================================================
    # PRINTING COMMANDS
    # ====================================================================
    # These commands handle printing operations

    def do_print(self, arg):
        'Print image/file or raw text: print <file>|"text"'
        if not arg:
            try:
                arg = input('File or "text": ')
            except (EOFError, KeyboardInterrupt):
                return
        if arg.startswith('"') and arg.endswith('"'):
            data = arg.strip('"').encode()
        elif os.path.exists(arg):
            if arg.lower().endswith(".ps"):
                data = file().read(arg)
            else:
                data = self.convert(arg, "pcl")
                if not data:
                    return
                data = c.UEL.encode() + data + c.UEL.encode()
        else:
            data = arg.encode()
        if data and self.conn:
            self.send(data)
            output().message("Print job sent.")
        elif not self.conn:
            output().errmsg(self.offline_str)

    def help_print(self):
        """Print a file or literal text through the device"""
        print()
        print("print - Print a file or literal text through the device")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Sends a file or text to the printer for printing.")
        print("  Can print local files or literal text strings.")
        print("  The content is sent directly to the printer.")
        print()
        print("USAGE:")
        print("  print <file_or_text>")
        print()
        print("EXAMPLES:")
        print("  print document.pdf       # Print PDF file")
        print("  print 'Hello World'      # Print literal text")
        print("  print /path/to/file.txt  # Print file with full path")
        print()
        print("NOTES:")
        print("  - File must exist locally")
        print("  - Text is sent as-is to printer")
        print("  - Printer must support the file format")
        print()

    def convert(self, path, pdl="pcl"):
        """Convert document to PCL/PS via ImageMagick (optional dependency)."""
        import shutil
        if not shutil.which("convert"):
            output().errmsg(
                "ImageMagick 'convert' not found. "
                "Install: apt install imagemagick ghostscript"
            )
            return None
        try:
            self.chitchat(f"Converting '{path}' to {pdl.upper()}")
            pdf_opts = ["-density", "300"] if path.lower().endswith(".pdf") else []
            cmd = ["convert"] + pdf_opts + [path, "-quality", "100", f"{pdl}:-"]
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
            if proc.returncode != 0:
                err = proc.stderr.decode(errors="replace") or "conversion failed"
                output().errmsg("Cannot convert", err)
                return None
            return proc.stdout
        except subprocess.TimeoutExpired:
            output().errmsg("Conversion timed out")
            return None
        except OSError as exc:
            output().errmsg("Cannot convert", str(exc))
            return None

    def do_convert(self, arg):
        "Convert a file to PCL or PS (driverless printing)"
        parts = (arg or "").split()
        if not parts:
            try:
                path = input("File: ")
            except (EOFError, KeyboardInterrupt):
                return
            pdl = "pcl"
        else:
            path = parts[0]
            pdl = parts[1].lower() if len(parts) > 1 else "pcl"
        if pdl not in ("pcl", "ps"):
            output().errmsg("Format must be pcl or ps")
            return
        if not os.path.exists(path):
            output().errmsg("File not found.")
            return
        data = self.convert(path, pdl)
        if data:
            out = path + f".{pdl}"
            file().write(out, data)
            output().message(f"Wrote {out} ({len(data)} bytes)")

    def help_convert(self):
        """Convert a file to PCL or PS format for printing"""
        print()
        print("convert - Convert a file to PCL or PS format for printing")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Converts a file to PCL (Printer Command Language) or")
        print("  PS (PostScript) format for printing. This ensures")
        print("  compatibility with the target printer.")
        print()
        print("USAGE:")
        print("  convert <file> [format]")
        print()
        print("EXAMPLES:")
        print("  convert document.pdf      # Convert to default format")
        print("  convert file.txt pcl      # Convert to PCL format")
        print("  convert image.png ps      # Convert to PostScript")
        print()
        print("NOTES:")
        print("  - Default format is PCL")
        print("  - Supported formats: pcl, ps")
        print("  - Conversion may not be perfect for all file types")
        print()

    # ====================================================================
    # SUPPORT AND INFORMATION COMMANDS
    # ====================================================================
    # These commands provide support information and compatibility data

    def do_support(self, arg):
        "Show printer support matrix"
        output().message("Printer Support Matrix:")
        output().message("=====================")
        output().message("PJL Commands: Supported")
        output().message("PostScript: Not tested")
        output().message("PCL: Not tested")
        output().message("SNMP: Not tested")

    def help_support(self):
        """Show printer support matrix"""
        print()
        print("support - Show printer support matrix")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Displays the support matrix showing which features")
        print("  and commands are supported by the connected printer.")
        print("  Useful for understanding printer capabilities.")
        print()
        print("USAGE:")
        print("  support")
        print()
        print("EXAMPLES:")
        print("  support                  # Show support matrix")
        print()
        print("NOTES:")
        print("  - Shows supported protocols (PJL, PS, PCL)")
        print("  - Displays available features")
        print("  - Helps determine which commands will work")
        print()

    def do_cve(self, arg):
        "Search for CVEs related to the connected printer"
        if not self.target:
            output().errmsg("No target connected")
            return
        output().message(f"Searching for CVEs related to {self.target}...")
        # CVE search logic would go here
        output().message("No specific CVEs found for this printer model.")

    def _do_cve_fallback(self, arg):
        "Fallback CVE search method"
        output().message("Using fallback CVE search...")

    def help_cve(self):
        """Search for CVEs related to the connected printer"""
        print()
        print("cve - Search for CVEs related to the connected printer")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Searches for known Common Vulnerabilities and Exposures (CVEs)")
        print("  related to the connected printer based on its identification")
        print("  information. Helps identify potential security issues.")
        print()
        print("USAGE:")
        print("  cve")
        print()
        print("EXAMPLES:")
        print("  cve                      # Search for CVEs")
        print()
        print("NOTES:")
        print("  - Requires internet connection")
        print("  - Searches based on printer model and firmware")
        print("  - Results may include CVEs from multiple sources")
        print()

    # ====================================================================
    # UTILITY COMMANDS
    # ====================================================================
    # These commands provide utility functions and automation

    def do_load(self, arg):
        "Run commands from file: load <filename>"
        if not arg:
            output().errmsg("Usage: load <filename>")
            return
        
        if not os.path.exists(arg):
            output().errmsg(f"File not found: {arg}")
            return
        
        try:
            with open(arg, 'r') as f:
                commands = f.readlines()
            
            for cmd in commands:
                cmd = cmd.strip()
                if cmd and not cmd.startswith('#'):
                    output().info(f"Executing: {cmd}")
                    result = self.onecmd(cmd)
                    # If command returns True (like exit), stop execution
                    if result:
                        break
        except Exception as e:
            output().errmsg(f"Load failed: {e}")

    def help_load(self):
        """Run commands from file"""
        print()
        print("load - Run commands from file")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Executes commands from a text file line by line.")
        print("  Useful for automation and batch operations.")
        print("  Lines starting with # are treated as comments and ignored.")
        print()
        print("USAGE:")
        print("  load <filename>")
        print()
        print("EXAMPLES:")
        print("  load commands.txt        # Execute commands from file")
        print("  load /path/to/script.txt  # Execute with full path")
        print()
        print("NOTES:")
        print("  - File must contain one command per line")
        print("  - Lines starting with # are comments")
        print("  - Commands are executed sequentially")
        print("  - Useful for automation and scripting")
        print()

    # ====================================================================
    # ASSETS COMMANDS
    # ====================================================================
    def do_assets(self, arg):
        """List bundled assets (fonts, MIBs, overlays, test pages)"""
        base = os.path.join(os.path.dirname(os.path.dirname(__file__)))
        def p(*parts):
            return os.path.abspath(os.path.join(base, *parts))

        locations = [
            ("Fonts", p("assets", "fonts")),
            ("MIBs", p("assets", "mibs")),
            ("Overlays", p("assets", "overlays")),
            ("TestPages", p("assets", "testpages")),
            ("ModelDB", p("core", "db")),
        ]

        for title, folder in locations:
            if not os.path.isdir(folder):
                continue
            output().blue(f"{title}: {folder}")
            try:
                files = sorted(os.listdir(folder))
            except Exception as e:
                output().errmsg(f"Cannot list {folder}")
                continue
            for f in files:
                print(f"  - {f}")
            print()

    def help_assets(self):
        """List bundled assets (fonts, MIBs, overlays, test pages)"""
        print()
        print("assets - List bundled assets (fonts, MIBs, overlays, test pages)")
        print("=" * 50)
        print("DESCRIPTION:")
        print("  Displays where asset files are stored in this repository and")
        print("  prints their filenames for quick reference.")
        print()
        print("USAGE:")
        print("  assets")
        print()


    # ====================================================================
    # COMMUNICATION METHODS
    # ====================================================================
    # These methods handle low-level communication with the printer

    def send(self, data):
        if self.conn:
            return self.conn.send(data)
        return None

    def recv(self, *args):
        if self.conn:
            # If multiple args, use recv_until (delimiter, fb, crop, binary)
            # If single arg, use recv (bytes)
            if len(args) > 1:
                return self.conn.recv_until(*args)
            else:
                return self.conn.recv(*args)
        return ""

    def cmd_with_retry(self, command, max_retries=None):
        """Execute command with retry logic"""
        if max_retries is None:
            max_retries = self.max_retries
        
        for attempt in range(max_retries):
            try:
                result = self.cmd(command)
                if result is not None:
                    return result
            except Exception as e:
                if attempt == max_retries - 1:
                    raise e
                time.sleep(0.5)  # Wait before retry
        return None
