import atexit
import itertools
import pkgutil
import os
from pathlib import Path
import sys
import getopt
import signal
import traceback
from collections import Counter

# Adaptation credits: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

from routerxpl.core.exploit.exceptions import RouterXPLException
from routerxpl.core.exploit.utils import (
    index_modules,
    pythonize_path,
    humanize_path,
    import_exploit,
    stop_after,
    module_required,
    MODULES_DIR,
    WORDLISTS_DIR,
)
from routerxpl.core.exploit.printer import (
    print_info,
    print_success,
    print_error,
    print_status,
    print_warning,
    print_table,
    pprint_dict_in_order,
    PrinterThread,
    printer_queue
)
from routerxpl.core.exploit.exploit import GLOBAL_OPTS
from routerxpl.core.exploit.payloads import BasePayload

try:
    import readline
except ImportError:
    class _ReadlineShim:
        """Fallback shim for platforms without GNU readline (e.g. Windows)."""

        __doc__ = ""

        @staticmethod
        def read_history_file(*args, **kwargs):
            return None

        @staticmethod
        def set_history_length(*args, **kwargs):
            return None

        @staticmethod
        def write_history_file(*args, **kwargs):
            return None

        @staticmethod
        def parse_and_bind(*args, **kwargs):
            return None

        @staticmethod
        def set_completer(*args, **kwargs):
            return None

        @staticmethod
        def set_completer_delims(*args, **kwargs):
            return None

        @staticmethod
        def get_line_buffer():
            return ""

        @staticmethod
        def get_begidx():
            return 0

        @staticmethod
        def get_endidx():
            return 0

    readline = _ReadlineShim()


def is_libedit():
    return isinstance(readline.__doc__, str) and "libedit" in readline.__doc__


class BaseInterpreter:
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        if not os.path.exists(self.history_file):
            with open(self.history_file, "a+") as history:
                if is_libedit():
                    history.write("_HiStOrY_V2_\n\n")

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

        readline.parse_and_bind("set enable-keypad on")

        readline.set_completer(self.complete)
        readline.set_completer_delims(" \t\n;")
        if is_libedit():
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument, named_arguments)
        """
        kwargs = dict()
        command, _, arg = line.strip().partition(" ")
        args = arg.strip().split()
        for word in args:
            if '=' in word:
                (key, value) = word.split('=', 1)
                kwargs[key.lower()] = value
                arg = arg.replace(word, '')
        return command, ' '.join(arg.split()), kwargs

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise RouterXPLException("Unknown command: '{}'".format(command))

        return command_handler

    def start(self):
        """ RouterXPL main entry point. Starting interpreter loop. """
        
        if not sys.stdin.isatty():
            print_info("stdin is not a TTY. Ensure `stdin_open` and `tty` are set")
            sys.exit(1)
        
        if hasattr(self, "_rich_banner") and self._rich_banner:
            from routerxpl.core.exploit.printer import console as _con
            _con.print(self._rich_banner)
        elif self.banner:
            print_info(self.banner)
        printer_queue.join()
        
        while True:
            try:
                command, args, kwargs = self.parse_line(input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args, **kwargs)
            except RouterXPLException as err:
                print_error(err)
            except (EOFError, SystemExit):
                print_info()
                print_error("RouterXPL stopped")
                os._exit(0)
            except KeyboardInterrupt:
                print_info()
                print_error("Use Ctrl+D to exit")
            finally:
                printer_queue.join()

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args, _ = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


class RouterXPLInterpreter(BaseInterpreter):
    history_file = os.path.expanduser("~/.rxf_history")
    global_help = """Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    sysinfo                     Show detected hardware (CPU, RAM, GPU)
    compute <cpu|gpu|hybrid|auto>  Set compute mode for ML/GPU operations
    discover <subnet/CIDR>      Scan network and match targets to exploit catalog
    sessions [list|show|delete|purge|export]  Manage scan session history
    exit                        Exit RouterXPL"""

    module_help = """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit"""

    def __init__(self):
        super(RouterXPLInterpreter, self).__init__()
        PrinterThread().start()
        
        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = "rxf"
        self.show_sub_commands = ("info", "options", "advanced", "devices", "all", "encoders", "creds", "exploits", "scanners", "wordlists")
        self.search_sub_commands = ("type", "device", "language", "payload", "vendor")

        self.global_commands = sorted(["use ", "exec ", "help", "exit", "show ", "search ", "sysinfo", "compute ", "discover ", "sessions "])
        self.module_commands = ["run", "back", "set ", "setg ", "check"]
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()

        self.modules = index_modules()
        self.modules_count = Counter()
        self.modules_count.update([module.split('.')[0] for module in self.modules])
        self.main_modules_dirs = [module for module in os.listdir(MODULES_DIR) if not module.startswith("__")]

        self.__parse_prompt()

        from routerxpl.core.hw_profiler import HWProfiler
        from routerxpl.core import config as rxf_config
        from routerxpl.core.session import SessionManager
        self._hw_profile = HWProfiler.detect()
        self._session_mgr = SessionManager()

        saved_mode = rxf_config.get("compute_mode", "auto")
        if saved_mode in ("cpu", "gpu", "hybrid", "auto"):
            self._hw_profile.compute_mode = saved_mode
        self._validate_compute_mode(silent=True)

        total_modules = sum(self.modules_count.values())
        from rich.text import Text
        from routerxpl.core.exploit.printer import console as _con

        hw_line = self._hw_profile.one_liner()

        banner_lines = [
            "",
            " [bold cyan] ____  __  __ _____ [/bold cyan]",
            " [bold cyan]|  _ \\\\ \\\\ \\\\/ /|  ___| [/bold cyan]  [bold]RouterXPL-Forge[/bold] v0.4.0-beta",
            " [bold cyan]| |_) | \\\\  / | |_   [/bold cyan]  Network Device Security Assessment Framework",
            " [bold cyan]|  _ <  /  \\\\ |  _|  [/bold cyan]",
            " [bold cyan]|_| \\\\_\\\\/_/\\\\_\\\\|_|    [/bold cyan]  [dim]Author: Andre Henrique (@mrhenrike) | Uniao Geek[/dim]",
            "",
            " [blue]Target scope:[/blue] Routers - Switches L2/L3 - TAPs - SOHO Edge",
            "",
            " [green]\\[modules][/green] {total} total -- Exploits: {exploits} | Scanners: {scanners} | Creds: {creds} | Generic: {generic} | Payloads: {payloads} | Encoders: {encoders}",
            " [yellow]\\[system][/yellow]  {hw_line}",
            "",
        ]
        formatted = "\n".join(banner_lines).format(
            total=total_modules,
            exploits=self.modules_count["exploits"],
            scanners=self.modules_count["scanners"],
            creds=self.modules_count["creds"],
            generic=self.modules_count["generic"],
            payloads=self.modules_count["payloads"],
            encoders=self.modules_count["encoders"],
            hw_line=hw_line,
        )
        self.banner = ""
        self._rich_banner = formatted

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("RXF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("RXF_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    def __handle_if_noninteractive(self, argv):
        """ Keep old method for backward compat only """
        self.nonInteractive(argv)

    def nonInteractive(self, argv):
        """ Execute specific command and return result without launching the interactive CLI

        :return:

        """
        module = ""
        set_opts = []

        try:
            opts, args = getopt.getopt(argv[1:], "hm:s:", ["help=", "module=", "set="])
        except getopt.GetoptError:
            print_info("{} -m <module> -s \"<option> <value>\"".format(argv[0]))
            printer_queue.join()
            return

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_info("{} -m <module> -s \"<option> <value>\"".format(argv[0]))
                printer_queue.join()
                return
            elif opt in ("-m", "--module"):
                module = arg
            elif opt in ("-s", "--set"):
                set_opts.append(arg)

        if not len(module):
            print_error('A module is required when running non-interactively')
            printer_queue.join()
            return

        self.command_use(module)

        for opt in set_opts:
            self.command_set(opt)

        self.command_exploit()

        # Wait for results if needed
        printer_queue.join()

        return

    @property
    def module_metadata(self):
        return getattr(self.current_module, "_{}__info__".format(self.current_module.__class__.__name__))

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname, module=self.module_metadata['name'])
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def available_modules_completion(self, text):
        """ Looking for tab completion hints using setup.py entry_points.

        May need optimization in the future!

        :param text: argument of 'use' command
        :return: list of tab completion hints
        """
        text = pythonize_path(text)
        all_possible_matches = filter(lambda x: x.startswith(text), self.modules)
        matches = set()
        for match in all_possible_matches:
            head, sep, tail = match[len(text):].partition('.')
            if not tail:
                sep = ""
            matches.add("".join((text, head, sep)))
        return list(map(humanize_path, matches))  # humanize output, replace dots to forward slashes

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        if self.current_module and GLOBAL_OPTS:
            return sorted(itertools.chain(self.module_commands, ("unsetg ",)))
        elif self.current_module:
            return self.module_commands
        else:
            return self.global_commands

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_use(self, module_path, *args, **kwargs):
        module_path = pythonize_path(module_path)
        module_path = ".".join(("routerxpl", "modules", module_path))
        # module_path, _, exploit_name = module_path.rpartition('.')
        try:
            self.current_module = import_exploit(module_path)()
        except RouterXPLException as err:
            print_error(str(err))

    @stop_after(2)
    def complete_use(self, text, *args, **kwargs):
        if text:
            return self.available_modules_completion(text)
        else:
            return self.main_modules_dirs

    def __command_sigint_handler(self, signum, frame):
        raise KeyboardInterrupt

    @module_required
    def command_run(self, *args, **kwargs):
        print_status("Running module {}...".format(self.current_module))
        import time as _time
        from routerxpl.core.session import ModuleResult

        previous_sigint_handler = signal.getsignal(signal.SIGINT)
        t0 = _time.monotonic()
        mod_path = str(self.current_module)
        target_ip = getattr(self.current_module, "target", "")
        error_msg = None

        try:
            signal.signal(signal.SIGINT, self.__command_sigint_handler)
            self.current_module.run()
        except KeyboardInterrupt:
            print_info()
            print_error("Operation cancelled by user")
            error_msg = "cancelled"
        except Exception:
            print_error(traceback.format_exc())
            error_msg = traceback.format_exc().splitlines()[-1] if traceback.format_exc() else "unknown"
        finally:
            signal.signal(signal.SIGINT, previous_sigint_handler)

        elapsed = _time.monotonic() - t0
        self._record_module_result(
            target_ip, mod_path,
            vulnerable=None,
            error=error_msg,
            elapsed=elapsed,
            port=getattr(self.current_module, "port", 0),
        )


    def command_exploit(self, *args, **kwargs):
        self.command_run()

    @module_required
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(" ")
        if key in self.current_module.options:
            setattr(self.current_module, key, value)
            self.current_module.exploit_attributes[key][0] = value

            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
            print_success("{} => {}".format(key, value))
        else:
            print_error("You can't set option '{}'.\n"
                        "Available options: {}".format(key, self.current_module.options))

    @stop_after(2)
    def complete_set(self, text, *args, **kwargs):
        if text:
            return [" ".join((attr, "")) for attr in self.current_module.options if attr.startswith(text)]
        else:
            return self.current_module.options

    @module_required
    def command_setg(self, *args, **kwargs):
        kwargs['glob'] = True
        self.command_set(*args, **kwargs)

    @stop_after(2)
    def complete_setg(self, text, *args, **kwargs):
        return self.complete_set(text, *args, **kwargs)

    @module_required
    def command_unsetg(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        try:
            del GLOBAL_OPTS[key]
        except KeyError:
            print_error("You can't unset global option '{}'.\n"
                        "Available global options: {}".format(key, list(GLOBAL_OPTS.keys())))
        else:
            print_success({key: value})

    @stop_after(2)
    def complete_unsetg(self, text, *args, **kwargs):
        global_opt_keys = list(GLOBAL_OPTS.keys())
        if text:
            return [' '.join((attr, "")) for attr in global_opt_keys if attr.startswith(text)]
        else:
            return global_opt_keys

    @module_required
    def get_opts(self, *args):
        """ Generator returning module's Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key][1]
                opt_display_value = self.current_module.exploit_attributes[opt_key][0]
                if self.current_module.exploit_attributes[opt_key][2]:
                    continue
            except (KeyError, IndexError, AttributeError):
                pass
            else:
                yield opt_key, opt_display_value, opt_description

    @module_required
    def get_opts_adv(self, *args):
        """ Generator returning module's advanced Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key][1]
                opt_display_value = self.current_module.exploit_attributes[opt_key][0]
            except (KeyError, AttributeError):
                pass
            else:
                yield opt_key, opt_display_value, opt_description

    @module_required
    def _show_info(self, *args, **kwargs):
        pprint_dict_in_order(
            self.module_metadata,
            ("name", "description", "devices", "authors", "references"),
        )
        print_info()

    @module_required
    def _show_options(self, *args, **kwargs):
        target_names = ["target", "port", "ssl", "rhost", "rport", "lhost", "lport"]
        target_opts = [opt for opt in self.current_module.options if opt in target_names]
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        print_info("\nTarget options:")
        print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            print_info("\nModule options:")
            print_table(headers, *self.get_opts(*module_opts))

        print_info()

    @module_required
    def _show_advanced(self, *args, **kwargs):
        target_names = ["target", "port", "ssl", "rhost", "rport", "lhost", "lport"]
        target_opts = [opt for opt in self.current_module.options if opt in target_names]
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        print_info("\nTarget options:")
        print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            print_info("\nModule options:")
            print_table(headers, *self.get_opts_adv(*module_opts))

        print_info()

    @module_required
    def _show_devices(self, *args, **kwargs):  # TODO: cover with tests
        try:
            devices = self.current_module._Exploit__info__['devices']

            print_info("\nTarget devices:")
            i = 0
            for device in devices:
                if isinstance(device, dict):
                    print_info("   {} - {}".format(i, device['name']))
                else:
                    print_info("   {} - {}".format(i, device))
                i += 1
            print_info()
        except KeyError:
            print_info("\nTarget devices are not defined")

    @module_required
    def _show_wordlists(self, *args, **kwargs):
        headers = ("Wordlist", "Path")
        wordlists = [
            (f, Path(os.path.join(WORDLISTS_DIR, f)).resolve().as_uri())
            for f in os.listdir(WORDLISTS_DIR)
            if f.endswith(".txt")
        ]

        print_table(headers, *wordlists, max_column_length=100)

    @module_required
    def _show_encoders(self, *args, **kwargs):
        if issubclass(self.current_module.__class__, BasePayload):
            encoders = self.current_module.get_encoders()
            if encoders:
                headers = ("Encoder", "Name", "Description")
                print_table(headers, *encoders, max_column_length=100)
                return

        print_error("No encoders available")

    def __show_modules(self, root=''):
        for module in [module for module in self.modules if module.startswith(root)]:
            print_info(module.replace('.', os.sep))

    def _show_all(self, *args, **kwargs):
        self.__show_modules()

    def _show_scanners(self, *args, **kwargs):
        self.__show_modules('scanners')

    def _show_exploits(self, *args, **kwargs):
        self.__show_modules('exploits')

    def _show_creds(self, *args, **kwargs):
        self.__show_modules('creds')

    def _show_devices(self, *args, **kwargs):
        """Display supported device types and vendor coverage."""
        from routerxpl.core.exploit.printer import print_table, print_info
        vendors = set()
        for mod in self.modules:
            parts = mod.split(".")
            if len(parts) >= 3:
                vendors.add(parts[2])
        vendors.discard("generic")
        vendors.discard("multi")

        device_types = [
            ("Routers", "SOHO routers, enterprise gateways, CPE", "Primary"),
            ("Switches L2/L3", "Managed and unmanaged network switches", "Expanding"),
            ("TAPs", "Network TAP devices", "Planned"),
            ("SOHO Edge", "Small office / home office edge appliances", "Expanding"),
        ]
        headers = ("Device Type", "Description", "Coverage")
        print_table(headers, *device_types)
        print_info("  Vendors covered: {}".format(", ".join(sorted(vendors))))
        print_info()

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        try:
            getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
        except AttributeError:
            print_error("Unknown 'show' sub-command '{}'. "
                        "What do you want to show?\n"
                        "Possible choices are: {}".format(sub_command, self.show_sub_commands))

    @stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        if text:
            return [command for command in self.show_sub_commands if command.startswith(text)]
        else:
            return self.show_sub_commands

    @module_required
    def command_check(self, *args, **kwargs):
        import time as _time
        from routerxpl.core.session import ModuleResult

        t0 = _time.monotonic()
        mod_path = str(self.current_module)
        target_ip = getattr(self.current_module, "target", "")
        vuln_result = None
        error_msg = None

        try:
            result = self.current_module.check()
        except Exception as error:
            print_error(error)
            error_msg = str(error)
        else:
            if result is True:
                print_success("Target is vulnerable")
                vuln_result = True
            elif result is False:
                print_error("Target is not vulnerable")
                vuln_result = False
            else:
                print_status("Target could not be verified")

        elapsed = _time.monotonic() - t0
        self._record_module_result(
            target_ip, mod_path,
            vulnerable=vuln_result,
            error=error_msg,
            elapsed=elapsed,
            port=getattr(self.current_module, "port", 0),
        )

    def command_help(self, *args, **kwargs):
        print_info(self.global_help)
        if self.current_module:
            print_info("\n", self.module_help)

    def command_exec(self, *args, **kwargs):
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        mod_type = ''
        mod_detail = ''
        mod_vendor = ''
        existing_modules = [name for _, name, _ in pkgutil.iter_modules([MODULES_DIR])]
        devices = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'exploits')])]
        languages = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'encoders')])]
        payloads = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'payloads')])]

        try:
            keyword = args[0].strip("'\"").lower()
        except IndexError:
            keyword = ''

        if not (len(keyword) or len(kwargs.keys())):
            print_error("Please specify at least search keyword. e.g. 'search cisco'")
            print_error("You can specify options. e.g. 'search type=exploits device=routers vendor=linksys WRT100 rce'")
            return

        for (key, value) in kwargs.items():
            if key == 'type':
                if value not in existing_modules:
                    print_error("Unknown module type.")
                    return
                # print_info(' - Type  :\t{}'.format(value))
                mod_type = "{}.".format(value)
            elif key in ['device', 'language', 'payload']:
                if key == 'device' and (value not in devices):
                    print_error("Unknown exploit type.")
                    return
                elif key == 'language' and (value not in languages):
                    print_error("Unknown encoder language.")
                    return
                elif key == 'payload' and (value not in payloads):
                    print_error("Unknown payload type.")
                    return
                # print_info(' - {}:\t{}'.format(key.capitalize(), value))
                mod_detail = ".{}.".format(value)
            elif key == 'vendor':
                # print_info(' - Vendor:\t{}'.format(value))
                mod_vendor = ".{}.".format(value)

        for module in self.modules:
            if mod_type not in str(module):
                continue
            if mod_detail not in str(module):
                continue
            if mod_vendor not in str(module):
                continue
            if not all(word in str(module) for word in keyword.split()):
                continue

            found = humanize_path(module)

            if len(keyword):
                from routerxpl.core.exploit.printer import console as _con
                from rich.text import Text
                text_obj = Text(found)
                for word in keyword.split():
                    text_obj.highlight_words([word], style="bold red")
                _con.print(text_obj)
            else:
                print_info(found)

    @stop_after(2)
    def complete_search(self, text, *args, **kwargs):
        if text:
            return [command for command in self.search_sub_commands if command.startswith(text)]
        else:
            return self.search_sub_commands

    def _validate_compute_mode(self, silent: bool = False) -> bool:
        """Validate current compute_mode against available hardware.

        If mode is ``gpu`` or ``hybrid`` but no GPU is present, falls back
        to ``cpu`` and optionally warns the user.

        Returns:
            True if the mode is valid as-is, False if a fallback occurred.
        """
        mode = self._hw_profile.compute_mode
        has_gpu = self._hw_profile.has_gpu()

        if mode in ("gpu", "hybrid") and not has_gpu:
            self._hw_profile.compute_mode = "cpu"
            if not silent:
                print_warning(
                    "No GPU detected -- falling back to compute_mode=cpu"
                )
            return False
        return True

    def command_sysinfo(self, *args, **kwargs):
        """Display detailed hardware profile of the host machine."""
        from routerxpl.core.hw_profiler import HWProfiler
        from routerxpl.core.exploit.printer import console as _con
        from rich.table import Table
        from rich.panel import Panel

        profile = HWProfiler.detect(force=True)
        self._hw_profile = profile

        from routerxpl.core import config as rxf_config
        saved_mode = rxf_config.get("compute_mode", "auto")
        if saved_mode in ("cpu", "gpu", "hybrid", "auto"):
            profile.compute_mode = saved_mode

        cpu_table = Table(title="CPU", show_header=True, header_style="bold cyan",
                          border_style="dim", pad_edge=True)
        cpu_table.add_column("Property", style="bold")
        cpu_table.add_column("Value")
        cpu_table.add_row("Model", profile.cpu_model)
        cpu_table.add_row("Architecture", profile.cpu_arch)
        cpu_table.add_row("Cores", str(profile.cpu_cores))
        cpu_table.add_row("Threads", str(profile.cpu_threads))
        freq_str = "{} MHz".format(profile.cpu_freq_mhz) if profile.cpu_freq_mhz else "N/A"
        cpu_table.add_row("Frequency", freq_str)
        _con.print(cpu_table)

        ram_table = Table(title="Memory (RAM)", show_header=True, header_style="bold cyan",
                          border_style="dim", pad_edge=True)
        ram_table.add_column("Property", style="bold")
        ram_table.add_column("Value")
        ram_table.add_row("Total", "{:,} MB".format(profile.ram_total_mb))
        ram_table.add_row("Available", "{:,} MB".format(profile.ram_available_mb))
        _con.print(ram_table)

        if profile.gpus:
            gpu_table = Table(title="GPU Devices", show_header=True, header_style="bold cyan",
                              border_style="dim", pad_edge=True)
            gpu_table.add_column("#", style="dim")
            gpu_table.add_column("Name", style="bold")
            gpu_table.add_column("Vendor")
            gpu_table.add_column("VRAM")
            gpu_table.add_column("Backend")
            gpu_table.add_column("Driver")
            gpu_table.add_column("Compute Cap")
            for g in profile.gpus:
                vram = "{:,} MB".format(g.vram_mb) if g.vram_mb else "N/A"
                gpu_table.add_row(
                    str(g.index), g.name, g.vendor, vram,
                    g.backend, g.driver or "N/A", g.compute_cap or "N/A",
                )
            _con.print(gpu_table)
        else:
            print_warning("No GPU detected on this system")

        mode = profile.compute_mode
        if mode == "auto":
            resolved = "hybrid" if profile.has_gpu() else "cpu"
            mode_display = "auto -> {}".format(resolved)
        else:
            mode_display = mode
        _con.print(
            "\n [bold]Compute mode:[/bold] [cyan]{}[/cyan]  |  "
            "[bold]Best backend:[/bold] [cyan]{}[/cyan]\n".format(
                mode_display, profile.best_backend
            )
        )

    def command_compute(self, *args, **kwargs):
        """Set the compute mode for ML/GPU operations.

        Usage: compute <cpu|gpu|hybrid|auto>
        """
        from routerxpl.core import config as rxf_config

        try:
            mode = args[0].strip().lower()
        except (IndexError, AttributeError):
            mode = ""

        valid_modes = ("cpu", "gpu", "hybrid", "auto")
        if mode not in valid_modes:
            print_error(
                "Invalid compute mode '{}'. Choose from: {}".format(
                    mode, ", ".join(valid_modes)
                )
            )
            return

        self._hw_profile.compute_mode = mode
        if not self._validate_compute_mode():
            rxf_config.set_val("compute_mode", self._hw_profile.compute_mode)
            return

        rxf_config.set_val("compute_mode", mode)
        print_success("compute_mode => {}".format(mode))

        if mode == "auto":
            resolved = "hybrid" if self._hw_profile.has_gpu() else "cpu"
            print_info("  auto resolves to: {}".format(resolved))

    @stop_after(2)
    def complete_compute(self, text, *args, **kwargs):
        modes = ["cpu", "gpu", "hybrid", "auto"]
        if text:
            return [m for m in modes if m.startswith(text)]
        return modes

    def command_discover(self, *args, **kwargs):
        """Scan a subnet and match live hosts against the exploit catalog.

        Session-aware: if a host was scanned before (same IP+MAC), shows
        previous findings and offers to resume (skip already-tested modules)
        or restart from scratch.

        Usage:
            discover <subnet/CIDR>
            discover <subnet/CIDR> --fresh   (ignore session, full rescan)

        Examples:
            discover 192.168.1.0/24
            discover 10.0.0.1
            discover 192.168.18.0/24 --fresh
        """
        import time as _time
        from datetime import datetime
        from routerxpl.core.discovery import NetworkDiscovery
        from routerxpl.core.session import SessionManager, host_id as _host_id
        from routerxpl.core.exploit.printer import console as _con
        from rich.table import Table
        from rich.panel import Panel

        try:
            raw_args = list(args)
            force_fresh = "--fresh" in raw_args
            if force_fresh:
                raw_args.remove("--fresh")
            target = raw_args[0].strip()
        except (IndexError, AttributeError):
            print_error("Usage: discover <subnet/CIDR>  (e.g. discover 192.168.1.0/24)")
            return

        try:
            import ipaddress
            ipaddress.ip_network(target, strict=False)
        except ValueError:
            try:
                ipaddress.ip_address(target)
            except ValueError:
                print_error("Invalid target: '{}'. Use IP or CIDR notation.".format(target))
                return

        def progress_cb(stage: str, detail: str) -> None:
            print_status("[{}] {}".format(stage, detail))

        print_info()
        print_status("Starting network discovery on {}".format(target))
        discovery = NetworkDiscovery(target)

        try:
            hosts = discovery.scan(callback=progress_cb)
        except KeyboardInterrupt:
            print_warning("Discovery cancelled by user")
            hosts = discovery.hosts
        except Exception as exc:
            print_error("Discovery failed: {}".format(exc))
            return

        if not hosts:
            print_warning("No live hosts found on {}".format(target))
            return

        # --- Session integration: check for existing sessions ---
        sessions_resumed = 0
        sessions_new = 0

        for h in hosts:
            session, is_existing = self._session_mgr.get_or_create(h.ip, h.mac)

            if is_existing and not force_fresh:
                sessions_resumed += 1
                prev_tested = len(session.modules_tested())
                prev_vulns = len(session.vulns_found)
                last_dt = datetime.fromtimestamp(session.last_scanned).strftime("%Y-%m-%d %H:%M")

                _con.print(
                    "\n[bold yellow]SESSION FOUND[/bold yellow] for "
                    "[bold]{ip}[/bold] ({mac}) — "
                    "last scan: {dt}, tested: {t}, vulns: {v}".format(
                        ip=h.ip,
                        mac=h.mac or "no-mac",
                        dt=last_dt,
                        t=prev_tested,
                        v=prev_vulns,
                    )
                )

                pending = session.modules_pending()
                if pending:
                    _con.print(
                        "  [dim]{} module(s) already tested, "
                        "{} pending — resuming from where it stopped[/dim]".format(
                            prev_tested, len(pending),
                        )
                    )

                if session.vulns_found:
                    _con.print("  [bold red]Previous vulns:[/bold red]")
                    for v in session.vulns_found:
                        _con.print("    [red]• {}[/red]".format(v))
            else:
                sessions_new += 1

            session.merge_discovery(
                ip=h.ip,
                mac=h.mac,
                hostname=h.hostname,
                vendor=h.vendor_guess,
                model=h.model_guess,
                open_ports=h.open_ports,
                banners={str(k): v for k, v in h.banners.items()},
                fingerprint_confidence=h.fingerprint_confidence,
                matched_modules=h.matched_modules,
                has_wireless=h.has_wireless,
                wireless_ssids=h.wireless_ssids,
                wireless_recommendation=h.wireless_recommendation,
            )
            self._session_mgr.save(session)

        if sessions_resumed:
            _con.print()
            print_success(
                "{} host(s) resumed from session history, {} new".format(
                    sessions_resumed, sessions_new,
                )
            )
            _con.print("[dim]Use 'discover {} --fresh' to ignore history and rescan from zero[/dim]".format(target))
        elif sessions_new:
            print_info("{} new session(s) created".format(sessions_new))

        # --- Results table ---
        results_table = Table(
            title="Discovered Hosts ({})".format(len(hosts)),
            show_header=True,
            header_style="bold cyan",
            border_style="dim",
            pad_edge=True,
        )
        results_table.add_column("IP", style="bold")
        results_table.add_column("MAC")
        results_table.add_column("Hostname")
        results_table.add_column("Ports")
        results_table.add_column("Vendor", style="bold green")
        results_table.add_column("Model")
        results_table.add_column("Confidence")
        results_table.add_column("Modules", style="bold yellow")
        results_table.add_column("Tested", style="green")
        results_table.add_column("Pending", style="red")
        results_table.add_column("WiFi", style="cyan")

        for h in hosts:
            ports = ",".join(str(p) for p in h.open_ports[:8])
            conf_str = "{:.0%}".format(h.fingerprint_confidence) if h.fingerprint_confidence else "-"
            mod_count = str(len(h.matched_modules)) if h.matched_modules else "-"
            wifi_flag = "Yes" if h.has_wireless else "-"

            session = self._session_mgr.load(h.ip, h.mac)
            tested_count = str(len(session.modules_tested())) if session else "0"
            pending_count = str(len(session.modules_pending())) if session else mod_count

            results_table.add_row(
                h.ip,
                h.mac or "-",
                h.hostname or "-",
                ports or "-",
                h.vendor_guess or "-",
                h.model_guess or "-",
                conf_str,
                mod_count,
                tested_count,
                pending_count,
                wifi_flag,
            )

        _con.print(results_table)

        # --- Module matching details ---
        targets_with_mods = discovery.hosts_with_modules()
        if targets_with_mods:
            print_success(
                "\n{} host(s) matched against the exploit catalog:".format(len(targets_with_mods))
            )
            for h in targets_with_mods:
                vendor_tag = "[{}]".format(h.vendor_guess) if h.vendor_guess else ""
                model_tag = h.model_guess or ""

                session = self._session_mgr.load(h.ip, h.mac)
                tested_set = set(session.modules_tested()) if session else set()
                vuln_set = set(session.vulns_found) if session else set()

                _con.print(
                    "  [bold]{ip}[/bold] {vendor} {model} -- "
                    "[yellow]{count}[/yellow] exploit module(s)".format(
                        ip=h.ip,
                        vendor=vendor_tag,
                        model=model_tag,
                        count=len(h.matched_modules),
                    )
                )

                for mod in h.matched_modules[:15]:
                    if mod in vuln_set:
                        status_tag = " [bold red]VULN[/bold red]"
                    elif mod in tested_set:
                        status_tag = " [green]tested[/green]"
                    else:
                        status_tag = " [dim]pending[/dim]"
                    _con.print("    use {mod}{st}".format(
                        mod=mod.replace(".", "/"),
                        st=status_tag,
                    ))
                if len(h.matched_modules) > 15:
                    _con.print(
                        "    [dim]... and {} more[/dim]".format(
                            len(h.matched_modules) - 15
                        )
                    )
        else:
            print_info("No discovered hosts matched the exploit catalog.")

        # --- WirelessXPL-Forge cross-reference ---
        wifi_hosts = discovery.hosts_with_wireless()
        if wifi_hosts:
            _con.print()
            for h in wifi_hosts:
                if h.wireless_recommendation:
                    ssid_label = ""
                    if h.wireless_ssids:
                        ssid_label = "  SSIDs: {}".format(", ".join(h.wireless_ssids))
                    tag = "[bold magenta]RECOMMENDED[/bold magenta]" if not h.matched_modules else "[bold cyan]COMPLEMENTARY[/bold cyan]"
                    _con.print(Panel(
                        "{tag} {ip} ({vendor} {model}){ssid}\n\n"
                        "[dim]{rec}[/dim]".format(
                            tag=tag,
                            ip=h.ip,
                            vendor=h.vendor_guess or "Unknown",
                            model=h.model_guess or "",
                            ssid=ssid_label,
                            rec=h.wireless_recommendation,
                        ),
                        title="[bold]WirelessXPL-Forge[/bold]",
                        border_style="magenta" if not h.matched_modules else "cyan",
                        expand=False,
                    ))

        print_info()

    def command_sessions(self, *args, **kwargs):
        """Manage scan session history (like John the Ripper's --restore).

        Usage:
            sessions                     List all saved sessions
            sessions list                Same as above
            sessions show <ip>           Show detailed session for a host
            sessions delete <ip>         Delete session for a host
            sessions export <ip>         Export session as JSON
            sessions purge               Delete ALL sessions (asks confirmation)
        """
        from routerxpl.core.exploit.printer import console as _con
        from rich.table import Table
        from rich.panel import Panel
        from datetime import datetime

        sub = ""
        sub_args: list = []
        if args:
            parts = args[0].strip().split() if isinstance(args[0], str) else list(args)
            if parts:
                sub = parts[0].lower()
                sub_args = parts[1:]

        if sub in ("", "list"):
            sessions = self._session_mgr.list_sessions()
            if not sessions:
                print_info("No saved sessions. Run 'discover <target>' to create one.")
                return

            tbl = Table(
                title="Saved Sessions ({})".format(len(sessions)),
                show_header=True,
                header_style="bold cyan",
                border_style="dim",
            )
            tbl.add_column("#", style="dim")
            tbl.add_column("IP", style="bold")
            tbl.add_column("MAC")
            tbl.add_column("Vendor", style="green")
            tbl.add_column("Model")
            tbl.add_column("Scans", style="yellow")
            tbl.add_column("Tested", style="green")
            tbl.add_column("Pending", style="red")
            tbl.add_column("Vulns", style="bold red")
            tbl.add_column("Last Scan")
            tbl.add_column("ID", style="dim")

            for i, s in enumerate(sessions, 1):
                last_dt = "-"
                if s.get("last_scanned"):
                    last_dt = datetime.fromtimestamp(s["last_scanned"]).strftime("%Y-%m-%d %H:%M")
                tbl.add_row(
                    str(i),
                    s.get("ip", "?"),
                    s.get("mac", "-"),
                    s.get("vendor", "-"),
                    s.get("model", "-"),
                    str(s.get("total_scans", 0)),
                    str(s.get("tested", 0)),
                    str(s.get("pending", 0)),
                    str(s.get("vulns", 0)),
                    last_dt,
                    s.get("host_id", "?")[:8],
                )
            _con.print(tbl)
            _con.print("[dim]Use 'sessions show <ip>' for details[/dim]")
            return

        if sub == "show":
            if not sub_args:
                print_error("Usage: sessions show <ip>")
                return
            ip = sub_args[0]
            session = self._session_mgr.load(ip)
            if not session:
                print_warning("No session found for {}".format(ip))
                return

            first_dt = datetime.fromtimestamp(session.first_seen).strftime("%Y-%m-%d %H:%M") if session.first_seen else "-"
            last_dt = datetime.fromtimestamp(session.last_scanned).strftime("%Y-%m-%d %H:%M") if session.last_scanned else "-"

            header = (
                "[bold]{ip}[/bold] ({mac})\n"
                "Vendor: [green]{vendor}[/green]  Model: {model}\n"
                "First seen: {first}  Last scan: {last}\n"
                "Total scans: [yellow]{scans}[/yellow]  "
                "Ports: {ports}\n"
                "WiFi: {wifi}{ssids}"
            ).format(
                ip=session.ip,
                mac=session.mac or "no-mac",
                vendor=session.vendor or "?",
                model=session.model or "?",
                first=first_dt,
                last=last_dt,
                scans=session.total_scans,
                ports=",".join(str(p) for p in session.open_ports[:12]) or "-",
                wifi="Yes" if session.has_wireless else "No",
                ssids=" ({})".format(", ".join(session.wireless_ssids)) if session.wireless_ssids else "",
            )
            _con.print(Panel(header, title="[bold]Session Detail[/bold]", border_style="cyan"))

            # Module results breakdown
            tested = session.modules_tested()
            vulns = session.modules_vulnerable()
            safe = session.modules_safe()
            errored = session.modules_errored()
            pending = session.modules_pending()

            _con.print("\n[bold]Module Execution Summary:[/bold]")
            _con.print("  Matched:  [yellow]{}[/yellow]".format(len(session.matched_modules)))
            _con.print("  Tested:   [green]{}[/green]".format(len(tested)))
            _con.print("  Pending:  [red]{}[/red]".format(len(pending)))
            _con.print("  Vuln:     [bold red]{}[/bold red]".format(len(vulns)))
            _con.print("  Safe:     [green]{}[/green]".format(len(safe)))
            _con.print("  Errored:  [yellow]{}[/yellow]".format(len(errored)))

            if vulns:
                _con.print("\n[bold red]Confirmed Vulnerabilities:[/bold red]")
                for v in vulns:
                    _con.print("  [red]• {}[/red]".format(v))

            if pending:
                _con.print("\n[bold]Pending Modules (not yet tested):[/bold]")
                for m in pending[:20]:
                    _con.print("  [dim]• {}[/dim]".format(m))
                if len(pending) > 20:
                    _con.print("  [dim]... and {} more[/dim]".format(len(pending) - 20))

            if session.module_results:
                _con.print("\n[bold]Execution History (last 20):[/bold]")
                hist_tbl = Table(show_header=True, header_style="dim", border_style="dim", pad_edge=True)
                hist_tbl.add_column("Module")
                hist_tbl.add_column("Result")
                hist_tbl.add_column("Time")
                hist_tbl.add_column("Elapsed")

                for r in session.module_results[-20:]:
                    if r.vulnerable is True:
                        res_str = "[bold red]VULNERABLE[/bold red]"
                    elif r.vulnerable is False:
                        res_str = "[green]safe[/green]"
                    elif r.error:
                        res_str = "[yellow]error[/yellow]"
                    else:
                        res_str = "[dim]unknown[/dim]"
                    ts = datetime.fromtimestamp(r.timestamp).strftime("%m-%d %H:%M") if r.timestamp else "-"
                    hist_tbl.add_row(
                        r.module_path.split(".")[-1] if "." in r.module_path else r.module_path,
                        res_str,
                        ts,
                        "{:.1f}s".format(r.elapsed_s),
                    )
                _con.print(hist_tbl)

            if session.notes:
                _con.print("\n[bold]Notes:[/bold]")
                for note in session.notes:
                    _con.print("  [dim]{}[/dim]".format(note))

            return

        if sub == "delete":
            if not sub_args:
                print_error("Usage: sessions delete <ip>")
                return
            ip = sub_args[0]
            if self._session_mgr.delete(ip):
                print_success("Session for {} deleted".format(ip))
            else:
                print_warning("No session found for {}".format(ip))
            return

        if sub == "export":
            if not sub_args:
                print_error("Usage: sessions export <ip>")
                return
            ip = sub_args[0]
            data = self._session_mgr.export_session(ip)
            if data:
                _con.print(data)
            else:
                print_warning("No session found for {}".format(ip))
            return

        if sub == "purge":
            _con.print("[bold red]WARNING: This will delete ALL saved sessions![/bold red]")
            try:
                confirm = input("Type 'yes' to confirm: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print_info("Cancelled")
                return
            if confirm == "yes":
                count = self._session_mgr.purge_all()
                print_success("Purged {} session(s)".format(count))
            else:
                print_info("Cancelled")
            return

        print_error("Unknown sub-command '{}'. Use: list, show, delete, export, purge".format(sub))

    def _record_module_result(
        self,
        target_ip: str,
        module_path: str,
        vulnerable=None,
        error=None,
        elapsed: float = 0.0,
        port: int = 0,
    ) -> None:
        """Record a module execution result into the session for the target host."""
        if not target_ip:
            return
        from routerxpl.core.session import ModuleResult
        import time as _time

        session = self._session_mgr.load(target_ip)
        if not session:
            session, _ = self._session_mgr.get_or_create(target_ip)

        result = ModuleResult(
            module_path=module_path,
            vulnerable=vulnerable,
            error=error,
            elapsed_s=elapsed,
            port=port,
            timestamp=_time.time(),
        )
        session.add_result(result)
        self._session_mgr.save(session)

    def command_apt(self, *args, **kwargs):
        """Browse and execute APT group attack chains.

        Usage:
            apt                          List all APT groups
            apt list                     Same as above
            apt show <group_id>          Show attacks for a group
            apt search <keyword>         Search groups by device/CVE
            apt run <group_id>           Run ALL attacks for a group (interactive)
            apt run <group_id> <attack#> Run a specific attack by index
        """
        from routerxpl.core.apt_catalog import get_catalog, get_group, list_groups, find_groups_by_device, find_groups_by_cve
        from routerxpl.core.exploit.printer import console as _con
        from rich.table import Table
        from rich.panel import Panel

        sub = ""
        sub_args: list = []
        if args:
            parts = args[0].strip().split() if isinstance(args[0], str) else list(args)
            if parts:
                sub = parts[0].lower()
                sub_args = parts[1:]

        if sub in ("", "list"):
            groups = list_groups()
            tbl = Table(
                title="APT Groups Targeting Network Devices ({})".format(len(groups)),
                show_header=True, header_style="bold cyan", border_style="dim",
            )
            tbl.add_column("ID", style="bold")
            tbl.add_column("Name", style="green")
            tbl.add_column("Country")
            tbl.add_column("Aliases", style="dim")
            tbl.add_column("Attacks", justify="center")
            tbl.add_column("MITRE")

            for g in groups:
                tbl.add_row(
                    g.id, g.name, g.country,
                    ", ".join(g.aliases[:3]),
                    str(len(g.attacks)),
                    g.mitre_id,
                )
            _con.print(tbl)
            print_info("Use 'apt show <group_id>' for details or 'apt run <group_id>' to execute")
            return

        if sub == "show":
            if not sub_args:
                print_error("Usage: apt show <group_id>")
                return
            group = get_group(sub_args[0])
            if not group:
                print_error("Unknown group: {}".format(sub_args[0]))
                return

            header = "[bold]{name}[/bold] ({country})\n{desc}".format(
                name=group.name, country=group.country, desc=group.description,
            )
            _con.print(Panel(header, title="APT Profile: {}".format(group.id), border_style="red"))

            tbl = Table(show_header=True, header_style="bold red", border_style="dim")
            tbl.add_column("#", style="dim", width=3)
            tbl.add_column("Phase", style="cyan")
            tbl.add_column("Attack", style="bold")
            tbl.add_column("CVEs", style="yellow")
            tbl.add_column("Modules", style="green")
            tbl.add_column("Devices")
            tbl.add_column("Auth", justify="center")

            for i, atk in enumerate(group.attacks):
                tbl.add_row(
                    str(i), atk.phase, atk.name,
                    "\n".join(atk.cves) if atk.cves else "-",
                    "\n".join(atk.modules),
                    "\n".join(atk.target_devices[:2]),
                    "Yes" if atk.requires_auth else "No",
                )
            _con.print(tbl)
            print_info("Use 'apt run {} [attack#]' to execute".format(group.id))
            return

        if sub == "search":
            keyword = " ".join(sub_args) if sub_args else ""
            if not keyword:
                print_error("Usage: apt search <device_or_cve>")
                return

            results = find_groups_by_device(keyword) if not keyword.upper().startswith("CVE-") else find_groups_by_cve(keyword)
            if not results:
                print_info("No APT groups found for '{}'".format(keyword))
                return

            for g in results:
                print_success("{} ({}) — {} attacks".format(g.name, g.country, len(g.attacks)))
                for atk in g.attacks:
                    if keyword.lower() in " ".join(atk.target_devices).lower() or keyword.upper() in atk.cves:
                        print_info("  -> {} [{}]".format(atk.name, ", ".join(atk.cves) if atk.cves else atk.phase))
            return

        if sub == "run":
            if not sub_args:
                print_error("Usage: apt run <group_id> [attack_index]")
                return
            group = get_group(sub_args[0])
            if not group:
                print_error("Unknown group: {}".format(sub_args[0]))
                return

            attack_idx = None
            if len(sub_args) > 1:
                try:
                    attack_idx = int(sub_args[1])
                except ValueError:
                    print_error("Attack index must be a number")
                    return

            attacks_to_run = [group.attacks[attack_idx]] if attack_idx is not None else group.attacks

            for atk in attacks_to_run:
                if not atk.modules:
                    print_status("Skipping '{}' — no executable module".format(atk.name))
                    continue

                module_path = atk.modules[0]
                print_status("[{}] {} — loading {}".format(atk.phase, atk.name, module_path))

                try:
                    self.command_use(module_path)
                    if hasattr(self, "current_module") and self.current_module:
                        print_status("Module loaded. Set target and run with 'run' or 'check'")
                        return
                except Exception as exc:
                    print_error("Failed to load {}: {}".format(module_path, exc))
            return

        print_error("Unknown subcommand: {}. Use 'apt', 'apt list', 'apt show', 'apt search', 'apt run'".format(sub))

    def command_exit(self, *args, **kwargs):
        raise EOFError