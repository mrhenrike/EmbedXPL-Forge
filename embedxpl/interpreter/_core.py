import atexit
import getopt
import itertools
import os
import signal
import sys
import traceback
from collections import Counter
from pathlib import Path

# Adaptation credits: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
from embedxpl.core.exploit.exceptions import EmbedXPLException
from embedxpl.core.exploit.exploit import GLOBAL_OPTS
from embedxpl.core.exploit.payloads import BasePayload
from embedxpl.core.exploit.printer import (
    PrinterThread,
    pprint_dict_in_order,
    print_error,
    print_info,
    print_status,
    print_success,
    print_table,
    print_warning,
    printer_queue,
)
from embedxpl.core.exploit.utils import (
    MODULES_DIR,
    WORDLISTS_DIR,
    humanize_path,
    import_exploit,
    index_modules,
    module_required,
    pythonize_path,
    stop_after,
)

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


from embedxpl.interpreter._base import BaseInterpreter

class _EmbedXPLInterpreterCore(BaseInterpreter):
    history_file = os.path.expanduser("~/.exf_history")
    global_help = """Global commands:
    help                            Print this help menu
    use <module>                    Select a module for usage
    exec <shell command> <args>     Execute a command in a shell
    search <keyword>                Search modules by keyword (CVE, vendor, product, type)
    search cve-2018-14847           Search by CVE ID
    search type:router              Search by category (router/camera/firewall/ics/printer/wireless)
    search vendor:hikvision         Search by vendor name
    autopwn <segment> <target>      Run all modules for a segment against a target
    sysinfo                         Show detected hardware (CPU, RAM, GPU)
    discover <subnet/CIDR>          Scan network and match targets to exploit catalog
    workspace [list|<name>]         Manage workspaces
    hosts                           List discovered hosts in current workspace
    vulns                           List found vulnerabilities
    creds                           List captured credentials
    sessions [list|show|delete]     Manage scan session history
    build <component> [options]     Build malware (dropper|rat|wiper|ransomware|backdoor|rootkit)
      Examples:
        build dropper --lang python --arch armle --transport https --c2 10.0.0.1
        build rat --lang go --arch arm64 --persist cron --evasion defender
        build wiper --lang c --arch x64
        build ransomware --lang python --evasion defender
    nse install                     Install EmbedXPL NSE scripts into nmap
    nse list                        List NSE scripts and install status
    exit                            Exit EmbedXPL"""

    module_help = """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit"""

    def __init__(self):
        super(EmbedXPLInterpreter, self).__init__()
        PrinterThread().start()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = "exf"
        self.show_sub_commands = ("info", "options", "advanced", "devices", "all", "encoders", "creds", "exploits", "scanners", "wordlists")
        self.search_sub_commands = ("type", "device", "language", "payload", "vendor")

        self.global_commands = sorted(["use ", "exec ", "help", "exit", "show ", "search ",
                                        "sysinfo", "compute ", "discover ", "sessions ",
                                        "build ", "nse ", "workspace ", "hosts ", "vulns ", "creds "])
        self.module_commands = ["run", "back", "set ", "setg ", "check"]
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()

        self.modules = index_modules()
        self.modules_count = Counter()
        self.modules_count.update([module.split('.')[0] for module in self.modules])
        self.main_modules_dirs = [module for module in os.listdir(MODULES_DIR) if not module.startswith("__")]

        self.__parse_prompt()

        from embedxpl.core import config as exf_config
        from embedxpl.core.hw_profiler import HWProfiler
        from embedxpl.core.session import SessionManager
        self._hw_profile = HWProfiler.detect()
        self._session_mgr = SessionManager()

        saved_mode = exf_config.get("compute_mode", "auto")
        if saved_mode in ("cpu", "gpu", "hybrid", "auto"):
            self._hw_profile.compute_mode = saved_mode
        self._validate_compute_mode(silent=True)

        self.banner = ""
        self._rich_banner = ""   # banner novo via banner.py — exibido em start()

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("EXF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("EXF_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    def __handle_if_noninteractive(self, argv):
        """ Keep old method for backward compat only """
        self.nonInteractive(argv)

    def nonInteractive(self, argv):
        """ Execute specific command and return result without launching the interactive CLI.

        Supports standard module flags as well as infrastructure context flags:

            exf -m <module> -s "<option> <value>"
            exf -T <targets.txt>
            exf --infra ot --context ics --target 192.168.1.0/24
            exf --infra wizard

        Returns:
            None
        """
        module = ""
        set_opts = []
        targets_file = ""
        infra_type = ""
        infra_context = ""
        infra_target = ""
        infra_wizard = False

        try:
            opts, args = getopt.getopt(
                argv[1:],
                "hm:s:T:",
                [
                    "help=", "module=", "set=", "targets=",
                    "infra=", "context=", "target=", "wizard",
                ],
            )
        except getopt.GetoptError:
            print_info(
                "{prog} -m <module> -s \"<option> <value>\"\n"
                "       {prog} -T <targets.txt>  (multi-target scan from file)\n"
                "       {prog} --infra ot --context ics --target 192.168.1.0/24\n"
                "       {prog} --infra wizard  (interactive infrastructure selection)".format(
                    prog=argv[0]
                )
            )
            printer_queue.join()
            return

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_info(
                    "{prog} -m <module> -s \"<option> <value>\"\n"
                    "       {prog} -T <targets.txt>  (multi-target scan from file)\n"
                    "       {prog} --infra ot --context ics --target 192.168.1.0/24\n"
                    "       {prog} --infra wizard  (interactive infrastructure selection)".format(
                        prog=argv[0]
                    )
                )
                printer_queue.join()
                return
            elif opt in ("-m", "--module"):
                module = arg
            elif opt in ("-s", "--set"):
                set_opts.append(arg)
            elif opt in ("-T", "--targets"):
                targets_file = arg
            elif opt == "--infra":
                if arg.lower() == "wizard":
                    infra_wizard = True
                else:
                    infra_type = arg.lower()
            elif opt == "--context":
                infra_context = arg.lower()
            elif opt == "--target":
                infra_target = arg

        # --infra wizard mode: interactive taxonomy selection
        if infra_wizard:
            self._run_infra_wizard()
            printer_queue.join()
            return

        # --infra/--context mode: resolve modules via InfraOrchestrator
        if infra_type:
            self._run_infra_scan(infra_type, infra_context, infra_target)
            printer_queue.join()
            return

        # -T mode: scan all targets from file, then exit
        if targets_file:
            self._scan_from_targets_file(targets_file)
            printer_queue.join()
            return

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

    def _run_infra_wizard(self) -> None:
        """Launch the interactive InfraOrchestrator wizard.

        Presents a numbered menu for infra type and context selection,
        then lists resolved modules without executing them.
        """
        try:
            from embedxpl.core.orchestrator import InfraOrchestrator
        except ImportError as exc:
            print_error("InfraOrchestrator unavailable: {}".format(exc))
            return

        orch = InfraOrchestrator()
        try:
            plan = orch.interactive_wizard()
            print_status(
                "Scan plan ready: {} modules for {}/{}".format(
                    len(plan.modules), plan.infra, plan.context
                )
            )
        except (KeyboardInterrupt, EOFError):
            print_warning("Wizard cancelled by user.")
        except Exception as exc:
            print_error("Wizard error: {}".format(exc))

    def _run_infra_scan(
        self, infra: str, context: str, target: str
    ) -> None:
        """Resolve and display modules for the given infra/context pair.

        When a target is provided, prints the ordered module list that
        would be executed by a full scan. Does not auto-run exploits —
        the user selects modules interactively after reviewing the plan.

        Args:
            infra: Infrastructure type key (e.g. ``'ot'``).
            context: Operational context key (e.g. ``'ics'``).
            target: IP address or CIDR range for the scan plan.
        """
        try:
            from embedxpl.core.orchestrator import InfraOrchestrator
        except ImportError as exc:
            print_error("InfraOrchestrator unavailable: {}".format(exc))
            return

        orch = InfraOrchestrator()

        try:
            infra_types = orch.list_infra_types()
        except Exception as exc:
            print_error("Failed to load infra profiles: {}".format(exc))
            return

        if infra not in infra_types:
            print_error(
                "Unknown infra type '{}'. Valid: {}".format(
                    infra, ", ".join(infra_types)
                )
            )
            return

        if not context:
            # Show available contexts
            try:
                contexts = orch.list_contexts(infra)
            except Exception as exc:
                print_error(str(exc))
                return
            print_info(
                "Available contexts for --infra {}:\n  {}".format(
                    infra, "\n  ".join(contexts)
                )
            )
            return

        try:
            plan = orch.build_scan_plan(
                target or "127.0.0.1", infra, context
            )
        except KeyError as exc:
            print_error(str(exc))
            return
        except Exception as exc:
            print_error("Plan build error: {}".format(exc))
            return

        print_status(plan.summary())
        print_info(
            "Use -m <module> -s \"target {}\" to run individual modules.".format(
                plan.target
            )
        )
        print_info(
            "Or launch interactive shell and type 'use <module>' to explore.".format()
        )

    def _scan_from_targets_file(self, targets_file: str) -> None:
        """Run multi-target network discovery from a targets file (-T flag).

        Reads IPs/CIDRs one per line (skips blank lines and # comments),
        scans each target in parallel using :func:`~embedxpl.core.discovery.scan_from_file`,
        and prints results as they complete.

        Args:
            targets_file: Path to a plain-text file with one IP or CIDR per line.
        """
        import os as _os

        from embedxpl.core.discovery import scan_from_file as _scan_from_file

        if not _os.path.isfile(targets_file):
            print_error("Targets file not found: {}".format(targets_file))
            return

        print_status("Multi-target scan from file: {}".format(targets_file))

        def progress_cb(target: str, stage: str, detail: str) -> None:
            if stage == "done":
                print_success("[{}] done — {}".format(target, detail))
            else:
                print_status("[{}] [{}] {}".format(target, stage, detail))

        try:
            results = _scan_from_file(
                targets_file,
                timing=3,
                callback=progress_cb,
                max_file_workers=4,
            )
        except KeyboardInterrupt:
            print_warning("Multi-target scan cancelled by user")
            return
        except Exception as exc:
            print_error("Multi-target scan failed: {}".format(exc))
            return

        total_hosts = sum(len(v) for v in results.values())
        print_success(
            "\nScan complete — {} target(s), {} total host(s) found".format(
                len(results), total_hosts
            )
        )

        for target, hosts in sorted(results.items()):
            if not hosts:
                print_info("  {} — no live hosts".format(target))
                continue
            print_info("  {} — {} host(s):".format(target, len(hosts)))
            for h in hosts:
                print_info("    {}".format(h.summary()))

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
        module_path = ".".join(("embedxpl", "modules", module_path))
        # module_path, _, exploit_name = module_path.rpartition('.')
        try:
            self.current_module = import_exploit(module_path)()
        except EmbedXPLException as err:
            print_error(str(err))
            return

        # Apply globally-set options (setg) to the newly loaded module
        if GLOBAL_OPTS:
            for key, value in GLOBAL_OPTS.items():
                if key in self.current_module.options:
                    try:
                        setattr(self.current_module, key, value)
                        self.current_module.exploit_attributes[key][0] = value
                    except Exception:
                        pass

        # Show tested status from module_test_status.json
        try:
            from embedxpl.tools.search import _load_test_status as _lts
            status = _lts()
            rel_file = module_path.replace(".", "/") + ".py"
            info = status.get(rel_file)
            if info is None:
                for key, val in status.items():
                    if key.replace("\\", "/").endswith("/" + rel_file.split("/", 2)[-1] if "/" in rel_file else rel_file):
                        info = val
                        break
            if info:
                tested = info.get("tested")
                evidence = info.get("evidence", "")
                if tested is True:
                    badge = "\033[92m[TESTED]\033[0m"
                    evstr = f"  evidence: {evidence}" if evidence else ""
                    print_info(f"Test status: {badge}{evstr}")
                elif tested is False:
                    print_info("Test status: \033[93m[UNTESTED]\033[0m  (stub/theoretical)")
                else:
                    print_info("Test status: \033[2m[UNKNOWN]\033[0m")
        except Exception:
            pass

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


        previous_sigint_handler = signal.getsignal(signal.SIGINT)
        t0 = _time.monotonic()
        mod_path = str(self.current_module)
        target_ip = getattr(self.current_module, "target", "")
        error_msg = None

        try:
            signal.signal(signal.SIGINT, self.__command_sigint_handler)
            if hasattr(self.current_module, "_enforce_hardware_gate"):
                self.current_module._enforce_hardware_gate()
            self.current_module.run()
        except KeyboardInterrupt:
            print_info()
            print_error("Operation cancelled by user")
            error_msg = "cancelled"
        except SystemExit:
            pass
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

        # Show tested status badge
        try:
            from embedxpl.tools.search import _load_test_status as _lts
            module_path = str(self.current_module.__class__.__module__)
            status = _lts()
            rel_file = module_path.replace(".", "/") + ".py"
            info = status.get(rel_file)
            if info is None:
                for key, val in status.items():
                    if key.replace("\\", "/").endswith(rel_file.split("/", 2)[-1] if "/" in rel_file else rel_file):
                        info = val
                        break
            if info:
                tested = info.get("tested")
                evidence = info.get("evidence", "")
                cves = info.get("cves", [])
                if tested is True:
                    badge = "\033[92m[TESTED — {}]\033[0m".format(evidence) if evidence else "\033[92m[TESTED]\033[0m"
                    cve_str = "  CVEs: {}".format(", ".join(cves[:4])) if cves else ""
                    print_info("Test status: {}{}".format(badge, cve_str))
                elif tested is False:
                    print_info("Test status: \033[93m[UNTESTED]\033[0m  (stub/theoretical)")
                else:
                    print_info("Test status: \033[2m[UNKNOWN]\033[0m")
        except Exception:
            pass

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
        from embedxpl.core.exploit.printer import print_info, print_table
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


        t0 = _time.monotonic()
        mod_path = str(self.current_module)
        target_ip = getattr(self.current_module, "target", "")
        vuln_result = None
        error_msg = None

        try:
            if hasattr(self.current_module, "_enforce_hardware_gate"):
                self.current_module._enforce_hardware_gate()
            result = self.current_module.check()
        except SystemExit:
            return
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
        """Rich search: keyword, CVE, vendor, type, tested flag — integrates tools/search.py engine."""
        try:
            query = " ".join(args).strip("'\"") if args else ""
        except Exception:
            query = ""

        if not query and not kwargs:
            print_error(
                "Usage: search <keyword>  |  search cve-2024-54085  |  "
                "search type:router  |  search vendor:cisco  |  "
                "search tested:yes  |  search tested:no"
            )
            return

        # Build full query string (include any key=value kwargs)
        for k, v in kwargs.items():
            query = f"{query} {k}:{v}".strip()

        print_info(f"Searching: {query!r}")

        # --- Use rich search engine from tools/search.py ---
        try:
            from embedxpl.tools.search import print_results
            from embedxpl.tools.search import search as _xpl_search
            results = _xpl_search(query, limit=60)
            if results:
                print_results(results, query)
                print_info("Tip: use <module_path> to load a module")
                return
        except Exception:
            pass

        # --- Fallback: legacy path-based search ---
        keyword = query.lower()
        found_any = False
        for module in self.modules:
            if not all(word in str(module) for word in keyword.split()):
                continue
            found_any = True
            path = humanize_path(module)
            try:
                from rich.text import Text

                from embedxpl.core.exploit.printer import console as _con
                text_obj = Text(path)
                for word in keyword.split():
                    text_obj.highlight_words([word], style="bold red")
                _con.print(text_obj)
            except Exception:
                print_info(path)
        if not found_any:
            print_error(f"No modules found for: {query!r}")

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

