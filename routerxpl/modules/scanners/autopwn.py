import os
import time
from concurrent.futures import TimeoutError

from routerxpl.core.exploit import *
from routerxpl.core.exploit.exploit import Protocol
from routerxpl.core.exploit.module_target_scope import (
    is_module_permitted_for_class,
    normalize_target_class,
)
from routerxpl.core.pool import SmartPool, PoolStrategy
from routerxpl.core.ml.advisor import AttackAdvisor, advisor_context_from_autopwn
from routerxpl.core.ml.gpu import gpu_capability_summary


class Exploit(Exploit):
    __info__ = {
        "name": "AutoPwn",
        "description": "Module scans for vulnerabilities and weaknesses. Supports timing templates T0..T5 (default: balanced/T3).",
        "authors": (
            "Marcin Bury",
            "André Henrique (@mrhenrike)",
        ),
        "devices": (
            "Routers",
            "Switches",
            "TAPs",
            "FW",
            "NGFW",
        ),
    }

    modules = ["generic", "routers", "misc"]
    MIN_THREADS = 1
    MAX_THREADS = 300
    TIMING_PROFILES = {
        "t0": {"name": "paranoid", "threads": 1, "confirm_passes": 3, "inconclusive_retries": 2, "delay_s": 1.0},
        "t1": {"name": "sneaky", "threads": 2, "confirm_passes": 2, "inconclusive_retries": 2, "delay_s": 0.5},
        "t2": {"name": "polite", "threads": 4, "confirm_passes": 2, "inconclusive_retries": 1, "delay_s": 0.2},
        "t3": {"name": "balanced", "threads": 8, "confirm_passes": 2, "inconclusive_retries": 1, "delay_s": 0.0},
        "t4": {"name": "aggressive", "threads": 16, "confirm_passes": 1, "inconclusive_retries": 0, "delay_s": 0.0},
        "t5": {"name": "insane", "threads": 32, "confirm_passes": 1, "inconclusive_retries": 0, "delay_s": 0.0},
    }
    PROFILE_ALIASES = {
        "paranoid": "t0",
        "sneaky": "t1",
        "polite": "t2",
        "balanced": "t3",
        "normal": "t3",
        "aggressive": "t4",
        "insane": "t5",
    }

    target = OptIP("", "Target IPv4 or IPv6 address")

    vendor = OptString("any", "Vendor concerned (default: any)")
    target_device_class = OptString(
        "multi",
        "Target class filter: multi|router|switch|tap|fw|ngfw|isp_cpe (see resources/catalogs/module_target_scope.json)",
        advanced=True,
    )
    timing_template = OptString(
        "balanced",
        "Timing template: T0..T5 or paranoid/sneaky/polite/balanced/aggressive/insane",
    )

    check_exploits = OptBool(True, "Check exploits against target: true/false", advanced=True)
    check_creds = OptBool(True, "Check factory credentials against target: true/false", advanced=True)

    http_use = OptBool(True, "Check HTTP[s] service: true/false")
    http_port = OptPort(80, "Target Web Interface Port", advanced=True)
    http_ssl = OptBool(False, "HTTPS enabled: true/false")

    ftp_use = OptBool(True, "Check FTP[s] service: true/false")
    ftp_port = OptPort(21, "Target FTP port (default: 21)", advanced=True)
    ftp_ssl = OptBool(False, "FTPS enabled: true/false")

    ssh_use = OptBool(True, "Check SSH service: true/false")
    ssh_port = OptPort(22, "Target SSH port (default: 22)", advanced=True)

    sftp_use = OptBool(True, "Check SFTP service: true/false")
    sftp_port = OptPort(22, "Target SFTP port (default: 22)", advanced=True)

    telnet_use = OptBool(True, "Check Telnet service: true/false")
    telnet_port = OptPort(23, "Target Telnet port (default: 23)", advanced=True)

    snmp_use = OptBool(True, "Check SNMP service: true/false")
    snmp_community = OptString("public", "Target SNMP community name (default: public)", advanced=True)
    snmp_version = OptInteger(1, "SNMP version for v1/v2 modules (0:v1, 1:v2c)", advanced=True)
    snmp_port = OptPort(161, "Target SNMP port (default: 161)", advanced=True)

    tcp_use = OptBool(True, "Check custom TCP services", advanced=True)
    # tcp_port = OptPort(None, "Restrict TCP custom service tests to specific port (default: None)")

    udp_use = OptBool(True, "Check custom UDP services", advanced=True)
    # udp_port = OptPort(None, "Restrict UDP custom service tests to specific port (default: None)")

    threads = OptInteger(8, "Number of threads (min: 1, max: 300)")
    verify_positive_twice = OptBool(True, "Re-check positive exploit result to reduce false positives", advanced=True)
    show_timing_help = OptBool(True, "Show timing template help before scan: true/false", advanced=True)
    module_timeout_s = OptInteger(
        20,
        "Per-module timeout in seconds for check/check_default (0 disables timeout)",
        advanced=True,
    )

    ml_advisor = OptBool(
        False,
        "Enable ML/heuristic advisor: prioritizes modules, suggests or applies timing (extra CPU/RAM: low for scoring; threads dominate)",
        advanced=True,
    )
    ml_auto_timing = OptBool(
        False,
        "When ml_advisor true: overwrite timing_template with advisor suggestion (T0–T5)",
        advanced=True,
    )
    ml_use_gpu = OptBool(
        False,
        "When ml_advisor true: run timing logits on PyTorch CUDA if installed (marginal; network checks stay I/O bound)",
        advanced=True,
    )

    def __init__(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []
        self._active_profile = self.TIMING_PROFILES["t3"]
        self._timeout_pool = None
        self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module) for module in self.modules]
        self._creds_directories = [os.path.join(utils.MODULES_DIR, "creds", module) for module in self.modules]

    def _resolve_timing_template(self) -> dict:
        template = str(self.timing_template).strip().lower()
        if template.startswith("-t"):
            template = template[1:]
        if template in {"0", "1", "2", "3", "4", "5"}:
            template = "t{}".format(template)
        template = self.PROFILE_ALIASES.get(template, template)

        if template not in self.TIMING_PROFILES:
            print_error(
                "Unknown timing template '{}'. Falling back to balanced (T3).".format(self.timing_template)
            )
            template = "t3"

        profile = self.TIMING_PROFILES[template].copy()
        profile["template"] = template.upper()
        return profile

    def _print_timing_help(self):
        if not self.show_timing_help:
            return

        headers = ("Template", "Alias", "Threads", "Confirm", "Retry(Inconclusive)", "Delay(s)")
        rows = []
        for key, data in sorted(self.TIMING_PROFILES.items()):
            rows.append((
                key.upper(),
                data["name"],
                data["threads"],
                data["confirm_passes"],
                data["inconclusive_retries"],
                data["delay_s"],
            ))

        print_info()
        print_status("AutoPwn timing profiles (Nmap-style -T0..-T5):")
        print_table(headers, *rows)
        print_status("Default profile: balanced (T3). Use: set timing_template T4 or set timing_template aggressive")

    def _configure_runtime_profile(self):
        profile = self._resolve_timing_template()
        self._active_profile = profile

        # Keep historical default behavior when user does not tune threads explicitly.
        if self.threads == 8:
            self.threads = profile["threads"]
        self._validate_threads()
        self._warn_high_thread_count()

        print_status(
            "AutoPwn timing template {} ({}) active: threads={}, confirm_passes={}, inconclusive_retries={}, delay={}s".format(
                profile["template"],
                profile["name"],
                self.threads,
                profile["confirm_passes"],
                profile["inconclusive_retries"],
                profile["delay_s"],
            )
        )

    def _validate_threads(self):
        if self.threads < self.MIN_THREADS:
            print_error(
                "Invalid thread count {}. Minimum is {}. Applying minimum.".format(
                    self.threads, self.MIN_THREADS
                )
            )
            self.threads = self.MIN_THREADS
        elif self.threads > self.MAX_THREADS:
            print_error(
                "Invalid thread count {}. Maximum is {}. Applying maximum.".format(
                    self.threads, self.MAX_THREADS
                )
            )
            self.threads = self.MAX_THREADS

    def _warn_high_thread_count(self):
        if self.threads >= 200:
            print_error(
                "ALERT: {} threads configured. This may consume high CPU/RAM and impact scan host stability.".format(
                    self.threads
                )
            )
        elif self.threads >= 100:
            print_status(
                "WARNING: {} threads configured. High concurrency can significantly increase CPU/RAM usage.".format(
                    self.threads
                )
            )

    def _profiled_check(self, exploit):
        retries = self._active_profile["inconclusive_retries"]
        delay_s = self._active_profile["delay_s"]

        response = None
        for attempt in range(retries + 1):
            response = self._run_with_timeout(exploit.check)
            if response is not None:
                break
            if delay_s > 0 and attempt < retries:
                time.sleep(delay_s)

        return response

    def _ensure_timeout_pool(self) -> SmartPool:
        """Lazily create a shared SmartPool for module timeout execution."""
        if self._timeout_pool is None:
            workers = max(2, self._active_profile.get("threads", 8))
            self._timeout_pool = SmartPool(
                max_workers=workers,
                strategy=PoolStrategy.THREADS,
                thread_name_prefix="rxf-autopwn",
            )
        return self._timeout_pool

    def _run_with_timeout(self, fn):
        """Execute fn with timeout using the shared SmartPool."""
        timeout = int(self.module_timeout_s)
        if timeout <= 0:
            return fn()

        pool = self._ensure_timeout_pool()
        future = pool.submit(fn)
        try:
            return future.result(timeout=timeout)
        except TimeoutError:
            future.cancel()
            raise RuntimeError(
                "Module execution timed out after {}s (set module_timeout_s=0 to disable)".format(timeout)
            )

    def run(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []
        self._scope_skipped = 0
        self._print_timing_help()
        self._configure_runtime_profile()

        tcls = normalize_target_class(str(self.target_device_class))
        if tcls == "tap":
            print_info(
                "\033[93m[!]\033[0m",
                (
                    "target_device_class=tap: passive TAPs usually have no in-scope management plane; "
                    "most modules will be skipped. Use multi only for lab misconfiguration scenarios."
                ),
            )
        elif tcls not in ("multi",):
            print_info(
                "\033[94m[*]\033[0m",
                "Device class filter active: {} (modules outside module_target_scope.json rules are skipped)".format(tcls),
            )

        # Update list of directories with specific vendor if needed
        if self.vendor != 'any':
            self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module, self.vendor) for module in self.modules]

        if self.check_exploits:
            # vulnerabilities
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting vulnerability check...".format(self.target))

            modules = []
            for directory in self._exploits_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            if advisor is not None and advisor_ctx is not None:
                modules = advisor.prioritize_modules(modules, advisor_ctx)
                print_status("ML advisor reordered {} exploit modules (higher expected yield first).".format(len(modules)))

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.exploits_target_function, data)

        if self.check_creds:
            # default creds
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting default credentials check...".format(self.target))
            modules = []
            for directory in self._creds_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            if advisor is not None and advisor_ctx is not None:
                modules = advisor.prioritize_modules(modules, advisor_ctx)
                print_status("ML advisor reordered {} credential modules (higher expected yield first).".format(len(modules)))

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.creds_target_function, data)

        # results:
        print_info()
        if self.not_verified:
            print_info("\033[94m[*]\033[0m", "{} Could not verify exploitability:".format(self.target))
            for v in self.not_verified:
                print_info(" - {}:{} {} {}".format(*v))
            print_info()

        if self.vulnerabilities:
            print_info("\033[92m[+]\033[0m", "{} Device is vulnerable:".format(self.target))
            headers = ("Target", "Port", "Service", "Exploit")
            print_table(headers, *self.vulnerabilities)
            print_info()
        else:
            print_info(
                "\033[91m[-]\033[0m",
                (
                    "{} During this AutoPwn run, no exploitable weakness was confirmed by the current RouterXPL-Forge "
                    "module base. This does not mean the target is secure, does not exclude unknown vectors/zero-days, "
                    "and does not replace broader assessment methods.\n"
                ).format(self.target),
            )

        if self.creds:
            print_info("\033[92m[+]\033[0m", "{} Found default credentials:".format(self.target))
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.creds)
            print_info()
        else:
            print_info(
                "\033[91m[-]\033[0m",
                (
                    "{} During this AutoPwn run, no valid default credential was confirmed with the current "
                    "credential datasets and checks."
                ).format(self.target),
            )

        if self._scope_skipped and tcls != "multi":
            print_info(
                "\033[94m[*]\033[0m",
                "Skipped {} module(s) not permitted for target_device_class={}".format(self._scope_skipped, tcls),
            )

    def exploits_target_function(self, running, data):
        tcls = normalize_target_class(str(self.target_device_class))
        while running.is_set():
            try:
                module = data.next()
                exploit = module()
            except StopIteration:
                break
            except Exception as err:
                print_error("Failed to initialize exploit module in AutoPwn", err)
                continue
            else:
                exploit.target = self.target

                if not is_module_permitted_for_class(exploit.__module__, "exploits", tcls):
                    self._scope_skipped += 1
                    continue

                # Avoid checking specific protocol - reduce network impact
                if exploit.target_protocol == Protocol.HTTP:
                    if not self.http_use:
                        continue
                    exploit.port = self.http_port
                    if self.http_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.HTTPS

                elif exploit.target_protocol is Protocol.FTP:
                    if not self.ftp_use:
                        continue
                    exploit.port = self.ftp_port
                    if self.ftp_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.FTPS

                elif exploit.target_protocol is Protocol.TELNET:
                    if not self.telnet_use:
                        continue
                    exploit.port = self.telnet_port

                elif exploit.target_protocol is Protocol.SSH:
                    if not self.ssh_use:
                        continue
                    exploit.port = self.ssh_port

                elif exploit.target_protocol is Protocol.SFTP:
                    if not self.sftp_use:
                        continue
                    exploit.port = self.sftp_port

                elif exploit.target_protocol is Protocol.SNMP:
                    if not self.snmp_use:
                        continue
                    exploit.port = self.snmp_port
                    if hasattr(exploit, "snmp_community"):
                        exploit.snmp_community = self.snmp_community

                elif exploit.target_protocol is Protocol.TCP:
                    if not self.tcp_use:
                        continue

                elif exploit.target_protocol is Protocol.UDP:
                    if not self.udp_use:
                        continue

        #        elif exploit.target_protocol not in ["tcp", "udp"]:
        #            exploit.target_protocol = "custom"

                try:
                    response = self._profiled_check(exploit)
                except Exception as err:
                    print_error(
                        "{}:{} {} {} check failed with exception".format(
                            exploit.target, exploit.port, exploit.target_protocol, exploit
                        ),
                        err,
                    )
                    self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                    continue
                if response is True and self.verify_positive_twice:
                    confirmed = True
                    for _ in range(max(0, self._active_profile["confirm_passes"] - 1)):
                        if self._profiled_check(exploit) is not True:
                            print_info(
                                "\033[94m[*]\033[0m",
                                "{}:{} {} {} positive result was not confirmed under profile checks".format(
                                    exploit.target, exploit.port, exploit.target_protocol, exploit
                                ),
                            )
                            self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                            confirmed = False
                            break
                    if not confirmed:
                        continue

                if response is True:
                    print_info("\033[92m[+]\033[0m", "{}:{} {} {} is vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.vulnerabilities.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                elif response is False:
                    print_info("\033[91m[-]\033[0m", "{}:{} {} {} is not vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                else:
                    print_info("\033[94m[*]\033[0m", "{}:{} {} {} Could not be verified".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))

    def creds_target_function(self, running, data):
        tcls = normalize_target_class(str(self.target_device_class))
        while running.is_set():
            try:
                module = data.next()
                exploit = module()

                if not is_module_permitted_for_class(exploit.__module__, "creds", tcls):
                    self._scope_skipped += 1
                    continue

                generic = False
                if exploit.__module__.startswith("routerxpl.modules.creds.generic"):
                    if exploit.__module__.endswith("default"):
                        generic = True
                    else:
                        continue

            except StopIteration:
                break
            except Exception as err:
                print_error("Failed to initialize credential module in AutoPwn", err)
                continue
            else:
                exploit.target = self.target
                exploit.verbosity = "false"
                exploit.stop_on_success = "false"
                exploit.threads = self.threads

                if exploit.target_protocol == Protocol.HTTP:
                    exploit.port = self.http_port
                    if self.http_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.HTTPS

                elif generic:
                    if exploit.target_protocol is Protocol.HTTP:
                        exploit.port = self.http_port
                        if self.http_ssl:
                            exploit.ssl = "true"
                            exploit.target_protocol = Protocol.HTTPS
                    elif exploit.target_protocol == Protocol.SSH:
                        exploit.port = self.ssh_port
                    elif exploit.target_protocol == Protocol.SFTP:
                        exploit.port = self.sftp_port
                    elif exploit.target_protocol == Protocol.FTP:
                        exploit.port = self.ftp_port
                        if self.ftp_ssl:
                            exploit.ssl = "true"
                            exploit.target_protocol = Protocol.FTPS

                    elif exploit.target_protocol == Protocol.TELNET:
                        exploit.port = self.telnet_port
                    elif exploit.target_protocol == Protocol.SNMP:
                        exploit.port = self.snmp_port
                        if hasattr(exploit, "version"):
                            exploit.version = self.snmp_version
                        if hasattr(exploit, "community_string"):
                            exploit.community_string = self.snmp_community
                else:
                    continue

                try:
                    response = self._run_with_timeout(exploit.check_default)
                except Exception as err:
                    print_error(
                        "{}:{} {} {} check_default failed with exception".format(
                            exploit.target, exploit.port, exploit.target_protocol, exploit
                        ),
                        err,
                    )
                    self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                    continue
                if response:
                    print_info("\033[92m[+]\033[0m", "{}:{} {} {} is vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))

                    for creds in response:
                        self.creds.append(creds)
                else:
                    print_info("\033[91m[-]\033[0m", "{}:{} {} {} is not vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))