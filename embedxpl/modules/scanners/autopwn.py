import os
import time
from concurrent.futures import TimeoutError

from embedxpl.core.exploit import *
from embedxpl.core.exploit.exploit import Protocol
from embedxpl.core.exploit.printer import print_warning
from embedxpl.core.exploit.module_target_scope import (
    is_module_permitted_for_class,
    normalize_target_class,
)
from embedxpl.core.pool import SmartPool, PoolStrategy
from embedxpl.core.ml.advisor import AttackAdvisor, advisor_context_from_autopwn
from embedxpl.core.ml.gpu import gpu_capability_summary


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

    http_use = OptBool(False, "Check HTTP service: true/false")
    http_port = OptPort(80, "Primary HTTP port (used when http_ports is empty)")
    http_ports = OptString(
        "",
        "HTTP port list, comma-separated (e.g. 80,8080,9080). Overrides http_port when set",
    )
    http_ssl = OptBool(False, "Use HTTPS instead of HTTP for HTTP-protocol modules: true/false")

    https_use = OptBool(False, "Check HTTPS service: true/false")
    https_port = OptPort(443, "Primary HTTPS port (used when https_ports is empty)")
    https_ports = OptString(
        "",
        "HTTPS port list, comma-separated (e.g. 443,8443). Overrides https_port when set",
    )

    ftp_use = OptBool(False, "Check FTP service: true/false")
    ftp_port = OptPort(21, "Primary FTP port (used when ftp_ports is empty)")
    ftp_ports = OptString("", "FTP port list, comma-separated (e.g. 21,2121)")
    ftp_ssl = OptBool(False, "Use FTPS instead of FTP: true/false")

    ssh_use = OptBool(False, "Check SSH service: true/false")
    ssh_port = OptPort(22, "Primary SSH port (used when ssh_ports is empty)")
    ssh_ports = OptString("", "SSH port list, comma-separated (e.g. 22,2222)")

    sftp_use = OptBool(False, "Check SFTP service: true/false")
    sftp_port = OptPort(22, "Primary SFTP port (used when sftp_ports is empty)")
    sftp_ports = OptString("", "SFTP port list, comma-separated (e.g. 22,2222)")

    telnet_use = OptBool(False, "Check Telnet service: true/false")
    telnet_port = OptPort(23, "Primary Telnet port (used when telnet_ports is empty)")
    telnet_ports = OptString("", "Telnet port list, comma-separated (e.g. 23,2323)")

    snmp_use = OptBool(False, "Check SNMP service: true/false")
    snmp_port = OptPort(161, "Primary SNMP port (used when snmp_ports is empty)")
    snmp_ports = OptString("", "SNMP port list, comma-separated (e.g. 161,1161)")
    snmp_community = OptString("public", "Target SNMP community name (default: public)", advanced=True)
    snmp_version = OptInteger(1, "SNMP version for v1/v2 modules (0:v1, 1:v2c)", advanced=True)

    tcp_use = OptBool(False, "Check custom TCP services: true/false")
    tcp_port = OptString("", "Single TCP port override (used when tcp_ports is empty)")
    tcp_ports = OptString(
        "",
        "Custom TCP port list for custom/tcp modules (comma-separated, e.g. 554,8555,2870)",
    )

    udp_use = OptBool(False, "Check custom UDP services: true/false")
    udp_port = OptString("", "Single UDP port override (used when udp_ports is empty)")
    udp_ports = OptString(
        "",
        "Custom UDP port list for custom/udp modules (comma-separated, e.g. 161,1900)",
    )

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

    @staticmethod
    def _parse_ports_list(raw_ports, fallback_port=None):
        """Return deduplicated port list from comma/semicolon string or single fallback."""
        raw = str(raw_ports or "").strip()
        if raw:
            seen = set()
            ports = []
            for part in raw.replace(";", ",").split(","):
                part = part.strip()
                if not part:
                    continue
                try:
                    port = int(part)
                except ValueError:
                    print_warning("AutoPwn: ignoring invalid port {!r}".format(part))
                    continue
                if port not in seen:
                    seen.add(port)
                    ports.append(port)
            if ports:
                return ports
        if fallback_port is not None:
            return [int(fallback_port)]
        return []

    def _print_service_ports(self):
        print_status(
            "AutoPwn services — HTTP:{} HTTPS:{} FTP:{} SSH:{} SFTP:{} Telnet:{} SNMP:{} TCP:{} UDP:{}".format(
                self.http_use,
                self.https_use,
                self.ftp_use,
                self.ssh_use,
                self.sftp_use,
                self.telnet_use,
                self.snmp_use,
                self.tcp_use,
                self.udp_use,
            )
        )
        print_status(
            "AutoPwn service ports — HTTP: {} | HTTPS: {} | FTP: {} | SSH: {} | SFTP: {} | Telnet: {} | SNMP: {} | TCP: {} | UDP: {}".format(
                self._parse_ports_list(self.http_ports, self.http_port),
                self._parse_ports_list(self.https_ports, self.https_port),
                self._parse_ports_list(self.ftp_ports, self.ftp_port),
                self._parse_ports_list(self.ssh_ports, self.ssh_port),
                self._parse_ports_list(self.sftp_ports, self.sftp_port),
                self._parse_ports_list(self.telnet_ports, self.telnet_port),
                self._parse_ports_list(self.snmp_ports, self.snmp_port),
                self._tcp_ports_resolved(),
                self._udp_ports_resolved(),
            )
        )

    def _resolve_tcp_ports(self):
        ports = self._parse_ports_list(self.tcp_ports, None)
        if ports:
            return ports
        return self._parse_ports_list(self.tcp_port, None)

    def _resolve_udp_ports(self):
        ports = self._parse_ports_list(self.udp_ports, None)
        if ports:
            return ports
        return self._parse_ports_list(self.udp_port, None)

    def _tcp_ports_resolved(self):
        return self._resolve_tcp_ports() or ["(module default)"]

    def _udp_ports_resolved(self):
        return self._resolve_udp_ports() or ["(module default)"]

    @staticmethod
    def _get_exploit_protocol(exploit):
        """Resolve target_protocol from instance or class without raising."""
        protocol = getattr(exploit, "target_protocol", None)
        if protocol is None:
            protocol = getattr(type(exploit), "target_protocol", Protocol.CUSTOM)
        return protocol

    @staticmethod
    def _exploit_default_port(exploit):
        port_meta = getattr(type(exploit), "exploit_attributes", {}).get("port")
        if not port_meta:
            return None
        try:
            return int(port_meta[0])
        except (TypeError, ValueError):
            return None

    _PORT_SERVICE_HINTS = {
        21: Protocol.FTP,
        22: Protocol.SSH,
        23: Protocol.TELNET,
        80: Protocol.HTTP,
        443: Protocol.HTTPS,
        161: Protocol.SNMP,
        8080: Protocol.HTTP,
        8443: Protocol.HTTPS,
    }

    _PATH_SERVICE_HINTS = (
        (Protocol.HTTPS, ("https",)),
        (Protocol.HTTP, ("http", "webinterface", "ews", "upnp")),
        (Protocol.SFTP, ("sftp",)),
        (Protocol.SSH, ("ssh",)),
        (Protocol.FTP, ("ftp", "ftps")),
        (Protocol.TELNET, ("telnet",)),
        (Protocol.SNMP, ("snmp",)),
    )

    def _infer_service_family(self, exploit, protocol):
        """Map custom/tcp/udp modules to a service family when possible."""
        if protocol not in (Protocol.CUSTOM, Protocol.TCP, Protocol.UDP):
            return protocol

        path = exploit.__module__.lower()
        tail = path.rsplit(".", 1)[-1]
        for family, keys in self._PATH_SERVICE_HINTS:
            for key in keys:
                if key in tail or "/{}/".format(key) in path:
                    return family

        default_port = self._exploit_default_port(exploit)
        if default_port is not None:
            return self._PORT_SERVICE_HINTS.get(default_port)
        return None

    def _service_enabled(self, protocol):
        if protocol in (Protocol.HTTP,):
            return bool(self.http_use)
        if protocol in (Protocol.HTTPS,):
            return bool(self.https_use)
        if protocol in (Protocol.FTP, Protocol.FTPS):
            return bool(self.ftp_use)
        if protocol is Protocol.SSH:
            return bool(self.ssh_use)
        if protocol is Protocol.SFTP:
            return bool(self.sftp_use)
        if protocol is Protocol.TELNET:
            return bool(self.telnet_use)
        if protocol is Protocol.SNMP:
            return bool(self.snmp_use)
        if protocol is Protocol.TCP:
            return bool(self.tcp_use)
        if protocol is Protocol.UDP:
            return bool(self.udp_use)
        return False

    def _ports_for_protocol(self, protocol, *, http_ssl_override=None):
        """Resolve configured port list for a protocol enum/string."""
        use_https = bool(self.http_ssl) if http_ssl_override is None else bool(http_ssl_override)

        if protocol in (Protocol.HTTP, "http"):
            if use_https:
                return self._parse_ports_list(self.https_ports, self.https_port)
            return self._parse_ports_list(self.http_ports, self.http_port)
        if protocol in (Protocol.HTTPS, "https"):
            return self._parse_ports_list(self.https_ports, self.https_port)
        if protocol in (Protocol.FTP, "ftp"):
            return self._parse_ports_list(self.ftp_ports, self.ftp_port)
        if protocol in (Protocol.FTPS, "ftps"):
            return self._parse_ports_list(self.ftp_ports, self.ftp_port)
        if protocol in (Protocol.SSH, "ssh"):
            return self._parse_ports_list(self.ssh_ports, self.ssh_port)
        if protocol in (Protocol.SFTP, "sftp"):
            return self._parse_ports_list(self.sftp_ports, self.sftp_port)
        if protocol in (Protocol.TELNET, "telnet"):
            return self._parse_ports_list(self.telnet_ports, self.telnet_port)
        if protocol in (Protocol.SNMP, "snmp"):
            return self._parse_ports_list(self.snmp_ports, self.snmp_port)
        if protocol in (Protocol.TCP, "custom/tcp"):
            return self._resolve_tcp_ports()
        if protocol in (Protocol.UDP, "custom/udp"):
            return self._resolve_udp_ports()
        return []

    def _prepare_exploit_for_protocol(self, exploit):
        """Return (skip, runs) where runs is a list of (port, use_ssl) tuples."""
        protocol = self._get_exploit_protocol(exploit)
        inferred = self._infer_service_family(exploit, protocol)
        family = inferred or protocol

        if not self._service_enabled(family):
            return True, []

        effective = protocol
        if protocol is Protocol.CUSTOM and inferred is not None:
            effective = inferred

        if effective in (Protocol.HTTP, Protocol.HTTPS):
            runs = []
            if effective is Protocol.HTTPS:
                if self.https_use:
                    for port in self._ports_for_protocol(Protocol.HTTPS):
                        runs.append((port, True))
            else:
                if self.http_use:
                    if self.http_ssl:
                        for port in self._ports_for_protocol(Protocol.HTTPS):
                            runs.append((port, True))
                    else:
                        for port in self._ports_for_protocol(Protocol.HTTP, http_ssl_override=False):
                            runs.append((port, False))
                if self.https_use and not self.http_ssl:
                    seen = {port for port, _ in runs}
                    for port in self._ports_for_protocol(Protocol.HTTPS):
                        if port not in seen:
                            runs.append((port, True))
            return (not runs), runs

        if effective in (Protocol.FTP, Protocol.FTPS):
            use_ssl = effective is Protocol.FTPS or bool(self.ftp_ssl)
            ports = self._ports_for_protocol(Protocol.FTPS if use_ssl else Protocol.FTP)
            return (not ports), [(port, use_ssl) for port in ports]

        if effective is Protocol.TELNET:
            ports = self._ports_for_protocol(Protocol.TELNET)
            return (not ports), [(port, False) for port in ports]

        if effective is Protocol.SSH:
            ports = self._ports_for_protocol(Protocol.SSH)
            return (not ports), [(port, False) for port in ports]

        if effective is Protocol.SFTP:
            ports = self._ports_for_protocol(Protocol.SFTP)
            return (not ports), [(port, False) for port in ports]

        if effective is Protocol.SNMP:
            ports = self._ports_for_protocol(Protocol.SNMP)
            return (not ports), [(port, False) for port in ports]

        if effective is Protocol.TCP or (protocol is Protocol.CUSTOM and family is Protocol.CUSTOM):
            if not self.tcp_use:
                return True, []
            ports = self._resolve_tcp_ports()
            return False, [(port, False) for port in (ports or [None])]

        if effective is Protocol.UDP:
            if not self.udp_use:
                return True, []
            ports = self._resolve_udp_ports()
            return False, [(port, False) for port in (ports or [None])]

        return True, []

    @staticmethod
    def _snapshot_network(exploit):
        protocol = getattr(exploit, "target_protocol", None)
        if protocol is None:
            protocol = getattr(type(exploit), "target_protocol", Protocol.CUSTOM)
        return {
            "protocol": protocol,
            "ssl": getattr(exploit, "ssl", None) if hasattr(exploit, "ssl") else None,
        }

    @staticmethod
    def _restore_network(exploit, snapshot):
        setattr(exploit, "target_protocol", snapshot["protocol"])
        ssl_val = snapshot.get("ssl")
        if ssl_val is not None and hasattr(exploit, "ssl"):
            if str(ssl_val).lower() in ("true", "false"):
                exploit.ssl = str(ssl_val).lower()

    def _apply_exploit_network(self, exploit, port, use_ssl=False):
        protocol = self._get_exploit_protocol(exploit)
        if port is not None:
            exploit.port = port
        if use_ssl and protocol in (Protocol.HTTP, Protocol.FTP):
            exploit.ssl = "true"
            if protocol is Protocol.HTTP:
                exploit.target_protocol = Protocol.HTTPS
            elif protocol is Protocol.FTP:
                exploit.target_protocol = Protocol.FTPS
        if self._get_exploit_protocol(exploit) is Protocol.SNMP:
            if hasattr(exploit, "snmp_community"):
                exploit.snmp_community = self.snmp_community
            if hasattr(exploit, "community_string"):
                exploit.community_string = self.snmp_community
            if hasattr(exploit, "version"):
                exploit.version = self.snmp_version

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
                thread_name_prefix="exf-autopwn",
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
        self._print_service_ports()

        # Initialize ML advisor if enabled
        advisor = None
        advisor_ctx = None
        if self.ml_advisor:
            try:
                advisor = AttackAdvisor()
                advisor_ctx = advisor_context_from_autopwn(self)
                print_status("ML advisor enabled (CVSS + CVE recency + attack type scoring).")
                if self.ml_auto_timing:
                    suggested, ranked = advisor.suggest_timing_template(advisor_ctx, use_gpu=bool(self.ml_use_gpu))
                    print_status("ML advisor suggests timing: {} (probabilities: {})".format(
                        suggested.upper(),
                        ", ".join("{}={:.1%}".format(l, p) for l, p in ranked[:3]),
                    ))
            except Exception as exc:
                print_error("ML advisor initialization failed: {}".format(exc))
                advisor = None
                advisor_ctx = None

        tcls = normalize_target_class(str(self.target_device_class))
        if tcls == "tap":
            print_warning(
                "target_device_class=tap: passive TAPs usually have no in-scope management plane; "
                "most modules will be skipped. Use multi only for lab misconfiguration scenarios."
            )
        elif tcls not in ("multi",):
            print_status(
                "Device class filter active: {} (modules outside module_target_scope.json rules are skipped)".format(tcls),
            )

        # Update list of directories with specific vendor if needed
        if self.vendor != 'any':
            self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module, self.vendor) for module in self.modules]

        if self.check_exploits:
            # vulnerabilities
            print_info()
            print_status("{} Starting vulnerability check...".format(self.target))

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
            print_status("{} Starting default credentials check...".format(self.target))
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
            print_status("{} Could not verify exploitability:".format(self.target))
            for v in self.not_verified:
                print_info(" - {}:{} {} {}".format(*v))
            print_info()

        if self.vulnerabilities:
            print_success("{} Device is vulnerable:".format(self.target))
            headers = ("Target", "Port", "Service", "Exploit")
            print_table(headers, *self.vulnerabilities)
            print_info()
        else:
            print_error(
                "{} During this AutoPwn run, no exploitable weakness was confirmed by the current EmbedXPL-Forge "
                "module base. This does not mean the target is secure, does not exclude unknown vectors/zero-days, "
                "and does not replace broader assessment methods.".format(self.target),
            )

        if self.creds:
            print_success("{} Found default credentials:".format(self.target))
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.creds)
            print_info()
        else:
            print_error(
                "{} During this AutoPwn run, no valid default credential was confirmed with the current "
                "credential datasets and checks.".format(self.target),
            )

        if self._scope_skipped and tcls != "multi":
            print_status(
                "Skipped {} module(s) not permitted for target_device_class={}".format(self._scope_skipped, tcls),
            )

    def _evaluate_exploit(self, exploit):
        skip, runs = self._prepare_exploit_for_protocol(exploit)
        if skip or not runs:
            return

        for port, use_ssl in runs:
            snapshot = self._snapshot_network(exploit)
            self._apply_exploit_network(exploit, port, use_ssl=use_ssl)
            protocol = self._get_exploit_protocol(exploit)
            try:
                response = self._profiled_check(exploit)
            except Exception as err:
                print_error(
                    "{}:{} {} {} check failed with exception".format(
                        exploit.target, exploit.port, protocol, exploit
                    ),
                    err,
                )
                self.not_verified.append((exploit.target, exploit.port, protocol, str(exploit)))
                self._restore_network(exploit, snapshot)
                continue

            if response is True and self.verify_positive_twice:
                confirmed = True
                for _ in range(max(0, self._active_profile["confirm_passes"] - 1)):
                    if self._profiled_check(exploit) is not True:
                        print_status(
                            "{}:{} {} {} positive result was not confirmed under profile checks".format(
                                exploit.target, exploit.port, protocol, exploit
                            ),
                        )
                        self.not_verified.append((exploit.target, exploit.port, protocol, str(exploit)))
                        confirmed = False
                        break
                if not confirmed:
                    self._restore_network(exploit, snapshot)
                    continue

            if response is True:
                print_success("{}:{} {} {} is vulnerable".format(
                    exploit.target, exploit.port, protocol, exploit))
                self.vulnerabilities.append((exploit.target, exploit.port, protocol, str(exploit)))
            elif response is False:
                print_error("{}:{} {} {} is not vulnerable".format(
                    exploit.target, exploit.port, protocol, exploit))
            else:
                print_status("{}:{} {} {} Could not be verified".format(
                    exploit.target, exploit.port, protocol, exploit))
                self.not_verified.append((exploit.target, exploit.port, protocol, str(exploit)))

            self._restore_network(exploit, snapshot)

    def _evaluate_creds(self, exploit, generic=False):
        skip, runs = self._prepare_exploit_for_protocol(exploit)
        if skip or not runs:
            return

        for port, use_ssl in runs:
            snapshot = self._snapshot_network(exploit)
            self._apply_exploit_network(exploit, port, use_ssl=use_ssl)
            protocol = self._get_exploit_protocol(exploit)
            try:
                response = self._run_with_timeout(exploit.check_default)
            except Exception as err:
                print_error(
                    "{}:{} {} {} check_default failed with exception".format(
                        exploit.target, exploit.port, protocol, exploit
                    ),
                    err,
                )
                self.not_verified.append((exploit.target, exploit.port, protocol, str(exploit)))
                self._restore_network(exploit, snapshot)
                continue

            if response:
                print_success("{}:{} {} {} is vulnerable".format(
                    exploit.target, exploit.port, protocol, exploit))
                for creds in response:
                    self.creds.append(creds)
            else:
                print_error("{}:{} {} {} is not vulnerable".format(
                    exploit.target, exploit.port, protocol, exploit))

            self._restore_network(exploit, snapshot)

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

                self._evaluate_exploit(exploit)

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
                if exploit.__module__.startswith("embedxpl.modules.creds.generic"):
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

                skip, _runs = self._prepare_exploit_for_protocol(exploit)
                if skip:
                    continue

                self._evaluate_creds(exploit, generic=generic)