# Author: Andre Henrique (LinkedIn/X: @mrhenrike)
"""Page-cache LPE family hunter — DirtyPipe / DirtyFrag / DirtyClone / pedit COW.

Heuristic local checks inspired by Tracee/eBPF detection principles: identify
abnormal kernel prerequisites (user_ns, tc pedit, IPsec ESP, Squid FTP) rather
than chasing post-exploitation shells.

References:
  https://github.com/aquasecurity/tracee
  https://github.com/rafaeldtinoco/security
"""

from __future__ import annotations

import os

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptBool,
    OptString,
    print_status,
    print_success,
    print_error,
    print_info,
    print_table,
    print_warning,
)

from embedxpl.modules.exploits.embedded_os.linux_kernel.kernel_native_util import (
    get_kernel_version,
    kernel_release,
    module_loaded,
    userns_allowed,
    version_in_rc_range,
)


def _peditcow_vulnerable(ver):
    if not ver:
        return False
    major, minor, _p, rc = ver
    if major < 5 or (major == 5 and minor < 18):
        return False
    if major == 7 and minor == 1 and rc >= 7:
        return False
    if major > 7 or (major == 7 and minor > 1):
        return False
    return True


class Exploit(BaseExploit):
    __info__ = {
        "name": "Linux Page-Cache LPE Family Hunter (2026)",
        "description": (
            "Correlates kernel version and loaded modules for DirtyClone "
            "(CVE-2026-43503), pedit COW (CVE-2026-46331), and related "
            "page-cache write primitives. Maps to EmbedXPL exploit modules."
        ),
        "authors": ("Andre Henrique (@mrhenrike)",),
        "references": (
            "https://github.com/rafaeldtinoco/security",
            "https://github.com/aquasecurity/tracee",
        ),
        "devices": ("Linux hosts",),
        "cve": "CVE-2026-43503",
        "cvss": 0.0,
        "attack_class": "vulnerability_scanner",
        "status": "confirmed",
    }

    check_squid = OptBool(True, "Include Squid FTP gateway exposure hints")
    squid_port = OptString("3128", "Squid port for banner probe")

    def check(self) -> bool:
        return True

    def run(self) -> None:
        ver = get_kernel_version()
        rel = kernel_release()
        rows = []

        dc = version_in_rc_range(ver, 1, 4)
        rows.append(("DirtyClone", "CVE-2026-43503", "LIKELY" if dc else "no", "embedded_os/linux_kernel/linux_dirtyclone_lpe_cve_2026_43503"))

        pc = _peditcow_vulnerable(ver)
        rows.append(("pedit COW", "CVE-2026-46331", "LIKELY" if pc else "no", "embedded_os/linux_kernel/linux_peditcow_lpe_cve_2026_46331"))

        mods = []
        for m in ("xt_TEE", "esp4", "esp6", "act_pedit", "sch_ingress"):
            if module_loaded(m):
                mods.append(m)
        rows.append(("kernel_modules", "—", ", ".join(mods) or "none", "—"))

        rows.append(("user_ns", "—", "ok" if userns_allowed() else "restricted", "—"))
        rows.append(("kernel", "—", rel, "—"))

        print_table(["Family", "CVE", "Status", "IXF module"], rows, title="Page-Cache LPE Hunter")

        if dc:
            print_warning("DirtyClone window: kernel 7.1-rc1..rc4 + xt_TEE + esp4/esp6")
        if pc:
            print_warning("pedit COW: kernel >= 5.18, < 7.1-rc7 + act_pedit")

        if self.check_squid:
            print_info("Squidbleed CVE-2026-47729: use protocols/proxy/squid_ftp_memory_disclosure_cve_2026_47729")
        print_info("libssh2 CVE-2026-55200: use generic/libssh2_packet_length_rce_cve_2026_55200")
