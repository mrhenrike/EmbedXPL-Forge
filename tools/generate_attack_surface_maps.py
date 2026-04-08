#!/usr/bin/env python3
# Author: André Henrique (LinkedIn/X: @mrhenrike)
"""Generate RouterXPL-Forge Attack Surface Map diagrams.

Produces professional PNG diagrams in the style of router attack surface maps,
showing coverage status per access vector.

Usage:
    python tools/generate_attack_surface_maps.py
"""

import math
import os
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.patches as mpatches
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

# ── Output directory ──────────────────────────────────────────────────────────
OUT = Path(__file__).parent.parent / "docs" / "diagrams" / "architecture"
OUT.mkdir(parents=True, exist_ok=True)

# ── Colour palette (matches MikrotikAPI-BF reference style) ──────────────────
C_GREEN_CORE  = "#4CAF50"   # mandatory component, covered
C_ORANGE      = "#FF9800"   # access vector  — covered
C_ORANGE_RED  = "#E65100"   # access vector  — NOT covered
C_YELLOW      = "#FDD835"   # optional component
C_CYAN        = "#26C6DA"   # access target (device/system)
C_GREY_BG     = "#F5F5F5"   # canvas background
C_DARK_TEXT   = "#212121"
C_WHITE       = "#FFFFFF"
C_RED_X       = "#D32F2F"
C_GREEN_CHECK = "#2E7D32"
C_BORDER_GREY = "#BDBDBD"


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _draw_node(ax, x, y, label, color, text_color=C_DARK_TEXT,
               width=1.9, height=0.52, fontsize=7.8, badge=None):
    """Draw a rounded-rectangle node and optional ✓/✗ badge."""
    box = FancyBboxPatch(
        (x - width / 2, y - height / 2), width, height,
        boxstyle="round,pad=0.06",
        linewidth=1.2,
        edgecolor=C_BORDER_GREY,
        facecolor=color,
        zorder=3,
    )
    ax.add_patch(box)
    ax.text(x, y, label, ha="center", va="center",
            fontsize=fontsize, color=text_color,
            fontweight="bold" if color == C_GREEN_CORE else "normal",
            zorder=4, wrap=False)

    if badge == "check":
        ax.text(x + width / 2 - 0.17, y + height / 2 - 0.07, "✓",
                fontsize=9, color=C_GREEN_CHECK, fontweight="bold", zorder=5)
    elif badge == "cross":
        ax.text(x + width / 2 - 0.17, y + height / 2 - 0.07, "✗",
                fontsize=9, color=C_RED_X, fontweight="bold", zorder=5)


def _draw_core(ax, x, y, label, radius=0.62, color=C_GREEN_CORE):
    """Draw the central oval (device core)."""
    ell = mpatches.Ellipse((x, y), width=radius * 2.4, height=radius * 1.5,
                           facecolor=color, edgecolor=C_BORDER_GREY,
                           linewidth=1.5, zorder=3)
    ax.add_patch(ell)
    for i, line in enumerate(label.split("\n")):
        ax.text(x, y + (0.14 * (len(label.split("\n")) / 2 - i - 0.5)),
                line, ha="center", va="center",
                fontsize=7.5, color=C_WHITE, fontweight="bold", zorder=4)


def _arrow(ax, x0, y0, x1, y1):
    ax.annotate("", xy=(x1, y1), xytext=(x0, y0),
                arrowprops=dict(arrowstyle="-|>", color="#757575",
                                lw=1.1, mutation_scale=10),
                zorder=2)


def _legend(ax, x, y, covered_count, total_count, title):
    patches = [
        mpatches.Patch(color=C_GREEN_CORE,  label="Mandatory component (covered)"),
        mpatches.Patch(color=C_ORANGE,      label="Access vector — covered ✓"),
        mpatches.Patch(color=C_ORANGE_RED,  label="Access vector — NOT covered ✗"),
        mpatches.Patch(color=C_YELLOW,      label="Optional component"),
        mpatches.Patch(color=C_CYAN,        label="Access target"),
    ]
    leg = ax.legend(handles=patches, loc="lower left",
                    bbox_to_anchor=(x, y),
                    fontsize=7, title="Legend",
                    title_fontsize=7.5,
                    framealpha=0.92,
                    edgecolor=C_BORDER_GREY)
    leg.get_frame().set_linewidth(1.0)
    ax.text(0.5, 0.01,
            f"Coverage: {covered_count}/{total_count} Access Vectors ✓  |  {title}",
            transform=ax.transAxes,
            ha="center", fontsize=7.5, color="#424242",
            style="italic")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 1 — SOHO Router Attack Surface
# ─────────────────────────────────────────────────────────────────────────────

def diagram_soho_router():
    fig, ax = plt.subplots(figsize=(14, 9))
    ax.set_facecolor(C_GREY_BG)
    fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 14); ax.set_ylim(0, 9)
    ax.axis("off")
    fig.suptitle("RouterXPL-Forge v0.9.0 — SOHO Router Attack Surface Map",
                 fontsize=13, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    cx, cy = 7.0, 4.5
    _draw_core(ax, cx, cy, "SOHO Gateway\nSoC · NAND · Linux\nvendor firmware")

    # access vectors — left side
    vectors_left = [
        (4.5, 7.5, "telnet :23",         C_ORANGE,     "check"),
        (3.2, 6.5, "ssh :22",            C_ORANGE,     "check"),
        (4.5, 5.5, "web HTTP/HTTPS :80", C_ORANGE,     "check"),
        (3.2, 4.5, "snmp :161",          C_ORANGE,     "check"),
        (4.5, 3.5, "ftp :21",            C_ORANGE,     "check"),
        (3.2, 2.5, "winbox (MikroTik)",  C_ORANGE,     "check"),
        (4.5, 1.5, "upnp/ssdp :1900",   C_ORANGE,     "check"),
    ]

    # access vectors — right side
    vectors_right = [
        (9.5, 7.5, "console / serial",   C_ORANGE_RED, "cross"),
        (10.8, 6.5, "jtag / uart",       C_ORANGE_RED, "cross"),
        (9.5, 5.5, "netboot / tftp",     C_ORANGE_RED, "cross"),
        (10.8, 4.5, "vpn ipsec/l2tp",    C_YELLOW,     None),
        (9.5, 3.5, "wan ethernet/dsl",   C_YELLOW,     None),
        (10.8, 2.5, "wlan 802.11",       C_YELLOW,     None),
        (9.5, 1.5, "api ros :8728",      C_ORANGE,     "check"),
    ]

    for (x, y, lbl, col, badge) in vectors_left + vectors_right:
        _draw_node(ax, x, y, lbl, col, badge=badge, width=2.1)
        _arrow(ax, x, y, cx, cy)

    # targets / exploits box
    targets = [
        (cx - 1.1, 0.65, "RCE modules\n(540+)",  C_CYAN),
        (cx + 1.1, 0.65, "creds modules\n(88)",   C_CYAN),
    ]
    for (x, y, lbl, col) in targets:
        _draw_node(ax, x, y, lbl, col, width=1.9, height=0.7, fontsize=7)
        _arrow(ax, cx, cy, x, y)

    _legend(ax, 0.01, 0.01, covered_count=9, total_count=14,
            title="SOHO Router · 700 modules · 55 vendors")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_soho_router.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 2 — TP-Link Attack Surface (APT28 Campaign)
# ─────────────────────────────────────────────────────────────────────────────

def diagram_tplink_apt28():
    fig, ax = plt.subplots(figsize=(14, 9))
    ax.set_facecolor(C_GREY_BG); fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 14); ax.set_ylim(0, 9); ax.axis("off")
    fig.suptitle(
        "RouterXPL-Forge — TP-Link Attack Surface Map with APT28/GRU Coverage",
        fontsize=12, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    cx, cy = 7.0, 5.0
    _draw_core(ax, cx, cy, "TP-Link WR/Archer\nSoC · Linux · httpd\nDropbear SSH")

    vectors = [
        # left
        (4.2, 7.8, "HTTP :80 admin",         C_ORANGE,     "check"),
        (2.8, 6.8, "ssh :22 dropbear",       C_ORANGE,     "check"),
        (4.2, 5.8, "telnet :23",             C_ORANGE,     "check"),
        (2.8, 4.8, "snmp :161",              C_ORANGE,     "check"),
        (4.2, 3.8, "/loginFs/ path bypass",  C_ORANGE,     "check"),
        (2.8, 2.8, "ParentalCtrl url_0 inj", C_ORANGE,     "check"),
        (4.2, 1.8, "DHCP DNS rewrite",       C_ORANGE,     "check"),
        # right
        (9.8, 7.8, "serial/console",         C_ORANGE_RED, "cross"),
        (11.2, 6.8, "jtag/uart",             C_ORANGE_RED, "cross"),
        (9.8, 5.8, "wlan 802.11",            C_YELLOW,     None),
        (11.2, 4.8, "upnp/ssdp",             C_YELLOW,     None),
        (9.8, 3.8, "wan/dsl",                C_YELLOW,     None),
    ]

    for (x, y, lbl, col, badge) in vectors:
        _draw_node(ax, x, y, lbl, col, badge=badge, width=2.2)
        _arrow(ax, x, y, cx, cy)

    # APT28 chain box
    chain_items = [
        (5.0, 0.8, "CVE-2023-50224\ncred disclosure", C_CYAN),
        (7.0, 0.8, "CVE-2025-9377\nRCE persistence",  C_CYAN),
        (9.0, 0.8, "APT28 DNS hijack\nfull chain",     C_CYAN),
    ]
    for (x, y, lbl, col) in chain_items:
        _draw_node(ax, x, y, lbl, col, width=2.0, height=0.7, fontsize=7)
        _arrow(ax, cx, cy, x, y)

    _legend(ax, 0.01, 0.01, covered_count=7, total_count=12,
            title="TP-Link multi-model · APT28/GRU campaign (NCSC Apr 2026)")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_tplink_apt28.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 3 — MikroTik Attack Surface
# ─────────────────────────────────────────────────────────────────────────────

def diagram_mikrotik():
    fig, ax = plt.subplots(figsize=(14, 9))
    ax.set_facecolor(C_GREY_BG); fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 14); ax.set_ylim(0, 9); ax.axis("off")
    fig.suptitle(
        "RouterXPL-Forge — MikroTik RouterOS Attack Surface Map with Coverage Status",
        fontsize=12, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    cx, cy = 7.0, 5.0
    _draw_core(ax, cx, cy, "MikroTik RouterOS\nMIPS · Kernel 3.x\nSwitch ASIC")

    vectors = [
        # left — covered
        (4.2, 7.8, "winbox :8291",        C_ORANGE,     "check"),
        (2.8, 6.8, "ssh :22",             C_ORANGE,     "check"),
        (4.2, 5.8, "telnet :23",          C_ORANGE,     "check"),
        (2.8, 4.8, "api ros :8728",       C_ORANGE,     "check"),
        (4.2, 3.8, "ftp :21",             C_ORANGE,     "check"),
        (2.8, 2.8, "http/https :80/:443", C_ORANGE,     "check"),
        (4.2, 1.8, "snmp :161",           C_ORANGE,     "check"),
        # right — not covered / partial
        (9.8, 7.8, "dude :8291",          C_ORANGE_RED, "cross"),
        (11.2, 6.8, "netinstall/serial",  C_ORANGE_RED, "cross"),
        (9.8, 5.8, "ipsec vpn",           C_YELLOW,     None),
        (11.2, 4.8, "btest :2000",        C_ORANGE_RED, "cross"),
        (9.8, 3.8, "smb :445",            C_ORANGE,     "check"),
        (11.2, 2.8, "dhcp",               C_ORANGE_RED, "cross"),
    ]

    for (x, y, lbl, col, badge) in vectors:
        _draw_node(ax, x, y, lbl, col, badge=badge, width=2.2)
        _arrow(ax, x, y, cx, cy)

    cve_nodes = [
        (4.5, 0.7, "CVE-2018-14847\nWinbox cred",     C_CYAN),
        (7.0, 0.7, "CVE-2019-3978\nDNS cache poison",  C_CYAN),
        (9.5, 0.7, "APT28 DNS hijack\nRouterOS API",   C_CYAN),
    ]
    for (x, y, lbl, col) in cve_nodes:
        _draw_node(ax, x, y, lbl, col, width=2.0, height=0.65, fontsize=7)
        _arrow(ax, cx, cy, x, y)

    _legend(ax, 0.01, 0.01, covered_count=8, total_count=13,
            title="MikroTik RouterOS · Volt Typhoon + APT28 targets")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_mikrotik.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 4 — GPON ONT Attack Surface (Huawei EG8145)
# ─────────────────────────────────────────────────────────────────────────────

def diagram_gpon_ont():
    fig, ax = plt.subplots(figsize=(15, 9))
    ax.set_facecolor(C_GREY_BG); fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 15); ax.set_ylim(0, 9); ax.axis("off")
    fig.suptitle(
        "RouterXPL-Forge — GPON ONT Attack Surface Map (Huawei EG8145X6-10 / EG8145V5-V2)",
        fontsize=12, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    cx, cy = 7.5, 5.0
    _draw_core(ax, cx, cy, "GPON ONT / CPE\nDopra Linux 5.10\nBBSP/ASP webstack\nHuawei EG8145")

    vectors = [
        # left — covered
        (4.5, 8.0, "web UI HTTP :80",         C_ORANGE,     "check"),
        (2.9, 7.1, "ssh :22 (filtered)",       C_ORANGE,     "check"),
        (4.5, 6.1, "telnet :23 (filtered)",    C_ORANGE,     "check"),
        (2.9, 5.0, "upnp IGD :49652",          C_ORANGE,     "check"),
        (4.5, 4.0, "snmp :161",                C_ORANGE,     "check"),
        (2.9, 3.0, "tr-069 :37443",            C_YELLOW,     None),
        (4.5, 2.0, "csrf non-validation",      C_ORANGE,     "check"),
        # right — not covered / partial
        (10.5, 8.0, "gpon/xgs-pon if",        C_ORANGE_RED, "cross"),
        (12.1, 7.1, "omci channel",            C_ORANGE_RED, "cross"),
        (10.5, 6.1, "uart/jtag physical",      C_ORANGE_RED, "cross"),
        (12.1, 5.0, "wlan 2.4G/5G",            C_YELLOW,     None),
        (10.5, 4.0, "easy mesh controller",    C_YELLOW,     None),
        (12.1, 3.0, "pppoe credentials",       C_ORANGE,     "check"),
    ]

    for (x, y, lbl, col, badge) in vectors:
        _draw_node(ax, x, y, lbl, col, badge=badge, width=2.3)
        _arrow(ax, x, y, cx, cy)

    cve_nodes = [
        (4.5, 0.75, "pre-auth info\ndisclosure",      C_CYAN),
        (6.5, 0.75, "AES config\ndecrypt",             C_CYAN),
        (8.5, 0.75, "CSRF autopwn\n9-phase chain",     C_CYAN),
        (10.5, 0.75, "CVE-2025-49599\nEpuser bypass",  C_CYAN),
    ]
    for (x, y, lbl, col) in cve_nodes:
        _draw_node(ax, x, y, lbl, col, width=1.95, height=0.7, fontsize=7)
        _arrow(ax, cx, cy, x, y)

    _legend(ax, 0.01, 0.01, covered_count=8, total_count=13,
            title="Huawei GPON ONT · 11 dedicated modules")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_gpon_ont.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 5 — APT Group Attack Chain (overview)
# ─────────────────────────────────────────────────────────────────────────────

def diagram_apt_chain():
    fig, ax = plt.subplots(figsize=(15, 9))
    ax.set_facecolor(C_GREY_BG); fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 15); ax.set_ylim(0, 9); ax.axis("off")
    fig.suptitle(
        "RouterXPL-Forge — APT Group Attack Chains Against Network Devices",
        fontsize=12, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    # central node = RouterXPL engine
    cx, cy = 7.5, 5.0
    _draw_core(ax, cx, cy, "RouterXPL-Forge\nAPT Engine\n700 modules")

    # APT groups
    groups = [
        (2.5, 7.5, "APT28 / Forest Blizzard\nRussia · GRU",  C_ORANGE_RED),
        (2.5, 5.5, "Volt Typhoon\nChina",                    C_ORANGE_RED),
        (2.5, 3.5, "Sandworm / APT44\nRussia · GRU",         C_ORANGE_RED),
        (2.5, 1.5, "Quad7 / CovertNetwork\nChina",           C_ORANGE_RED),
        (12.5, 7.5, "Turla\nRussia · FSB",                   C_ORANGE_RED),
        (12.5, 5.5, "APT40 / Leviathan\nChina · MSS",        C_ORANGE_RED),
    ]
    for (x, y, lbl, col) in groups:
        _draw_node(ax, x, y, lbl, col, C_WHITE, width=2.6, height=0.75, fontsize=7.5, badge="check")
        _arrow(ax, x, y, cx, cy)

    # target devices
    devices = [
        (5.5, 8.3, "TP-Link\n20+ models",  C_CYAN),
        (7.5, 8.5, "MikroTik\nRouterOS",   C_CYAN),
        (9.5, 8.3, "Cisco\nRV/IOS",        C_CYAN),
        (5.5, 1.7, "ASUS\nRT series",      C_CYAN),
        (7.5, 1.5, "Netgear\nProSafe/DGN", C_CYAN),
        (9.5, 1.7, "Ubiquiti\nAirOS",      C_CYAN),
    ]
    for (x, y, lbl, col) in devices:
        _draw_node(ax, x, y, lbl, col, width=1.8, height=0.65, fontsize=7.5)
        _arrow(ax, cx, cy, x, y)

    # TTP labels on arrows (simulated as text)
    ttps = [
        (4.5, 7.0, "DNS hijack\nCVE-2023-50224"),
        (4.5, 5.0, "KV Botnet\nCVE-2019-1652"),
        (4.5, 3.0, "Cyclops Blink\ndefault creds"),
        (4.5, 1.9, "password spray\nCVE-2025-9377"),
        (11.2, 7.0, "SSH tunnel\nrelay ORB"),
        (11.2, 5.0, "Fortinet backdoor\nCVE-2016-1909"),
    ]
    for (x, y, lbl) in ttps:
        ax.text(x, y, lbl, ha="center", va="center", fontsize=6.2,
                color="#555555", style="italic", zorder=5,
                bbox=dict(boxstyle="round,pad=0.2", fc=C_GREY_BG, ec=C_BORDER_GREY, lw=0.7))

    _legend(ax, 0.01, 0.01, covered_count=6, total_count=6,
            title="6 APT groups · 20+ reproducible attack chains · MITRE ATT&CK mapped")
    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_apt_chains.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Diagram 6 — Module Architecture Overview
# ─────────────────────────────────────────────────────────────────────────────

def diagram_module_architecture():
    fig, ax = plt.subplots(figsize=(14, 8))
    ax.set_facecolor(C_GREY_BG); fig.patch.set_facecolor(C_GREY_BG)
    ax.set_xlim(0, 14); ax.set_ylim(0, 8); ax.axis("off")
    fig.suptitle(
        "RouterXPL-Forge v0.9.0 — Module Architecture Overview",
        fontsize=12, fontweight="bold", color=C_DARK_TEXT, y=0.97)

    # core engine
    cx, cy = 7.0, 4.5
    _draw_core(ax, cx, cy, "RouterXPL Engine\nInterpreter · Discovery\nAPT Catalog · Session Mgr")

    # module families
    families = [
        (3.0, 7.2, "Exploits\n540+ modules",     C_ORANGE,  "check"),
        (5.5, 7.2, "Credentials\n88 modules",     C_ORANGE,  "check"),
        (8.5, 7.2, "Scanners\n5 modules",         C_ORANGE,  "check"),
        (11.0, 7.2, "Generic\n14 modules",        C_ORANGE,  "check"),
        (3.0, 1.8, "Payloads\n32 modules",        C_ORANGE,  "check"),
        (5.5, 1.8, "Encoders\n13 modules",        C_ORANGE,  "check"),
        (8.5, 1.8, "APT Engine\n6 groups",        C_ORANGE,  "check"),
        (11.0, 1.8, "Discovery\nNmap/Masscan",    C_ORANGE,  "check"),
    ]
    for (x, y, lbl, col, badge) in families:
        _draw_node(ax, x, y, lbl, col, badge=badge, width=2.2, height=0.75)
        _arrow(ax, cx, cy, x, y)

    # vendor coverage
    vendors = [
        (2.0, 4.5, "55 Vendors\ncovered",      C_CYAN),
        (12.0, 4.5, "350 CVEs\nmapped",         C_CYAN),
        (7.0, 6.2, "Python 3.8+\ncross-platform", C_YELLOW),
    ]
    for (x, y, lbl, col) in vendors:
        _draw_node(ax, x, y, lbl, col, width=2.0, height=0.65, fontsize=7.5)
        _arrow(ax, cx, cy, x, y)

    # pip install note
    ax.text(7.0, 0.35, "pip install routerxpl   |   python -m routerxpl",
            ha="center", fontsize=9, color="#1565C0", fontweight="bold",
            bbox=dict(boxstyle="round,pad=0.3", fc="#E3F2FD", ec="#1565C0", lw=1.2))

    plt.tight_layout(rect=[0, 0.04, 1, 0.97])
    out = OUT / "rxf_arch_overview.png"
    plt.savefig(out, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out.name}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Generating RouterXPL-Forge attack surface maps...")
    diagram_soho_router()
    diagram_tplink_apt28()
    diagram_mikrotik()
    diagram_gpon_ont()
    diagram_apt_chain()
    diagram_module_architecture()
    print(f"\nAll diagrams written to {OUT}")
