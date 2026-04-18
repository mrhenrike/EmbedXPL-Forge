# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek
"""Mirai/Condi reference source orchestrator for EmbedXPL-Forge lab.

Provides a Python API to manage the Mirai/Condi reference C source trees
located in ``laboratory/notmirai-lab/mirai-references/``.  The orchestrator
enables lab researchers to:

  1. **Inventory** reference source trees (condi, classic-mirai, pymirai).
  2. **Compile analysis tools** (enc.c encoder, single_load.c report tool)
     inside an isolated Docker container -- NOT the bot, loader, or DLR binaries.
  3. **Decode obfuscated strings** using the XOR table key (delegates to
     ``embedxpl.modules.tools.mirai_string_decoder``).
  4. **Inspect attack vector opcodes** from attack.h extracted constants.
  5. **Report C2 schema** structure from the public db.sql (MySQL tables).
  6. **Run PyMirai Python components** (from tanc7-pymirai) for cross-reference.

IMPORTANT — Scope limitation:
  This orchestrator ONLY manages ANALYSIS AND DETECTION tooling.  It will
  NOT compile or execute: bot/main.c, loader/, dlr/main.c (the actual
  malware infection chain).  Those binaries serve no legitimate detection
  purpose and fall outside the framework's ethical scope.

Directory layout expected (from EmbedXPL-Forge workspace root):
  ../../laboratory/notmirai-lab/mirai-references/
    lion001am-condi/          <- Condi-Mirai source (canonical reference)
    honeyvig-condi/           <- duplicate of lion001am-condi
    tanc7-pymirai/            <- PyMirai Python ports
    hklcf-mirai/              <- Classic Mirai research tree
    jgamblin-mirai-source/    <- jgamblin public fork (used for db.sql / ForumPost)

MITRE ATT&CK:
  T1027   — Obfuscated Files or Information (analysis capability)
  T1140   — Deobfuscate/Decode Files or Information
  T1046   — Network Service Discovery (coordinating lab tests)

Version: 1.0.0
"""

from __future__ import annotations

import logging
import os
import pathlib
import subprocess
import sys
from typing import Any, Dict, List, Optional

from embedxpl.core.exploit import (
    Exploit as BaseExploit,
    OptBool,
    OptIP,
    OptInt,
    OptString,
    mute,
    print_error,
    print_info,
    print_status,
    print_success,
    print_warning,
)

# Author: André Henrique (@mrhenrike) | União Geek — https://github.com/Uniao-Geek

logger = logging.getLogger("embedxpl.modules.tools.mirai_ref_orchestrator")

# ---------------------------------------------------------------------------
# Reference tree constants
# ---------------------------------------------------------------------------

# Relative path from EmbedXPL-Forge repo root to mirai-references
_REF_ROOT_RELPATH = os.path.join(
    os.path.dirname(__file__),  # embedxpl/modules/tools/
    "..", "..", "..", "..",      # up to EmbedXPL-Forge root
    "..", "..", "laboratory",   # then into laboratory/
    "notmirai-lab", "mirai-references"
)
_REF_ROOT = pathlib.Path(_REF_ROOT_RELPATH).resolve()

# Known reference source trees
REFERENCE_TREES: Dict[str, Dict[str, Any]] = {
    "condi": {
        "path": _REF_ROOT / "lion001am-condi",
        "description": "Condi-Mirai variant with GPON/Realtek scanners (lion001am fork)",
        "type": "C+Go",
        "has_enc": True,
        "has_pymirai": False,
    },
    "condi-alt": {
        "path": _REF_ROOT / "honeyvig-condi",
        "description": "Duplicate of lion001am-condi for diff/verification",
        "type": "C+Go",
        "has_enc": True,
        "has_pymirai": False,
    },
    "pymirai": {
        "path": _REF_ROOT / "tanc7-pymirai",
        "description": "Partial Python ports of Mirai bot/loader + Original C tree",
        "type": "Python+C",
        "has_enc": True,
        "has_pymirai": True,
    },
    "classic": {
        "path": _REF_ROOT / "hklcf-mirai",
        "description": "Classic Mirai research tree with db.sql and crosscompiler",
        "type": "C+Go",
        "has_enc": True,
        "has_pymirai": False,
    },
    "jgamblin": {
        "path": _REF_ROOT / "jgamblin-mirai-source",
        "description": "Public jgamblin research fork with ForumPost and LICENSE",
        "type": "C+Go",
        "has_enc": True,
        "has_pymirai": False,
    },
}

# ONLY these C files are eligible for compilation (analysis tools only)
_ALLOWED_COMPILE_TARGETS: Dict[str, str] = {
    "enc":         "bot/enc.c or enc/enc.c -- XOR string encoder/decoder tool",
    "single_load": "mirai/tools/single_load.c -- bulk reporting helper",
    "badbot":      "mirai/tools/badbot.c -- minimal test stub",
    "nogdb":       "mirai/tools/nogdb.c -- anti-debug test helper",
}

# Prohibited targets (never compile or execute)
_PROHIBITED_TARGETS = frozenset([
    "main",     # bot/main.c -- actual botnet ELF
    "loader",   # loader/ -- infection mechanism
    "dlr",      # dlr/main.c -- staging binary
    "scanner",  # bot/scanner.c -- standalone scanner binary (not the EmbedXPL one)
    "cnc",      # cnc/*.go -- C2 server
    "gpon",     # gpon*_scanner.c -- GPON exploitation binary
    "realtek",  # realtek.c -- Realtek exploitation binary
])

# Attack vector opcodes extracted from lion001am-condi/bot/attack.h
ATTACK_VECTORS: Dict[int, str] = {
    0:  "ATK_VEC_STOMP      -- TCP session hijack flood",
    1:  "ATK_VEC_UDP_PLAIN  -- Plain UDP flood",
    2:  "ATK_VEC_STD        -- Standard UDP with GRE encap",
    3:  "ATK_VEC_TCP        -- Generic TCP flood",
    4:  "ATK_VEC_ACK        -- TCP ACK flood",
    5:  "ATK_VEC_SYN        -- TCP SYN flood",
    6:  "ATK_VEC_HEXFLOOD   -- Hex-pattern UDP flood",
    7:  "ATK_VEC_STDHEX     -- Standard + hex payload",
    8:  "ATK_VEC_NUDP       -- Null UDP payload flood",
    9:  "ATK_VEC_UDPHEX     -- UDP with hex pattern",
    10: "ATK_VEC_XMAS       -- TCP XMAS flag flood",
    11: "ATK_VEC_TCPBYPASS  -- TCP bypass (port 80)",
    12: "ATK_VEC_RAW        -- Raw IP flood",
    13: "ATK_VEC_UDP_CUSTOM -- Custom payload UDP flood",
    14: "ATK_VEC_OVHDROP    -- OVH anti-DDoS bypass (drop)",
    15: "ATK_VEC_NFO        -- NFO/null-byte flood",
    16: "ATK_VEC_OVH        -- OVH-targeted flood variant",
}

# CnC/infrastructure ports decoded from table.c (key 0xdeadbeef)
DECODED_PORTS: Dict[str, int] = {
    "cnc_bot_listener":    3778,   # TABLE_CNC_PORT   [0x2C, 0xE0] ^ 0xdeadbeef
    "scan_callback":       9555,   # TABLE_SCAN_CB_PORT [0x07, 0x71] ^ 0xdeadbeef
}

# MySQL C2 schema (jgamblin-mirai-source/scripts/db.sql)
MYSQL_SCHEMA: str = (
    "CREATE DATABASE mirai;\n"
    "TABLE users   (id, username, password, duration_limit, cooldown, wrc, "
    "last_paid, max_bots, admin, intvl, api_key)\n"
    "TABLE history (id, user_id, time_sent, duration, command, max_bots)\n"
    "TABLE whitelist (id, prefix, netmask)"
)


class MiraiRefOrchestrator:
    """Python orchestrator for the Mirai/Condi reference source trees.

    Provides inventory, analysis tool compilation (safe subset only),
    XOR decoding, and lab coordination capabilities.
    """

    def __init__(self, ref_root: Optional[pathlib.Path] = None) -> None:
        """Initialise orchestrator.

        Args:
            ref_root: Override path to the mirai-references root.
                      Defaults to auto-resolved relative path.
        """
        self.ref_root = ref_root or _REF_ROOT

    def is_available(self) -> bool:
        """Return True if the mirai-references directory exists on this machine.

        Returns:
            True if _REF_ROOT resolves to an existing directory.
        """
        return self.ref_root.is_dir()

    def inventory(self) -> Dict[str, Dict[str, Any]]:
        """Return inventory of available reference trees with existence flags.

        Returns:
            Dict mapping tree name to info dict with 'exists' key added.
        """
        result = {}
        for name, info in REFERENCE_TREES.items():
            exists = info["path"].is_dir()
            result[name] = {**info, "exists": exists, "path": str(info["path"])}
        return result

    def list_analysable_files(self, tree: str = "condi") -> List[str]:
        """List all .c, .h, .py, .go, .sh, and .sql files in a reference tree.

        Args:
            tree: Reference tree key (condi / pymirai / classic / jgamblin).

        Returns:
            Sorted list of relative file paths.
        """
        info = REFERENCE_TREES.get(tree)
        if not info or not info["path"].is_dir():
            return []
        files = []
        for ext in (".c", ".h", ".py", ".go", ".sh", ".sql", ".bash", ".txt", ".md"):
            files.extend(str(p.relative_to(info["path"])) for p in info["path"].rglob("*" + ext))
        return sorted(files)

    def compile_analysis_tool(
        self,
        target: str,
        tree: str = "condi",
        output_dir: Optional[str] = None,
        use_docker: bool = False,
    ) -> Dict[str, Any]:
        """Compile a whitelisted analysis tool from the reference source.

        Only tools in ``_ALLOWED_COMPILE_TARGETS`` may be compiled.
        Attempts gcc compilation on the host (Linux/WSL) or in Docker.

        Args:
            target: Tool name (enc / single_load / badbot / nogdb).
            tree: Reference tree to use.
            output_dir: Where to write the compiled binary (default: /tmp).
            use_docker: Run compilation inside ``embedxpl-lab`` Docker (safer).

        Returns:
            Dict with keys: success (bool), binary_path (str), stderr (str).
        """
        if target in _PROHIBITED_TARGETS:
            return {
                "success": False,
                "binary_path": "",
                "stderr": "BLOCKED: '{}' is a prohibited compile target (malware component).".format(target),
            }
        if target not in _ALLOWED_COMPILE_TARGETS:
            return {
                "success": False,
                "binary_path": "",
                "stderr": "Unknown target '{}'. Allowed: {}".format(
                    target, list(_ALLOWED_COMPILE_TARGETS.keys())),
            }

        tree_info = REFERENCE_TREES.get(tree)
        if not tree_info or not tree_info["path"].is_dir():
            return {"success": False, "binary_path": "", "stderr": "Tree '{}' not found.".format(tree)}

        src_path = self._find_source(tree_info["path"], target)
        if not src_path:
            return {"success": False, "binary_path": "",
                    "stderr": "Source file for '{}' not found in tree '{}'.".format(target, tree)}

        out_dir = pathlib.Path(output_dir or "/tmp")
        binary = str(out_dir / target)

        if use_docker:
            return self._docker_compile(src_path, binary)
        return self._host_compile(src_path, binary)

    def decode_table_string(self, hex_bytes: str, key: int = 0xDEADBEEF) -> str:
        """Decode a Mirai XOR-obfuscated table string.

        Args:
            hex_bytes: Space-separated or continuous hex string (e.g. '2C E0' or '2CE0').
            key: 32-bit XOR key.

        Returns:
            Decoded string (latin-1).
        """
        from embedxpl.modules.tools.mirai_string_decoder import MiraiStringDecoder
        dec = MiraiStringDecoder(key=key)
        raw = bytes(int(h, 16) for h in hex_bytes.replace("\\x", " ").split() if h)
        decoded = dec.decode_bytes(raw)
        try:
            return decoded.decode("latin-1")
        except Exception:
            return repr(decoded)

    def show_attack_vectors(self) -> Dict[int, str]:
        """Return the full Mirai attack vector opcode table.

        Returns:
            Dict mapping opcode int to description string.
        """
        return dict(ATTACK_VECTORS)

    def show_decoded_ports(self) -> Dict[str, int]:
        """Return CnC and scan-callback ports decoded from table.c.

        Returns:
            Dict mapping role name to port number.
        """
        return dict(DECODED_PORTS)

    def show_mysql_schema(self) -> str:
        """Return the Mirai MySQL C2 schema summary.

        Returns:
            Multi-line string describing the schema.
        """
        return MYSQL_SCHEMA

    def run_pymirai_scanner(self, module: str = "scanner_c") -> Optional[str]:
        """Attempt to run a PyMirai Python module for cross-reference analysis.

        This runs the Python module in a subprocess for inspection/analysis
        purposes only.  It does NOT invoke network scanning.

        Args:
            module: Python module stem in tanc7-pymirai/PyMirai/bot/ (e.g. 'scanner_c').

        Returns:
            stdout output or error description.
        """
        pymirai_base = REFERENCE_TREES["pymirai"]["path"] / "PyMirai" / "bot"
        module_path = pymirai_base / (module + ".py")
        if not module_path.exists():
            return "Module {} not found at {}".format(module, module_path)
        try:
            result = subprocess.run(
                [sys.executable, str(module_path), "--help"],
                capture_output=True, text=True, timeout=5
            )
            return result.stdout or result.stderr or "(no output)"
        except subprocess.TimeoutExpired:
            return "(module timed out -- expected for network-active code)"
        except Exception as exc:
            return "Error running module: {}".format(exc)

    # -------------------------------------------------------------------------
    # Private compilation helpers
    # -------------------------------------------------------------------------

    def _find_source(self, tree_path: pathlib.Path, target: str) -> Optional[pathlib.Path]:
        """Locate the .c source file for a given tool in the tree.

        Args:
            tree_path: Root path of the reference tree.
            target: Tool name (enc / single_load / etc.).

        Returns:
            Path to .c file if found, else None.
        """
        candidates = {
            "enc":         ["enc/enc.c", "mirai/tools/enc.c", "tools/enc.c"],
            "single_load": ["mirai/tools/single_load.c", "tools/single_load.c"],
            "badbot":      ["mirai/tools/badbot.c", "tools/badbot.c"],
            "nogdb":       ["mirai/tools/nogdb.c", "tools/nogdb.c"],
        }
        for rel in candidates.get(target, []):
            candidate = tree_path / rel
            if candidate.exists():
                return candidate
        return None

    def _host_compile(self, src: pathlib.Path, binary: str) -> Dict[str, Any]:
        """Attempt to compile src with gcc on the host.

        Args:
            src: Source .c file path.
            binary: Output binary path.

        Returns:
            Result dict.
        """
        try:
            result = subprocess.run(
                ["gcc", "-O2", "-o", binary, str(src)],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                return {"success": True, "binary_path": binary, "stderr": result.stderr}
            return {"success": False, "binary_path": "", "stderr": result.stderr}
        except FileNotFoundError:
            return {"success": False, "binary_path": "",
                    "stderr": "gcc not found on host. Use use_docker=True."}
        except Exception as exc:
            return {"success": False, "binary_path": "", "stderr": str(exc)}

    def _docker_compile(self, src: pathlib.Path, binary: str) -> Dict[str, Any]:
        """Compile inside the running embedxpl-lab Docker container.

        Args:
            src: Source .c file path.
            binary: Output binary path inside container.

        Returns:
            Result dict.
        """
        try:
            result = subprocess.run(
                [
                    "docker", "exec", "embedxpl-lab-router",
                    "sh", "-c",
                    "apt-get install -y gcc 2>/dev/null; "
                    "gcc -O2 -o /tmp/{} /dev/stdin < {}".format(
                        pathlib.Path(binary).name, src)
                ],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0:
                return {
                    "success": True,
                    "binary_path": "/tmp/{}".format(pathlib.Path(binary).name),
                    "stderr": result.stderr,
                }
            return {"success": False, "binary_path": "", "stderr": result.stderr}
        except FileNotFoundError:
            return {"success": False, "binary_path": "",
                    "stderr": "docker not found. Install Docker Desktop."}
        except Exception as exc:
            return {"success": False, "binary_path": "", "stderr": str(exc)}


class Exploit(BaseExploit):
    """Mirai/Condi reference source lab orchestrator (EmbedXPL module).

    Author: Andre Henrique (@mrhenrike) | Uniao Geek
    Version: 1.0.0
    """

    __info__ = {
        "name": "Mirai Reference Source Lab Orchestrator",
        "description": (
            "Manages the Mirai/Condi reference C source trees in laboratory/notmirai-lab/. "
            "Provides inventory, XOR string decoding, attack vector catalogue, "
            "MySQL C2 schema reference, and safe compilation of analysis tools only "
            "(enc/single_load/badbot/nogdb). Does NOT compile or run the actual "
            "bot binary, loader, DLR, GPON scanner, or CnC server."
        ),
        "authors": ["Andre Henrique (@mrhenrike) | Uniao Geek"],
        "references": [
            "https://github.com/jgamblin/Mirai-Source-Code",
            "laboratory/notmirai-lab/mirai-references/ (local)",
        ],
        "devices": ["N/A — lab orchestration module"],
        "severity": "info",
        "apt_groups": ["Mirai Botnet", "Condi Botnet"],
        "mitre": ["T1027", "T1140", "T1046"],
    }

    target = OptIP("", "Not used -- lab/analysis module")
    tree = OptString("condi", "Reference tree: condi / classic / pymirai / jgamblin")
    compile_tool = OptString("", "Analysis tool to compile: enc / single_load / badbot / nogdb")
    use_docker = OptBool(False, "Compile inside Docker lab container")
    show_vectors = OptBool(True, "Show attack vector opcode table")
    show_ports = OptBool(True, "Show decoded CnC/scan-callback ports")
    show_schema = OptBool(True, "Show MySQL C2 schema reference")

    @mute
    def check(self) -> bool:
        """Check if reference source trees are present on this machine.

        Returns:
            True if the mirai-references directory exists.
        """
        orch = MiraiRefOrchestrator()
        return orch.is_available()

    def run(self) -> None:
        """Execute orchestrator: inventory, analysis, optional compilation."""
        orch = MiraiRefOrchestrator()

        # 1. Inventory
        print_status("[MiraiOrch] Inventorying reference trees at {}...".format(orch.ref_root))
        inv = orch.inventory()
        for name, info in inv.items():
            exists_mark = "[OK]" if info["exists"] else "[--]"
            print_info("[MiraiOrch] {} {:15s} | {} | {}".format(
                exists_mark, name, info["type"], info["description"]))

        if not orch.is_available():
            print_warning("[MiraiOrch] Reference root not found at {}.".format(orch.ref_root))
            print_info("[MiraiOrch] Showing static constants derived from source analysis.")

        # 2. Attack vectors
        if self.show_vectors:
            print_info("[MiraiOrch] Mirai/Condi attack vectors (from attack.h):")
            for opcode, desc in orch.show_attack_vectors().items():
                print_info("[MiraiOrch]   {:2d} = {}".format(opcode, desc))

        # 3. Decoded ports
        if self.show_ports:
            print_info("[MiraiOrch] Decoded CnC/infra ports (table.c XOR 0xdeadbeef):")
            for role, port in orch.show_decoded_ports().items():
                print_success("[MiraiOrch]   {:30s} = {}".format(role, port))

        # 4. MySQL schema
        if self.show_schema:
            print_info("[MiraiOrch] MySQL C2 schema (db.sql):")
            for line in orch.show_mysql_schema().splitlines():
                print_info("[MiraiOrch]   {}".format(line))

        # 5. File inventory for selected tree
        tree_name = str(self.tree).lower()
        files = orch.list_analysable_files(tree=tree_name)
        if files:
            print_status("[MiraiOrch] Files in '{}' tree ({} total):".format(tree_name, len(files)))
            for f in files[:40]:
                print_info("[MiraiOrch]   {}".format(f))
            if len(files) > 40:
                print_info("[MiraiOrch]   ... {} more".format(len(files) - 40))
        else:
            print_warning("[MiraiOrch] No files found for tree '{}' (directory missing?).".format(
                tree_name))

        # 6. Optional compilation
        tool = str(self.compile_tool).strip()
        if tool:
            if tool in _PROHIBITED_TARGETS:
                print_error("[MiraiOrch] BLOCKED: '{}' is a prohibited target (malware component).".format(tool))
                print_info("[MiraiOrch] Allowed tools: {}".format(list(_ALLOWED_COMPILE_TARGETS.keys())))
                return
            print_status("[MiraiOrch] Compiling '{}' from tree '{}'...".format(tool, tree_name))
            result = orch.compile_analysis_tool(
                target=tool, tree=tree_name, use_docker=bool(self.use_docker))
            if result["success"]:
                print_success("[MiraiOrch] Compiled: {}".format(result["binary_path"]))
            else:
                print_error("[MiraiOrch] Compilation failed: {}".format(result["stderr"][:200]))
