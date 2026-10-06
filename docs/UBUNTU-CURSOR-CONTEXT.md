# EmbedXPL v5.0.0 — Ubuntu Cursor Context
## Read this at the start of every session on Ubuntu

---

## What You're Building

**EmbedXPL v5.0.0** — Unified XPL Suite Framework.

EmbedXPL absorbs a full copy of all specialized XPL Suite tools:
- WirelessXPL (wireless/drones) → stays active standalone
- PrinterXPL (printers/MFP) → stays active standalone
- FirewallXPL (firewall/NGFW/IDS/IPS/NAC) → stays active standalone
- IndustrialXPL (ICS/OT/AT/SCADA/PLC/RTU/IED) → stays active standalone
- WordlistXPL (wordlists engine) → stays active standalone
- **MikrotikAPI-BF** → absorbed COMPLETELY, that repo stops development

Plus unique EmbedXPL-only content: routers, cameras, mikrotik, malware research,
native C/C++/Go/Ruby source trees, Rapid7 MSF Ruby integration.

**The multi-language runtime** enables modules in: Python (default) + C + C++ + Go + Rust + Ruby.

---

## Phase Gate Protocol (MANDATORY)

```
Each phase MUST:
1. Execute the work
2. Present COMPLETION REPORT (files created, modules count, issues)
3. STOP and wait for: "APROVADO: P<N+1>"
4. Only then proceed

Never auto-advance phases.
```

---

## Current State (as of 2026-09-26 on Windows)

| Component | Status |
|---|---|
| Plan | ✅ `~/projects/XPL-Suite/docs/PLAN-EMBEDXPL-V5.md` |
| Phase 0 runtime | ❌ NOT DONE — start here |
| Phase 1–15 | ❌ NOT DONE |
| EmbedXPL version | v3.9.0 (bump to v5.0.0 at Phase 15) |
| Existing `multi_lang_module.py` | ✅ 161 lines — base for Phase 0 |

---

## Key Paths (Ubuntu)

```
~/projects/XPL-Suite/EmbedXPL-Forge/     ← main target
~/projects/XPL-Suite/FirewallXPL-Forge/
~/projects/XPL-Suite/IndustrialXPL-Forge/
~/projects/XPL-Suite/WirelessXPL-Forge/
~/projects/XPL-Suite/PrinterXPL-Forge/
~/projects/XPL-Suite/WordlistXPL-Forge/
~/projects/MikrotikAPI-BF/
~/projects/Labs/new-arsenal-2026-09/
~/projects/Labs/malware-samples/
~/projects/Labs/rapid7/metasploit-framework/
~/projects/Labs/rapid7/recog/
~/projects/Submodulos/OT/                 ← 62K files
~/projects/Submodulos/IoT/                ← 56K files
~/projects/Submodulos/Hacking/            ← 23K files, 26 tools
~/projects/Submodulos/malware/thezoo/
~/projects/XPL-Suite/docs/PLAN-EMBEDXPL-V5.md   ← full plan
```

---

## Phase 0 — What To Build (start here)

Create `~/projects/XPL-Suite/EmbedXPL-Forge/embedxpl/runtime/`:

```python
# executor.py — XplRuntime orchestrator
class XplRuntime:
    def execute(self, module, **kwargs):
        lang = getattr(module, 'native_language', 'python')
        executor = self._executors[lang]
        return executor.run(module, **kwargs)

# Module declares language:
class MyExploit(BaseExploit):
    native_language = "go"           # or "c", "cpp", "rust", "ruby"
    native_source = "native_src/go/cameradar"
    native_arch = ["amd64", "arm64"]
```

Files to create:
- `runtime/__init__.py`
- `runtime/executor.py`
- `runtime/python_exec.py`
- `runtime/c_exec.py`      ← gcc/clang + ARM/MIPS cross-compile
- `runtime/cpp_exec.py`
- `runtime/go_exec.py`     ← go build + binary cache
- `runtime/rust_exec.py`
- `runtime/ruby_exec.py`   ← MSF-compatible
- `runtime/toolchain.py`   ← auto-detect all compilers
- `runtime/crosscompile.py`← ARM/MIPS/MIPSLE targets
- `runtime/cache.py`       ← binary cache

Also create:
- `embedxpl/native_src/__init__.py` (placeholder)
- `embedxpl/intel/__init__.py` (placeholder)
- `embedxpl/malware_research/__init__.py` (placeholder)
- `embedxpl/engines/__init__.py` (update to include wordlists, nuclei, dahua_console)

Extend existing `embedxpl/core/multi_lang_module.py` — it has `run_c_source()`,
`run_ruby_source()`, `run_bash_source()`. Phase 0 builds the proper runtime
that replaces/supersedes this with structured executors.

---

## Cross-Compile Targets (Ubuntu has all of these via apt)

```python
CROSS_COMPILERS = {
    "arm":    "arm-linux-gnueabi-gcc",    # cameras, old routers
    "arm64":  "aarch64-linux-gnu-gcc",    # modern routers, smart TVs
    "mips":   "mips-linux-gnu-gcc",       # TP-Link, D-Link, Tenda (BE)
    "mipsle": "mipsel-linux-gnu-gcc",     # Netis, some D-Link (LE)
    "x86":    "gcc",                      # x86 targets
    "x64":    "gcc",                      # x64 targets
}
```

---

## Domain Boundaries (do NOT cross)

| Domain | Canonical Tool | EmbedXPL gets |
|---|---|---|
| WiFi, BLE, LoRaWAN, drones | WirelessXPL | full copy |
| Printers, MFP | PrinterXPL | full copy |
| ICS, OT, SCADA, PLC, RTU, IED, IIoT | IndustrialXPL | full copy |
| Firewall, NGFW, IDS, IPS, NAC, UTM | FirewallXPL | full copy |
| Wordlists engine | WordlistXPL | full copy |
| Routers, cameras, mikrotik, malware | **EmbedXPL only** | original |
| LLM, AI, red team ops | TupaXPL (private) | NO |

---

## Language Roles in XPL Suite

| Language | Role | Examples |
|---|---|---|
| Python | Core (95%+) | all existing exploit modules |
| C | Low-level exploits | meltdown, Mirai IoT source, ROP chains |
| C++ | Complex exploits | oboromi, cfc toolkit |
| Go | Scanners, C2 | Cameradar RTSP, pocindex |
| Rust | Evasion (future) | anti-analysis payloads |
| Ruby | MSF compat | rapid7/metasploit-framework modules |

---

## After Each Phase — Report Format

```
=== PHASE N COMPLETE ===
Files created: N
Modules integrated: N
New capabilities: [list]
Issues: [list or "none"]
Tests passed: [yes/no]
Next phase preview: [what P(N+1) will do]
=== AWAITING: APROVADO: P(N+1) ===
```
