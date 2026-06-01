# sysinfo and compute Commands

**Language:** English (en-US) | **pt-BR:** [../pt-BR/14-sysinfo-e-compute.md](../pt-BR/14-sysinfo-e-compute.md)

---

## `sysinfo` — display hardware profile

### Syntax

```
sysinfo
```

No parameters. Always performs a fresh hardware detection (`force=True`). The previously saved `compute_mode` is re-applied after detection.

### Full output — CPU + RAM only (no GPU)

```
exf> sysinfo

┌─────────────────────────────┐
│             CPU             │
├──────────────┬──────────────┤
│ Property     │ Value        │
├──────────────┼──────────────┤
│ Model        │ Intel Core i7-11800H @ 2.30GHz │
│ Architecture │ x86_64       │
│ Cores        │ 8            │
│ Threads      │ 16           │
│ Frequency    │ 2300 MHz     │
└──────────────┴──────────────┘

┌─────────────────────────────┐
│        Memory (RAM)         │
├──────────────┬──────────────┤
│ Property     │ Value        │
├──────────────┼──────────────┤
│ Total        │ 32,768 MB    │
│ Available    │ 18,432 MB    │
└──────────────┴──────────────┘

[WARN] No GPU detected on this system

 Compute mode: auto -> cpu  |  Best backend: cpu
```

---

### Full output — with NVIDIA GPU

```
exf> sysinfo

┌─────────────────────────────────────────────────┐
│                       CPU                       │
├──────────────────┬──────────────────────────────┤
│ Property         │ Value                        │
├──────────────────┼──────────────────────────────┤
│ Model            │ AMD Ryzen 9 7950X @ 4.50GHz  │
│ Architecture     │ x86_64                       │
│ Cores            │ 16                           │
│ Threads          │ 32                           │
│ Frequency        │ 4500 MHz                     │
└──────────────────┴──────────────────────────────┘

┌───────────────────────────┐
│       Memory (RAM)        │
├───────────────┬───────────┤
│ Property      │ Value     │
├───────────────┼───────────┤
│ Total         │ 65,536 MB │
│ Available     │ 52,480 MB │
└───────────────┴───────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                             GPU Devices                                  │
├───┬───────────────────────────┬────────┬──────────┬────────┬─────┬───────┤
│ # │ Name                      │ Vendor │ VRAM     │Backend │Driver│Compute│
├───┼───────────────────────────┼────────┼──────────┼────────┼─────┼───────┤
│ 0 │ NVIDIA GeForce RTX 4090   │ nvidia │ 24,576 MB│ cuda   │555.85│ 8.9  │
└───┴───────────────────────────┴────────┴──────────┴────────┴─────┴───────┘

 Compute mode: auto -> hybrid  |  Best backend: cuda
```

---

### Full output — with AMD GPU (ROCm)

```
exf> sysinfo

 ... (CPU and RAM tables as above) ...

┌──────────────────────────────────────────────────────────────────────────┐
│                             GPU Devices                                  │
├───┬───────────────────────────┬────────┬──────────┬────────┬──────┬──────┤
│ # │ Name                      │ Vendor │ VRAM     │Backend │Driver│Compute│
├───┼───────────────────────────┼────────┼──────────┼────────┼──────┼──────┤
│ 0 │ AMD Radeon RX 7900 XTX    │ amd    │ 24,576 MB│ rocm   │ 6.0.2│gfx1100│
└───┴───────────────────────────┴────────┴──────────┴────────┴──────┴──────┘

 Compute mode: auto -> hybrid  |  Best backend: rocm
```

---

### Full output — multi-GPU system

```
exf> sysinfo

 ... (CPU and RAM tables) ...

┌──────────────────────────────────────────────────────────────────────────────┐
│                               GPU Devices                                    │
├───┬─────────────────────────────┬────────┬──────────┬────────┬──────┬────────┤
│ # │ Name                        │ Vendor │ VRAM     │Backend │Driver│Compute │
├───┼─────────────────────────────┼────────┼──────────┼────────┼──────┼────────┤
│ 0 │ NVIDIA GeForce RTX 4070     │ nvidia │  8,192 MB│ cuda   │555.85│ 8.9    │
│ 1 │ NVIDIA GeForce RTX 3060     │ nvidia │ 12,288 MB│ cuda   │555.85│ 8.6    │
└───┴─────────────────────────────┴────────┴──────────┴────────┴──────┴────────┘

 Compute mode: auto -> hybrid  |  Best backend: cuda
```

---

### What `sysinfo` detects

| Field | Source | Notes |
|-------|--------|-------|
| CPU Model | `/proc/cpuinfo` (Linux), `wmic cpu` (Windows), `sysctl` (macOS) | |
| CPU Architecture | `platform.machine()` | e.g. `x86_64`, `aarch64`, `armv7l` |
| Cores | `os.cpu_count()` / psutil | Physical cores |
| Threads | `os.cpu_count()` | Logical threads (including HT) |
| Frequency (MHz) | `/proc/cpuinfo` `cpu MHz`, psutil | May show 0 on throttled systems |
| RAM Total | psutil / `/proc/meminfo` | In MB |
| RAM Available | psutil `available` | Excludes buffers/cache |
| GPU Name | `nvidia-smi`, `rocm-smi`, `clinfo`, `wmic path Win32_VideoController` | |
| GPU VRAM | `nvidia-smi --query-gpu=memory.total` | |
| GPU Backend | CUDA / ROCm / OpenCL auto-detected | |
| GPU Driver | `nvidia-smi`, `amdgpu` version | `N/A` if unavailable |
| Compute Capability | CUDA `sm_XX`, ROCm `gfxXXXX` | `N/A` for other backends |

---

### Startup system line

The hardware one-liner shown in the startup banner is generated by `HWProfile.one_liner()`:

```
[system]  Intel Core i7-11800H (16T) | 32768MB RAM | No GPU detected | compute_mode: auto->cpu
[system]  AMD Ryzen 9 7950X (32T)    | 65536MB RAM | NVIDIA GeForce RTX 4090 24576MB | compute_mode: auto->hybrid
```

---

## `compute` — set compute mode

### Syntax

```
compute <cpu|gpu|hybrid|auto>
```

### Parameters

| Value | Meaning |
|-------|---------|
| `cpu` | Force CPU-only for all operations. All GPU-accelerated modules fall back to CPU paths. |
| `gpu` | Force GPU for all operations. Falls back to CPU silently if no GPU is present. |
| `hybrid` | Use GPU for ML-accelerated modules (banner fingerprinting, credential ranking, fuzzing entropy estimation) and CPU for all standard exploits. |
| `auto` | Automatically resolve at runtime: `hybrid` if GPU is present, `cpu` if not. (Default) |

The selected mode is **persisted** to the EmbedXPL config file (`~/.exf_config.json`) and restored on the next launch.

### Tab completion

```
exf> compute <TAB>
auto    cpu    gpu    hybrid
```

---

### `compute cpu`

```
exf> compute cpu
[+] compute_mode => cpu
```

---

### `compute gpu` (GPU present)

```
exf> compute gpu
[+] compute_mode => gpu
```

---

### `compute gpu` (no GPU — automatic fallback)

```
exf> compute gpu
[WARN] No GPU detected -- falling back to compute_mode=cpu
```

The mode is saved as `cpu` even though `gpu` was requested.

---

### `compute hybrid`

```
exf> compute hybrid
[+] compute_mode => hybrid
```

---

### `compute hybrid` (no GPU — automatic fallback)

```
exf> compute hybrid
[WARN] No GPU detected -- falling back to compute_mode=cpu
```

---

### `compute auto`

```
exf> compute auto
[+] compute_mode => auto
  auto resolves to: cpu
```

```
exf> compute auto
[+] compute_mode => auto
  auto resolves to: hybrid
```

---

### Invalid mode

```
exf> compute quantum
[-] Invalid compute mode 'quantum'. Choose from: cpu, gpu, hybrid, auto
```

---

### `sysinfo` after changing compute mode

`sysinfo` re-reads the saved config and shows the current effective mode:

```
exf> compute gpu
[+] compute_mode => gpu

exf> sysinfo
...
 Compute mode: gpu  |  Best backend: cuda
```

---

## Which modules use GPU compute?

| Module category | GPU use |
|-----------------|---------|
| Standard exploits | Never (CPU only) |
| Standard scanners | Never (CPU only) |
| Standard creds | Never (CPU only) |
| `core/ml/banner_fingerprint.py` | Yes — device fingerprinting via transformer model |
| `core/ml/advisor.py` | Yes — module priority ranking using ML scoring |
| `core/gpu/backend.py` | Yes — GPU backend dispatcher for ML modules |
| Fuzzing entropy estimator | Yes (hybrid: GPU for scoring, CPU for delivery) |

If no GPU is present, all ML modules fall back to CPU paths automatically — they are slower but functionally equivalent.
