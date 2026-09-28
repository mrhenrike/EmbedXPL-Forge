# Comandos sysinfo e compute

**Idioma:** Português (pt-BR). **English:** [../en-US/14-sysinfo-and-compute.md](../en-US/14-sysinfo-and-compute.md)

---

## `sysinfo` — exibir perfil de hardware

### Sintaxe

```
sysinfo
```

Sem parâmetros. Sempre realiza uma detecção de hardware atualizada (`force=True`). O `compute_mode` salvo anteriormente é reaplicado após a detecção.

### Saída completa — apenas CPU + RAM (sem GPU)

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

### Saída completa — com GPU NVIDIA

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

### Saída completa — com GPU AMD (ROCm)

```
exf> sysinfo

 ... (tabelas de CPU e RAM como acima) ...

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

### Saída completa — sistema multi-GPU

```
exf> sysinfo

 ... (tabelas de CPU e RAM) ...

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

### O que o `sysinfo` detecta

| Campo | Fonte | Notas |
|-------|-------|-------|
| Modelo da CPU | `/proc/cpuinfo` (Linux), `wmic cpu` (Windows), `sysctl` (macOS) | |
| Arquitetura da CPU | `platform.machine()` | ex.: `x86_64`, `aarch64`, `armv7l` |
| Núcleos | `os.cpu_count()` / psutil | Núcleos físicos |
| Threads | `os.cpu_count()` | Threads lógicos (incluindo HT) |
| Frequência (MHz) | `/proc/cpuinfo` `cpu MHz`, psutil | Pode mostrar 0 em sistemas com throttling |
| RAM Total | psutil / `/proc/meminfo` | Em MB |
| RAM Disponível | psutil `available` | Exclui buffers/cache |
| Nome da GPU | `nvidia-smi`, `rocm-smi`, `clinfo`, `wmic path Win32_VideoController` | |
| VRAM da GPU | `nvidia-smi --query-gpu=memory.total` | |
| Backend da GPU | CUDA / ROCm / OpenCL auto-detectado | |
| Driver da GPU | `nvidia-smi`, versão `amdgpu` | `N/A` se indisponível |
| Capacidade de Computação | CUDA `sm_XX`, ROCm `gfxXXXX` | `N/A` para outros backends |

---

### Linha de sistema na inicialização

A linha de hardware de uma linha exibida no banner de inicialização é gerada por `HWProfile.one_liner()`:

```
[system]  Intel Core i7-11800H (16T) | 32768MB RAM | No GPU detected | compute_mode: auto->cpu
[system]  AMD Ryzen 9 7950X (32T)    | 65536MB RAM | NVIDIA GeForce RTX 4090 24576MB | compute_mode: auto->hybrid
```

---

## `compute` — definir modo de computação

### Sintaxe

```
compute <cpu|gpu|hybrid|auto>
```

### Parâmetros

| Valor | Significado |
|-------|-------------|
| `cpu` | Forçar apenas CPU para todas as operações. Todos os módulos acelerados por GPU voltam para caminhos de CPU. |
| `gpu` | Forçar GPU para todas as operações. Volta para CPU silenciosamente se nenhuma GPU estiver presente. |
| `hybrid` | Usar GPU para módulos acelerados por ML (fingerprinting de banner, classificação de credenciais, estimativa de entropia de fuzzing) e CPU para todos os exploits padrão. |
| `auto` | Resolver automaticamente em tempo de execução: `hybrid` se GPU presente, `cpu` se não. (Padrão) |

O modo selecionado é **persistido** no arquivo de configuração do EmbedXPL (`~/.exf_config.json`) e restaurado na próxima inicialização.

### Completamento por Tab

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

### `compute gpu` (GPU presente)

```
exf> compute gpu
[+] compute_mode => gpu
```

---

### `compute gpu` (sem GPU — fallback automático)

```
exf> compute gpu
[WARN] No GPU detected -- falling back to compute_mode=cpu
```

O modo é salvo como `cpu` mesmo que `gpu` tenha sido solicitado.

---

### `compute hybrid`

```
exf> compute hybrid
[+] compute_mode => hybrid
```

---

### `compute hybrid` (sem GPU — fallback automático)

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

### Modo inválido

```
exf> compute quantum
[-] Invalid compute mode 'quantum'. Choose from: cpu, gpu, hybrid, auto
```

---

### `sysinfo` após mudar o modo de computação

`sysinfo` relê a configuração salva e mostra o modo efetivo atual:

```
exf> compute gpu
[+] compute_mode => gpu

exf> sysinfo
...
 Compute mode: gpu  |  Best backend: cuda
```

---

## Quais módulos usam computação GPU?

| Categoria de módulo | Uso de GPU |
|--------------------|-----------|
| Exploits padrão | Nunca (apenas CPU) |
| Scanners padrão | Nunca (apenas CPU) |
| Creds padrão | Nunca (apenas CPU) |
| `core/ml/banner_fingerprint.py` | Sim — fingerprinting de dispositivo via modelo transformer |
| `core/ml/advisor.py` | Sim — classificação de prioridade de módulo usando pontuação ML |
| `core/gpu/backend.py` | Sim — dispatcher de backend GPU para módulos ML |
| Estimador de entropia de fuzzing | Sim (hybrid: GPU para pontuação, CPU para entrega) |

Se nenhuma GPU estiver presente, todos os módulos ML voltam automaticamente para caminhos de CPU — são mais lentos, mas funcionalmente equivalentes.

---

[Hub da Wiki](../README.md)
