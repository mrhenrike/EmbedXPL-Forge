<h3 align="left">
    <img src="https://github.com/enty8080/HatAsm/blob/main/data/logo.png" alt="logo" height="250px">
</h3>

[![Developer](https://img.shields.io/badge/developer-EntySec-blue.svg)](https://entysec.com)
[![Language](https://img.shields.io/badge/language-Python-blue.svg)](https://github.com/EntySec/HatAsm)
[![Forks](https://img.shields.io/github/forks/EntySec/HatAsm?style=flat&color=green)](https://github.com/EntySec/HatAsm/forks)
[![Stars](https://img.shields.io/github/stars/EntySec/HatAsm?style=flat&color=yellow)](https://github.com/EntySec/HatAsm/stargazers)
[![CodeFactor](https://www.codefactor.io/repository/github/EntySec/HatAsm/badge)](https://www.codefactor.io/repository/github/EntySec/HatAsm)

HatAsm is a powerful assembler and disassembler that provides support for all common architectures.

## Features

* Assembler and disassembler both available in one tool.
* Support for most common architectures (e.g **x64**, **x86**, **aarch64**, **armle**, **mipsle**, **mipsbe**, etc).
* Ability to assemble code right into the byte code or pack into an executable (e.g. **ELF**, **Mach-O**, **PE**).

## Installation

```shell
pip3 install git+https://github.com/EntySec/HatAsm
```

## Examples

### Assemble

```python3
from hatasm import HatAsm

hatasm = HatAsm()
code = """
start:
    mov al, 0xa2
    syscall

    mov al, 0xa9
    mov edx, 0x1234567
    mov esi, 0x28121969
    mov edi, 0xfee1dead
    syscall
"""

result = hatasm.assemble('x64', code)

for line in hatasm.hexdump(result):
    print(line)
```

<details>
    <summary>Result</summary><br>
    <pre>
00000000  b0 a2 0f 05 b0 a9 ba 67  45 23 01 be 69 19 12 28 |.......gE#..i..(|
00000010  bf ad de e1 fe 0f 05                             |.......         |</pre>
</details>

## Disassemble

```python3
from hatasm import HatAsm

hatasm = HatAsm()
code = (
    b"\xb0\xa2\x0f\x05\xb0\xa9\xba\x67\x45\x23\x01\xbe"
    b"\x69\x19\x12\x28\xbf\xad\xde\xe1\xfe\x0f\x05"
)

for line in hatasm.disassemble('x64', code):
    print(line.mnemonic, line.op_str)
```

<details>
    <summary>Result</summary><br>
    <pre>
mov al, 0a2h
syscall
mov al, 0a9h
mov edx, 1234567h
mov esi, 28121969h
mov edi, 0fee1deadh
syscall</pre>
</details>

## HatAsm CLI

HatAsm also has its own command line interface that can be invoked by executing `hatasm` command:

```
usage: hatasm [-h] [--arch ARCH] [--mode MODE] [--syntax SYNTAX] [-i INPUT]
              [-o OUTPUT] [-a] [-d] [-e] [-f FORMAT] [--formats]

HatAsm is a powerful assembler and disassembler that provides support for all
common architectures.

options:
  -h, --help            show this help message and exit
  --arch ARCH           Architecture to assemble or disassemble for.
  --mode MODE           Architecture mode (for example - arm/thumb).
  --syntax SYNTAX       Assembler/Disassembler syntax (for example -
                        intel/att).
  -i INPUT, --input INPUT
                        Input file for assembler or disassembler.
  -o OUTPUT, --output OUTPUT
                        Output file to write output.
  -a, --assemble        Launch HatAsm assembler.
  -d, --disassemble     Launch HatAsm disassembler.
  -e, --emulate         Emulate assembled code (use with -a).
  -f FORMAT, --format FORMAT
                        Output file format (e.g. elf, macho, pe).
  --formats             Display all available formats.
  
```

### Examples

```
hatasm -a --arch x64
```

Run interactive assembler shell for **x64** architecture.

```
[hatasm]> nop
00000000  90                                               |.               |
[hatasm]> start:
........     xor rax, rax
........     cdq
........     nop
........     
00000000  48 31 c0 99 90                                   |H1...           |
[hatasm]>
```

Write macOS **x64** execve() /bin/sh shellcode from command-line.

```
[hatasm]> start:
........     xor rax, rax
........     cdq
........     push rax
........     mov rdi, 0x68732f6e69622f2f
........     push rdi
........     push rsp
........     pop rdi
........     xor rsi, rsi
........     mov al, 0x2
........     ror rax, 0x28
........     mov al, 0x3b
........     syscall
........
00000000  48 31 c0 99 50 48 bf 2f  2f 62 69 6e 2f 73 68 57 |H1..PH.//bin/shW|
00000010  54 5f 48 31 f6 b0 02 48  c1 c8 28 b0 3b 0f 05    |T_H1...H..(.;.. |
[hatasm]>
```

Use `.start` and `.end` to assemble full block of code:

```
[hatasm]> .start
[0x10000000]> start:
..............    cdq
..............    nop
..............
[0x10000002]> string:
..............    .asciz "/bin/sh"
..............
[0x1000000a]> .end
00000000  99 90 2f 62 69 6e 2f 73 68 00                   |../bin/sh.      |
[hatasm]>
```
