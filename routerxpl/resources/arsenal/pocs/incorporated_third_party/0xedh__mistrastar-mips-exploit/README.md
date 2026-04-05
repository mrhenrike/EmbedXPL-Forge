<h1 align="center">
  <br>Mitrastar MIPS router, reversing and exploitaition</br>
</h1>

<h3 align="center">
Analysis of a widely used SOHO router
</h3>

<p align="center">
  <strong>
  <a href="https://asciinema.org/a/UDZsP7ISimZkKyI8C4DkpYrye">
    POC
  </a>,
  <a href="https://twitter.com/0xedh">
    Twitter
  </a>,
  <a href="https://pax0r.com/">
    Pax0r
  </a>
  </strong>
</p>

<p align="center">
  <a href="https://asciinema.org/a/UDZsP7ISimZkKyI8C4DkpYrye">
    <img src="https://user-images.githubusercontent.com/50701542/118243530-d49fb180-b49e-11eb-9a60-d0b45918c5a1.png" width="700" />
  </a>
</p>

## Contents index

- [Why](#Why)
- [Firmware analysis](#Firmware)
    - [Firmware layout and modification](#Layout)
- [Exploitation](#Exploitation)
    - [ROP chain](#ROP)
- [Summary](#Summary)

## Why

A few moths ago my ISP charged me what I consider a lot of money for a "Broadcom" Mitrastar router I couldn't return. So, let's have some fun with it at least! My goal was to obtain root access to the router with the newest firmware image and look for some memory bugs that could lead to RCE.

## Firmware

My first approach was the typical one, open the device and look for some test pins in order to find UART, JTAG or something useful to interact with our device. After finding the UART pins and connect to them, we have an unlocked CFE bootloader:

```
*** Press any key to stop auto run (1 seconds) ***
Auto run second count down: 1
web info: Waiting for connection on socket 0.

CFE>
Available commands: ATSE, ATEN, ATSH, um, m, ATBL, ATDU, ATBR, ATGO, ATSR, ATMB, ATHE

CFE>

```

I didn't figure out how to dump the NAND flash without "dn" command available. I can't flash a new bootloader either without "r" command. Another option is to unsolder the flash and try to dump the firmware out of the board, but after read some string with ATDU command I tried another approach.

```
Creating 9 MTD partitions on "brcmnand.0":
0x000003260000-0x000006260000 : "rootfs"
0x000000040000-0x000003240000 : "rootfs_update"
0x000007b00000-0x000007f00000 : "data"
0x000000000000-0x000000020000 : "nvram"
0x000003240000-0x000006260000 : "image"
0x000000020000-0x000003240000 : "image_update"
0x000006260000-0x000007900000 : "app"
0x000007900000-0x000007a00000 : "usrcfg"
0x000007a00000-0x000007b00000 : "cfg_upgrade"
```

Why not just install a vulnerable firmware version (<a href="https://www.exploit-db.com/exploits/43061">this one</a>), get a root shell and, after that, force a firmware upgrade and grab the new firmware image? There's no need to wait for TR-069 on 7547 if you force a firmware upgrade via the reset button. So after grabbing a compiled MIPS tcpdump bin and force the upgrade a few times, I catched a fresh firmware image requested to the ISP's CDN:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/118468831-70caf200-b705-11eb-9de6-eb1d9afc0737.png" width="700" />
</p>

I am not interested in researching an old firmware version, so the next steps were to modify this fresh firmware image into one that can give us a root shell and then look for some vulnerabilities in the up to date firmware. As far as I know, there aren't known bugs or ways to execute arbitrary commands as root in newest firmware versions.

## Layout

Let's take a look at the firmware with binwalk:

```
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
131072        0x20000         Squashfs filesystem, little endian, version 4.0, compression:xz, size: 22454151 bytes, 1342 inodes, blocksize: 131072 bytes, created: 2020-05-04 05:10:56
22585356      0x158A00C       LZMA compressed data, properties: 0x6D, dictionary size: 4194304 bytes, uncompressed size: 4588512 bytes
```

After manual analysis I found the firmware was composed of:

- BCM tag header from 0 to 0x20000
- Squashfs filesystem from 0x20000 to 0x158a000
- Kernel preceded by code address and entry address from 0x158a000 to end.

When the firmware update process starts, there were some CRC checks before the image is accepted and some checks after the first boot to ensure the kernel and image CRC is correct. Our modified firmware needs to pass both checks in order to work, or the router will switch to a previous validated image.

Some of those CRC checks are in the BCM tag header (0-0x20000), I have uploaded to this repository a modified version of an analyze tag program who works with this specific firmware image. In order to pass the CRC checks, we need to modify the following values in BCM tag header:

- Rootfs CRC
- Kernel CRC
- Image CRC
- Header CRC

Let's take a look at the BCM tag hexdump to clarify:

```
00000000  36 00 00 00 4d 53 54 43  5f 61 30 30 31 00 00 00  |6...MSTC_a001...|
00000010  00 00 00 00 00 00 00 00  76 65 72 2e 20 32 2e 30  |........ver. 2.0|
00000020  00 00 00 00 00 00 36 38  33 38 00 00 47 50 54 2d  |......6838..GPT-|
00000030  32 35 34 31 47 4e 41 43  00 00 00 00 31 00 32 33  |2541GNAC....1.23|
00000040  39 37 37 34 33 34 00 00  30 00 00 00 00 00 00 00  |977434..0.......|
00000050  00 00 00 00 30 00 00 00  00 00 00 00 00 00 33 32  |....0.........32|
00000060  31 37 32 39 33 33 31 32  00 00 32 32 34 35 34 32  |17293312..224542|
00000070  37 32 00 00 33 32 33 39  37 34 37 35 38 34 00 00  |72..3239747584..|
00000080  31 35 32 33 31 36 32 00  00 00 00 00 00 00 31 30  |1523162.......10|
00000090  30 56 4e 4a 30 62 31 00  00 00 00 00 00 00 00 00  |0VNJ0b1.........|
000000a0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 45 53  |..............ES|
000000b0  5f 67 33 2e 35 5f 31 30  30 56 4e 4a 30 62 35 34  |_g3.5_100VNJ0b54|
000000c0  5f 37 5f 43 41 00 00 00  00 00 00 00 00 00 00 00  |_7_CA...........|
000000d0  00 00 00 00 00 00 00 00  **2c b2 12 e3** **98 d1 b9 d5**  |........,.......|
000000e0  **9e db b0 36** 00 00 00 00  00 00 00 00 **34 68 8c 0b**  |...6........4h..|
000000f0  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000100  ff ff ff ff ff ff ff ff  ff ff ff ff ff ff ff ff  |................|
*
00020000

```

In this occasion, Kernel CRC is 9edbb036, Rootfs CRC is 98d1b9d5, Image CRC is 2cb212e3 and Header CRC is 34688c0b. When we modify the firmware, we need to set up the new calculated CRC values at those positions, ending with Header CRC value.

At this point, to obtain a root shell is easy. I used unsquashfs and mksquashfs version 4.4 (with xz support) and modified inittab to "unjail" us from "consoled" program:

```
cat /etc/inittab
# See examples/inittab for full description of fields.
# This file contains customizations for the Broadcom CPE Router SDK

# "bcm_boot_launcher start" will execute all scripts in /etc/rc3.d starting
# with letter S in lexicographical order
::sysinit:/bin/sh -l -c "bcm_boot_launcher start"

# if you don't want to type username/passwd in console login, copy this
# file to inittab.custom and replace "-/bin/sh -l -c consoled" below with "-/bin/sh"
# The '-' means interactive, is still attached to terminal
# Remove '-l -c consoled'
::respawn:-/bin/sh -l -c consoled

# Currently, there are no scripts for shutdown
::shutdown:/bin/sh -l -c "bcm_boot_launcher stop"
```

After the desired modifications, make the squashfs filesystem again, append the Kernel at the end of it and the BCM tag header at the start. Then, modify the CRC values, ending with Header CRC. I wrote a dirty bash script to automatize this process, DM me if you need it.

If now we let the system start without interrupt it and we connect through UART, we'll have a root shell in latest firmware version:

```
# ls  QTN bootup done. qtnModuleInitCheckCnt = 0/10
/etc
getMiniBootCalstate@211: read calstate =3  from =/var/qtn_mini_boot_calstate===

GPT-2541GNAC-TEF            profile
adsl                        protocols
appwatchdog.sh              psk.txt
arl                         qharvestd.conf
cms_entity_info.d           qharvestdwatchdog.sh
csmd.json                   racoon.conf
default.cfg                 radvd.conf.sample
dhcp                        rc3.d
dhcp6c.conf.sample          rdpa_common_filter_init.sh
dhcp6s.conf.sample          rdpa_common_init.sh
dms.conf                    rdpa_gpon_init.sh
dyndscp.sh                  re_test.sh
ethertypes                  resolv.conf
extra_func.sh               rmt_ip.conf
filesystems                 rsa_host_key
fstab                       samba
fstab.squashfs              services
gateway.conf                sftp_download.sh
group                       sftp_update.sh
hosts                       shgw
init.d                      shgwrestart.sh
inittab                     smt.cfg
iproute2                    snmp
ipsec.conf                  soft_bridge
ipv6_start.sample           sskwatchdog.sh
mdk                         start_soniq.sh
mfg25                       sysconfig
mfg6                        syslog-ng.conf
mini5g.sh                   sysmsg
miniboot.sh                 udhcpd.conf
minifw_version              udhcpd.leases
mtab                        vlan
passwd                      wlan
ppp                         wrt54g.large.ico
pppmsg                      wrt54g.small.ico
prbs.sh
#
```

## Exploitation

A stack-based buffer overflow exists in libcms_cli.so "passwd" functionality:

<p align="center">
    <img src="https://user-images.githubusercontent.com/50701542/118489382-0f168200-b71d-11eb-92bd-0c08f92ed4e4.png" width="700" />
</p>

I'm sure there are more vulnerabilities in this router, but this is a good start in my opinion. We're dealing with ASLR and NX, so we need to build a ROP-chain and, due to the fact I didn't found a memory leak yet, we can bruteforce libc.so base address because ASLR protection. In the worst scenario we need to perform about 8000 tries to successfully guess where the libc base address is. As only the child and not the parent process is terminating after segfault when connecting via SSH, in the worst scenario this will take a few hours, but it's working. After achieve RCE you can modify whatever you want, outside of the read-only filesystem, in order to gain a more reliable shell access. A working POC was uploaded to this repository.

```
>
> passwd
Username: aaaa
Password: unrecognized username #python -c "print('A'*250)"| xclip -sel clip

Segmentation fault (core dumped)
#
```

## ROP

In this occasion, I used the following gadgets to call libc.so system() function:

- Libc base address + 0x0005a380 = libc.so system()

- Libc base address + 0x63338 = libc.so '/bin/sh'

- Gadget 1. Libc base address + 0x00038834 = addiu $a0, $sp, 0x20 ; lw $ra, 0x64($sp) ; move $v0, $s2 ; lw $s3, 0x60($sp) ; lw $s2, 0x5c($sp) ; lw $s1, 0x58($sp) ; lw $s0, 0x54($sp) ; jr $ra ; addiu $sp, $sp, 0x68

- Gadget 2. Libc base address + 0x0001f654 = move $t9, $s2 ; jalr $t9 ; move $a1, $s0

To summarize, to call system with '/bin/sh' argument we need to:

- Send 116 bytes of junk.

- Send address of Gagdet 1. Gadget 1 is at $ra / $pc +8.

- Send address of libc.so '/bin/sh', 23 times (yes, I'm lazy) for a total of 92 bytes.

- Send address of libc.so system() function. We want libc.so system() at $s2.

- Send 4 bytes of junk. In the exploit in the repository I set a random address I was testing.

- Send address of Gadget 2.

When Gadget 1 is called, it sets libc.so system() at $s2, Gadget 2 at $ra and libc.so '/bin/sh' at $s3, although system()'s argument will be taken from stack later when system() is called. Then, Gadget 2 takes system() from $s2 to $t9 and calls it with '/bin/sh' argument. After this, we can send the command we want to execute in the router.

## Summary

It is well known that IOT devices and SOHO routers security is far from being ideal as we have seen in the last years. I have the feeling that other vulnerabilities can easily be found in this router model. It's been fun analyzing the device for a while! If you need additional information or you have found others vulnerabilities feel free to contact me. Any improvements are welcome, see you soon.
