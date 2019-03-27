from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
from time import sleep
import sys

#class for APP fuzzing
class APPFuzzer(TCPSession):
	def __init__(self, src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		self.defaultset = list()
		self.file_set = list()
		self.valid = 0
		self.invalid = 0

	#build default test set
	#the number of tests can be specified by user
	#size can be a int, it means the payload size is fixed
	#size can be a tuple, means the range of the payload size
	#each byte in payload will be generated randomly
	def build_default(self, number, size):
		#fixed size paylaod
		if isinstance(size, int):
			for i in range(number):
				payload = b''
				for j in range(size):
					payload += bytes([random.randint(0, 255)])
				self.defaultset.append(payload)
		#variable size payload
		elif isinstance(size, tuple):
			for i in range(number):
				payload = b''
				s = random.randint(size[0],size[1])
				for j in range(s):
					payload += bytes([random.randint(0, 255)])
				self.defaultset.append(payload)

	#fuzzing using default set
	#establish a session before sending payload
	#finally close the session correctly
	def default_run(self, number, size):
		self.build_default(number, size)

		self.connect()
		for p in self.defaultset:
			sleep(0.5)
			print("[+] Sending payload:", end = ' ')
			print(p)
			self.send(p)
		self.close()

	#overwrite ack func in TCPSession class
	#process server's response 0x00 or 0xff to update counts
	#send ack to server
	def _ack(self, p):
		self.ack = p[TCP].seq + len(p[Raw].load)
		self.seq = p[TCP].ack
		resp = p[Raw].load
		if resp == b'\x00':
			self.valid += 1
		if resp == b'\xff':
			self.invalid += 1
		ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
		send(ack, verbose = 0)
	
	#generate test set from file
	def build_tests_from_file(self, filename):
		tests = self.file_read_in(filename)
		if not tests:
			print("fail to read tests from file")
			sys.exit(0)
		for line in tests:
			line = line.strip().replace(' ', '')
			if not line: continue
			if len(line) > 2000: #len of payload shouldn't be larger than 1000 bytes
				print("[-]Payload is too long: {p}".format(p = line))
				sys.exit(-1)
			try:
				byte_seq = bytes.fromhex(line)
			except:
				print("[-]ERROR: wrong format in the file")
				sys.exit(0)
			else:
				self.file_set.append(byte_seq)

	#fuzz using payload from file
	def run_from_file(self, filename):
		self.build_tests_from_file(filename)
		self.connect()
		for p in self.file_set:
			sleep(0.5)
			print("[+] Sending payload:", end = ' ')
			print(p)
			self.send(p)
		self.close()



