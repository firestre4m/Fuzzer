from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
from time import sleep
import sys

class APPFuzzer(TCPSession):
	def __init__(self, src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		# self.defaultset = defaultdict(list)
		self.defaultset = list()
		self.file_set = list()
		self.valid = 0
		self.invalid = 0


	def build_default(self, number, size):
		
		if isinstance(size, int):
			for i in range(number):
				payload = b''
				for j in range(size):
					payload += bytes([random.randint(0, 255)])
				# payload = 'a'*size
				# payload = bytes(payload, encoding = 'utf-8')
				self.defaultset.append(payload)

		elif isinstance(size, tuple):
			for i in range(number):
				payload = b''
				s = random.randint(size[0],size[1])
				for j in range(s):
					payload += bytes([random.randint(0, 255)])
				# payload = "\x00"* random.randint(0,9) + "\x33"
				# payload = 'a'*random.randint(size[0],size[1])
				# payload = bytes(payload, encoding = 'utf-8')
				self.defaultset.append(payload)


	def default_run(self, number, size):
		self.build_default(number, size)

		self.connect()
		for p in self.defaultset:
			sleep(0.5)
			print("[+] Sending payload:", end = ' ')
			print(p)
			self.send(p)
			# print(ans)
		self.close()

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
	
	def build_tests_from_file(self, filename):
		tests = self.file_read_in(filename)
		if not tests:
			print("fail to read tests from file")
			sys.exit(0)
		for line in tests:
			line = line.strip().replace(' ', '')
			if not line: continue
			if len(line) > 2000:
				print("payload is too long: {p}".format(p = line))
				sys.exit(-1)
			try:
				byte_seq = bytes.fromhex(line)
			except:
				print("wrong format in the file")
				sys.exit(0)
			else:
				self.file_set.append(byte_seq)

	def run_from_file(self, filename):
		self.build_tests_from_file(filename)
		self.connect()
		for p in self.file_set:
			sleep(0.5)
			print("[+] Sending payload:", end = ' ')
			print(p)
			self.send(p)
		self.close()


if __name__ == '__main__':
	src_ip = "10.0.2.15"
	dst_ip = "192.168.0.26"
	# dst_ip = "129.236.238.135"
	dport = 9999
	sport = 7890
	print("[*]Begin APPFuzzer, presss CTRL-C to terminate")
	try:
		fuzzer = APPFuzzer(src_ip, dst_ip, sport, dport)
		fuzzer.default_run(10, 5)
		print("[+]Finished, {valid} valid, {invalid} invalid".format(valid = fuzzer.valid, invalid = fuzzer.invalid))
	except KeyboardInterrupt:
		fuzzer.close()
		sleep(0.5)
		print("[*]Terminated!")
		sys.exit(0)


