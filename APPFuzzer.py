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
		self.valid = 0
		self.invalid = 0


	def build_default(self):
		for i in range(100):
			# payload = "\x00"* random.randint(0,9) + "\x33"
			payload = 'a'*random.randint(0,5) + 'b'
			payload = bytes(payload, encoding = 'utf-8')
			self.defaultset.append(payload)


	def default_run(self):
		self.build_default()

		self.connect()
		for p in self.defaultset:
			sleep(0.5)
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
		



if __name__ == '__main__':
	src_ip = "10.0.2.15"
	dst_ip = "192.168.0.26"
	# dst_ip = "129.236.238.135"
	dport = 9998
	sport = 7890
	print("[*]Begin APPFuzzer, presss CTRL-C to terminate")
	try:
		fuzzer = APPFuzzer(src_ip, dst_ip, sport, dport)
		fuzzer.default_run()
		print("[+]Finished, {valid} valid, {invalid} invalid".format(valid = fuzzer.valid, invalid = fuzzer.invalid))
	except KeyboardInterrupt:
		fuzzer.close()
		sleep(0.5)
		print("[*]Terminated!")
		sys.exit(0)


