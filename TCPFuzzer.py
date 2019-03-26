from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
from time import sleep
import sys

class TCPFuzzer(TCPSession):
	def __init__(self, src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		# self.payload = "hello world"
		self.defaultset = defaultdict(list)
		self.file_set = list()
		self.read_payload('default_payload.txt')

	def build_default(self):
		# self.defaultset['seq'].append(self.seq)
		# self.defaultset['seq'].append(1000)
		# self.defaultset['seq'].append(2000)
		# self.defaultset['ack'].append(1000)
		for s in range(0, 2**32, 2**28):
			self.defaultset['seq'].append(s)
		for a in range(0, 2**32, 2**20):
			self.defaultset['ack'].append(a)
		for f in range(0, 2**8):
			self.defaultset['flags'].append(f)
		for w in range(0, 2**16, 2**14):
			self.defaultset['window'].append(w)
		for u in range(0, 2**16, 2**14):
			self.defaultset['urgptr'].append(u)
		for d in range(2**4):
			self.defaultset['dataofs'].append(d)
		for r in range(0, 2**6, 2**2):
			self.defaultset['reserved'].append(r)

		#dataofs, reserved, options

	def default_run(self, target_field = None):
		self.build_default()

		ip = IP(dst = self.dst)
		if target_field is None:
			for field, values in self.defaultset.items():
				tcp = TCP(sport = self.sport, dport = self.dport,flags = "PA", seq = self.seq, ack = self.ack)
				for val in values:
					self.connect()
					tcp.seq = self.seq
					tcp.ack = self.ack
					tcp.setfieldval(field, val)
					# payload = b'aaa'
					packet = ip/tcp/Raw(load = self.payload)
					# print(packet[TCP].ack) 
					self.send(packet, field, val)
		else:
			tcp = TCP(sport = self.sport, dport = self.dport,flags = "PA", seq = self.seq, ack = self.ack)
			for val in self.defaultset.get(target_field):
				self.connect()
				tcp.seq = self.seq
				tcp.ack = self.ack
				tcp.setfieldval(target_field, val)
				# payload = b'aaa'
				packet = ip/tcp/Raw(load = self.payload)
				# print(packet[TCP].ack) 
				self.send(packet, target_field, val)


	def send(self, packet, field = '{Multi fields}', val = '{multi values}'):
		# self.connect()
		if not self.connected:
			print("[-]TCP connect fail")
			return
		# try:
		sleep(0.2)
		# except KeyboardInterrupt:
		# 	self.close()
		# 	print("[*]Terminated!")
		# 	sys.exit(0)
		try:
			ans = sr1(packet, timeout = 0.1, verbose = 0)
			# self.seq += len(packet[Raw])

		except:
			print("[-]INVALID value for field ({field}): {val}".format(field = field, val = str(val)))
			self.close()
		else:
			if not ans:
				print("[-]something wrong, value for field ({field}): {val}".format(field = field, val = str(val)))
				self.close()
			elif ans[TCP].ack != self.seq:
				print("[-]received wrong ack, value for field ({field}): {val}".format(field = field, val = str(val)))
				self.close()
			else:
				# self.seq += len(packet[Raw])
				self.close()

	def build_tests_from_file(self, filename):
		tests = self.file_read_in(filename)
		if not tests:
			print("fail to read tests from file")
			sys.exit(0)
		for line in tests:
			try:
				one_entry = line.strip().replace(' ', '').split(',')
				one_test = list()
				for fv in one_entry:
					field = fv.split(':')[0]
					val_s = fv.split(':')[1]
					val = int(val_s, 16)
					# print(field + ":", end = ' ')
					# print(val)
					one_test.append((field, val))
				self.file_set.append(one_test)
			except ValueError as e:
				# print("Some values are wrong in the file")
				print('[-]ERROR:', end = ' ')
				print(e)
				print('Please check your file')
				sys.exit(-1)
			except:
				print("Please follow the format requirement, see sample file")
				sys.exit(-1)

	def run_from_file(self,filename):
		self.build_tests_from_file(filename)
		# for t in self.file_set:
		# 	print(t)
		ip = IP(dst = self.dst)
		for test in self.file_set:
			tcp = TCP(sport = self.sport, dport = self.dport,flags = "PA", seq = self.seq, ack = self.ack)
			self.connect()
			tcp.seq = self.seq
			tcp.ack = self.ack
			for fv in test:
				field = fv[0]
				val = fv[1]
				tcp.setfieldval(field, val)
			# payload = b'aaa'
			packet = ip/tcp/Raw(load = self.payload)
			self.send(packet)


if __name__ == '__main__':
	src_ip = "10.0.2.15"
	dst_ip = "192.168.0.26"
	# dst_ip = "129.236.238.135"
	dport = 9999
	sport = 7890
	print("[*]Begin TCPFuzzer, presss CTRL-C to terminate")
	try:
		fuzzer = TCPFuzzer(src_ip, dst_ip, sport, dport)
		fuzzer.default_run()
	except KeyboardInterrupt:
		fuzzer.close()
		sleep(0.2)
		print("[*]Terminated!")
		sys.exit(0)





