from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
import sys
from time import sleep

class IPFuzzer(TCPSession):
	def __init__(self,src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		self.defaultset = defaultdict(list)
		# self.payload = "hello world"
		self.file_set = list()
		self.read_payload('default_payload.txt')

	# def send(self, IPpacket, field, val):
	# 	payload = self.payload + " " + field + " " + str(val)
	# 	packet = IPpacket/TCP(sport = self.sport, dport = self.dport, flags = 'PA', seq = self.seq, ack = self.ack)/payload
	# 	try:
	# 		# self.seq += len(packet[Raw])
	# 		ack = sr1(packet, timeout = 0.5, verbose = 0)
	# 	except:
	# 		print("[-]INVALID value for field ({field}): {val}".format(field = field, val = str(val)))
	# 		return
	# 	else:
	# 		if not ack:
	# 			print("[-]no response, value for field ({field}): {val}".format(field = field, val = str(val)))
	# 			return 
	# 			# self.restart()
	# 			# return

	# 		self.seq += len(packet[Raw])

	# 		# print("seq num is " + str(self.seq))

	# 		if ack[TCP].ack != self.seq:
	# 			print('INVALID ACK value' + str(ack[TCP].ack))

	def send(self, IPpacket, field = '{multi field}', val = '{mulit values}'):
		# payload = self.payload + " " + field + " " + str(val)
		packet = IPpacket/TCP(sport = self.sport, dport = self.dport, flags = "A")/self.payload
		try:
			ans = sr1(packet, timeout = 0.5, verbose = 0)
		except Exception as e:
			print(e)
			print("[-]INVALID value for field ({field}): {val}".format(field = field, val = str(val)))
			return 
		else:
			if not ans:
				print("[-]no response value for field ({field}): {val}".format(field = field, val = str(val)))
				return
			if ans and ans.haslayer(TCP) and ans[TCP].flags == 'R':
				print("[+]VALID value for field ({field}): {val}".format(field = field, val = str(val)))



	def default_run(self, target_field = None):
		print("default fuzzing for IP layer")
		
		self.build_defaultset()
		if target_field is None:
			for field, values in self.defaultset.items():
				for val in values:
					packet = IP(dst = self.dst)
					packet.setfieldval(field, val)
					self.send(packet, field, val)
					try:
						sleep(0.1)
					except KeyboardInterrupt:
						print("[*]Terminated!")
						sys.exit(0)
		else:
			for val in self.defaultset.get(target_field):
				packet = IP(dst = self.dst)
				packet.setfieldval(target_field, val)
				self.send(packet, target_field, val)
				try:
					sleep(0.1)
				except KeyboardInterrupt:
					print("[*]Terminated!")
					sys.exit(0)



		

	def build_defaultset(self):
		for v in range(2**4):
			# self.defaultset['version'].append(IP(version = v))
			self.defaultset['version'].append(v)
		for ihl in range(2**4):
			# self.defaultset['ihl'].append(IP(ihl = ihl))
			self.defaultset['ihl'].append(ihl)
		for tos in range(2**8):
			# self.defaultset['tos'].append(IP(tos = tos))
			self.defaultset['tos'].append(tos)
		for length in range(0, 2**16, 2**6):
			# self.defaultset['len'].append(IP(len = length))
			self.defaultset['len'].append(length)
		for idnum in range(0, 2**16, 2**6):
			self.defaultset['id'].append(idnum)
			# self.defaultset['id'].append(IP(id = idnum))
		for flag in range(2**3):
			self.defaultset['flags'].append(flag)
			# self.defaultset['flags'].append(IP(flags = flag))
		for frag in range(0, 2**13, 2**5):
			self.defaultset['frag'].append(frag)
			# self.defaultset['frag'].append(IP(frag = frag))
		for ttl in range(2**8):
			self.defaultset['ttl'].append(ttl)
			# self.defaultset['ttl'].append(IP(ttl = ttl))
		for pro in range(2**8):
			self.defaultset['proto'].append(pro)
			# self.defaultset['proto'].append(IP(proto = pro))

	def check_field_val(self, field, val):
		pass

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

	def run_from_file(self, filename):
		self.build_tests_from_file(filename)

		for test in self.file_set:
			packet = IP(dst = self.dst)
			for fv in test:
				packet.setfieldval(fv[0], fv[1])
			self.send(packet)
			print("packet sent")
			# try:
			sleep(0.2)
			# except KeyboardInterrupt:
			# 	print("[*]Terminated!")
			# 	sys.exit(0)




if __name__ == "__main__":
	src_ip = "10.0.2.15"
	# dst_ip = "52.14.181.116"
	dst_ip = "192.168.0.26"
	# dst_ip = "129.236.238.135"
	# dport = 80
	dport = 9998
	sport = 7890
	print("[*]Begin IPFuzzer, presss CTRL-C to terminate")
	try:
		fuzzer = IPFuzzer(src_ip, dst_ip, sport, dport)
		fuzzer.default_run()
	except KeyboardInterrupt:
		print("[*]Terminated!")
		sys.exit(0)








