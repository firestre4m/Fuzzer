from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
import sys
from time import sleep

class IPFuzzer(TCPSession):
	def __init__(self,src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		self.defaultset = defaultdict(list)
		self.payload = "hello world"

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

	def send(self, IPpacket, field, val):
		payload = self.payload + " " + field + " " + str(val)
		packet = IPpacket/TCP(sport = self.sport, dport = self.dport, flags = "A")
		try:
			ans = sr1(packet, timeout = 0.5, verbose = 0)
		except:
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

	def parse_file(self, filename):
		lines = self.file_read_in(filename)
		if not lines:
			print("empty tests")
			return
		for line in lines:
			onetest = line.split()
			for fv in onetest:
				field = fv.split(":")[0]
				val = int(fv.split(":")[1])
				if check_field_val(field, val):
					pass




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








