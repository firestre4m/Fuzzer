from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
import sys
from time import sleep

#class for IP fuzzing
class IPFuzzer(TCPSession):
	def __init__(self,src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		self.defaultset = defaultdict(list)
		self.file_set = list()
		self.read_payload('default_payload.txt')

	#func to send a packet
	#invalid packet will never reach transport
	#so if we receive a RST tcp response, that means ip packet is valid
	def send(self, IPpacket, field = '{multi field}', val = '{multi values}'):
		packet = IPpacket/TCP(sport = self.sport, dport = self.dport, flags = "A")/self.payload
		try:
			ans = sr1(packet, timeout = 0.5, verbose = 0)
		except Exception:
			print("[-]INVALID value for field ({field}): {val}".format(field = field, val = str(val)))
			return 
		else:
			if not ans:
				print("[-]No response value for field ({field}): {val}".format(field = field, val = str(val)))
				return
			if ans and ans.haslayer(TCP) and ans[TCP].flags == 'R':
				print("[+]VALID value for field ({field}): {val}".format(field = field, val = str(val)))


	#default run
	#if user specify a field, fuzz that field
	#else fuzz all field
	def default_run(self, target_field = None, number = None):
		print("default fuzzing for IP layer")
		
		self.build_defaultset(number)

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

		
	#build the test set for default run
	#if user specify a number to run, generate field value randomly
	#else generate field values as many as possible
	#use number to express value in the field, for example
	# range(2**4) means every possible value in a 4-bit range
	def build_defaultset(self, number = None):
		if number is None:
			for v in range(2**4):
				self.defaultset['version'].append(v)
			for ihl in range(2**4):
				self.defaultset['ihl'].append(ihl)
			for tos in range(2**8):
				self.defaultset['tos'].append(tos)
			for length in range(0, 2**16):
				self.defaultset['len'].append(length)
			for idnum in range(0, 2**16):
				self.defaultset['id'].append(idnum)
			for flag in range(2**3):
				self.defaultset['flags'].append(flag)
			for frag in range(0, 2**13):
				self.defaultset['frag'].append(frag)
			for ttl in range(2**8):
				self.defaultset['ttl'].append(ttl)
			for pro in range(2**8):
				self.defaultset['proto'].append(pro)
		else:
			for i in range(number):
				self.defaultset['version'].append(random.randint(0, 2**4))
				self.defaultset['ihl'].append(random.randint(0, 2**4))
				self.defaultset['tos'].append(random.randint(0, 2**8))
				self.defaultset['len'].append(random.randint(0, 2**16))
				self.defaultset['id'].append(random.randint(0, 2**16))
				self.defaultset['flags'].append(random.randint(0, 2**3))
				self.defaultset['frag'].append(random.randint(0, 2**13))
				self.defaultset['ttl'].append(random.randint(0, 2**8))
				self.defaultset['proto'].append(random.randint(0, 2**8))



	#build test set from a txt file
	def build_tests_from_file(self, filename):
		tests = self.file_read_in(filename)
		if not tests:
			print("[-]ERROR:fail to read tests from file")
			sys.exit(0)
		for line in tests:
			try:
				one_entry = line.strip().replace(' ', '').split(',')
				one_test = list()
				for fv in one_entry:
					field = fv.split(':')[0]
					val_s = fv.split(':')[1]
					val = int(val_s, 16)
					one_test.append((field, val))
				self.file_set.append(one_test)
			except ValueError as e:
				print('[-]ERROR:', end = ' ')
				print(e)
				print('Please check your file')
				sys.exit(-1)
			except:
				print("Please follow the format requirement, see sample file")
				sys.exit(-1)

	#run those tests that come from the file
	def run_from_file(self, filename):
		self.build_tests_from_file(filename)

		for test in self.file_set:
			packet = IP(dst = self.dst)
			for fv in test:
				packet.setfieldval(fv[0], fv[1])
			self.send(packet)
			print("packet sent")
			sleep(0.2)

