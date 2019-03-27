from TcpSession import TCPSession
from collections import defaultdict
from scapy.all import *
from time import sleep
import sys
import random

#class for TCP fuzzing
class TCPFuzzer(TCPSession):
	def __init__(self, src, dst, sport, dport):
		TCPSession.__init__(self, src, dst, sport, dport)
		self.defaultset = defaultdict(list)
		self.file_set = list()
		self.read_payload('default_payload.txt') # read default payload from file

	#build the test set for default run
	#if user specify a number to run, generate field value randomly
	#else generate field values as many as possible
	#use number to express value in the field, for example
	# range(2**32) means every possible value in a 32-bit range
	def build_default(self, number = None):
		if not number:
			for s in range(0, 2**32, 2**20): # 2**32 is too big.., generate less value
				self.defaultset['seq'].append(s)
			for a in range(0, 2**32, 2**20):
				self.defaultset['ack'].append(a)
			for f in range(0, 2**8):
				self.defaultset['flags'].append(f)
			for w in range(0, 2**16):
				self.defaultset['window'].append(w)
			for u in range(0, 2**16):
				self.defaultset['urgptr'].append(u)
			for d in range(2**4):
				self.defaultset['dataofs'].append(d)
			for r in range(0, 2**6):
				self.defaultset['reserved'].append(r)
		else:
			for i in range(number):
				self.defaultset['seq'].append(random.randint(0, 2**32))
				self.defaultset['ack'].append(random.randint(0, 2**32))
				self.defaultset['flags'].append(random.randint(0, 2**8))
				self.defaultset['window'].append(random.randint(0, 2**16))
				self.defaultset['urgptr'].append(random.randint(0, 2**16))
				self.defaultset['dataofs'].append(random.randint(0, 2**4))
				self.defaultset['reserved'].append(random.randint(0, 2**6))

	#default run
	#if user specify a field, fuzz that field
	#else fuzz all field
	#for each packet, establish a TCP session
	#after sending the fuzzing packet, close the session correctly
	def default_run(self, target_field = None, number = None):
		self.build_default(number)

		ip = IP(dst = self.dst)
		if target_field is None:
			for field, values in self.defaultset.items():
				tcp = TCP(sport = self.sport, dport = self.dport,flags = "PA", seq = self.seq, ack = self.ack)
				for val in values:
					self.connect()
					tcp.seq = self.seq
					tcp.ack = self.ack
					tcp.setfieldval(field, val)
					packet = ip/tcp/Raw(load = self.payload)
					self.send(packet, field, val)
		else:
			tcp = TCP(sport = self.sport, dport = self.dport,flags = "PA", seq = self.seq, ack = self.ack)
			for val in self.defaultset.get(target_field):
				self.connect()
				tcp.seq = self.seq
				tcp.ack = self.ack
				tcp.setfieldval(target_field, val)
				packet = ip/tcp/Raw(load = self.payload)
				self.send(packet, target_field, val)

	#send a fuzzing packet
	#if something wrong, we know a packet is invalid
	#then correctly close the session
	def send(self, packet, field = '{Multi fields}', val = '{multi values}'):
		if not self.connected:
			print("[-]TCP connect fail")
			return
		sleep(0.2)
		try:
			ans = sr1(packet, timeout = 0.1, verbose = 0)
		except:
			print("[-]INVALID value for field ({field}): {val}".format(field = field, val = str(val)))
			self.close()
		else:
			if not ans:
				print("[-]No response from server, value for field ({field}): {val}".format(field = field, val = str(val)))
				self.close()
			elif ans[TCP].ack != self.seq:
				print("[-]Received wrong ack, value for field ({field}): {val}".format(field = field, val = str(val)))
				self.close()
			else:
				self.close()

	#build test set from the file
	def build_tests_from_file(self, filename):
		tests = self.file_read_in(filename)
		if not tests:
			print("[-]ERROR: fail to read tests from file")
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

	#run those tests in file 
	def run_from_file(self,filename):
		self.build_tests_from_file(filename)
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
			packet = ip/tcp/Raw(load = self.payload)
			self.send(packet)



