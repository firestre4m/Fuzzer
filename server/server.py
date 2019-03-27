from socketserver import BaseRequestHandler, TCPServer
import sys
import re
import argparse

#handler class 
class EchoHandler(BaseRequestHandler):

	#this function will be called when a new connection come in
	#check the received payload, reponse with 0x00 if payload match pattern, 
	#else respons with 0xff
	#In the mean time, maintain the valid and invalid counts for every sigle connection
	def handle(self):
		print('Got new connection from', self.client_address)
		self.server.valid_count = 0
		self.server.invalid_count = 0
		while True:
			msg = self.request.recv(8192)
			
			if not msg:
				if self.server.valid_count or self.server.invalid_count:
					print("Totally {valid} valid, {invalid} invalid ".format(valid=str(self.server.valid_count), invalid = str(self.server.invalid_count)))
				else:
					print("Packet has been dropped at transport layer")
				break

			if self.validate(msg):
				self.server.valid_count += 1
				print("valid msg", end = ' ')
				print(msg, end = ' ')
				print(self.server.valid_count)
				self.request.send(b'\x00')
			else:
				self.server.invalid_count += 1
				print("invalid msg", end = ' ')
				print(msg, end = ' ')
				print(self.server.invalid_count)
				self.request.send(b'\xff')

	#helper function to valid the payload
	def validate(self, msg):
		self.pattern_head = b'^' + self.server.pattern + b'.*'
		self.pattern = re.compile(self.pattern_head)
		res = re.match(self.pattern, msg)
		if res is not None:
			return True
		else:
			return False



class Server(TCPServer):
	def __init__(self, target, handler):
		TCPServer.__init__(self, target, handler)
		self.valid_count = 0
		self.invalid_count = 0
		self.read_pattern("server_pattern.txt") # read the user-defined pattern from file

	#read pattern from file
	#the pattern should be 1 line and less than 1000 bytes
	def read_pattern(self, filename):
		try:
			with open(filename, 'r') as file:
				line = file.readlines()
				if len(line) > 1:
					print("Please write pattern in one line")
					sys.exit(0)
				line = line[0].strip().replace(' ', '')
				if len(line) > 2000:
					print("Pattern lengh might be too long!")
					sys.exit(0)
				self.pattern = bytes.fromhex(line)
		except Exception as e:
			print("[-]ERROR", end = ' ')
			print(e)
			print("fail to read pattern, check filename or content in the file")
			sys.exit(0)

#helper function to validate the port
def check_port(port):
	if port < 1 or port > 65535:
		print("[-]ERROR:invalid port number")
		return False
	else:
		return True


if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog = "server", usage = 'python3 server.py -p [port]')
	parser.add_argument('-p', '--port', dest = 'port', type = int, required = True, help = 'port to listen')
	args = parser.parse_args()

	if not check_port(args.port):
		sys.exit(-1)
	try:
		serv = Server(('', args.port), EchoHandler)
		print("[*]The server is running, press CTRL-C to stop")
	except OSError:
		print("[-]ERROR: port is being used, try another port")
		sys.exit(-1)

	try:
		serv.serve_forever()
	except KeyboardInterrupt:
		print("You pressed CTRL-C")
		print("Aborted! So far {valid} valid, {invalid} invalid ".format(valid=str(serv.valid_count), invalid = str(serv.invalid_count)))
		sys.exit(0)