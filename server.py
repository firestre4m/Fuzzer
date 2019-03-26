from socketserver import BaseRequestHandler, TCPServer
import signal
import sys
import re

class EchoHandler(BaseRequestHandler):

	def handle(self):
		print('Got connection from', self.client_address)
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


	def validate(self, msg):
		# self.pattern_head = b'^aaaa.*'
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
		self.read_pattern("server_pattern.txt")

	def read_pattern(self, filename):
		try:
			with open(filename, 'r') as file:
				line = file.readlines()
				if len(line) > 1:
					print("Please write pattern in one line")
					sys.exit(0)
				line = line[0].strip().replace(' ', '')
				self.pattern = bytes.fromhex(line)
		except Exception as e:
			print("[-]ERROR", end = ' ')
			print(e)
			print("fail to read pattern, check filename or content in the file")
			sys.exit(0)




if __name__ == '__main__':
    # serv = TCPServer(('', 9999), EchoHandler)
    serv = Server(('', 9998), EchoHandler)
    TCPServer.allow_resuse_address = True
    serv.allow_resuse_address = True
    try:
    	serv.serve_forever()
    except KeyboardInterrupt:
    	print("You pressed CTRL-C")
    	print("Aborted! So far {valid} valid, {invalid} invalid ".format(valid=str(serv.valid_count), invalid = str(serv.invalid_count)))
    	sys.exit(0)