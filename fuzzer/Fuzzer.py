import argparse
import sys
from IPFuzzer import IPFuzzer
from TCPFuzzer import TCPFuzzer
from APPFuzzer import APPFuzzer
from time import sleep
import re

#helper func to validate the format of ip string
def check_ip(ip):
	p = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$')
	if p.match(ip):
		return True
	else:
		print("[-]ERROR: invalid ip")
		return False

#check the range of port
def check_port(port):
	if port < 1 or port > 65535:
		print("[-]ERROR:invalid port number")
		return False
	else:
		return True

#check args taken from user input
def check_args(args, valid_fields):
	if args.number and args.number <=0:
		print("[-]ERROR:number is invalid")
		sys.exit(0)

	if not (check_ip(args.src) and check_ip(args.dst) and check_port(args.sport) and check_port(args.dport)):
		sys.exit(0)

	#for IP and TCP
	if args.layer in ['IP', 'TCP']:
		if args.size: # IP and TCP don't have size arg
			print("[-]ERROR: not APP layer fuzzing, no need for size")
			parser.print_help()
			sys.exit(0)
		if args.field and args.field not in valid_fields.get(args.layer):
			print("[-]ERROR: invalid field")
			parser.print_help()
			sys.exit(0)
		if args.file and args.field: # can't specify field and file at the same time, must choose one
			print("[-]Please choose to run default test or run from file")
			sys.exit(0)
	#for APP
	else:
		if args.field:
			print("[-]App layer fuzzing, no need for field")
			parser.print_help()
			sys.exit(0)
		if args.file and (args.number or args.size):
			print("[-]Please choose to default run or run from file")
			sys.exit(0)

		if args.size:
			pattern = re.compile('^\d+$|^\d+-\d+$') #size arg should be a single int(like 5) or a range (like 5-10)
			if not re.match(pattern, args.size):
				print("size argument format is wrong, example: 5 or 5-10")
				sys.exit(0)

		if not args.number and args.layer == 'APP': # set the number arg default to 10
			args.number = 10
		if not args.size: # set size default to 10
			args.size = "10"

#helper func to extract size arg from user input
def get_size(size_str):
	size_input = size_str.split('-')
	if len(size_input) == 1: # means it is a single int
		return int(size_input[0])
	elif len(size_input) == 2:# it is a range
		return (int(size_input[0]), int(size_input[1]))
	else:
		print("[-]ERROR:wrong size input")
		sys.exit(0)


def run(args):
	src_ip = args.src
	dst_ip = args.dst
	dport = args.dport
	sport = args.sport

	if args.layer == "IP":
		# no specified file, run default fuzzing
		if not args.file:
			print("IP default run")
			try:
				fuzzer = IPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(target_field = args.field, number = args.number)
			except KeyboardInterrupt:
				print("[*]Terminated!")
				sys.exit(0)
		#specified file exist, run tests from file
		else:
			print("IP run from file")
			try:
				fuzzer = IPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.run_from_file(args.file)
			except KeyboardInterrupt:
				print("[*]Terminated!")
				sys.exit(0)

	elif args.layer == 'TCP':
		if not args.file:
			print("TCP default run")
			try:
				fuzzer = TCPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(target_field = args.field, number = args.number)
			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)
		else:
			print("TCP run from file")
			try:
				fuzzer = TCPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.run_from_file(args.file)

			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)

	else: # APP layer fuzzing
		if not args.file:
			print("APP default run")
			size = get_size(args.size)
			try:
				fuzzer = APPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(args.number, size)
				print("[+]Finished, {total} packets sent, {valid} valid, {invalid} invalid".format(total = fuzzer.valid+fuzzer.invalid, valid = fuzzer.valid, invalid = fuzzer.invalid))
			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)
		else:
			print("APP run from file")
			try:
				fuzzer = APPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.run_from_file(args.file)
				print("[+]Finished, {total} packets sent, {valid} valid, {invalid} invalid".format(total = fuzzer.valid+fuzzer.invalid, valid = fuzzer.valid, invalid = fuzzer.invalid))
			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)



if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog = 'Fuzzer', usage = 'python3 Fuzzer.py --src [source_ip] --dst [target_ip] --sport [source_port] --dport [target_port] -l [layer] {optional args}}')
	parser.add_argument('--src', dest = 'src', required = True, type = str, help = 'source ip')
	parser.add_argument('--dst', dest = 'dst', required = True, type = str, help = 'target ip')
	parser.add_argument('--sport', dest = 'sport', required = True, type = int, help = 'source port')
	parser.add_argument('--dport', dest = 'dport', required = True, type = int, help = 'target port')
	parser.add_argument('-l', '--layer', dest = 'layer', choices = {'IP', 'TCP', 'APP'}, required = True, help = 'layer to be fuzzed, can be IP/TCP/APP')
	parser.add_argument('-t', '--target_field', dest = 'field', help = 'field to be fuzzed')
	parser.add_argument('-n', '--number', dest = 'number', type = int, help = 'number of tests to run')
	parser.add_argument('-s', '--size', dest = 'size', type = str, help = 'size of payload')
	parser.add_argument('-f', '--file', dest = 'file', help = 'file containing tests')
	
	args = parser.parse_args()

	valid_fields = {'IP': ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto'],
	'TCP' : ['seq', 'ack', 'flags', 'window', 'urgptr', 'dataofs', 'reserved']}

	check_args(args, valid_fields)

	try:
		run(args)
	except Exception as e:
		print("[-]ERROR:", end = ' ')
		print(e)

