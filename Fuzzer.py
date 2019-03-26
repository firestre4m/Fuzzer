import argparse
import sys
from IPFuzzer import IPFuzzer
from TCPFuzzer import TCPFuzzer
from APPFuzzer import APPFuzzer
from time import sleep
import re

def check_args(args):
	if args.layer in ['IP', 'TCP']:
		# if not args.field:
		# 	print("default run")
		if args.number or args.size:
			print("not app, no need for num and size")
			parser.print_help()
			sys.exit(0)
		if args.field and args.field not in valid_fields.get(args.layer):
			print("invalid field")
			parser.print_help()
			sys.exit(0)
		if args.file and args.field:
			print("please choose to default run or run from file")
			sys.exit(0)
	else:
		if args.field:
			print("app layer, no need for field")
			parser.print_help()
			sys.exit(0)
		if args.file and (args.number or args.size):
			print("please choose to default run or run from file")
			sys.exit(0)
		# remember to check validation of size
		if args.size:
			pattern = re.compile('^\d+$|^\d+-\d+$')
			if not re.match(pattern, args.size):
				print("size argument is wrong")
				sys.exit(0)

		if not args.number:
			args.number = 10
		if not args.size:
			args.size = "10"

def get_size(size_str):
	size_input = size_str.split('-')
	if len(size_input) == 1:
		return int(size_input[0])
	elif len(size_input) == 2:
		return (int(size_input[0]), int(size_input[1]))
	else:
		print("wrong size input")
		sys.exit(0)

def run(args):
	src_ip = "10.0.2.15"
	dst_ip = "192.168.0.26"
	dport = 9998
	sport = 7890

	if args.layer == "IP":
		if not args.file:
			print("IP default run")
			try:
				fuzzer = IPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(target_field = args.field)
			except KeyboardInterrupt:
				# fuzzer.close()
				# sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)
		else:
			print("IP run from file")
			try:
				fuzzer = IPFuzzer(src_ip, dst_ip, sport, dport)
				# fuzzer.default_run(target_field = args.field)
				fuzzer.run_from_file(args.file)

			except KeyboardInterrupt:
				# fuzzer.close()
				# sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)

	elif args.layer == 'TCP':
		if not args.file:
			print("TCP default run")
			try:
				fuzzer = TCPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(target_field = args.field)
			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)
		else:
			print("TCP run from file")
			try:
				fuzzer = TCPFuzzer(src_ip, dst_ip, sport, dport)
				# fuzzer.default_run(target_field = args.field)
				fuzzer.run_from_file(args.file)

			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)
	else:
		if not args.file:
			print("APP default run")
			size = get_size(args.size)
			try:
				fuzzer = APPFuzzer(src_ip, dst_ip, sport, dport)
				fuzzer.default_run(args.number, size)
				print("[+]Finished, {valid} valid, {invalid} invalid".format(valid = fuzzer.valid, invalid = fuzzer.invalid))
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
				print("[+]Finished, {valid} valid, {invalid} invalid".format(valid = fuzzer.valid, invalid = fuzzer.invalid))
			except KeyboardInterrupt:
				fuzzer.close()
				sleep(0.2)
				print("[*]Terminated!")
				sys.exit(0)






if __name__ == '__main__':
	parser = argparse.ArgumentParser(prog = 'Fuzzer', usage = 'python3 Fuzzer.py -l [layer] -f [field] -n [number] -s [size]')
	parser.add_argument('-l', '--layer', dest = 'layer', choices = {'IP', 'TCP', 'APP'}, required = True, help = 'layer to be fuzzed, can be IP/TCP/APP')
	parser.add_argument('-t', '--target_field', dest = 'field', help = 'field to be fuzzed')
	parser.add_argument('-n', '--number', dest = 'number', type = int, choices = range(0, 51), help = 'number of tests to run')
	parser.add_argument('-s', '--size', dest = 'size', type = str, help = 'size of payload')
	parser.add_argument('-f', '--file', dest = 'file', help = 'file containing tests')
	args = parser.parse_args()

	valid_fields = {'IP': ['version', 'ihl', 'tos', 'len', 'id', 'flags', 'frag', 'ttl', 'proto'],
	'TCP' : ['seq', 'ack', 'flags', 'window', 'urgptr', 'dataofs', 'reserved']}

	check_args(args)
	run(args)

