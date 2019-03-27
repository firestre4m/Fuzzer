from scapy.all import *
from scapy.layers.inet import IP
import time
import socket
from threading import Thread
from time import sleep
import sys

#base class for IP TCP and APP fuzzer
#build a TCP session by three way handshake
#close session by four way handshake
#maintain seq and ack for a session
class TCPSession:
    def __init__(self, src, dst, sport, dport):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.seq = 0
        self.ack = 0
        self.ip = IP(dst=self.dst)
        self.connected = False

    #start a TCP session by 3 way handshake
    def connect(self):
        # SYN
        self.seq = self.ack = 0
        SYN=TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        
        
        # SYN-ACK
        SYNACK=sr1(self.ip/SYN, timeout = 2, verbose = 0)
        self.seq += 1
        if not SYNACK or SYNACK[TCP].flags != "SA":
            print("[-]ERROR: Fail to receive SYNACK from server!")
            return False

        # ACK
        self.ack = SYNACK[TCP].seq + 1
        ACK=TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(self.ip/ACK, verbose = 0)
        
        self.connected = True
        self._start_ackThread()
        print("[*] Connected!")
        return True
        
    #close the session correctly by 4 way handshake
    def close(self):
        self.connected = False

        FIN=self.ip/TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
        
        FINACK=sr1(FIN, timeout = 1, verbose = 0)
        self.seq += 1
        if not FINACK:
            print("[-]ERROR: fail to receive FINACK")
            return False

        #buffer time before sending last ack
        from time import sleep
        sleep(1)

        self.ack = FINACK[TCP].seq + 1
        LASTACK=self.ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack)
        send(LASTACK, verbose = 0)
        print("[+] Disconnect Successfully!")
        return True

    #normally send a packet with a payload in this session
    #this function will be overwritten by subclasses
    def send(self, payload):
        packet = self.ip/TCP(sport = self.sport, dport = self.dport, flags = 'PA', seq = self.seq, ack = self.ack)/payload
        self.seq += len(packet[Raw])
        ack = sr1(packet, timeout = 2, verbose = 0)
        
        if ack[TCP].ack != self.seq:
            print('[-]INVALID ACK value' + str(ack[TCP].ack))

    #will be called when receive a response from server
    #respond with valid ack packet
    def _ack(self, p):
        self.ack = p[TCP].seq + len(p[Raw].load)
        self.seq = p[TCP].ack

        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        print("sending ack")
        send(ack, verbose = 0)

    #will be called when receive FA packet
    #respond with a valid ack
    def _ack_close(self):
        self.connected = False
        self.ack += 1
        fin_ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout = 2, verbose = 0)
        self.seq += 1

    #check received packets in order to make correct response
    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            #when receive a response packet from server, send an ack
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p.haslayer(Raw):
                self._ack(p)
            #when receive a FA packet with server, send ack
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].flags == 'FA':
                self._ack_close()

        s.close()

    #use a new thread to sniff
    def _start_ackThread(self):
        try:
            self._ackThread = Thread(name='AckThread',target=self._sniff)
            self._ackThread.setDaemon(True)
            self._ackThread.start()
        except KeyboardInterrupt:
            sys.exit(0)

    #helper func to read in test file
    def file_read_in(self, filename):
        try:
            with open(filename, 'r') as file:
                tests = file.readlines()
        except:
            print("[-] ERROR: read test file fails!")
        else:
            return tests

    #read default payload from file
    def read_payload(self, filename):
        try:
            with open(filename, 'r') as file:
                line = file.readlines()
                if len(line) > 1:
                    print("[-]ERROR:Please write payload in one line")
                    sys.exit(0)
                line = line[0].strip().replace(' ', '')
                self.payload = bytes.fromhex(line)
        except Exception as e:
            print("[-]ERROR", end = ' ')
            print(e)
            print("Fail to read payload, check filename or content in the file")
            sys.exit(0)
