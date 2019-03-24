from scapy.all import *
from scapy.layers.inet import IP
from datetime import datetime
import time
import socket
from threading import Thread
from time import sleep
import sys

src_ip = "10.0.2.15"
# dst_ip = "52.14.181.116"
dst_ip = "192.168.0.26"
# dport = 80
dport = 9997
sport = 7890

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

    
    def connect(self):
        # SYN
        # self.seq = random.randrange(0,(2**32)-1)
        self.seq = self.ack = 0
        SYN=TCP(sport=self.sport, dport=self.dport, flags='S', seq=self.seq)
        
        
        # SYN-ACK
        SYNACK=sr1(self.ip/SYN, timeout = 2, verbose = 0)
        self.seq += 1
        if not SYNACK or SYNACK[TCP].flags != "SA":
            print("[ERROR] Fail to receive SYNACK from server!")
            return False

        # ACK
        self.ack = SYNACK[TCP].seq + 1
        # self.seq = SYNACK[TCP].ack
        ACK=TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        send(self.ip/ACK, verbose = 0)
        

        
        self.connected = True
        self._start_ackThread()
        print("[OJBK] Connected!")
        return True
        
    def close(self):
        # self.seq = random.randrange(0,(2**32)-1)
        self.connected = False

        FIN=self.ip/TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
        # self.seq += 1
        # print("[OJBK] Send FINACK to Server!")
        
        FINACK=sr1(FIN, timeout = 2, verbose = 0)
        self.seq += 1
        if not FINACK:
            print("fail to receive FINACK")
            return False

        # if FINACK[TCP].ack != self.seq+1:
        #     print "ack number is wrong"
        #     return False
        # if not FINACK or FINACK[TCP].flags != 'FA':
        #     try:
        #         print("[ERROR] Receive "+ str(FINACK[TCP].flags) + " instead of FA from server!")
        #     except:
        #         print("[ERROR] Fail to receive FINACK from server")
        #     return False
        from time import sleep
        sleep(1)

        self.ack = FINACK[TCP].seq + 1
        # self.seq = FINACK[TCP].ack
        LASTACK=self.ip/TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack)
        send(LASTACK, verbose = 0)
        # print("[OJBK] Send ACK to Server!")
        # self.connected = False
        print("[+] Disconnect Successfully!")
        return True

    def restart(self):
        self.close()
        self.seq = self.ack = 0
        self.connect()

    # def send(self, packet):
    #     packet.src = self.src
    #     packet.dst = self.dst
        
    #     packet.payload.sport = self.sport
    #     packet.payload.dport = self.dport
    #     packet.payload.flags = "PA" 
    #     packet.payload.seq = self.seq
    #     packet.payload.ack = self.ack
        
    #     ACK = sr1(packet, timeout=3)
    #     if not ACK or not ACK[TCP].flags.A:
    #         print("[ERROR] Fail to receive ACK from server")
            
        
    #     self.seq += len(packet.payload.payload)

    #     print("[OJBK] Packet sent")
    #     return True

    def send(self, payload):
        # sleep(0.5)
        # payload = "hello world"
        # print("my ack"+ str(self.ack))
        packet = self.ip/TCP(sport = self.sport, dport = self.dport, flags = 'PA', seq = self.seq, ack = self.ack)/payload
        self.seq += len(packet[Raw])
        ack = sr1(packet, timeout = 2, verbose = 0)
        

        # print("seq num is " + str(self.seq))
        if ack[TCP].ack != self.seq:
            print('INVALID ACK value' + str(ack[TCP].ack))
        # if ack.haslayer(Raw) and ack[Raw].load is not None:
        #     return ack[Raw].load

    def _ack(self, p):
        # if p.haslayer(Raw):
        self.ack = p[TCP].seq + len(p[Raw].load)
        self.seq = p[TCP].ack
        # print(p[Raw])
        # print(self.ack, self.seq, p[TCP].ack, p[TCP].seq, len(p[Raw].load))
        # self.ack = self.seq + len(p[Raw])
        # else:
        #     self.ack = p[TCP].seq
            # print("my ack here"+ str(self.ack))

        ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=self.ack)
        print("sending ack")
        send(ack, verbose = 0)

    def _ack_close(self):
        self.connected = False
        self.ack += 1
        fin_ack = self.ip/TCP(sport=self.sport, dport=self.dport, flags='FA', seq=self.seq, ack=self.ack)
        ack = sr1(fin_ack, timeout = 2, verbose = 0)
        self.seq += 1


    def _sniff(self):
        s = L3RawSocket()
        while self.connected:
            p = s.recv(MTU)
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p.haslayer(Raw):
                # print("hhh i am here")
                self._ack(p)
            if p.haslayer(TCP) and p[TCP].dport == self.sport and p[TCP].flags == 'FA':
                self._ack_close()
                # pass
                # self.restart()

        s.close()
        # self._ackThread = None
        print("ACK thread stopped")

    def _start_ackThread(self):
        try:
            self._ackThread = Thread(name='AckThread',target=self._sniff)
            self._ackThread.setDaemon(True)
            self._ackThread.start()
        except KeyboardInterrupt:
            print("ACK thread terminated")
            sys.exit(0)


    # def sniffer_func(packet):
    #     if packet[TCP].flags=='P':
    #         ACK = TCP(sport=self.sport, dport=self.dport, flags='A', seq=self.seq, ack=ack)
    #         send(self.ip/ACK)


if __name__ == "__main__":
    conn = TCPSession(src_ip, dst_ip, sport, dport)
    conn.connect()

    tests = ['hello', 'world', 'boom']
    for p in tests:
        conn.send(p)



    conn.close()

    # test_payload = datetime.now().strftime("%m/%y %H:%M:%S")
    # conn.send(IP()/TCP()/Raw(load=test_payload))