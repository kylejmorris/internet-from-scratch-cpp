from flask import Flask
import time
from multiprocessing import Process
import struct
from enum import Enum
from bitstring import BitArray
import binascii

a = BitArray('0b001')

TCP_PACKET_SIZE = 65535 * 8
TCP_HEADER_SIZE = 192
TCP_DATA_SIZE = TCP_PACKET_SIZE - TCP_HEADER_SIZE
IPV6_HEADER_SIZE = 320
PACKET_PATH = "/dev/proc/shared/net/tcp6"

def log(msg):
    t = time.time()
    print("[{0}] {1}".format(t, msg))

def server():
    print("we in server")
    host = "client_ip"
    conn = TCPConnection(host, 8000)
    conn.listen() # should be background process
    data = conn.recv()
    return

def client():
    print("we in client")
    host = "server_ip"
    conn = TCPConnection(host, 8000)

    success = conn.open()

    if success:
        conn.send("yo")
        conn.send("hey!")
        conn.send("ohhhhh")
        conn.send("heyyyy")
        conn.send("oh!")

    conn.close()
    return

class PacketReadWriter:
    # read n write packets

    def write_ip(self, ip_packet):
        # add new IPPacket to filesystem
        bits = ip_packet.to_bits()
        now_ns = time.time_ns()

        f = open("{0}/{1}".format(PACKET_PATH,now_ns), "wb")
        bits.tofile(f)
        f.close()

        return
    
    def read_tcp(self):
        # return list of TCPPacket
        import os
        files = os.listdir(PACKET_PATH)
        packets = []
        for file in files:
            if os.path.isfile(os.path.join(PACKET_PATH, file)):
                f = open(os.path.join(PACKET_PATH, file),'rb')
                bits = BitArray(f)
                packet = TCPPacket.from_bits(bits)
                packets.append(packet)

                f.close()
        return packets

class TCPPacket:
    SEQ_OFFSET = 32
    ACK_OFFSET = 64

    # 1024 bit packet
    def __init__(self, data, seq, ack):
        self.data = data
        self.seq = seq
        self.ack = ack

    def to_bits(self):
        # init bitstring header
        bits = BitArray(length=TCP_PACKET_SIZE)

        b_seq = BitArray(uint=self.seq, length=32)
        b_ack = BitArray(uint=self.ack, length=32)

        bits.overwrite(BitArray(uint=self.seq, length=32), pos=self.SEQ_OFFSET)
        bits.overwrite(BitArray(uint=self.ack, length=32), pos=self.ACK_OFFSET)

        # data
        b_data = bin(int.from_bytes(self.data.encode(), 'big'))
        bits.overwrite(b_data,pos=TCP_HEADER_SIZE)

        return bits

    @staticmethod
    def from_bits(bits):
        assert(bits!="")

        SEQ_OFFSET = IPV6_HEADER_SIZE +  TCPPacket.SEQ_OFFSET
        ACK_OFFSET = IPV6_HEADER_SIZE +  TCPPacket.ACK_OFFSET
        DATA_OFFSET = IPV6_HEADER_SIZE + TCP_HEADER_SIZE

        res = TCPPacket(data="", seq=0, ack=0)

        # init bitstring header
        b_seq = bits[SEQ_OFFSET:SEQ_OFFSET+32]
        b_ack = bits[ACK_OFFSET:ACK_OFFSET+32]

        res.seq = BitArray.unpack(b_seq, 'uint:32')[0]
        res.ack = BitArray.unpack(b_ack,'uint:32')[0]

        # data
        res.data = bits[DATA_OFFSET:DATA_OFFSET+TCP_DATA_SIZE]
        return res

class IPV6Packet:
    def __init__(self, tcp_packet=TCPPacket, src_ip=0, dest_ip=0):
        self.tcp_packet = tcp_packet

        self.src_ip = src_ip
        self.dest_ip = dest_ip

    def to_bits(self):
        # header
        ip_bits = BitArray(length=TCP_PACKET_SIZE + IPV6_HEADER_SIZE)

        # data
        tcp_bits = self.tcp_packet.to_bits()
        ip_bits.overwrite(tcp_bits, pos=IPV6_HEADER_SIZE)

        return ip_bits

def test_tcp_to_bits():
    # ensure seq/ack are set
    packet = TCPPacket(data="hello", seq=1, ack=1)
    bits = packet.to_bits()
    assert(bits[63]==1) # syn bit
    assert(bits[95]==1) # ack bit
    assert(bits[192]==1) # data begins here

def test_ip_to_bits():
    # ensure seq/ack are set
    packet = TCPPacket(data="hello", seq=1, ack=1)
    ip_packet = IPV6Packet(tcp_packet=packet, src_ip=0, dest_ip=0)
    bits = ip_packet.to_bits()
    assert(bits[320+32+31]==1) # syn bit

class TCPConnection:
    class State (Enum):
        CLOSED = 0
        LISTENING = 1
        SYNSENT = 2
        SYNRECEIVED = 3
        ESTABLISHED = 4

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.state = self.State.CLOSED
        self.bits_sent = 0
        self.bits_received = 0
        self.packetinterface = PacketReadWriter()

    def __send_syn_packet(self):
        # write output packet 
        log("Connection.__send_syn_packet(): sending syn packet to {0}".format(self.host))
        packet_tcp = TCPPacket("", seq=self.bits_sent, ack=self.bits_received)
        ip_packet = IPV6Packet(packet_tcp, src_ip=0, dest_ip=0)

        # write to output file
        self.packetinterface.write_ip(ip_packet)

        self.bits_sent = self.bits_sent + 1

        return True 
   
    def __check_for_syn_packet(self):
        # looking for packet with seq == 0, ack == 0. Return None if we don't
        packets = self.packetinterface.read_tcp()
        for packet in packets:
            if packet.seq == 0 and packet.ack == 0:
                self.bits_received = self.bits_received + 1
                return True
        
        return False


    def __check_for_ack_packet(self):
        # looking for packet with seq == 1, ack == 1. Return None if we don't
        packets = self.packetinterface.read_tcp()
        for packet in packets:
            if packet.seq == 1 and packet.ack == 1:
                self.bits_received = self.bits_received + 1
                return True
 
        return False

    def __check_for_synack_packet(self):
        # looking for packet with seq == 0, ack == 1. Return None if we don't
        packets = self.packetinterface.read_tcp()
        for packet in packets:
            if packet.seq == 0 and packet.ack == 1:
                self.bits_received = self.bits_received + 1
                return True
        
        return False

    def __send_ack_packet(self):
        # TODO impl
        # write output packet 
        log("Connection.__send_ack_packet(): sending ack packet to {0}".format(self.host))
        tcp_packet = TCPPacket("", seq=self.bits_sent, ack=self.bits_received)
        ip_packet = IPV6Packet(tcp_packet, src_ip=0, dest_ip=0)

        # write to output file
        self.packetinterface.write_ip(ip_packet)
        self.bits_sent = self.bits_sent + 1
        return True 

    def __send_synack_packet(self):
        # write output packet 
        log("Connection.__send_synack_packet(): sending synack packet to {0}".format(self.host))
        tcp_packet = TCPPacket("", seq=self.bits_sent, ack=self.bits_received)
        ip_packet = IPV6Packet(tcp_packet, src_ip=0, dest_ip=0)

        # write to output file
        self.packetinterface.write_ip(ip_packet)
        self.bits_sent = self.bits_sent + 1
 
        return True 

    def open(self):
        log("Connection.open(): trying to open connection with {0}".format(self.host))

        # send SYN req
        self.__send_syn_packet()
        self.state = self.State.SYNSENT

        gotSynAck = False
        while not gotSynAck:
            # check local file for synack payload in /dev/proc/PID/
            gotSynAck = self.__check_for_synack_packet()
            time.sleep(1)

        self.__send_ack_packet()

        self.state = self.State.ESTABLISHED
        time.sleep(3)
        print("Connection.open(): established connection with {0}".format(self.host))
        return True

    def close(self):
        self.state = self.state.CLOSED
        log("Connection.close(): closed connection with {0}".format(self.host))

    def listen(self):
        self.state = self.State.LISTENING
        log("Connection.listen(): waiting for connection with {0}".format(self.host))
        time.sleep(3)
        gotSyn = False
        while not gotSyn:
            # check local file for synack payload in /dev/proc/PID/
            gotSyn = self.__check_for_syn_packet()
            time.sleep(1)

        self.state = self.State.SYNRECEIVED

        self.__send_synack_packet()

        # wait for ACK packet
        gotAck = False
        while not gotAck:
            # check local file for synack payload in /dev/proc/PID/
            gotAck = self.__check_for_ack_packet()
            time.sleep(1)
        
        self.state = self.State.ESTABLISHED

        print("Connection.listen(): received connection from {0}".format(self.host))
    
    def __split(self, payload):
        # split payload into bitarray chunks of size TCP_DATA_SIZE
        # divising by 8 because python len calculation uses bytes not bits
        chonks = [payload[i:i+int(TCP_DATA_SIZE/8)] for i in range(0, len(payload), int(TCP_DATA_SIZE/8))]

        # create packets with increasing seq number
        packets = []
        for chonk in chonks:
            t = TCPPacket(data=chonk, seq=self.bits_sent, ack=self.bits_received)
            packet = IPV6Packet(tcp_packet=t, src_ip=0, dest_ip=0)
            packets.append(packet)
            self.bits_sent = self.bits_sent + len(chonk)*8

        return packets

    def send(self, payload):
        log("Connection.send(): sending payload... {0}".format(self.host))

        # convert payload into bitarray
        bits = bin(int.from_bytes(payload.encode(), 'big'))

        # split payload into TCP packets with correct seq/ack numbers
        packets = self.__split(bits)

        for packet in packets:
            log("Connection.send(): sending packet... {0}".format(self.host))
            time.sleep(1)
            self.packetinterface.write_ip(packet)

        log("Connection.send(): sent payload... {0}".format(self.host))
        return

    def recv(self):
        log("Connection.receive(): received payload from... {0}".format(self.host))

        packets = self.packetinterface.read_tcp()

        gotFin = False

        while not gotFin:
            log("listening..")
            # find next packet to print out 
            for packet in packets:
                if packet.seq == self.bits_received:
                    log("received packet... {0}".format(packet.seq))
                    self.bits_received = self.bits_received + len(packet.data)
            time.sleep(1)

class WifiDriver:
    def listen():
        # listen for packet data... IRL over radio
        # save packets on filesystem
        return 

    def broadcast(self):
        # scan file system for packets
        # broadcast a packet to the world over radio
        # delete packet from filesystem

if __name__ == '__main__':
    s = Process(target=server, args=())
    c = Process(target=client, args=())

    s.start()
    c.start()

    s.join()
    c.join()