from flask import Flask
import time
from multiprocessing import Process
from enum import Enum
from bitstring import BitArray

a = BitArray('0b001')
b = 1
print(b << b)

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

    conn.close()
    return

#class FileSocket
class IPV6Packet:
    def __init__(self, data, src_ip, dest_ip):
        self.data = data

        # header: 320 bits
        self.src_ip = src_ip
        self.dest_ip = dest_ip

class TCPPacket:
    # 1024 bit packet
    def __init__(self, data, seq, ack):
        self.data = data
        self.seq = seq
        self.ack = ack

    def to_bits(self):
        # init bitstring header
        bin = 0b0*1024
        return self.data

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

    def __send_syn_packet(self):
        # write output packet 
        print("Connection.__send_syn_packet(): sending syn packet to {0}".format(self.host))
        payload = "" # write the tcp segment header with seq 0, ack = 0

        return True 
   
    def __check_for_syn_packet(self):
        # looking for packet with seq == 0, ack == 0. Return None if we don't
        payload = "" # needs to be a bitstring
        return payload


    def __check_for_ack_packet(self):
        # looking for packet with seq == 1, ack == 1. Return None if we don't
        payload = "" # needs to be a bitstring
        return payload

    def __check_for_synack_packet(self):
        # looking for packet with seq == 0, ack == 1. Return None if we don't
        payload = "" # needs to be a bitstring
        return payload

    def __send_ack_packet(self):
        # write output packet 
        print("Connection.__send_ack_packet(): sending ack packet to {0}".format(self.host))
        payload = "" # write the tcp segment header with seq 1, ack 1

        return True 

    def __send_synack_packet(self):
        # write output packet 
        print("Connection.__send_ack_packet(): sending synack packet to {0}".format(self.host))
        payload = "" # write the tcp segment header with seq 1, ack 1

        return True 

    def __send_data_packet(self):
        # write output packet 
        print("Connection.__send_data_packet(): sending data packet to {0}".format(self.host))
        payload = "" # write the tcp segment header with seq=?, ack=?
        
        bits_to_send = 1024

        # write to output file
        # increment bits sent by datasize of packet
        self.bits_sent += bits_to_send
        return True 

    def open(self):
        print("Connection.open(): trying to open connection with {0}".format(self.host))

        # send SYN req
        self.__send_syn_packet()
        self.state = self.State.SYNSENT

        gotSynAck = False
        while not gotSynAck:
            # check local file for synack payload in /dev/proc/PID/
            payload = self.__check_for_synack_packet()
            if payload is not None:
                getSynAck = True

            time.sleep(1)

        self.__send_ack_packet()

        self.state = self.State.ESTABLISHED
        time.sleep(3)
        print("Connection.open(): established connection with {0}".format(self.host))

    def close(self):
        self.state = self.state.CLOSED
        print("Connection.close(): closed connection with {0}".format(self.host))

    def listen(self):
        self.state = self.State.LISTENING
        print("Connection.listen(): waiting for connection with {0}".format(self.host))
        time.sleep(3)
        gotSyn = False
        while not gotSyn:
            # check local file for synack payload in /dev/proc/PID/
            payload = self.__check_for_syn_packet()
            if payload is not None:
                gotSyn = True
            time.sleep(1)

        self.state = self.State.SYNRECEIVED

        self.__send_synack_packet()

        # wait for ACK packet
        gotAck = False
        while not gotAck:
            # check local file for synack payload in /dev/proc/PID/
            payload = self.__check_for_ack_packet()
            if payload is not None:
                gotAck = True
            time.sleep(1)
        
        self.state = self.State.ESTABLISHED

        print("Connection.listen(): received connection from {0}".format(self.host))
    
    def __split(self, payload):
        return [payload, 1, 2, 3]

    def send(self, payload):
        print("Connection.send(): sending payload... {0}".format(self.host))

        # split payload into TCP packets with correct seq/ack numbers
        packets = self.__split(payload)

        for packet in packets:
            print("Connection.send(): sending packet... {0}".format(self.host))
            time.sleep(1)
            self.__send_data_packet(packet)

        print("Connection.send(): sent payload... {0}".format(self.host))
        return

    def recv(self):
        print("Connection.receive(): received payload from... {0}".format(self.host))

        # simplification: assume when we get FIN bit we're done.
        # check we got all the data, if not throw error, otherwise close
        # TODO: scan packets to see if we have all the data
        # TODO: send close request / do closing handshake
        return "payload"

if __name__ == '__main__':
    s = Process(target=server, args=())
    c = Process(target=client, args=())

    s.start()
    c.start()

    s.join()
    c.join()