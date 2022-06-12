from flask import Flask
import time
from multiprocessing import Process

def server():
    print("we in server")
    host = "client_ip"
    conn = Connection(host, 8000)
    conn.listen() # should be background process
    data = conn.recv()
    return

def client():
    print("we in client")
    host = "server_ip"
    conn = Connection(host, 8000)
    success = conn.open()

    if success:
        conn.send("yo")

    conn.close()

# interface:
#- open, close, send, receive, status 
class Connection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.state = "START"

    def open(self):
        self.state = "START"
        print("Connection.open(): trying to open connection with {0}".format(self.host))
        time.sleep(3)
        print("Connection.open(): established connection with {0}".format(self.host))

    def close(self):
        self.state = "CLOSED"
        print("Connection.close(): closed connection with {0}".format(self.host))

    def listen(self):
        self.state = "LISTENING"
        print("Connection.listen(): waiting for connection with {0}".format(self.host))
        time.sleep(3)
        # handshake serverside

        print("Connection.listen(): received connection from {0}".format(self.host))
    
    def __split(self, payload):
        return [payload, 1, 2, 3]

    def send(self, payload):
        print("Connection.send(): sending payload... {0}".format(self.host))

        packets = self.__split(payload)

        for packet in packets:
            print("Connection.send(): sending packet... {0}".format(self.host))
            time.sleep(1)

        print("Connection.send(): sent payload... {0}".format(self.host))
        return

    def recv(self):
        print("Connection.receive(): received payload from... {0}".format(self.host))
        return

        """
        global state

        if state == "START":
            # check local files for inbound payload
            synFound = False
            if synFound:
                # broadcast synack
                state = "WAIT_ACK"
            return
        if state == "WAIT_ACK":
            # check local files for inbound ack payload
            ackFound = False
            if ackFound:
                # nice! openly listen for packets
                state = "RECEIVING"
            return
        if state == "RECEIVING":
            # check for inbound payload
            return

        global state
        # states
        if state == "START":
            # do start
            # check local file for inbound payload
            # if local payload, broadcast syn
            return

        if state == "WAIT_SYNACK":
            # check local file for synack payload
            # if local payload found, broadcast ack
            state = "SENDING"
            return

        if state == "SENDING":
            # sleep for a bit
            # broadcast payload... 
            return
        """

if __name__ == '__main__':
    s = Process(target=server, args=())
    c = Process(target=client, args=())

    s.start()
    c.start()

    s.join()
    c.join()