from flask import Flask
import time
from multiprocessing import Process

def server():
    print("we in server")
    """
    host = "client_ip"
    conn = Connection(host, 8000)
    conn.Listen() # should be background process
    data = conn.Recv()
    return
    """

def client():
    print("we in client")
    """
    host = "server_ip"
    conn = Connection(host, 8000)
    success = conn.Open()

    if success:
        conn.Send("yo")

    conn.Close()
    """

# interface:
#- open, close, send, receive, status 
class Connection:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.state = "START"

    def open(self):
        self.state = "START"

    def close(self):
        self.state = "CLOSED"
    
    def send(self, payload):
        return

    def receive(self):
        return

    def status(self):
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