#!/usr/bin/env python2

## Inspired from https://docs.python.org/2/library/socketserver.html

import socket
import os, os.path
import sys
import SocketServer

SOCKFILE = "/tmp/dances_alert"


class DancesHandler(SocketServer.BaseRequestHandler):

    def handle(self):
        # self.request is the TCP socket connected to the client
        self.data = self.request.recv(1024).strip()
        print "{} wrote:".format(self.client_address[0])
        print self.data
        # send back an acknowledgement
        self.request.sendall("Received!")
        # Send to controller
        client = socket.socket( socket.AF_UNIX, socket.SOCK_DGRAM )
        client.connect(SOCKFILE)
        client.send(self.data)
        client.close()


if __name__ == "__main__":
    HOST, PORT = "localhost", 9090

    # Create the server, binding to localhost on port 9090
    server = SocketServer.TCPServer((HOST, PORT), DancesHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()


