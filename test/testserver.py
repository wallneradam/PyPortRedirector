#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import asyncio

__author__ = "Adam Wallner"
__copyright__ = "Copyright 2017, Adam Wallner"
__credits__ = []
__license__ = "GPLv3"
__version__ = "0.1"
__maintainer__ = "Adam Wallner"
__email__ = "adam.wallner@gmail.com"
__status__ = "Beta"
__doc__ = "Test server for testing if port redirection is working"


class ServerProtocol(asyncio.Protocol):
    transport = None
    peer = ""

    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        self.peer = peername[0] + ':' + str(peername[1])
        print('Connection from ' + self.peer)
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received from {}: {!r}'.format(self.peer, message))
        # Echo data back with the detected ip of the peer
        self.transport.write(str.encode(self.peer + ': ') + data)
        # Exit if asked from the client
        if message.strip() == 'exit':
            self.transport.close()

    def connection_lost(self, exc):
        print(self.peer + ' disconnected')

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('port', help='The port where the server will listen on.')

args = parser.parse_args()


loop = asyncio.get_event_loop()
# Each client connection will create a new protocol instance
coro = loop.create_server(ServerProtocol, '0.0.0.0', args.port)
server = loop.run_until_complete(coro)

# Serve requests until CTRL+c is pressed
sockname = server.sockets[0].getsockname()
print('Serving on {}:{}'.format(sockname[0], sockname[1]))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
