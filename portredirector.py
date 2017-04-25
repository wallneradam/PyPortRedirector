#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

import sys
import argparse
import asyncio
import socket
import signal

try:
    # noinspection PyPackageRequirements
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    uvloop = None


__doc__ = """
PyPortRedirector is a Linux TCP client-server proxy able to redirect all data from one address to another by 
preserving source IP address. The client can listen on one or more ports then transfer data to the server. 
The server creates Linux iptables SNAT and DNAT rules for all connections to be able to return packets on the same 
route back. On server you need to enable "route_localnet" with the following command:
sysctl -w net.ipv4.conf.eth0.route_localnet=1
"""
__author__ = "Adam Wallner"
__copyright__ = "Copyright 2017, Adam Wallner"
__credits__ = []
__license__ = "GPLv3"
__version__ = "0.1"
__maintainer__ = "Adam Wallner"
__email__ = "adam.wallner@gmail.com"
__status__ = "Beta"


# The name of redirector iptables chain
IPTABLES_CHAIN_PREFIX = 'PYPORTREDIRECT_'


class Server(object):
    """
    Server listening for portredirector clients
    """
    servicePorts = {}
    replacePorts = {}

    serviceConnections = set()

    loop = None

    @classmethod
    def createServer(cls, lhost, lport, servicePorts, replacePorts):
        loop = asyncio.get_event_loop()
        Server.loop = loop

        try:
            # Process service ports
            for sport in servicePorts:
                if ':' in sport:
                    fhost, sport = sport.split(':')
                else:
                    fhost = '127.0.0.1'
                sport = int(sport)
                Server.servicePorts[sport] = (fhost, sport)

            # Process replace prots
            if replacePorts is not None:
                for rport in replacePorts:
                    rport = rport.split('.')
                    if len(rport) != 2: continue
                    Server.replacePorts[int(rport[0])] = int(rport[1])

        except ValueError:
            print("Port numbers must be integer!", file=sys.stderr)
            return

        # Initialize iptables
        loop.run_until_complete(Server.Iptables.createChains())

        # Create listen socket
        make_server = loop.create_server(Server.RedirectorServer, lhost, int(lport), reuse_port=True)
        server = loop.run_until_complete(make_server)

        peerAddress = lhost + ':' + str(lport)
        print('Waiting for redirector client connections on {}...'.format(peerAddress))

        # Waiting until an end signal
        loop.run_forever()

        # Close everything gracefully
        server.close()
        loop.run_until_complete(server.wait_closed())

        # Close client connections
        for service in Server.serviceConnections:
            service.close()

        # Finalize iptables
        loop.run_until_complete(Server.Iptables.deleteChains())

        # Close the loop
        loop.close()

    class RedirectorServer(asyncio.Protocol):
        """
        Accept connections from redirector client then create connection to service and transfer data between them
        """
        def __init__(self):
            self.redirectorClientTransport = None
            self.serviceTransport = None
            self.redirectorClientAddress = None

            self.shost = None
            self.sport = None
            self.serviceAddress = None

            self.phost = None
            self.pport = None
            self.peerAddress = None

            # This is the client address (bind for SNAT)
            self.cport = None
            self.clientAddress = None

            self.snatRule = None
            self.dnatRule = None

            self.buffer = bytearray()

        async def create_service_connection(self, protocol_factory, sock, host, port):
            """ Create iptables rules and connect to service """
            loop = Server.loop
            await Server.Iptables.addNatRules(self.clientAddress, self.cport, self.shost, self.sport,
                                              self.phost, self.pport)
            sock.setblocking(False)
            await loop.sock_connect(sock, (host, port))
            transport, protocol = await loop.create_connection(protocol_factory, sock=sock)
            return transport, protocol

        def connection_made(self, redirectorClientTransport):
            try:
                self.redirectorClientTransport = redirectorClientTransport
                peername = redirectorClientTransport.get_extra_info('peername')
                self.redirectorClientAddress = peername[0] + ':' + str(peername[1])
                print('Redirector client connection from ' + self.redirectorClientAddress)
            except BrokenPipeError:
                pass

        def data_received(self, data):
            # 1st data must contain peer address and the port to connect to
            if self.sport is None:
                try:
                    # Max length of 1st message is ("111.222.333.444:12345:54321\n") 28
                    chunk = data[:28]
                    if b"\n" not in chunk or b":" not in chunk: raise ValueError()
                    # Split concatenated messages
                    peerData, data = data.split(b"\n", 1)

                    # Store possibly remaining message in the buffer
                    self.buffer.extend(data)

                    # Process peerdata
                    peerData = peerData.decode()
                    self.phost, self.pport, sport = peerData.split(':')
                    # The address of the peer
                    self.peerAddress = self.phost + ':' + self.pport
                    self.pport = int(self.pport)
                    # Parse service port
                    self.shost, self.sport = Server.servicePorts[int(sport)]
                    # Replace ports
                    if self.sport in Server.replacePorts:
                        self.sport = Server.replacePorts[self.sport]
                    self.serviceAddress = self.shost + ':' + str(self.sport)

                except ValueError:
                    print("Error: Protocol error!", file=sys.stderr)

                except KeyError:
                    print("Error: No service on the specified port: {!r}".format(data), file=sys.stderr)

                # Here we know the peer address and port and the destination port as well so we can create the iptables
                # rules and connect to
                if self.sport is not None:
                    # Create a socket and get a free port to communicate with
                    try:
                        csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        csock.bind((self.shost, 0))
                        self.cport = csock.getsockname()[1]
                        self.clientAddress = self.shost + ':' + str(self.cport)
                    except socket.error as e:
                        print("Error: ", e, file=sys.stderr)
                        self.redirectorClientTransport.close()
                        return

                    # Connected callback
                    def cbConnected(future: asyncio.Future):
                        try:
                            # Handle exception
                            exc = future.exception()
                            if exc is None:
                                print(self.peerAddress, 'connected to', self.serviceAddress)
                            else:
                                print("Error: Redirecting connection from " + self.peerAddress + ' to ' +
                                      self.serviceAddress + ":", exc)
                                # Close client connection
                                self.redirectorClientTransport.close()
                        except BrokenPipeError:
                            self.redirectorClientTransport.close()

                    # Create connection to service - we use our own socket to make our snat rule working
                    ctask = asyncio.ensure_future(self.create_service_connection(lambda: Server.ServiceClient(self),
                                                                                 csock, self.shost, self.sport))
                    ctask.add_done_callback(cbConnected)

                # Still none?
                else: self.redirectorClientTransport.close()

            # Send data to the service
            elif self.redirectorClientTransport is None:
                if data is not None: self.buffer.extend(data)

            # Send data
            else:
                try:
                    self.serviceTransport.write(data)
                except AttributeError:
                    pass

        def connection_lost(self, exc):
            if self.serviceTransport is not None:
                self.serviceTransport.close()
            try:
                if self.peerAddress and self.serviceAddress:
                    print(self.peerAddress, 'disconnected from', self.serviceAddress)

                print("Redirector client disconnected from", self.redirectorClientAddress)
            except BrokenPipeError: pass

            # Delete rules
            asyncio.ensure_future(Server.Iptables.deleteNatRules(self.clientAddress))

    class ServiceClient(asyncio.Protocol):
        """
        Connect to the original service ports
        """
        def __init__(self, redirectorServer):
            self.transport = None
            self.redirectorServer = redirectorServer
            self.redirectorClientTransport = redirectorServer.redirectorClientTransport

        def connection_made(self, transport: asyncio.Transport):
            self.transport = self.redirectorServer.serviceTransport = transport
            Server.serviceConnections.add(transport)
            # Send buffered data
            if len(self.redirectorServer.buffer) > 0:
                transport.write(self.redirectorServer.buffer)
                # No longer needed
                self.redirectorServer.buffer = None

        def connection_lost(self, exc):
            self.redirectorClientTransport.close()
            self.redirectorServer = None
            Server.serviceConnections.remove(self.transport)

        def data_received(self, data):
            if not self.redirectorClientTransport.is_closing():
                self.redirectorClientTransport.write(data)

    class Iptables(object):
        """
        IPTables handling
        """

        # Iptables command
        IPTABLES = 'iptables'

        # Rules by clientAddress
        rules = {}

        @classmethod
        async def call(cls, rule):
            res = False
            while not res:
                # Add waiting for LOCK_EX, and all our rules are in the "nat" table
                rule = ('-w', '-t', 'nat') + rule
                creator = asyncio.create_subprocess_exec(cls.IPTABLES, *rule, stderr=asyncio.subprocess.PIPE)
                proc = await creator
                # Read error messages
                error = await proc.stderr.readline()
                # Wait for exit, if exit code is 0 then it is successfull
                res = not await proc.wait()
                if not res:
                    # On resource error we need to try again
                    if error == b"iptables: Resource temporarily unavailable.\n":
                        continue
                    # Expected error
                    if error != b"iptables: No chain/target/match by that name.\n":
                        print("Error:", error.rstrip().decode())
                    break
            return res

        @classmethod
        async def addNatRules(cls, clientAddress, cport, shost, sport, phost, pport):
            dnatRule = (IPTABLES_CHAIN_PREFIX + 'DNAT', '-s', shost, '-d', phost, '-p', 'tcp', '-m', 'tcp',
                        '--sport', str(sport), '--dport', str(pport), '-j', 'DNAT', '--to-destination', clientAddress)
            if not await cls.call(('-I',) + dnatRule): return False

            snatRule = (IPTABLES_CHAIN_PREFIX + 'SNAT', '-s', shost, '-p', 'tcp', '-m', 'tcp',
                        '--sport', str(cport), '--dport', str(sport), '-j', 'SNAT', '--to-source',
                        phost + ':' + str(pport))
            if not await cls.call(('-I',) + snatRule): return False

            # Store rules for easier delete
            cls.rules[clientAddress] = (dnatRule, snatRule)

            return True

        @classmethod
        async def deleteNatRules(cls, clientAddress):
            try:
                dnatRule, snatRule = cls.rules[clientAddress]
                await cls.call(('-D',) + dnatRule)
                await cls.call(('-D',) + snatRule)
                # Delete from rule cache
                del cls.rules[clientAddress]
            except KeyError: pass

        @classmethod
        async def createChains(cls):
            # Create chains
            await cls.call(('-N', IPTABLES_CHAIN_PREFIX + 'DNAT'))
            await cls.call(('-N', IPTABLES_CHAIN_PREFIX + 'SNAT'))
            # Create NAT rules
            await cls.call(('-D', 'OUTPUT', '-j', IPTABLES_CHAIN_PREFIX + 'DNAT'))  # Try deleting 1st
            await cls.call(('-I', 'OUTPUT', '-j', IPTABLES_CHAIN_PREFIX + 'DNAT'))
            await cls.call(('-D', 'POSTROUTING', '-j', IPTABLES_CHAIN_PREFIX + 'SNAT'))  # Try deleting 1st
            await cls.call(('-I', 'POSTROUTING', '-j', IPTABLES_CHAIN_PREFIX + 'SNAT'))
            # Create RETURN rules
            await cls.call(('-A', IPTABLES_CHAIN_PREFIX + 'DNAT', '-j', 'RETURN'))
            await cls.call(('-A', IPTABLES_CHAIN_PREFIX + 'SNAT', '-j', 'RETURN'))

        @classmethod
        async def deleteChains(cls):
            await cls.call(('-D', 'OUTPUT', '-j' + IPTABLES_CHAIN_PREFIX + 'DNAT'))
            await cls.call(('-D', 'POSTROUTING', '-j' + IPTABLES_CHAIN_PREFIX + 'SNAT'))
            # Flush chains
            await cls.call(('-F', IPTABLES_CHAIN_PREFIX + 'DNAT'))
            await cls.call(('-F', IPTABLES_CHAIN_PREFIX + 'SNAT'))
            # Remove chains
            await cls.call(('-X', IPTABLES_CHAIN_PREFIX + 'DNAT'))
            await cls.call(('-X', IPTABLES_CHAIN_PREFIX + 'SNAT'))


class Client(object):
    """
    Client accepting and forwarding connections and data to the server
    """
    servers = []
    redirectorClientConnections = set()

    redirectorServerHost = None
    redirectorServerPort = None
    redirectorServerAddress = None

    loop = None

    @classmethod
    def createClient(cls, host, port, redirectingPorts):
        loop = asyncio.get_event_loop()
        Client.loop = loop

        try:
            Client.redirectorServerHost = host
            Client.redirectorServerPort = int(port)
            Client.redirectorServerAddress = host + ':' + str(port)

            # Create listen sockets for forwarding ports
            for forwardPort in redirectingPorts:
                if type(forwardPort) is str and ':' in forwardPort:
                    forwardHost, forwardPort = forwardPort.split(':')
                else:
                    forwardHost = '0.0.0.0'

                make_server = loop.create_server(Client.PeerServer, forwardHost, int(forwardPort), reuse_port=True)
                server = loop.run_until_complete(make_server)

                listenAddress = forwardHost + ':' + str(forwardPort)
                print('Waiting for client connections on {}...'.format(listenAddress))

                Client.servers.append(server)

            # Waiting until an end signal
            loop.run_forever()

            # Tasks for closing connections
            closeTasks = []

            # Close server connections
            for server in Client.servers:
                server.close()
                closeTasks.append(server.wait_closed())

            # Close client connections
            for redirectorClient in Client.redirectorClientConnections:
                redirectorClient.close()

            loop.run_until_complete(asyncio.wait(closeTasks))

        except RuntimeError:
            pass

        # Close the loop
        loop.close()

    class RedirectorClient(asyncio.Protocol):
        """
        Connect to redirector server
        """
        def __init__(self, peerServer):
            self.transport = None
            self.peerServer = peerServer
            self.peerTransport = peerServer.peerTransport

        def connection_made(self, redirectorTransport):
            # Send peer info to the redirector server as 1st message
            redirectorTransport.write(str.encode(self.peerServer.peerAddress + ':' + self.peerServer.lport + "\n"))
            # Now we can accept data from peers
            self.transport = self.peerServer.redirectorTransport = redirectorTransport
            Client.redirectorClientConnections.add(redirectorTransport)
            # Send buffered data
            if len(self.peerServer.buffer) > 0:
                redirectorTransport.write(self.peerServer.buffer)
            # No need the buffer anymore
            self.peerServer.buffer = None

        def data_received(self, data):
            self.peerTransport.write(data)

        def connection_lost(self, exc):
            self.peerTransport.close()
            self.peerServer = None
            Client.redirectorClientConnections.remove(self.transport)

    class PeerServer(asyncio.Protocol):
        """
        Accept connections on the service ports and transfer data through the client
        """
        def __init__(self):
            self.peerTransport = None
            self.redirectorTransport = None
            self.peerAddress = None
            self.lport = None
            self.listenAddress = None
            self.buffer = bytearray()

        def connection_made(self, peerTransport: asyncio.BaseTransport):
            self.peerTransport = peerTransport
            peername = peerTransport.get_extra_info('peername')
            sockname = peerTransport.get_extra_info('sockname')
            peerAddress = peername[0] + ':' + str(peername[1])
            self.lport = str(sockname[1])
            listenAddress = sockname[0] + ':' + self.lport
            self.peerAddress = peerAddress
            self.listenAddress = listenAddress

            # Connected callback
            def cbConnected(future: asyncio.Future):
                # Handle exception
                exc = future.exception()
                if exc is None:
                    print(peerAddress, 'connected to', listenAddress)
                else:
                    print("Error: Redirecting connection from " + peerAddress + ' to ' + listenAddress + " was failed!")
                    # Close client connection
                    peerTransport.close()

            # Create connection to redirector server
            ctask = asyncio.ensure_future(Client.loop.create_connection(
                lambda: Client.RedirectorClient(self),
                Client.redirectorServerHost, Client.redirectorServerPort))
            ctask.add_done_callback(cbConnected)

        def connection_lost(self, exc):
            self.peerTransport.close()
            if self.redirectorTransport is not None:
                self.redirectorTransport.close()
            print(self.peerAddress, 'disconnected from', self.listenAddress)

        def data_received(self, data):
            # If no server connection is ready, we store data into a buffer
            if self.redirectorTransport is None:
                self.buffer.extend(data)

            # Send data
            else:
                self.redirectorTransport.write(data)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description=__doc__)

    parser.add_argument('-l', '--listen', type=str, help='Start server on the specified interface and port (e.g '
                                                         '0.0.0.0:1234). If only port is specified 0.0.0.0 is used as '
                                                         'host.')
    parser.add_argument('-c', '--connect', type=str, help='Connect to the given server (e.g. 1.2.3.4:1234)')
    parser.add_argument('-p', '--port', action='append', type=str,
                        help='The original service port. The server will connect to this local port,'
                             'the client will listen on it and forward data to the server. '
                             'Multiple ports can be specified by more, separated --port parameters.'
                             'On client the ports can contain a listen address as well if not need to listen on all '
                             'interfaces (e.g. --port 1.1.1.1:443 --port 80).')
    parser.add_argument('-r', '--replace', action='append', type=str,
                        help='If the local port on the redirector client is not the same as the listen port on server '
                             'side, this parameter can replace the remote port sent by client to a new one. '
                             'The old and new port should be separated by comma (e.g. 80.1080)')

    args = parser.parse_args()

    if (not args.listen and not args.connect) or not args.port:
        parser.print_usage()
        exit(1)

    if args.listen and args.connect:
        print("Either client or server must be selected, not both!", file=sys.stderr)
        parser.print_usage()
        exit(2)

    forwardPorts = args.port
    replacePorts = args.replace

    # The event loop
    loop = asyncio.get_event_loop()

    # Signal handler for exiting the loop
    async def shutdown():
        print("\b\b", end='')  # Remove ^C from command line
        print("Shutting down...")
        asyncio.get_event_loop().stop()

    # Add signal handlers
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(shutdown()))

    # Start client or server based on listen or connect arguments
    if args.listen:
        try:
            if ':' in args.listen:
                host, port = args.listen.split(":")
            else:
                host = '0.0.0.0'
                port = int(args.listen)
            Server.createServer(host, port, forwardPorts, replacePorts)
        except ValueError:
            print("Wrong listen address format! It should be like 0.0.0.0:1234...", file=sys.stderr)
            parser.print_usage()
            exit(4)
    else:
        try:
            host, port = args.connect.split(":")
            Client.createClient(host, port, forwardPorts)
        except ValueError:
            print("Wrong address format! It should be like 0.0.0.0:1234...", file=sys.stderr)
            parser.print_usage()
            exit(5)


if __name__ == '__main__': main()
