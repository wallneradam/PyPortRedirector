#!/usr/bin/python3 -u
# -*- coding: utf-8 -*-

import sys
import argparse
import asyncio
import socket
import signal
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

try:
    import iptc
except ImportError:
    iptc = None
    print("Error: Package python-iptables is needed.", file=sys.stderr)
    exit(11)

try:
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

# Global lock for iptables
iptLock = Lock()


class Server(object):
    """
    Server listening for portredirector clients
    """
    servicePorts = {}
    replacePorts = {}

    serviceConnections = set()

    loop = None

    ipt_nat_table = None
    ipt_snat_chain = None
    ipt_dnat_chain = None

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

        ipt_nat_table = iptc.Table(iptc.Table.NAT)
        ipt_nat_table.autocommit = False
        Server.ipt_nat_table = ipt_nat_table
        # Refresh table
        ipt_nat_table.refresh()
        # Create iptables chains
        try:
            Server.ipt_snat_chain = ipt_nat_table.create_chain(IPTABLES_CHAIN_PREFIX + 'SNAT')
        except iptc.ip4tc.IPTCError:
            Server.ipt_snat_chain = iptc.Chain(ipt_nat_table, IPTABLES_CHAIN_PREFIX + 'SNAT')
            Server.ipt_snat_chain.flush()
        try:
            Server.ipt_dnat_chain = ipt_nat_table.create_chain(IPTABLES_CHAIN_PREFIX + 'DNAT')
        except iptc.ip4tc.IPTCError:
            Server.ipt_dnat_chain = iptc.Chain(ipt_nat_table, IPTABLES_CHAIN_PREFIX + 'DNAT')
            Server.ipt_dnat_chain.flush()
        # Create SNAT rule
        snatChain = iptc.Chain(ipt_nat_table, 'POSTROUTING')
        snat_rule = iptc.Rule()
        snat_rule.create_target(IPTABLES_CHAIN_PREFIX + 'SNAT')
        try: snatChain.delete_rule(snat_rule)
        except iptc.ip4tc.IPTCError: pass
        snatChain.insert_rule(snat_rule)
        # Create DNAT rule - (OUTPUT because local packets don't touch prerouting chain)
        dnatChain = iptc.Chain(ipt_nat_table, 'OUTPUT')
        dnat_rule = iptc.Rule()
        dnat_rule.create_target(IPTABLES_CHAIN_PREFIX + 'DNAT')
        try: dnatChain.delete_rule(dnat_rule)
        except iptc.ip4tc.IPTCError: pass
        dnatChain.insert_rule(dnat_rule)
        # Create RETURN rules
        return_rule = iptc.Rule()
        return_rule.create_target('RETURN')
        Server.ipt_snat_chain.append_rule(return_rule)
        return_rule = iptc.Rule()
        return_rule.create_target('RETURN')
        Server.ipt_dnat_chain.append_rule(return_rule)

        # Commit table
        ipt_nat_table.commit()

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

        # Delete iptables rules and chains
        ipt_nat_table.refresh()
        Server.ipt_snat_chain.flush()
        Server.ipt_dnat_chain.flush()
        snatChain.delete_rule(snat_rule)
        dnatChain.delete_rule(dnat_rule)
        ipt_nat_table.commit()
        ipt_nat_table.delete_chain(Server.ipt_snat_chain)
        ipt_nat_table.delete_chain(Server.ipt_dnat_chain)

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

        def create_rules(self):
            """ Create iptables DNAT and SNAT rules """
            with iptLock:
                # Refresh rules
                Server.ipt_nat_table.refresh()

                # Create iptables SNAT rule
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                rule.src = self.shost
                match = rule.create_match('tcp')
                match.sport = str(self.cport)
                match.dport = str(self.sport)
                target = rule.create_target('SNAT')
                target.to_source = self.peerAddress
                Server.ipt_snat_chain.insert_rule(rule)
                self.snatRule = rule

                # Create iptables DNAT rule
                rule = iptc.Rule()
                rule.protocol = 'tcp'
                rule.src = self.shost
                rule.dst = self.phost
                match = rule.create_match('tcp')
                match.sport = str(self.sport)
                match.dport = str(self.pport)
                target = rule.create_target('DNAT')
                target.to_destination = self.clientAddress
                Server.ipt_dnat_chain.insert_rule(rule)
                self.dnatRule = rule

                # Commit changes
                Server.ipt_nat_table.commit()

        def delete_rules(self):
            """ Remove iptables nat rules """
            with iptLock:
                # Refresh table
                Server.ipt_nat_table.refresh()
                try:
                    if self.snatRule: Server.ipt_snat_chain.delete_rule(self.snatRule)
                except iptc.ip4tc.IPTCError:
                    pass
                try:
                    if self.dnatRule: Server.ipt_dnat_chain.delete_rule(self.dnatRule)
                    # Commit changes
                    Server.ipt_nat_table.commit()
                except iptc.ip4tc.IPTCError:
                    pass

        async def create_service_connection(self, protocol_factory, sock, host, port):
            """ Create iptables rules and connect to service """
            loop = Server.loop
            await loop.run_in_executor(None, self.create_rules)
            sock.setblocking(False)
            await loop.sock_connect(sock, (host, port))
            transport, protocol = await loop.create_connection(protocol_factory, sock=sock)
            return transport, protocol

        def connection_made(self, redirectorClientTransport):
            self.redirectorClientTransport = redirectorClientTransport
            peername = redirectorClientTransport.get_extra_info('peername')
            self.redirectorClientAddress = peername[0] + ':' + str(peername[1])
            print('Redirector client connection from ' + self.redirectorClientAddress)

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
                        # Handle exception
                        exc = future.exception()
                        if exc is None:
                            print(self.peerAddress, 'connected to', self.serviceAddress)
                        else:
                            print("Error: Redirecting connection from " + self.peerAddress + ' to ' +
                                  self.serviceAddress + ":", exc)
                            # Close client connection
                            self.redirectorClientTransport.close()

                    # Create connection to service - we use our own socket to make our snat rule working
                    ctask = asyncio.ensure_future(self.create_service_connection(
                        lambda: Server.ServiceClient(self),
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

            if self.peerAddress and self.serviceAddress:
                print(self.peerAddress, 'disconnected from', self.serviceAddress)

            print("Redirector client disconnected from", self.redirectorClientAddress)

            # Delete rules in non blocking way
            asyncio.ensure_future(Server.loop.run_in_executor(None, self.delete_rules))

    class ServiceClient(asyncio.Protocol):
        """
        Connect to the original service ports
        """
        def __init__(self, redirectorServer):
            self.transport = None
            self.redirectorServer = redirectorServer
            self.redirectorClientTransport = redirectorServer.redirectorClientTransport

        def connection_made(self, transport):
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
            self.redirectorClientTransport.write(data)


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
    parser.add_argument('-t', '--threads', type=int, help='Starting more worker threads. By default it is 2.',
                        default=2)

    args = parser.parse_args()

    if (not args.listen and not args.connect) or not args.port:
        parser.print_usage()
        exit(1)

    if args.listen and args.connect:
        print("Either client or server must be selected, not both!", file=sys.stderr)
        parser.print_usage()
        exit(2)

    if args.threads and args.threads < 1:
        print("The worker-thread parameter must be greater than 0!")
        exit(3)
    threadCount = args.threads

    forwardPorts = args.port
    replacePorts = args.replace

    # The event loop
    loop = asyncio.get_event_loop()

    # Process executor
    loop.set_default_executor(ThreadPoolExecutor(threadCount))

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
