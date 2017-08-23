#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import argparse
import asyncio
import async_timeout
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
__version__ = "0.3"
__maintainer__ = "Adam Wallner"
__email__ = "adam.wallner@gmail.com"
__status__ = "Production"


# The name of redirector iptables chain
IPTABLES_CHAIN_PREFIX = 'PYPORTREDIRECT_'

# Timeouts
CONNECT_TIMEOUT = 15  # sec - Timeout waiting for a good connection
READ_TIMEOUT = 120  # sec - The maximum time a connection can be opened without communication

# Socket read size, the maximum number of bytes can be read at once
READ_SIZE = 65536


def error(*args, **kwargs):
    """ Shortcut for printing errors """
    print(*args, file=sys.stderr, **kwargs)


class GoToEnd(Exception):
    """ Dummy exception to go to function exit and finalize if needed. """


class Server(object):
    """
    Server listening for redirector clients
    """

    def __init__(self, lhost: str, lport: int, servicePorts: list, replacePorts: list, loop=None):
        self.loop = loop or asyncio.get_event_loop()

        self.servicePorts = {}
        self.replacePorts = {}

        try:
            # Process service ports
            for sport in servicePorts:
                if ':' in sport:
                    fhost, sport = sport.split(':')
                else:
                    fhost = '127.0.0.1'
                sport = int(sport)
                self.servicePorts[sport] = (fhost, sport)

            # Process replace prots
            if replacePorts is not None:
                for rport in replacePorts:
                    rport = rport.split('.')
                    if len(rport) != 2: continue
                    self.replacePorts[int(rport[0])] = int(rport[1])

        except ValueError:
            error("Port numbers must be integer!")
            return

        # Initialize iptables
        self.loop.run_until_complete(Server.Iptables.createChains())

        # Create listen socket
        make_server = asyncio.start_server(self.handleConnection, lhost, int(lport),
                                           reuse_address=True, reuse_port=True, loop=self.loop)
        server = self.loop.run_until_complete(make_server)

        self.listenAddress = lhost + ':' + str(lport)
        print('Waiting for redirector client connections on {}…'.format(self.listenAddress))

        # Waiting until an end signal
        self.loop.run_forever()

        # Close server gracefully
        server.close()
        self.loop.run_until_complete(server.wait_closed())

        # Finalize iptables
        self.loop.run_until_complete(Server.Iptables.deleteChains())

        # Close the loop
        self.loop.close()

    async def handleConnection(self, redirectorClientReader: asyncio.StreamReader,
                               redirectorClientWriter: asyncio.StreamWriter):
        """ Handle connections from redirector clients """
        line = b''
        sport = pport = shost = phost = None
        serviceAddress = peerAddress = None
        serviceReader = serviceWriter = None
        redirectorClientAddress = None
        tasks = []

        try:
            # fix buffering issues (backpressure effect)
            redirectorClientWriter.transport.set_write_buffer_limits(0)
            # Get client address from socket
            peername = redirectorClientWriter.transport.get_extra_info('peername')
            redirectorClientAddress = peername[0] + ':' + str(peername[1])
            print('Redirector client connected from', redirectorClientAddress, 'to', self.listenAddress)

            try:
                with async_timeout.timeout(CONNECT_TIMEOUT, loop=self.loop):
                    try:
                        # Wait for the 1st packet (line), which is
                        line = await redirectorClientReader.readline()
                        ll = len(line)

                        # Validate message
                        if ll < 11 or ll > 28 or line[-1:] != b"\n" or b":" not in line:
                            raise ValueError()

                        peerData = line[:-1].decode()
                        phost, pport, sport = peerData.split(':')
                        # The address of the peer
                        peerAddress = phost + ':' + pport
                        pport = int(pport)
                        # Parse service port
                        shost, sport = self.servicePorts[int(sport)]
                        # Replace ports
                        if sport in self.replacePorts:
                            sport = self.replacePorts[sport]
                        serviceAddress = shost + ':' + str(sport)

                    except ValueError: pass

                    except KeyError:
                        error("Error: No service is on the specified port: {!r}".format(line))
                        raise GoToEnd()

            except asyncio.TimeoutError:
                error('Error: Client', redirectorClientAddress, 'protocol error, no data in time!')
                raise GoToEnd()

            except BrokenPipeError:
                error('Client has immediately closed connection!')
                raise GoToEnd()

            if sport is None:
                error('Error: Client', redirectorClientAddress, 'protocol error!')
                raise GoToEnd()

            # Here we know the peer address and port and the destination port as well so we can create the iptables
            # rules and connect to
            try:
                # Create a socket and get a free port to communicate with. We need to use our own socket to be able to
                #  get listening port and create iptables rules before connection
                csock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                csock.bind((shost, 0))
                scport = csock.getsockname()[1]
                serviceClientAddress = shost + ':' + str(scport)
            except socket.error as e:
                error("Socket error: ", e)
                raise GoToEnd()

            try:
                with async_timeout.timeout(CONNECT_TIMEOUT, loop=self.loop):
                    print(peerAddress, "connecting through", redirectorClientAddress + '…')
                    # Add IPTables rules
                    res = await Server.Iptables.addNatRules(redirectorClientAddress, serviceClientAddress,
                                                            scport, shost, sport, phost, pport)
                    # Exit if not connected or no rules
                    if res != 0: raise GoToEnd()
                    try:
                        # Use our own socket to connect
                        csock.setblocking(False)
                        await self.loop.sock_connect(csock, (shost, sport))
                        serviceReader, serviceWriter = await asyncio.open_connection(sock=csock)
                    except (ConnectionError, BrokenPipeError, OSError, GeneratorExit):
                        error("Error: service connection from", peerAddress, 'to', serviceAddress, 'is failed!')
                        raise GoToEnd()

            except asyncio.TimeoutError:
                error('Error: service', serviceAddress, 'connection error timeout!')
                raise GoToEnd()

            if not serviceReader or not serviceWriter:
                error('Error: service', serviceAddress, 'connection error!')
                raise GoToEnd()

            # Here connection successfull
            print(peerAddress, 'through', redirectorClientAddress, 'connected to', serviceAddress)

            async def relayStream(reader, writer, otherWriter):
                """ Transfer data from reader to writer """
                try:
                    while True:
                        # Stop if no data has received in time
                        with async_timeout.timeout(READ_TIMEOUT, loop=self.loop):
                            try:
                                await writer.drain()
                                data = await reader.read(READ_SIZE)
                                l = len(data)
                                if l == 0:  # EOF
                                    if not otherWriter.transport.is_closing():
                                        if reader == redirectorClientReader:
                                            print('Peer ', peerAddress, 'through', redirectorClientAddress,
                                                  'has closed connection to', serviceAddress)
                                        else:
                                            print('Service', serviceAddress,
                                                  'has closed connection from peer', peerAddress,
                                                  'through', redirectorClientAddress)
                                    break
                                writer.write(data)
                            except (ConnectionError, BrokenPipeError):
                                if reader == redirectorClientReader:
                                    error('Peer', peerAddress, 'through', redirectorClientAddress,
                                          'has disconnected from service', serviceAddress)
                                else:
                                    error('Service', serviceAddress, 'has disconnected from peer', peerAddress,
                                          'through', redirectorClientAddress)
                                break
                except OSError as err:
                    error('Error: OS error:', str(err))

                except asyncio.TimeoutError:
                    if reader == redirectorClientReader:
                        error('Peer', peerAddress, 'through', redirectorClientAddress,
                              'read timeout occured. Closing connection.')
                    else:
                        error('Service', serviceAddress, 'read timeout occured. Closing connection.')

                except asyncio.CancelledError: pass

                # Close connection
                if not writer.transport.is_closing():
                    await writer.drain()
                    writer.close()
                    # To let the socket actually close
                    await asyncio.sleep(0, loop=self.loop)

            # Create relay tasks
            tasks = [
                asyncio.ensure_future(relayStream(redirectorClientReader, serviceWriter, redirectorClientWriter),
                                      loop=self.loop),
                asyncio.ensure_future(relayStream(serviceReader, redirectorClientWriter, serviceWriter),
                                      loop=self.loop)
            ]

            # Stop waiting when any connection endpoint has closed
            done, pending = await asyncio.wait(tasks, loop=self.loop, return_when=asyncio.FIRST_COMPLETED)
            # Cancel remaining task
            for task in pending: task.cancel()
            if pending: await asyncio.wait(pending, loop=self.loop, timeout=1)
            tasks = []

        except asyncio.CancelledError: pass
        except GoToEnd: pass

        finally:
            # If we have pending tasks, close them
            if tasks:
                for task in tasks: task.cancel()
                await asyncio.wait(tasks, loop=self.loop, timeout=1)
            # Close connection from the client if still connected
            if not redirectorClientWriter.transport.is_closing():
                await redirectorClientWriter.drain()
                redirectorClientWriter.close()
            # Close connection to the service if still connected
            if serviceWriter and not serviceWriter.transport.is_closing():
                await serviceWriter.drain()
                serviceWriter.close()
            # Delete iptables rules
            if redirectorClientAddress and Server.Iptables.hasNatRule(redirectorClientAddress):
                await Server.Iptables.deleteNatRules(redirectorClientAddress)

    class Iptables(object):
        """
        Asynchronous IPTables handling
        """

        # Iptables command
        IPTABLES = 'iptables'

        # Rules by redirectorClientAddress
        rules = {}

        @classmethod
        async def call(cls, rule):
            while True:
                # All our rules are in the "nat" table
                rule = ('-t', 'nat') + rule
                creator = asyncio.create_subprocess_exec(cls.IPTABLES, *rule, stderr=asyncio.subprocess.PIPE)
                proc = await creator
                # Wait for exit and get exit code
                res = await proc.wait()
                # Read error messages
                err = await proc.stderr.readline()
                # Handle errors
                if res:
                    # On lock (res == 4) or resource error we need to try again
                    if res == 4 or err == b"iptables: Resource temporarily unavailable.\n":
                        continue
                    # Expected errors
                    if res != 1 or (err != b"iptables: No chain/target/match by that name.\n" and
                                    err != b"iptables: Chain already exists.\n"):
                        error("Error (" + str(res) + "): " + err.rstrip().decode())
                # We are done
                break
            return res

        @classmethod
        def hasNatRule(cls, redirectorClientAddress):
            return redirectorClientAddress in cls.rules

        @classmethod
        async def addNatRules(cls, redirectorClientAddress, clientAddress, cport, shost, sport, phost, pport):
            dnatRule = (IPTABLES_CHAIN_PREFIX + 'DNAT', '-s', shost, '-d', phost, '-p', 'tcp', '-m', 'tcp',
                        '--sport', str(sport), '--dport', str(pport), '-j', 'DNAT', '--to-destination', clientAddress)
            res = await cls.call(('-I',) + dnatRule)

            if res == 0:
                snatRule = (IPTABLES_CHAIN_PREFIX + 'SNAT', '-s', shost, '-p', 'tcp', '-m', 'tcp',
                            '--sport', str(cport), '--dport', str(sport), '-j', 'SNAT', '--to-source',
                            phost + ':' + str(pport))
                res = await cls.call(('-I',) + snatRule)

                cls.rules[redirectorClientAddress] = (dnatRule, snatRule)
                if res != 0:
                    cls.deleteNatRules(redirectorClientAddress)

            return res

        @classmethod
        async def deleteNatRules(cls, redirectorClientAddress):
            try:
                dnatRule, snatRule = cls.rules[redirectorClientAddress]
                await cls.call(('-D',) + dnatRule)
                await cls.call(('-D',) + snatRule)

                # Delete from rule cache
                del cls.rules[redirectorClientAddress]

            # If the address is not in the list of rules
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

    def __init__(self, host: str, port: int, redirectingPorts: list, loop=None):
        self.loop = loop or asyncio.get_event_loop()

        servers = []

        try:
            self.redirectorServerHost = host
            self.redirectorServerPort = int(port)
            self.redirectorServerAddress = host + ':' + str(port)

            # Create listen sockets for forwarding ports
            for forwardPort in redirectingPorts:
                if type(forwardPort) is str and ':' in forwardPort:
                    forwardHost, forwardPort = forwardPort.split(':')
                else:
                    forwardHost = '0.0.0.0'

                make_server = asyncio.start_server(self.handleConnection, forwardHost, int(forwardPort),
                                                   reuse_address=True, reuse_port=True, loop=self.loop)
                server = self.loop.run_until_complete(make_server)

                listenAddress = forwardHost + ':' + str(forwardPort)
                print('Waiting for peer connections on {}…'.format(listenAddress))

                servers.append(server)

            # Waiting until an end signal
            self.loop.run_forever()

            # Tasks for closing connections
            closeTasks = []

            # Close server connections
            for server in servers:
                server.close()
                closeTasks.append(server.wait_closed())

            self.loop.run_until_complete(asyncio.wait(closeTasks, loop=self.loop, timeout=5))

        except RuntimeError:
            pass

        # Close the loop
        self.loop.close()

    async def handleConnection(self, peerReader: asyncio.StreamReader, peerWriter: asyncio.StreamWriter):
        """ Accepts peer connections """
        redirectorReader = redirectorWriter = None
        tasks = []
        try:
            # fix buffering issues (backpressure effect)
            peerWriter.transport.set_write_buffer_limits(0)
            # Get socket info
            peername = peerWriter.get_extra_info('peername')
            sockname = peerWriter.get_extra_info('sockname')
            # Calculate peer and liten address info
            peerAddress = peername[0] + ':' + str(peername[1])
            listenPort = str(sockname[1])
            listenAddress = sockname[0] + ':' + listenPort
            print('Peer', peerAddress, 'connected to', listenAddress)

            # Connect to redirector server
            try:
                with async_timeout.timeout(CONNECT_TIMEOUT, loop=self.loop):
                    try:
                        redirectorReader, redirectorWriter = await asyncio.open_connection(self.redirectorServerHost,
                                                                                           self.redirectorServerPort,
                                                                                           ssl=False)
                        # fix buffering issues (backpressure effect)
                        redirectorWriter.transport.set_write_buffer_limits(0)
                        # Send peer info to the redirector server as 1st message
                        redirectorWriter.write(str.encode(peerAddress + ':' + listenPort + '\n'))

                    except (ConnectionError, BrokenPipeError, GeneratorExit, OSError):
                        error('Error: Redirecting connection from ' + peerAddress + ' to ' +
                              listenAddress + ' is failed!')

            except asyncio.TimeoutError:
                error('Error: Redirecting connection from ' + peerAddress + ' to ' + listenAddress +
                      ' was failed because of timeout!')

            # If connection was unsuccessfull
            if not redirectorReader or not redirectorWriter: raise GoToEnd()

            print("Peer", peerAddress, 'redirected to', self.redirectorServerAddress)

            async def relayStream(reader, writer, otherWriter):
                """ Transfer data from reader to writer """
                try:
                    while True:
                        # Stop if no data has received in time
                        with async_timeout.timeout(READ_TIMEOUT, loop=self.loop):
                            try:
                                await writer.drain()
                                data = await reader.read(READ_SIZE)
                                l = len(data)
                                if l == 0:  # EOF
                                    if not otherWriter.transport.is_closing():
                                        if reader == peerReader:
                                            print('Peer', peerAddress, 'has closed connection to',
                                                  self.redirectorServerAddress)
                                        else:
                                            print('Redirector', self.redirectorServerAddress,
                                                  'has closed connection from peer', peerAddress)
                                    break
                                writer.write(data)
                            except (ConnectionError, BrokenPipeError):
                                if reader == peerReader:
                                    error('Peer', peerAddress, 'has disconnected from', self.redirectorServerAddress)
                                else:
                                    error('Redirector', self.redirectorServerAddress,
                                          'has disconnected from', peerAddress)
                                break

                except OSError as e:
                    error('Error: OS error:', str(e))

                except asyncio.TimeoutError:
                    if reader == peerReader:
                        error('Peer', peerAddress, 'read timeout occured. Closing connection.')
                    else:
                        error('Redirector', self.redirectorServerAddress, 'read timeout occured. Closing connection.')

                except asyncio.CancelledError: pass

                # Close connection
                if not writer.transport.is_closing():
                    await writer.drain()
                    writer.close()
                    # To let the socket actually close
                    await asyncio.sleep(0, loop=self.loop)

            # Create relay tasks
            tasks = [
                asyncio.ensure_future(relayStream(peerReader, redirectorWriter, peerWriter), loop=self.loop),
                asyncio.ensure_future(relayStream(redirectorReader, peerWriter, redirectorWriter), loop=self.loop)
            ]

            # Stop waiting when any connection endpoint has closed
            done, pending = await asyncio.wait(tasks, loop=self.loop, return_when=asyncio.FIRST_COMPLETED)
            # Cancel remaining task
            for task in pending: task.cancel()
            if pending: await asyncio.wait(pending, loop=self.loop, timeout=1)
            tasks = []

        except BrokenPipeError:
            error('Error: Peer has immediately closed connection!')

        except asyncio.CancelledError: pass
        except GoToEnd: pass

        finally:
            # If we have pending tasks close them
            if tasks:
                for task in tasks: task.cancel()
                await asyncio.wait(tasks, loop=self.loop, timeout=1)
            # Close peer connection if still opened
            if not peerWriter.transport.is_closing():
                await peerWriter.drain()
                peerWriter.close()
            # Close redirector connection if still opened
            if redirectorWriter and not redirectorWriter.transport.is_closing():
                await redirectorWriter.drain()
                redirectorWriter.close()


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
        error("Either client or server must be selected, not both!")
        parser.print_usage()
        exit(2)

    forwardPorts = args.port
    replacePorts = args.replace

    # The event loop
    loop = asyncio.get_event_loop()

    # Signal handler for exiting the loop
    async def shutdown():
        print("\r", end='')  # Remove ^C from command line
        print("Shutting down…")

        # Find all running tasks:
        pending = asyncio.Task.all_tasks()
        # Cancel all still running tasks (except this shutdown task)
        for task in pending:
            if task is not asyncio.Task.current_task():
                task.cancel()

        # Stop loop
        loop.stop()

    # Add signal handlers
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGABRT):
        loop.add_signal_handler(sig, lambda: loop.create_task(shutdown()))

    # Start client or server based on listen or connect arguments
    if args.listen:  # Server
        try:
            if ':' in args.listen:
                host, port = args.listen.split(":")
            else:
                host = '0.0.0.0'
                port = int(args.listen)
            Server(host, port, forwardPorts, replacePorts, loop=loop)
        except ValueError:
            error("Wrong listen address format! It should be like 0.0.0.0:1234…")
            parser.print_usage()
            exit(4)
    else:  # Client
        try:
            host, port = args.connect.split(":")
            Client(host, port, forwardPorts, loop=loop)
        except ValueError:
            error("Wrong address format! It should be like 0.0.0.0:1234…")
            parser.print_usage()
            exit(4)


if __name__ == '__main__': main()
