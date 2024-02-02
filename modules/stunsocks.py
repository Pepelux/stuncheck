#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import socket
import ssl
import struct
import sys
import socket
import threading
from lib.color import Color
from lib.logos import Logo
from lib.functions import header_parse, attributes_parse, build_request, xor_address_parse


class StunSocks:
    def __init__(self):
        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'

        self.quit = False

        self.c = Color()

        self.user = ''
        self.pwd = ''

        self.socks_host = '127.0.0.1'
        self.socks_port = 1080

        self.sock = None
        self.sock2 = None
        self.ssl_sock = None
        self.ssl_sock2 = None

    def start(self):
        supported_protos = ['TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('stunsocks')
        logo.print()

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.WHITE)

        # seerver SOCK5 socket
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((self.socks_host, self.socks_port))
        server.listen(5)

        print(self.c.BYELLOW +
              f"Server started on {self.socks_host}:{self.socks_port}")

        try:
            while True:
                client_socket, _ = server.accept()
                client_handler = threading.Thread(
                    target=self.handle_client, args=(client_socket,))
                client_handler.setDaemon(True)
                client_handler.start()
        except KeyboardInterrupt:
            print(self.c.BYELLOW + "Shutting down the server..." + self.c.WHITE)
            server.close()

    # handle client connections
    def handle_client(self, client_socket):
        self.socks5_handshake(client_socket)
        self.socks5_request(client_socket, 0)

    # manage handshakes
    def socks5_handshake(self, client_socket):
        client_socket.recv(1)  # Read the version byte
        nmethods = ord(client_socket.recv(1))
        client_socket.recv(nmethods)  # Read the methods
        client_socket.sendall(b'\x05\x00')  # Send the selected method

    # manage client connections
    def socks5_request(self, client_socket, conn_status):
        response = b''

        try:
            version, cmd, _, atyp = struct.unpack(
                '!BBBB', client_socket.recv(4))
            if atyp == 1:  # IPv4
                addr = socket.inet_ntoa(client_socket.recv(4))
            elif atyp == 3:  # Domain name
                domain_length = ord(client_socket.recv(1))
                addr = client_socket.recv(domain_length)
            elif atyp == 4:  # IPv6
                addr = socket.inet_ntop(
                    socket.AF_INET6, client_socket.recv(16))
            else:
                client_socket.close()
                return

            port = struct.unpack('!H', client_socket.recv(2))[0]

            if cmd == 1:  # CONNECT
                remote_socket = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
                try:
                    remote_socket.connect((addr, port))
                except:
                    print("Error de conexión")

                # no authentication required
                client_socket.sendall(
                    b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')

                while True:
                    data = client_socket.recv(4096)
                    print(data)
                    if not data:
                        break
                    # send data through the TURN server
                    if conn_status == 0:
                        response = self.socks_init(addr, port)

                    response = self.socks_send(data)
                    conn_status = 1
                    # send response to the client
                    client_socket.sendall(response)
            else:
                client_socket.close()
        except Exception as e:
            print(f"Error: {e}")
        finally:
            if self.verbose > 0:
                print(self.c.BWHITE +
                      "[✓] Connection closed by the client" + self.c.WHITE)
            client_socket.close()
            self.socks_close()

    # connections to the TURN server
    def socks_init(self, dsthost, dstport):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            exit()

        ###
        # First connection => Send a Connection Bind Request to relay traffic
        ###
        response = b''

        try:
            addr = (self.ip, self.rport)

            self.sock.settimeout(2)

            if self.proto == 'TLS':
                self.sock_ssl = ssl.wrap_socket(
                    self.sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

                self.sock_ssl.connect(addr)
            else:
                if self.proto == 'TCP':
                    self.sock.connect(addr)

            # First request to obtain nonce and realm values (Allocate Request)
            transaction_id = random.randint(0, 0xFFFFFFFFFFFFFFFFFFFF)

            message = build_request(3, transaction_id, '06', True, '')

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            if self.verbose > 0:
                print(self.c.BWHITE + "[=>] " + self.c.GREEN +
                      headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request 1")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            if self.proto == 'TLS':
                self.sock_ssl.sendall(message)
                response = self.sock_ssl.recv(1024)
            else:
                self.sock.sendto(message, addr)
                response = self.sock.recv(1024)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            if self.verbose > 0:
                try:
                    print(self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] +
                          self.c.RED + ' (' + attributes['ERROR-CODE'] + ')' + self.c.WHITE)
                except:
                    print(
                        self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response 1")
                print(self.c.YELLOW + str(response.hex()))
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            realm = attributes['REALM']
            nonce = attributes['NONCE']

            # Second request (Allocate Request)
            message = build_request(
                3, transaction_id, '06', False, '', self.user, realm, nonce, self.pwd)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            if self.verbose > 0:
                try:
                    print(self.c.BWHITE + "[=>] " + self.c.GREEN + headers['MESSAGE_TYPE'] + self.c.CYAN + ' (username: ' + attributes['USERNAME'] + ' - ' +
                          'realm: ' + realm + ' - ' + 'nonce: ' + nonce + ')' + self.c.WHITE)
                except:
                    print(
                        self.c.BWHITE + "[=>] " + self.c.GREEN + headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request 2")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            if self.proto == 'TLS':
                self.sock_ssl.sendall(message)
                response = self.sock_ssl.recv(1024)
            else:
                self.sock.sendto(message, addr)
                response = self.sock.recv(1024)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            try:
                if self.verbose > 0:
                    print(self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] +
                          self.c.RED + ' (' + attributes['ERROR-CODE'] + ')' + self.c.WHITE)
                if attributes['ERROR-CODE']:
                    print(self.c.BWHITE + "[x] Connection error: " +
                          self.c.RED + 'Relay not allowed' + self.c.WHITE)
                    print()
                exit()
            except:
                if self.verbose > 0:
                    print(
                        self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)
                print(self.c.BWHITE + "[✓] Connection established to: " +
                      self.c.GREEN + self.ip + ':' + str(self.rport) + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response 2")
                print(self.c.YELLOW + response.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            # Third request (Connect Request)
            ipaddr = socket.gethostbyname(dsthost)
            ipaddr = ipaddr + ':' + str(dstport)

            message = build_request(
                10, transaction_id, '06', False, ipaddr, self.user, realm, nonce, self.pwd)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            try:
                print(self.c.BWHITE + "[✓] " + headers['MESSAGE_TYPE'] +
                      ': ' + self.c.GREEN + ipaddr + self.c.WHITE)
            except:
                print(self.c.RED + 'ERROR')
                exit()

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request 3")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            if self.proto == 'TLS':
                self.sock_ssl.sendall(message)
                response = self.sock_ssl.recv(1024)
            else:
                self.sock.sendto(message, addr)
                response = self.sock.recv(1024)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            try:
                if self.verbose > 0:
                    print(self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] +
                          self.c.RED + ' (' + attributes['ERROR-CODE'] + ')' + self.c.WHITE)
                if attributes['ERROR-CODE']:
                    print(self.c.BWHITE + "[x] Connection error: " +
                          self.c.RED + 'Relay not allowed' + self.c.WHITE)
                    print()
                exit()
            except:
                if self.verbose > 0:
                    print(
                        self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)
                print(self.c.BWHITE +
                      "[✓] Destination accepted" + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response 3")
                print(self.c.YELLOW + response.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            connectionid = attributes['CONNECTION-ID']

            try:
                self.sock2 = socket.socket(
                    socket.AF_INET, socket.SOCK_STREAM)
            except socket.error:
                print(self.c.RED + 'Failed to create socket')
                exit()

            self.sock2.settimeout(5)

            if self.proto == 'TLS':
                self.sock_ssl2 = ssl.wrap_socket(
                    self.sock2, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

                self.sock_ssl2.connect(addr)
            else:
                if self.proto == 'TCP':
                    self.sock2.connect(addr)

            # Fourth request (ConnectionBind Request)
            message = build_request(
                11, transaction_id, '06', False, '', self.user, realm, nonce, self.pwd, connectionid)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            if self.verbose > 0:
                print(self.c.BWHITE + "[=>] " + self.c.GREEN +
                      headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request 4")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)

            if self.proto == 'TLS':
                self.sock_ssl2.sendall(message)
                response = self.sock_ssl2.recv(1024)
            else:
                self.sock2.sendto(message, addr)
                response = self.sock2.recv(1024)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            try:
                if self.verbose > 0:
                    print(self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] +
                          self.c.RED + ' (' + attributes['ERROR-CODE'] + ')' + self.c.WHITE)
                if attributes['ERROR-CODE']:
                    print(self.c.BWHITE + "[x] Connection error: " +
                          self.c.RED + 'Relay not allowed' + self.c.WHITE)
                    print()
                exit()
            except:
                if self.verbose > 0:
                    print(
                        self.c.BWHITE + "[<=] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)
                print(self.c.BWHITE +
                      "[✓] Connection successfully linked" + self.c.WHITE)
                print()

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response 4")
                print(self.c.YELLOW + response.hex())
                print(self.c.WHITE)

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

                self.print(headers, attributes)
        except socket.timeout:
            print(self.c.RED + "Socket Timeout" + self.c.WHITE)
            exit()
        except:
            pass

        return response

    # send requests through the TURN server
    def socks_send(self, data):
        response = b''

        try:
            addr = (self.ip, self.rport)

            if self.verbose > 0:
                print(self.c.BWHITE +
                      "[=>] " + self.c.GREEN + 'Request:' + self.c.WHITE)
                try:
                    print(data.decode())
                except:
                    print(data)

            if self.proto == 'TLS':
                self.sock_ssl2.sendall(data)
            else:
                self.sock2.sendto(data, addr)

            try:
                while True:
                    if self.proto == 'TLS':
                        response += self.sock_ssl2.recv(4096)
                    else:
                        response += self.sock2.recv(4096)
            except:
                if self.verbose > 0:
                    print()

            if self.verbose > 0:
                print(self.c.BWHITE +
                      "[<=] " + self.c.YELLOW + 'Response:' + self.c.WHITE)
                try:
                    print(response.decode())
                except:
                    print(response)
        except socket.timeout:
            print(self.c.RED + "Socket Timeout" + self.c.WHITE)
            exit()
        except:
            pass

        return response

    # close sockets
    def socks_close(self):
        try:
            self.sock.close()
            self.sock2.close()

            if self.proto == 'TLS':
                self.sock_ssl.close()
                self.sock_ssl2.close()
        except:
            pass

    def print(self, headers, attributes):
        print(self.c.BWHITE + '[+] Headers:')

        print(self.c.BWHITE + '  [-]  ' + self.c.BLUE + 'Message Type: ' +
              self.c.YELLOW + headers['MESSAGE_TYPE'])
        print(self.c.BWHITE + '  [-]  ' + self.c.BLUE + 'Message Cookie: ' +
              self.c.YELLOW + headers['COOKIE'])
        print(self.c.BWHITE + '  [-]  ' + self.c.BLUE + 'Transaction ID: ' +
              self.c.YELLOW + headers['TRANSACTION_ID'])

        print(self.c.BWHITE + '[+] Attributes:')

        for a in attributes:
            try:
                print(self.c.BWHITE + '  [-]  ' + a + ": " +
                      self.c.GREEN + attributes[a] + self.c.WHITE)
            except:
                try:
                    input_bits = ''.join(format(byte, '08b')
                                         for byte in attributes[a])
                    att = xor_address_parse(input_bits)
                    print(self.c.BWHITE + '  [-]  ' + a + ": " + self.c.GREEN + att["ip"] +
                          self.c.WHITE + ":" + self.c.YELLOW + str(att["port"]) + self.c.WHITE)
                except:
                    hex_string = ''.join(format(byte, '02x')
                                         for byte in attributes[a])
                    print(self.c.BWHITE + '  [-]  ' + a + ": " +
                          self.c.GREEN + hex_string + self.c.WHITE)

        print(self.c.WHITE)
