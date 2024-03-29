#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

import random
import socket
import ssl
import sys
from lib.color import Color
from lib.logos import Logo
from lib.functions import header_parse, attributes_parse, build_request, get_protocol


class StunTransports:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'
        self.transport = ''

        self.quit = False

        self.c = Color()

        self.user = ''
        self.pwd = ''

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        self.verbose = int(self.verbose)

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        # check remote port
        if self.rport < 1 or self.rport > 65535:
            print(self.c.BRED + 'Invalid remote port %s' % self.rport)
            sys.exit()

        logo = Logo('stuntransports')
        logo.print()

        if self.proto == 'UDP':
            transport = '11'
        else:
            transport = '06'

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.BWHITE + '[✓] Username: ' + self.c.GREEN + '%s' %
              self.user)
        print(self.c.BWHITE + '[✓] Password: ' + self.c.GREEN + '%s' %
              self.pwd)
        print(self.c.WHITE)

        for i in range(256):
            if self.quit == False:
                transport = str(hex(i))[2:].zfill(2)
                if self.transport == transport or self.transport == '':
                    self.send_request_auth(self.user, self.pwd, transport)

        print(self.c.WHITE)

    # Send request to auth user
    def send_request_auth(self, username, password, protocol):
        if protocol == '06':
            proto = 'TCP'
        elif protocol == '11':
            proto = 'UDP'
        else:
            proto = self.proto

        try:
            if proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            exit()

        try:
            sock.settimeout(2)

            addr = (self.ip, self.rport)

            if proto == 'TCP':
                sock.connect(addr)

            if proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

                sock_ssl.connect(addr)

            # First request to obtain nonce and realm values
            transaction_id = random.randint(0, 0xFFFFFFFFFFFFFFFFFFFF)

            message = build_request(
                3, transaction_id, protocol, False, '')

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                headers = header_parse(message.hex()[0:40])
                attributes = attributes_parse(message.hex()[40:])

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

            if proto == 'TLS':
                sock_ssl.sendall(message)
                response = sock_ssl.recv(1024)
            else:
                sock.sendto(message, addr)
                response = sock.recv(1024)
 
            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response")
                print(self.c.YELLOW + str(response.hex()))
                print(self.c.WHITE)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            if self.verbose == 2:
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

            realm = attributes['REALM']
            nonce = attributes['NONCE']

            # Second request
            message = build_request(
                3, transaction_id, protocol, False, '', username, realm, nonce, password)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Request")
                print(self.c.GREEN + message.hex())
                print(self.c.WHITE)

                headers = header_parse(message.hex()[0:40])
                attributes = attributes_parse(message.hex()[40:])

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

            if proto == 'TLS':
                sock_ssl.sendall(message)
                response = sock_ssl.recv(1024)
            else:
                sock.sendto(message, addr)
                response = sock.recv(1024)

            if self.verbose == 2:
                print(self.c.BWHITE + "[+] Response")
                print(self.c.YELLOW + response.hex())
                print(self.c.WHITE)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            try:
                if attributes['ERROR-CODE'] == '401 Unauthorized':
                    print(self.c.RED + 'Wrong user/pass' + self.c.WHITE)
                    self.quit = True
                    return
            except:
                pass

            if self.verbose == 2:
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)
            else:
                if headers['MESSAGE_TYPE'] == 'Allocate Success Response':
                    print(self.c.BWHITE + '[✓] Proto %s (%s) ' %
                            (protocol, get_protocol(protocol)) + self.c.GREEN + 'Connection successful' + self.c.WHITE)
                else:
                    if self.verbose > 0:
                        print(self.c.BWHITE + '[x] Proto %s ' %
                                protocol + self.c.RED + 'Connection error' + self.c.WHITE)
        except KeyboardInterrupt:
            print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
            self.quit = True
        except socket.timeout:
            if self.verbose > 0:
                print(self.c.BWHITE + '[x] Proto %s ' % protocol + self.c.RED + 'Socket Timeout' + self.c.WHITE)
        except:
            pass
        finally:
            sock.close()

        if proto == 'TLS':
            sock_ssl.close()
