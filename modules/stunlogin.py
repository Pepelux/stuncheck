#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import socket
import ssl
import sys
from lib.color import Color
from lib.logos import Logo
from lib.functions import header_parse, attributes_parse, build_request


class StunLogin:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'

        self.c = Color()

        self.user = ''
        self.pwd = ''

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('stunlogin')
        logo.print()

        if self.proto == 'UDP':
            transport = '11'
        else:
            transport = '06'

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Remote port: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.BWHITE + '[✓] Username: ' + self.c.GREEN + '%s' %
              self.user)
        print(self.c.BWHITE + '[✓] Password: ' + self.c.GREEN + '%s' %
              self.pwd)
        print(self.c.WHITE)

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

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            print(self.c.BWHITE + "[+] " + self.c.GREEN + headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE + "[+] Request")
                    print(self.c.GREEN + message.hex())

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

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            print(self.c.BWHITE + "[-] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)
            try:
                print(self.c.BWHITE + "[-] " + self.c.RED + attributes['ERROR-CODE'] + self.c.WHITE)
            except:
                pass

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE + "[+] Response")
                    print(self.c.YELLOW + str(response.hex()))

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

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            print(self.c.BWHITE + "[+] " + self.c.GREEN + headers['MESSAGE_TYPE'] + self.c.WHITE)

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE + "[+] Request")
                    print(self.c.GREEN + message.hex())

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

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            print(self.c.BWHITE + "[-] " + self.c.YELLOW + headers['MESSAGE_TYPE'] + self.c.WHITE)
            try:
                print(self.c.BWHITE + "[-] " + self.c.RED + attributes['ERROR-CODE'] + self.c.WHITE)
            except:
                pass

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE + "[+] Response")
                    print(self.c.YELLOW + response.hex())

                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)
            else:
                if headers['MESSAGE_TYPE'] == 'Allocate Success Response':
                    print(self.c.BWHITE + '[✓] ' +
                          self.c.GREEN + 'Connection successful')
                else:
                    print(self.c.WHITE)
                    print(self.c.RED + 'Wrong user/pass')
        except socket.timeout:
            print(self.c.RED + "Socket Timeout" + self.c.WHITE)
            exit()
        except:
            pass
        finally:
            sock.close()

        if proto == 'TLS':
            sock_ssl.close()
