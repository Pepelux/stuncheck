#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import re
import socket
import ssl
import sys
import time
from lib.color import Color
from lib.logos import Logo
from lib.functions import header_parse, attributes_parse, build_request


class StunIpscan:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'

        self.c = Color()

        self.user = ''
        self.pwd = ''

        self.destip = ''

        self.listips = {
            "0.0.0.0",
            "::",
            "127.0.0.1",
            "127.0.0.8",
            "127.255.255.254",
            "::1",
            "10.0.0.1",
            "10.255.255.254",
            "172.16.0.1",
            "172.31.255.254",
            "192.168.0.1",
            "192.168.255.254",
            "169.254.0.1",
            "169.254.254.255",
            "224.0.0.1",
            "239.255.255.254",
            "100.64.0.0",
            "100.127.255.254",
            "192.0.0.1",
            "192.0.0.254",
            "192.0.2.1",
            "192.0.2.254",
            "198.18.0.1",
            "198.19.255.254",
            "198.51.100.1",
            "198.51.100.254",
            "203.0.113.1",
            "203.0.113.254",
            "240.0.0.1",
            "255.255.255.255",
            "169.254.169.254"
        }

    def start(self):
        supported_protos = ['TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        self.verbose = int(self.verbose)

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('stunipscan')
        logo.print()

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.WHITE)

        if self.destip != '':
            ipaddr = self.destip
            ipport = ipaddr + ':80'

        transport = '11'
        if self.destip == '':
            for ipaddr in self.listips:
                ipport = ipaddr + ':80'

                self.scan(transport, ipaddr, ipport)
        else:
            self.scan(transport, ipaddr, ipport)

        transport = '06'
        if self.destip == '':
            for ipaddr in self.listips:
                ipport = ipaddr + ':80'

                self.scan(transport, ipaddr, ipport)
        else:
            self.scan(transport, ipaddr, ipport)

    def scan(self, transport, ipaddr, ipport):
        if transport == '06':
            tr = 'TCP'
        else:
            tr = 'UDP'

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            return

        # try:
        sock.settimeout(2)

        addr = (self.ip, self.rport)

        if self.proto == 'TCP':
            sock.connect(addr)

        if self.proto == 'TLS':
            sock_ssl = ssl.wrap_socket(
                sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

            sock_ssl.connect(addr)

        # First request to obtain nonce and realm values: Allocate Request
        transaction_id = random.randint(0, 0xFFFFFFFFFFFFFFFFFFFF)

        message = build_request(3, transaction_id, transport, True, '')

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Request 1 (Allocate Request)")
            print(self.c.GREEN + message.hex())
            print(self.c.WHITE)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        if self.proto == 'TLS':
            sock_ssl.sendall(message)
            response = sock_ssl.recv(1024)
        else:
            sock.sendto(message, addr)
            response = sock.recv(1024)

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Response 1")
            print(self.c.YELLOW + str(response.hex()))
            print(self.c.WHITE)

        headers = header_parse(response.hex()[0:40])
        attributes = attributes_parse(response.hex()[40:])

        if self.verbose == 1:
            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        realm = attributes['REALM']
        nonce = attributes['NONCE']

        # Second request: Allocate Request
        message = build_request(
            3, transaction_id, transport, False, '', self.user, realm, nonce, self.pwd)

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Request 2 (Allocate Request)")
            print(self.c.GREEN + message.hex())
            print(self.c.WHITE)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        if self.proto == 'TLS':
            sock_ssl.sendall(message)
            response = sock_ssl.recv(1024)
        else:
            sock.sendto(message, addr)
            response = sock.recv(1024)

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Response 2")
            print(self.c.YELLOW + response.hex())
            print(self.c.WHITE)

        headers = header_parse(response.hex()[0:40])
        attributes = attributes_parse(response.hex()[40:])

        if self.verbose == 1:
            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        message = build_request(
            8, transaction_id, transport, False, ipport, self.user, realm, nonce, self.pwd)

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Request 3 (Create Perm Request)")
            print(self.c.GREEN + message.hex())
            print(self.c.WHITE)

            headers = header_parse(message.hex()[0:40])
            attributes = attributes_parse(message.hex()[40:])

            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        if self.proto == 'TLS':
            sock_ssl.sendall(message)
            response = sock_ssl.recv(1024)
        else:
            sock.sendto(message, addr)
            response = sock.recv(1024)

        if self.verbose == 1:
            print(self.c.BWHITE + "[+] Response 3")
            print(self.c.YELLOW + response.hex())
            print(self.c.WHITE)

        headers = header_parse(response.hex()[0:40])
        attributes = attributes_parse(response.hex()[40:])

        if self.verbose == 1:
            print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
            print(headers)
            print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
            print(attributes)
            print(self.c.WHITE)

        if headers['MESSAGE_TYPE'] == 'Create Perm Response':
            print(
                self.c.BWHITE + '[✓] ' + ipaddr + '/' + tr + ': ' + self.c.GREEN + 'Successfully connected' + self.c.WHITE)
        else:
            message_tytpe = headers['MESSAGE_TYPE']
            try:
                errorcode = attributes['ERROR-CODE']
            except:
                errorcode = ''
            print(
                self.c.BWHITE + '[x] ' + ipaddr + '/' + tr + ': ' + self.c.YELLOW + message_tytpe + ' (' + self.c.RED + errorcode + self.c.YELLOW + ')' + self.c.WHITE)
        # except socket.timeout:
        #     print(
        #         self.c.BWHITE + '[x] ' + ipaddr + '/' + tr + ': ' + self.c.RED + 'Error' + self.c.WHITE)
        #     pass
        # except:
        #     pass
        # finally:
        #     sock.close()

        # if self.proto == 'TLS':
        #     sock_ssl.close()
