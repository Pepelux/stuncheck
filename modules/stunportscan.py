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


class StunPortscan:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'
        self.ipdst = ''
        self.ports = ''
        self.fp = 0

        self.quit = False

        self.c = Color()

        self.user = ''
        self.pwd = ''

    def start(self):
        supported_protos = ['TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        if self.ports == '':
            self.ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        if self.ports.upper() == 'ALL':
            self.ports = '1-65536'

        logo = Logo('stunportscan')
        logo.print()

        # create a list of ports
        ports = []
        for p in self.ports.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    ports.append(x)
            else:
                ports.append(p)

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Remote port: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.ports)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.WHITE)

        start = time.time()
        self.scan(ports)
        end = time.time()
        self.totaltime = int(end-start)

    def scan(self, ports):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            exit()

        try:
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

            message = build_request(3, transaction_id, '06', True, '')

            if self.verbose > 1:
                print(self.c.BWHITE + "[+] Request")
                if self.verbose == 3:
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

            if self.verbose > 1:
                print(self.c.BWHITE + "[+] Response")
                if self.verbose == 3:
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

            # Second request: Allocate Request
            message = build_request(
                3, transaction_id, '06', False, '', self.user, realm, nonce, self.pwd)

            if self.verbose > 1:
                print(self.c.BWHITE + "[+] Request")
                if self.verbose == 3:
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

            if self.verbose > 1:
                print(self.c.BWHITE + "[+] Response")
                if self.verbose == 3:
                    print(self.c.YELLOW + response.hex())
                    print(self.c.WHITE)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            if self.verbose == 2:
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

            # Third request: Connect Request
            if self.ports != '1-65536':
                ports.sort()

            for p in ports:
                if self.ipdst != '':
                    ipaddr = self.ipdst
                else:
                    ipaddr = '127.0.0.1'
                port = p
                ipport = ipaddr + ':' + str(port)

                message = build_request(
                    10, transaction_id, '06', False, ipport, self.user, realm, nonce, self.pwd)

                if self.verbose > 1:
                    print(self.c.BWHITE + "[+] Request")
                    if self.verbose == 3:
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

                if self.verbose > 1:
                    print(self.c.BWHITE + "[+] Response")
                    if self.verbose == 3:
                        print(self.c.YELLOW + response.hex())
                        print(self.c.WHITE)

                headers = header_parse(response.hex()[0:40])
                attributes = attributes_parse(response.hex()[40:])

                if self.verbose == 2:
                    print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                    print(headers)
                    print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                    print(attributes)
                    print(self.c.WHITE)
                else:
                    if headers['MESSAGE_TYPE'] == 'Connect Success Response':
                        print(
                            self.c.BWHITE + '[✓] Port : ' + self.c.YELLOW + str(port) + self.c.GREEN + ' open')
                    else:
                        if self.verbose == 1:
                            print(
                                self.c.BWHITE + '[x] Port : ' + self.c.YELLOW + str(port) + self.c.RED + ' closed')

                try:
                    if attributes['ERROR-CODE'] == '401 Unauthorized':
                        print(self.c.RED + 'Wrong user/pass')
                        print(self.c.WHITE)
                        exit()
                except:
                    pass

                # Fingerprinting
                if self.fp == 1:
                    try:
                        connectionid = attributes['CONNECTION-ID']

                        try:
                            sock2 = socket.socket(
                                socket.AF_INET, socket.SOCK_STREAM)
                        except socket.error:
                            print(self.c.RED + 'Failed to create socket')
                            exit()

                        sock2.settimeout(2)

                        if self.proto == 'TCP':
                            sock2.connect(addr)

                        if self.proto == 'TLS':
                            sock_ssl2 = ssl.wrap_socket(
                                sock2, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

                            sock_ssl2.connect(addr)

                        # Fourth request (ConnectionBind Request)
                        message = build_request(
                            11, transaction_id, '06', False, '', self.user, realm, nonce, self.pwd, connectionid)

                        if self.verbose > 1:
                            print(self.c.BWHITE + "[+] Request")
                            if self.verbose == 3:
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
                            sock_ssl2.sendall(message)
                            response = sock_ssl2.recv(1024)
                        else:
                            sock2.sendto(message, addr)
                            response = sock2.recv(1024)
                    except:
                        pass

                    headers = header_parse(response.hex()[0:40])
                    attributes = attributes_parse(response.hex()[40:])

                    if self.verbose > 1:
                        print(self.c.BWHITE + "[+] Response")
                        if self.verbose == 3:
                            print(self.c.YELLOW + response.hex())
                            print(self.c.WHITE)

                        print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                        print(headers)
                        print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                        print(attributes)
                        print(self.c.WHITE)

                    version = ''
                    for x in range(1, 6):
                        try:
                            att = 'unknown attribute ' + str(x)
                            version = attributes[att]
                            print(self.c.RED + version + self.c.WHITE)
                        except:
                            pass

                    if version == '':
                        data = b'GET HTTP/1.0\r\n'

                        try:
                            if self.proto == 'TLS':
                                sock_ssl2.sendall(data)
                            else:
                                sock2.sendto(data, addr)

                            if self.proto == 'TLS':
                                response = sock_ssl2.recv(4096)
                            else:
                                response = sock2.recv(4096)

                            response_clear = response.decode()                        
                            pos = response_clear.find('<')
                            print(self.c.RED + response_clear[0:pos] + self.c.WHITE)
                        except:
                            pass

            print(self.c.WHITE)
        except socket.timeout:
            print(self.c.RED + "Socket Timeout" + self.c.WHITE)
            exit()
        except:
            pass
        finally:
            sock.close()

        if self.proto == 'TLS':
            sock_ssl.close()
