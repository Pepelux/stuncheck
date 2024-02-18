#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

import random
import socket
import ssl
import sys
from bitstring import Bits
from lib.color import Color
from lib.logos import Logo
from lib.functions import attributesValues, header_parse, attributes_parse, xor_address_parse


class StunInfo:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'

        self.c = Color()

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        self.proto = self.proto.upper()

        if self.verbose == None:
            self.verbose = 0

        # check protocol
        if self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        logo = Logo('stuninfo')
        logo.print()

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % self.ip)
        print(self.c.BWHITE + '[✓] Port: ' +
              self.c.GREEN + '%s' % self.rport)
        print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
              self.proto.upper())
        print(self.c.WHITE)

        self.send_request_info()
        self.send_request_transport('UDP')
        self.send_request_transport('TCP')

        print(self.c.WHITE)

    # Send request
    def send_request(self, request):
        response = ''

        try:
            if self.proto == 'UDP':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except socket.error:
            print(self.c.RED + 'Failed to create socket')
            exit()

        try:
            sock.settimeout(5)

            addr = (self.ip, self.rport)

            if self.proto == 'TCP':
                sock.connect(addr)

            if self.proto == 'TLS':
                sock_ssl = ssl.wrap_socket(
                    sock, ssl_version=ssl.PROTOCOL_TLS, ciphers='DEFAULT', cert_reqs=ssl.CERT_NONE)

                sock_ssl.connect(addr)
                sock_ssl.sendall(request)
                response = sock_ssl.recv(1024)
            else:
                sock.sendto(request, addr)
                response = sock.recv(1024)
        except socket.timeout:
            pass
        except:
            pass
        finally:
            sock.close()

            if self.proto == 'TLS':
                sock_ssl.close()

        return response

    # Send request to obtain info about the STUN/TURN server
    def send_request_info(self):
        transactionID = Bits(
            uint=random.randint(0, 2 ** 96 - 1), length=96)

        message = bytearray()
        message += b"\x00\x01"              # Message Type: Binding Request
        message += b"\x00\x00"              # Message Length: 0 = no attributes
        message += b"\x21\x12\xa4\x42"      # Magic Cookie
        message += transactionID.tobytes()  # Transaction ID

        print(self.c.BYELLOW + 'STUN info ... ' + self.c.WHITE)

        if self.verbose > 0:
            try:
                headers = header_parse(message.hex()[0:40])
                attributes = attributes_parse(message.hex()[40:])
                if self.verbose == 2:
                    print(self.c.BWHITE)
                    print('Request:')
                    print(message.hex())
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                # print(message.hex()[0:40])
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                # print(message.hex()[40:])
                print(attributes)
                print(self.c.WHITE)
            except:
                pass

        response = self.send_request(message)

        try:
            headers = header_parse(response.hex()[0:40])

            try:
                attributes = attributes_parse(response.hex()[40:])
            except:
                attributes = {}

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE)
                    print('Response:')
                    print(response.hex())
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                # print(response.hex()[0:40])
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                # print(response.hex()[40:])
                print(attributes)
                print(self.c.WHITE)

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
        except:
            print(self.c.RED + 'Error getting data. The server does not support the STUN protocol' + self.c.WHITE)
            exit()

        print(self.c.WHITE)

    # Send request to obtain info about the STUN/TURN server transport
    def send_request_transport(self, transport):
        transactionID = Bits(uint=random.randint(0, 2 ** 96 - 1), length=96)
        transport = attributesValues[transport]
        transport = bytearray.fromhex(
            hex(int(transport, base=16))[2:].zfill(2))

        attributes = bytearray()
        attributes += b"\x00\x19"           # Attribute: Requested Transport
        attributes += b"\x00\x04"           # Attribute Length
        attributes += transport             # Attribute value: UDP
        attributes += b"\x00\x00\x00"       # Reserved

        msglen = len(attributes).to_bytes(2, byteorder='big')

        message = bytearray()
        message += b"\x00\x03"              # Message Type: Allocate Request
        message += msglen                   # Message Length
        message += b"\x21\x12\xa4\x42"      # Magic Cookie
        message += transactionID.tobytes()  # Transaction ID

        message += attributes

        if self.verbose > 0:
            try:
                headers = header_parse(message.hex()[0:40])
                attributes = attributes_parse(message.hex()[40:])
                if self.verbose == 2:
                        print(self.c.BWHITE)
                        print('Request:')
                        print(message.hex())
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                # print(message.hex()[0:40])
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                # print(message.hex()[40:])
                print(attributes)
                print(self.c.WHITE)
            except:
                pass

        response = self.send_request(message)

        t = ''.join(format(byte, '02x') for byte in transport)
        if t == '06':
            tr = 'TCP'
        elif t == '11':
            tr = 'UDP'
        else:
            tr = 'Unknown'

        print(self.c.BYELLOW + 'TURN: Transport ... ' + tr + self.c.WHITE)

        try:
            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            if self.verbose > 0:
                if self.verbose == 2:
                    print(self.c.BWHITE)
                    print("Response:")
                    print(response.hex())
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

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
                    if a == 'ERROR-CODE':
                        byte_sequence = bytes(attributes[a][0:4], 'latin-1')
                        hex_string = ''.join(format(byte, '02x')
                                             for byte in byte_sequence)
                        print(self.c.BWHITE + '  [-]  ' + a + ": " +
                              self.c.GREEN + str(int(hex_string)) + ' ' + attributes[a] + self.c.WHITE)
                    else:
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
        except:
            print(self.c.RED + 'Error getting data. The TURN server does not support the ' + tr + ' protocol' + self.c.WHITE)

        print(self.c.WHITE)
