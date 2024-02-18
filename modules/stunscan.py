#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from concurrent.futures import ThreadPoolExecutor
import ipaddress
from itertools import product
import random
import re
import socket
import ssl
import sys
import time
from IPy import IP
from bitstring import Bits
from lib.color import Color
from lib.logos import Logo
from lib.functions import header_parse, attributes_parse, ip2long, long2ip, format_time, xor_address_parse


class StunScan:
    def __init__(self):

        self.ip = ''
        self.host = ''
        self.rport = '3478'
        self.proto = 'UDP'
        self.verbose = '0'
        self.nocolor = ''
        self.file = ''
        self.ofile = ''
        self.random = 0
        self.threads = '500'

        self.found = []
        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False
        self.totaltime = 0

        self.c = Color()

        self.nonce = ''
        self.realm = ''

    def remove_non_ascii(self, text):
        return re.sub(r'[^\x00-\x7F]', ' ', text)

    def start(self):
        supported_protos = ['UDP', 'TCP', 'TLS']

        if self.nocolor == 1:
            self.c.ansy()

        self.proto = self.proto.upper()
        if self.proto == 'UDP|TCP|TLS':
            self.proto = 'ALL'

        if self.verbose == None:
            self.verbose = 0

        # check protocol
        if self.proto != 'ALL' and self.proto not in supported_protos:
            print(self.c.BRED + 'Protocol %s is not supported' % self.proto)
            sys.exit()

        if self.rport == '3478' and (self.proto != 'UDP'):
            self.rport = '3478,5349'

        if self.rport.upper() == 'ALL':
            self.rport = '1-65536'

        logo = Logo('stunscan')
        logo.print()

        # create a list of protocols
        protos = []
        if self.proto == 'UDP' or self.proto == 'ALL':
            protos.append('UDP')
        if self.proto == 'TCP' or self.proto == 'ALL':
            protos.append('TCP')
        if self.proto == 'TLS' or self.proto == 'ALL':
            protos.append('TLS')

        # create a list of ports
        ports = []
        for p in self.rport.split(','):
            m = re.search('([0-9]+)-([0-9]+)', p)
            if m:
                for x in range(int(m.group(1)), int(m.group(2))+1):
                    ports.append(x)
            else:
                ports.append(p)

        # create a list of IP addresses
        if self.file != '':
            try:
                with open(self.file) as f:
                    line = f.readline()
                    line = line.replace('\n', '')

                    while (line):
                        error = 0

                        try:
                            if self.quit == False:
                                try:
                                    ip = socket.gethostbyname(line)
                                    self.ip = IP(ip, make_net=True)
                                except:
                                    try:
                                        self.ip = IP(line, make_net=True)

                                    except:
                                        if line.find('-') > 0:
                                            val = line.split('-')
                                            start_ip = val[0]
                                            end_ip = val[1]
                                            self.ip = line

                                            error = 1

                                ips = []

                                if error == 0:
                                    hosts = list(ipaddress.ip_network(
                                        str(self.ip)).hosts())

                                    if hosts == []:
                                        hosts.append(self.ip)

                                    last = len(hosts)-1
                                    start_ip = hosts[0]
                                    end_ip = hosts[last]

                                ipini = int(ip2long(str(start_ip)))
                                ipend = int(ip2long(str(end_ip)))

                                for i in range(ipini, ipend+1):
                                    if long2ip(i)[-2:] != '.0' and long2ip(i)[-4:] != '.255':
                                        ips.append(long2ip(i))

                                self.prepare_scan(ips, ports, protos, self.ip)
                        except:
                            pass

                        line = f.readline()

                f.close()
            except:
                print('Error reading file %s' % self.file)
                exit()
        else:
            ips = []
            for i in self.ip.split(','):
                hosts = []
                error = 0

                try:
                    if i.find('/') < 1:
                        i = socket.gethostbyname(i)
                        i = IP(i, make_net=True)
                    else:
                        i = IP(i, make_net=True)
                except:
                    if i.find('-') > 0:
                        val = i.split('-')
                        start_ip = val[0]
                        end_ip = val[1]

                        error = 1
                try:
                    if error == 0:
                        hlist = list(ipaddress.ip_network(str(i)).hosts())

                        if hlist == []:
                            hosts.append(i)
                        else:
                            for h in hlist:
                                hosts.append(h)

                        last = len(hosts)-1
                        start_ip = hosts[0]
                        end_ip = hosts[last]

                    ipini = int(ip2long(str(start_ip)))
                    ipend = int(ip2long(str(end_ip)))
                    iplist = i

                    for i in range(ipini, ipend+1):
                        if long2ip(i)[-2:] != '.0' and long2ip(i)[-4:] != '.255':
                            ips.append(long2ip(i))

                    self.prepare_scan(ips, ports, protos, iplist)
                except:
                    pass

    def prepare_scan(self, ips, ports, protos, iplist):
        max_values = 100000

        # threads to use
        nthreads = int(self.threads)
        total = len(list(product(ips, ports, protos)))
        if nthreads > total:
            nthreads = total
        if nthreads < 1:
            nthreads = 1

        print(self.c.BWHITE + '[✓] IP/Network: ' +
              self.c.GREEN + '%s' % str(iplist))
        print(self.c.BWHITE + '[✓] Port range: ' +
              self.c.GREEN + '%s' % self.rport)
        if self.proto == 'ALL':
            print(self.c.BWHITE + '[✓] Protocols: ' +
                  self.c.GREEN + 'UDP, TCP, TLS')
        else:
            print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
                  self.proto.upper())
        print(self.c.BWHITE + '[✓] Used threads: ' +
              self.c.GREEN + '%d' % nthreads)
        if nthreads > 800:
            print(self.c.BRED +
                  '[x] More than 800 threads can cause socket problems')
        if self.ofile != '':
            print(self.c.BWHITE + '[✓] Saving logs info file: ' +
                  self.c.CYAN + '%s' % self.ofile)
        if self.random == 1:
            print(self.c.BWHITE + '[✓] Random hosts: ' +
                  self.c.GREEN + 'True')
        print(self.c.WHITE)

        values = product(ips, ports, protos)
        values2 = []
        count = 0

        iter = (a for a in enumerate(values))
        total = sum(1 for _ in iter)

        values = product(ips, ports, protos)

        start = time.time()

        for i, val in enumerate(values):
            if self.quit == False:
                if count < max_values:
                    values2.append(val)
                    count += 1

                if count == max_values or i+1 == total:
                    try:
                        with ThreadPoolExecutor(max_workers=nthreads) as executor:
                            if self.quit == False:
                                if self.random == 1:
                                    random.shuffle(values2)

                                for j, val2 in enumerate(values2):
                                    val_ipaddr = val2[0]
                                    val_port = int(val2[1])
                                    val_proto = val2[2]

                                    executor.submit(self.send_request_info, val_ipaddr,
                                                    val_port, val_proto)
                    except KeyboardInterrupt:
                        print(self.c.RED + '\nYou pressed Ctrl+C!' + self.c.WHITE)
                        self.quit = True

                    values2.clear()
                    count = 0

        end = time.time()
        self.totaltime = int(end-start)

        self.found.sort()
        self.print()

    # Send request
    def send_request(self, request, ipaddr, port, proto):
        response = ''

        if self.quit == False:
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

                addr = (ipaddr, port)

                if proto == 'TCP':
                    sock.connect(addr)

                if proto == 'TLS':
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

                if proto == 'TLS':
                    sock_ssl.close()

        return response

    # Send request to obtain info about the STUN/TURN server
    def send_request_info(self, ipaddr, port, proto):
        if self.quit == False:
            print(self.c.BYELLOW + '[%s] Scanning %s:%d/%s'.ljust(100) %
                  (self.line[self.pos], ipaddr, port, proto), end='\r')
            self.pos += 1
            if self.pos > 3:
                self.pos = 0

            transactionID = Bits(
                uint=random.randint(0, 2 ** 96 - 1), length=96)

            message = bytearray()
            message += b"\x00\x01"              # Message Type: Binding Request
            message += b"\x00\x00"              # Message Length: 0 = no attributes
            message += b"\x21\x12\xa4\x42"      # Magic Cookie
            message += transactionID.tobytes()  # Transaction ID

            response = self.send_request(message, ipaddr, port, proto)

            headers = header_parse(response.hex()[0:40])
            attributes = attributes_parse(response.hex()[40:])

            if self.verbose == 2:
                print(self.c.WHITE)
                print(response.hex())
                print(self.c.WHITE + "   [-] Header:" + self.c.CYAN)
                print(headers)
                print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
                print(attributes)
                print(self.c.WHITE)

            if self.verbose > 0:
                print(self.c.WHITE)
                print(self.c.BWHITE + '[+] IP address: ' + self.c.GREEN + ipaddr)
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

            line = '%s###%d###%s###%s' % (
                ipaddr, port, proto, attributes['SOFTWARE'])
            self.found.append(line)

            print(self.c.WHITE)

    def print(self):
        iplen = len('IP address')
        polen = len('Port')
        prlen = len('Proto')
        solen = len('Software')

        for x in self.found:
            (ip, port, proto, software) = x.split('###')
            software = str(software)
            if len(ip) > iplen:
                iplen = len(ip)
            if len(port) > polen:
                polen = len(port)
            if len(proto) > prlen:
                prlen = len(proto)
            if len(software) > solen:
                solen = len(software)

        tlen = iplen+polen+prlen+solen+11

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'IP address'.ljust(iplen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Port'.ljust(polen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Proto'.ljust(prlen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Software'.ljust(solen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if self.ofile != '':
            f = open(self.ofile, 'a+')

        if len(self.found) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for x in self.found:
                (ip, port, proto, software) = x.split('###')

                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % port.ljust(polen) + self.c.WHITE +
                      ' | ' + self.c.GREEN + '%s' % proto.ljust(prlen) + self.c.WHITE +
                      ' | ' + self.c.BLUE + '%s' % software.ljust(solen) + self.c.WHITE + ' |')

                if self.ofile != '':
                    f.write('%s:%s/%s => %s\n' %
                            (ip, port, proto, self.remove_non_ascii(software)))

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

        print(self.c.BWHITE + 'Time elapsed: ' + self.c.YELLOW + '%s' %
              format_time(self.totaltime) + self.c.WHITE)
        print(self.c.WHITE)

        if self.ofile != '':
            f.close()

        self.found.clear()
