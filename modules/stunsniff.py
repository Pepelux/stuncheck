#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

import pyshark
import signal
import os
import platform
import re
import whois
import threading
import time
from lib.functions import searchInterface, header_parse, attributes_parse
from lib.color import Color
from lib.logos import Logo


class StunSniff:
    def __init__(self):
        self.dev = ''
        self.file = ''
        self.ofile = ''
        self.rport = '3478'
        self.verbose = '0'
        self.rtp = '0'
        self.whois = '0'

        self.f = ''

        self.run = True

        self.foundxma = []
        self.foundxpa = []
        self.foundxra = []
        self.foundma = []
        self.foundro = []
        self.foundaddr = []

        self.line = ['-', '\\', '|', '/']
        self.pos = 0
        self.quit = False

        self.c = Color()

    def signal_handler(self, sig, frame):
        print(self.c.BYELLOW + 'You pressed Ctrl+C!')
        print(self.c.BWHITE + '\nStopping sniffer ...')
        print(self.c.WHITE)

        self.stop()

    def stop(self):
        self.run = False

        if self.file != '':
            self.f.close()

        exit()

    def start(self):
        # x = bytearray.fromhex('0003005c2112a4420000ceb0f1f34b10bf6048cf001900040600000000060007706570656c757800001400167765627274632e7a6f6f6e74656c65636f6d2e636f6d0000001500103961646435613631643839633662396500080014c4c44330212b6ae354218e3c205c2959be957795')
        # headers = header_parse(x.hex()[0:40])
        # attributes = attributes_parse(x.hex()[40:])
        # print(self.c.BWHITE + "[+] Response")
        # print(self.c.YELLOW + str(x.hex()))
        # print(self.c.WHITE)
        # print(self.c.WHITE + "   [-] Headers:" + self.c.CYAN)
        # print(headers)
        # print(self.c.WHITE + "   [-] Attributes:" + self.c.CYAN)
        # print(attributes)
        # print(self.c.WHITE)
        # exit()

        if not self.verbose:
            self.verbose = '0'
        if not self.rtp:
            self.rtp = '0'
        if not self.whois:
            self.whois = '0'
        if self.ofile and self.ofile != '':
            if not re.search('.pcap$', self.ofile):
                self.ofile += '.pcap'

        if self.file != '':
            self.f = open(self.file, 'a+')

        current_user = os.popen('whoami').read()
        current_user = current_user.strip()
        ops = platform.system()

        if ops == 'Linux' and current_user != 'root':
            print(self.c.WHITE + 'You must be ' + self.c.RED +
                  'root' + self.c.WHITE + ' to use this module')
            return

        self.verbose = int(self.verbose)
        self.rtp = int(self.rtp)
        self.whois = int(self.whois)

        logo = Logo('stunsniff')
        logo.print()

        signal.signal(signal.SIGINT, self.signal_handler)
        print(self.c.BYELLOW + '\nPress Ctrl+C to stop')
        print(self.c.WHITE)

        self.proto = self.proto.upper()

        try:
            self.rport = self.rport.upper()
        except:
            pass

        if self.proto == 'TLS' and self.rport == '3478':
            self.rport = '5349'

        # define capture object
        if self.dev == '':
            networkInterface = searchInterface()
        else:
            networkInterface = self.dev

        print(self.c.BWHITE + '[✓] Listening on: ' +
              self.c.GREEN + '%s' % networkInterface)

        if self.rtp == 1:
            print(self.c.BWHITE + '[✓] Protocol: ' +
                  self.c.GREEN + 'RTP (UDP)')
        else:
            if self.proto == 'ALL':
                print(self.c.BWHITE + '[✓] Protocols: ' +
                      self.c.GREEN + 'UDP, TCP, TLS')
            else:
                print(self.c.BWHITE + '[✓] Protocol: ' + self.c.GREEN + '%s' %
                      self.proto)

        if self.whois == 1:
            print(self.c.BWHITE + '[✓] Whois: ' +
                  self.c.GREEN + 'Enabled')

        if self.ofile != '':
            print(
                self.c.BWHITE + '[✓] Save captured data in the file: ' + self.c.GREEN + '%s' % self.ofile)

        self.run = True

        threads = list()

        if self.ofile and self.ofile != '':
            t = threading.Thread(target=self.sniff, args=(
                networkInterface, self.ofile), daemon=True)
            threads.append(t)
            t.start()
            time.sleep(0.1)

        t = threading.Thread(target=self.sniff, args=(
            networkInterface, ''), daemon=True)
        threads.append(t)
        t.start()

        t.join()

    def sniff(self, networkInterface, file):
        if file != '':
            capture = pyshark.LiveCapture(
                interface=networkInterface, output_file=file)

        filter = ''

        if self.rtp == 1:
            filter = "rtp"
        else:
            if self.rport == 'ALL':
                if self.proto == 'UDP':
                    filter = "udp"
                elif self.proto == 'TCP' or self.proto == 'TLS':
                    filter = "tcp"
            else:
                if self.proto == 'UDP':
                    filter = "udp port " + self.rport
                elif self.proto == 'TCP':
                    filter = "tcp port " + self.rport
                elif self.proto == 'TLS':
                    filter = "tcp port " + self.rport

        if filter != '':
            print(self.c.BWHITE + '[✓] Filter: ' + self.c.GREEN + '%s' %
                  filter + self.c.WHITE)
            if filter == 'rtp':
                capture = pyshark.LiveCapture(
                    interface=networkInterface, bpf_filter='udp', include_raw=True, use_json=True)
                # capture = pyshark.LiveCapture(
                #     interface=networkInterface, bpf_filter='udp', decode_as={'udp.port==1234': 'rtp'}, include_raw=True, use_json=True)
            else:
                capture = pyshark.LiveCapture(
                    interface=networkInterface, bpf_filter=filter, include_raw=True, use_json=True)
        else:
            print(self.c.BWHITE + '[✓] Filter: ' + self.c.GREEN +
                  'capture all packets (no filter)' + self.c.WHITE)
            capture = pyshark.LiveCapture(
                interface=networkInterface, include_raw=True, use_json=True)

        print(self.c.WHITE)

        # for packet in capture.sniff_continuously(packet_count=100):
        for packet in capture.sniff_continuously():
            if self.run == False:
                try:
                    capture.clear()
                    capture.close()
                except:
                    pass
                return
            else:
                # adjusted output
                try:
                    if file == '':
                        # get packet content
                        protocol = packet.transport_layer   # protocol type
                        src_addr = packet.ip.src            # source address
                        src_port = packet[protocol].srcport  # source port
                        dst_addr = packet.ip.dst            # destination address
                        # destination port
                        dst_port = packet[protocol].dstport
                        try:
                            mac_addr = packet.eth.src            # MAC address
                        except:
                            mac_addr = ''

                        complete = 0

                        if self.rtp == 0:
                            try:
                                msg = packet[protocol].payload_raw[0]
                                bytes_object = bytes.fromhex(msg)

                                headers = header_parse(
                                    bytes_object.hex()[0:40])
                                complete = complete + 1

                                try:
                                    attributes = attributes_parse(
                                        bytes_object.hex()[40:])
                                    complete = complete + 1
                                except:
                                    attributes = {}

                                if self.verbose > 0:
                                    if complete == 1:
                                        print('Possible STUN packet found from %s:%s to %s:%s using %s' % (
                                            src_addr, src_port, dst_addr, dst_port, protocol))
                                        if self.whois == 1:
                                            self.dowhois(src_addr)
                                            self.dowhois(dst_addr)
                                    if complete == 2:
                                        print('STUN packet found from %s:%s to %s:%s using %s' % (
                                            src_addr, src_port, dst_addr, dst_port, protocol))
                                        if self.whois == 1:
                                            self.dowhois(src_addr)
                                            self.dowhois(dst_addr)

                                if self.verbose == 2:
                                    print(self.c.BWHITE + "[+] Response")
                                    print(self.c.YELLOW +
                                          str(bytes_object.hex()))
                                    print(self.c.WHITE)

                                if self.verbose == 2:
                                    print(self.c.WHITE +
                                          "   [-] Header:" + self.c.CYAN)
                                    print(headers)
                                    print(self.c.WHITE +
                                          "   [-] Attributes:" + self.c.CYAN)
                                    print(attributes)
                                    print(self.c.WHITE)

                                try:
                                    ipport = attributes['XOR-MAPPED-ADDRESS']
                                    if ipport not in self.foundxma and ipport != '':
                                        self.foundxma.append(ipport)
                                        self.print(
                                            ipport, 'XOR-MAPPED-ADDRESS', self.c.BGREEN)
                                except:
                                    pass

                                try:
                                    ipport = attributes['XOR-PEER-ADDRESS']
                                    if ipport not in self.foundxpa and ipport != '':
                                        self.foundxpa.append(ipport)
                                        self.print(
                                            ipport, 'XOR-PEER-ADDRESS', self.c.BGREEN)
                                except:
                                    pass

                                try:
                                    ipport = attributes['XOR-RELAYED-ADDRESS']
                                    if ipport not in self.foundxra and ipport != '':
                                        self.foundxra.append(ipport)
                                        self.print(
                                            ipport, 'XOR-RELAYED-ADDRESS', self.c.BGREEN)
                                except:
                                    pass

                                try:
                                    ipport = attributes['MAPPED-ADDRESS']
                                    if ipport not in self.foundma and ipport != '':
                                        self.foundma.append(ipport)
                                        self.print(
                                            ipport, 'MAPPED-ADDRESS', self.c.BGREEN)
                                except:
                                    pass

                                try:
                                    ipport = attributes['RESPONSE-ORIGIN']
                                    if ipport not in self.foundro and ipport != '':
                                        self.foundro.append(ipport)
                                        self.print(
                                            ipport, 'RESPONSE-ORIGIN', self.c.BCYAN)
                                except:
                                    pass

                                # ipport = src_addr + ":" + src_port
                                # if ipport not in self.foundaddr:
                                #     self.foundaddr.append(ipport)
                                #     self.print(ipport, 'Source Address', self.c.YELLOW)
                                # ipport = dst_addr + ":" + dst_port
                                # if ipport not in self.foundaddr:
                                #     self.foundaddr.append(ipport)
                                #     self.printipport, 'Destination Address', self.c.YELLOW)
                            except:
                                # Non ASCII data
                                pass

                        msg = packet[protocol].payload_raw[0]
                        bytes_object = bytes.fromhex(msg)
                        type = str(bytes_object.hex())[0:2]
                        # print(bytes_object.hex()[0:2])

                        if type == '90' or type == 'b0':
                            ipport = src_addr + ":" + src_port
                            if ipport not in self.foundaddr:
                                self.foundaddr.append(ipport)
                                self.print(ipport,
                                           'Traffic RTP', self.c.BMAGENTA)
                            ipport = dst_addr + ":" + dst_port
                            if ipport not in self.foundaddr:
                                self.foundaddr.append(ipport)
                                self.print(ipport,
                                           'Traffic RTP', self.c.BMAGENTA)
                except pyshark.capture.capture.TSharkCrashException:
                    print("Capture has crashed")
                except AttributeError as e:
                    # ignore packets other than TCP, UDP and IPv4
                    pass
        capture.clear()
        capture.close()

    def print(self, ipport, attr, color):
        (ip, port) = ipport.split(':')
        print(self.c.BWHITE + "Found " + self.c.BYELLOW + ipport +
              self.c.WHITE + " in " + color + attr + self.c.WHITE)

        if self.file != '':
            self.f.write("Found IP:PORT " + ipport +
                         " in " + attr + "\n")

        if self.whois == 1:
            self.dowhois(ip)

    def dowhois(self, ip):
        try:
            query = whois.whois(ip)
            print(self.c.YELLOW)
            print("      [+] Domain: ", query.domain)
            print("      [+] Update time: ", query.get('updated_date'))
            print("      [+] Expiration time: ",
                  query.get('expiration_date'))
            print("      [+] Name server: ", query.get('name_servers'))
            print("      [+] Email: ", query.get('emails'))
            print(self.c.BWHITE)

            if self.file != '':
                self.f.write("      [+] Domain: ", query.domain + "\n")
                self.f.write("      [+] Update time: ",
                             query.get('updated_date') + "\n")
                self.f.write("      [+] Expiration time: ",
                             query.get('expiration_date') + "\n")
                self.f.write("      [+] Name server: ",
                             query.get('name_servers') + "\n")
                self.f.write("      [+] Email: ",
                             query.get('emails') + "\n\n")
        except:
            pass
