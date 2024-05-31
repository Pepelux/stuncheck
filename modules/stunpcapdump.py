#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

import os
import re
from lib.color import Color
from lib.logos import Logo


class StunPCAPDump:
    def __init__(self):
        self.file = ''
        self.findips = 0

        self.involvedip = []
        self.allip = []

        self.c = Color()

    def start(self):
        logo = Logo('stunpcapdump')
        logo.print()

        print(self.c.BWHITE+'[✓] Input file: %s ...' % self.file)
        print(self.c.WHITE)

        if self.findips == 1:
            self.ips()
        self.stun()
        self.rtp()

        if self.findips == 1:
            self.print_ips()
        self.print()

    def ips(self):
        tmpfile = 'stunpcapdump.tmp'

        print(self.c.WHITE + 'Searching IPs involved in conversations ...')
        print(self.c.WHITE)
        os.system("tshark -r %s > %s" % (self.file, tmpfile))

        f = open(tmpfile, 'r')
        for line in f:
            line = line.replace('\n', '')

            regex = r'^^\s*[0-9]*\s*[0-9|.]*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s→\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s([a-x|A-Z|0-9]*)\s.*'
            m = re.search(regex, line)
            if m:
                ip1 = m.group(1).rjust(15)
                ip2 = m.group(2).ljust(15)
                data = f'{ip1} => {ip2}'
                proto = m.group(3)
                if (data, proto) not in self.allip:
                    self.allip.append((data, proto))

        f.close()
        os.remove(tmpfile)
            
    def stun(self):
        tmpfile = 'stunpcapdump.tmp'

        print(self.c.WHITE + 'Extracting STUN packages from PCAP file ...')
        print(self.c.WHITE)
        os.system("tshark -r %s -Y stun > %s" % (self.file, tmpfile))

        f = open(tmpfile, 'r')
        for line in f:
            line = line.replace('\n', '')

            regex = r'^\s*([0-9]*)\s*[0-9|.]*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s→\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*'
            m = re.search(regex, line)
            if m:
                id = m.group(1)
                ip1 = m.group(2).rjust(15)
                ip2 = m.group(3).ljust(15)
                data = f'{ip1} => {ip2}'
                msg = 'STUN messages'
                if (data, msg) not in self.involvedip:
                    self.involvedip.append((data, msg))

                self.search(r'MAPPED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'MAPPED-ADDRESS', data, id)
                self.search(r'RESPONSE-ORIGIN:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'RESPONSE-ORIGIN', data, id)
                self.search(r'XOR-MAPPED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-MAPPED-ADDRESS', data, id)
                self.search(r'XOR-PEER-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-PEER-ADDRESS', data, id)
                self.search(r'XOR-RELAYED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-RELAYED-ADDRESS', data, id)


        f.close()
        os.remove(tmpfile)
            
    def rtp(self):
        tmpfile = 'stunpcapdump.tmp'

        print(self.c.WHITE + 'Extracting RTP packages from PCAP file ...')
        print(self.c.WHITE)
        os.system("tshark -r %s -Y rtp > %s" % (self.file, tmpfile))

        f = open(tmpfile, 'r')
        for line in f:
            line = line.replace('\n', '')

            if line.find('RTP'):
                regex = r'^\s*[0-9]*\s*[0-9|.]*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s→\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*'
                m = re.search(regex, line)
                if m:
                    ip1 = m.group(1).rjust(15)
                    ip2 = m.group(2).ljust(15)
                    data = f'{ip1} => {ip2}'
                    msg = 'RTP stream'
                    if (data, msg) not in self.involvedip:
                        self.involvedip.append((data, msg))

        f.close()
        os.remove(tmpfile)
            
        os.system("tshark -r %s -Y 'udp and !stun and !dns and !quic and !icmp' > %s" % (self.file, tmpfile))

        f = open(tmpfile, 'r')
        for line in f:
            line = line.replace('\n', '')

            if line.find('RTP'):
                regex = r'^\s*[0-9]*\s*[0-9|.]*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s→\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*'
                m = re.search(regex, line)
                if m:
                    ip1 = m.group(1).rjust(15)
                    ip2 = m.group(2).ljust(15)
                    data = f'{ip1} => {ip2}'
                    msg = 'Possible RTP stream'
                    if (data, msg) not in self.involvedip:
                        self.involvedip.append((data, msg))

        f.close()
        os.remove(tmpfile)


    def search(self, regex, line, attribute, data, id):
        m = re.search(regex, line)
        if m:
            ip = m.group(1)
            msg = f'{attribute}: {ip}'
            if (data, msg) not in self.involvedip:
                self.involvedip.append((data, msg))


    def print(self):
        iplen = len('Conversation')
        folen = len('Found in')

        for ip, found in self.involvedip:
            if len(ip) > iplen:
                iplen = len(ip)
            if len(found) > folen:
                folen = len(found)

        tlen = iplen+folen+5

        print(self.c.BWHITE + 'IPs found:' + self.c.WHITE)

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'Conversation'.ljust(iplen) + self.c.WHITE +
              '| ' + self.c.BWHITE + 'Found in'.ljust(folen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.involvedip) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for ip, found in self.involvedip:
                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.BYELLOW + '%s' % found.ljust(folen) + self.c.WHITE + ' |')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)
        

    def print_ips(self):
        iplen = len('IP source => IP destination')
        prlen = len('Protocol')

        for ip, protocol in self.allip:
            if len(ip) > iplen:
                iplen = len(ip)
            if len(protocol) > prlen:
                prlen = len(protocol)

        tlen = iplen+prlen+5

        print(self.c.BWHITE + 'IPs found:' + self.c.WHITE)

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'IP source => IP destination'.ljust(iplen) + self.c.WHITE +
              '| ' + self.c.BWHITE + 'Protocol'.ljust(prlen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.involvedip) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for ip, protocol in self.allip:
                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.BYELLOW + '%s' % protocol.ljust(prlen) + self.c.WHITE + ' |')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)

