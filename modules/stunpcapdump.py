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

        self.ips = []
        self.data = []

        self.c = Color()

    def start(self):
        tmpfile = 'stunpcapdump.tmp'

        logo = Logo('stunpcapdump')
        logo.print()

        print(self.c.BWHITE+'[✓] Input file: %s ...' % self.file)
        print(self.c.WHITE)

        print(self.c.WHITE + 'Extracting STUN packages from PCAP file ...')
        print(self.c.WHITE)
        os.system("tshark -r %s -Y stun > %s" % (self.file, tmpfile))

        f = open(tmpfile, 'r')
        for line in f:
            line = line.replace('\n', '')

            regex = r'^\s*([0-9]*)\s*[0-9|.]*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s.*'
            m = re.search(regex, line)
            if m:
                id = m.group(1)
                ip1 = m.group(2)
                ip2 = m.group(3)
                data = f'{ip1} => {ip2}'
                msg = 'STUN messages'
                if (data, msg) not in self.ips:
                    self.ips.append((data, msg))
                    self.data.append((id, data, msg))

                self.search(r'MAPPED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'MAPPED-ADDRESS', data, id)
                self.search(r'RESPONSE-ORIGIN:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'RESPONSE-ORIGIN', data, id)
                self.search(r'XOR-MAPPED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-MAPPED-ADDRESS', data, id)
                self.search(r'XOR-PEER-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-PEER-ADDRESS', data, id)
                self.search(r'XOR-RELAYED-ADDRESS:\s([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}[:|0-9]*)\s', line, 'XOR-RELAYED-ADDRESS', data, id)


        f.close()
        os.remove(tmpfile)

        self.print()
            

    def search(self, regex, line, attribute, data, id):
        m = re.search(regex, line)
        if m:
            ip = m.group(1)
            msg = f'{attribute}: {ip}'
            if (data, msg) not in self.ips:
                self.ips.append((data, msg))
                self.data.append((id, data, msg))


    def print(self):
        iplen = len('Conversation')
        folen = len('Found in')
        frlen = len('Frame ID')

        for frame, ip, found in self.data:
            if len(ip) > iplen:
                iplen = len(ip)
            if len(found) > folen:
                folen = len(found)
            if len(found) > folen:
                frlen = len(frame)

        tlen = iplen+folen+frlen+7

        print(self.c.BWHITE + 'IPs found:' + self.c.WHITE)

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE +
              '| ' + self.c.BWHITE + 'Conversation'.ljust(iplen) + self.c.WHITE +
              '| ' + self.c.BWHITE + 'Found in'.ljust(folen) + self.c.WHITE +
              ' | ' + self.c.BWHITE + 'Frame ID'.ljust(frlen) + self.c.WHITE + ' |')
        print(self.c.WHITE + ' ' + '-' * tlen)

        if len(self.ips) == 0:
            print(self.c.WHITE + '| ' + self.c.WHITE +
                  'Nothing found'.ljust(tlen-2) + ' |')
        else:
            for frame, ip, found in self.data:
                print(self.c.WHITE +
                      '| ' + self.c.BGREEN + '%s' % ip.ljust(iplen) + self.c.WHITE +
                      ' | ' + self.c.BYELLOW + '%s' % found.ljust(folen) + self.c.WHITE +
                      ' | ' + self.c.BCYAN + '%s' % frame.ljust(frlen) + self.c.WHITE + ' |')

        print(self.c.WHITE + ' ' + '-' * tlen)
        print(self.c.WHITE)
        
        print("You can filter the conversation in wireshark using filter: 'frame.number==FRAME_ID'")
        print("or using tshark with the filter: -Y '(frame.number==FRAME_ID)'")
        print()

