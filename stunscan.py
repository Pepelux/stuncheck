#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.stunscan import StunScan
from lib.params import get_stunscan_args


def main():
    ip, host, rport, proto, threads, verbose, nocolor, file, ofile, random = get_stunscan_args()

    s = StunScan()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.threads = threads
    s.verbose = verbose
    s.nocolor = nocolor
    s.file = file
    s.ofile = ofile
    s.random = random

    s.start()


if __name__ == '__main__':
    main()
