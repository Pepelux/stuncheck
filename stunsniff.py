#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.stunsniff import StunSniff
from lib.params import get_sniff_args


def main():
    dev, rport, file, ofile, verbose, proto, rtp, whois = get_sniff_args()

    s = StunSniff()
    s.dev = dev
    s.rport = rport
    s.file = file
    s.ofile = ofile
    s.verbose = verbose
    s.proto = proto
    s.rtp = rtp
    s.whois = whois

    s.start()


if __name__ == '__main__':
    main()
