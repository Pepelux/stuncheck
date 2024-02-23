#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

from modules.stuninfo import StunInfo
from lib.params import get_stuninfo_args


def main():
    ip, host, rport, proto, verbose, nt = get_stuninfo_args()

    s = StunInfo()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.verbose = verbose
    s.nt = nt

    s.start()


if __name__ == '__main__':
    main()
