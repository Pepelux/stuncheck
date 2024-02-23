#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

from modules.stuntransports import StunTransports
from lib.params import get_stuntransports_args


def main():
    ip, host, rport, proto, transport, verbose, user, pwd = get_stuntransports_args()

    s = StunTransports()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.transport = transport
    s.verbose = verbose
    s.user = user
    s.pwd = pwd

    s.start()


if __name__ == '__main__':
    main()
