#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.stunipscan import StunIpscan
from lib.params import get_stunipscan_args


def main():
    ip, host, rport, proto, verbose, user, pwd, ipdst = get_stunipscan_args()

    s = StunIpscan()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.verbose = verbose
    s.user = user
    s.pwd = pwd
    s.ipdst = ipdst

    s.start()


if __name__ == '__main__':
    main()
