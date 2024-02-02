#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.stunsocks import StunSocks
from lib.params import get_stunsocks_args


def main():
    ip, host, rport, proto, verbose, user, pwd, serverip, serverport = get_stunsocks_args()

    s = StunSocks()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.verbose = verbose
    s.user = user
    s.pwd = pwd
    s.socks_host = serverip
    s.socks_port = serverport

    s.start()


if __name__ == '__main__':
    main()
