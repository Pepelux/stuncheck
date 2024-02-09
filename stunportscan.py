#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from modules.stunportscan import StunPortscan
from lib.params import get_stunportscan_args


def main():
    ip, host, rport, proto, verbose, user, pwd, ipdst, ports, fp = get_stunportscan_args()

    s = StunPortscan()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.verbose = verbose
    s.user = user
    s.pwd = pwd
    s.ipdst = ipdst
    s.ports = ports
    s.fp = fp

    s.start()


if __name__ == '__main__':
    main()
