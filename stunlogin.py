#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

from modules.stunlogin import StunLogin
from lib.params import get_stunlogin_args


def main():
    ip, host, rport, proto, verbose, user, pwd = get_stunlogin_args()

    s = StunLogin()
    s.ip = ip
    s.host = host
    s.rport = rport
    s.proto = proto
    s.verbose = verbose
    s.user = user
    s.pwd = pwd

    s.start()


if __name__ == '__main__':
    main()
