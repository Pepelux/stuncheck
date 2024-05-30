#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = 'Jose Luis Verdeguer'
__email__ = "pepeluxx@gmail.com"

from modules.stunpcapdump import StunPCAPDump
from lib.params import get_stunpcapdump_args


def main():
    file = get_stunpcapdump_args()

    s = StunPCAPDump()
    s.file = file

    s.start()


if __name__ == '__main__':
    main()
