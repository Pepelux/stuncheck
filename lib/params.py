import sys
import argparse

BRED = '\033[1;31;20m'
RED = '\033[0;31;20m'
BRED_BLACK = '\033[1;30;41m'
RED_BLACK = '\033[0;30;41m'
BGREEN = '\033[1;32;20m'
GREEN = '\033[0;32;20m'
BGREEN_BLACK = '\033[1;30;42m'
GREEN_BLACK = '\033[0;30;42m'
BYELLOW = '\033[1;33;20m'
YELLOW = '\033[0;33;20m'
BBLUE = '\033[1;34;20m'
BLUE = '\033[0;34;20m'
BMAGENTA = '\033[1;35;20m'
MAGENTA = '\033[0;35;20m'
BCYAN = '\033[1;36;20m'
CYAN = '\033[0;36;20m'
BWHITE = '\033[1;37;20m'
WHITE = '\033[0;37;20m'


def get_stunscan_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''
        
██████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN scan =-''' + WHITE,
        epilog=BWHITE + '''
STUN/TURN server scanner.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Host/IP address/network (ex: mystunserver.com | 192.168.0.10 | 192.168.0.0/24)', dest="ipaddr")
    parser.add_argument('-r', '--remote_port', type=str, help='Ports to scan. Ex: 3478 | 3478,8080,37833 | 3400-3500 | 3470,5000,5300-5400 | TOP for common ports | ALL for 1-65536 (default: 3478/udp/tcp or 5349/tls)', dest='remote_port', default='3478')
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server udp|tcp|tls|all (default: udp)', dest='proto', default='udp')
    parser.add_argument('-th', '--threads', type=int, help='Number of threads (default: 200)', dest='threads', default=200)
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-nocolor', help='Show result without colors', dest='nocolor', action="count")
    parser.add_argument('-f', '--file', type=str, help='File with several IPs or network ranges', dest='file', default='')
    parser.add_argument('-o', '--output_file', type=str, help='Save data into a log file', dest='ofile', default='')
    parser.add_argument('-random', help='Randomize target hosts', dest='random', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    if not args.ipaddr and not args.file:
        print(
            'error: one of the following arguments are required: -i/--ip, -f/--file')
        sys.exit()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        THREADS = args.threads
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        NOCOLOR = args.nocolor
        FILE = args.file
        OFILE = args.ofile
        RANDOM = args.random

        return IPADDR, HOST, PORT, PROTO, THREADS, VERBOSE, NOCOLOR, FILE, OFILE, RANDOM
    except ValueError:
        sys.exit(1)


def get_stuninfo_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

███████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─█▄▀─███─▄███─██─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN info =-''' + WHITE,
        epilog=BWHITE + '''
Get info about a STUN/TURN server.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return IPADDR, HOST, PORT, PROTO, VERBOSE
    except ValueError:
        sys.exit(1)


def get_stunlogin_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

███████████████████████████████████████████▀█████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄███─▄▄─█─▄▄▄▄█▄─▄█▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─██▀█─██─█─██▄─██─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN login =-''' + WHITE,
        epilog=BWHITE + '''
Check user/password access to a STUN server.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-u', '--user', type=str, help='Username', dest="user")
    parser.add_argument('-p', '--pass', type=str, help='Password', dest="pwd")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        USER = args.user
        PWD = args.pwd

        return IPADDR, HOST, PORT, PROTO, VERBOSE, USER, PWD
    except ValueError:
        sys.exit(1)


def get_stuntransports_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄─▄─█▄─▄▄▀██▀▄─██▄─▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─████─████─▄─▄██─▀─███─█▄▀─██▄▄▄▄─██─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▀▄▄▄▀▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN transports =-''' + WHITE,
        epilog=BWHITE + '''
Bruteforce transports of a STUN server.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server udp|tcp|tls (default: udp)', dest='proto', default='udp')
    parser.add_argument('-t', '--transport', type=str, help=' Transport number (default: ALL)', dest='transport', default='')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-u', '--user', type=str, help='Username', dest="user")
    parser.add_argument('-p', '--pass', type=str, help='Password', dest="pwd")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        TRANSPORT = args.transport
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        USER = args.user
        PWD = args.pwd

        return IPADDR, HOST, PORT, PROTO, TRANSPORT, VERBOSE, USER, PWD
    except ValueError:
        sys.exit(1)


def get_stunportscan_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN portscan =-''' + WHITE,
        epilog=BWHITE + '''
TCP Port scanner via TURN connection. It is possible to scan remote computers, from the internal network or the machine itself if it allows localhost connections.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server tcp|tls (default: tcp)', dest='proto', default='tcp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-vvv', '--much_more_verbose', help='Increase much more verbosity', dest='much_more_verbose', action="count")
    parser.add_argument('-u', '--user', type=str, help='Username', dest="user")
    parser.add_argument('-p', '--pass', type=str, help='Password', dest="pwd")
    parser.add_argument('-ipdst', type=str, help='IP to scan (default: 127.0.0.1)', dest='ipdst', default='127.0.0.1')
    parser.add_argument('-ports', type=str, help='Ports to scan. Ex: 80 | 80,8080 | 1-1000 | 21,22,80,1000-2000 | ALL for 1-65536 (default: TOP 20)', dest='ports', default='')
    parser.add_argument('-fp', '--fingerprinting', help='Fingerprinting', dest="fp", action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        MUCH_MORE_VERBOSE = args.much_more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        if MUCH_MORE_VERBOSE == 1:
            VERBOSE = 3
        USER = args.user
        PWD = args.pwd
        IPDST = args.ipdst
        PORTS = args.ports
        FP = args.fp

        return IPADDR, HOST, PORT, PROTO, VERBOSE, USER, PWD, IPDST, PORTS, FP
    except ValueError:
        sys.exit(1)


def get_stunipscan_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─▄▄▄█▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN IP scan =-''' + WHITE,
        epilog=BWHITE + '''
Tries to access to several pre-established IP addresses (or a specific IP address) over TURN connection.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server tcp|tls (default: tcp)', dest='proto', default='tcp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-u', '--user', type=str, help='Username', dest="user")
    parser.add_argument('-p', '--pass', type=str, help='Password', dest="pwd")
    parser.add_argument('-ipdst', type=str, help='IP address to check connection', dest="ipdst", default='')

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        VERBOSE = args.verbose
        USER = args.user
        PWD = args.pwd
        IPDST = args.ipdst

        return IPADDR, HOST, PORT, PROTO, VERBOSE, USER, PWD, IPDST
    except ValueError:
        sys.exit(1)


def get_stunsocks_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

█████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█─▄▄─█─▄▄▄─█▄─█─▄█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─█─██─█─███▀██─▄▀██▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BBLUE + ''' -= STUN socks =-''' + WHITE,
        epilog=BWHITE + '''
Relay traffic using a SOCK5 proxy.
 
''')

    # Add arguments
    parser.add_argument('-i', '--ip', type=str, help='Target IP address', dest="ipaddr", required=True)
    parser.add_argument('-r', '--remote_port', type=int, help='Remote port (default: 3478)', dest='remote_port', default=3478)
    parser.add_argument('-proto', type=str, help=' Protocol to connect TURN server tcp|tls (default: tcp)', dest='proto', default='tcp')
    parser.add_argument('-v', '--verbose', help='Increase verbosity', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-u', '--user', type=str, help='Username', dest="user")
    parser.add_argument('-p', '--pass', type=str, help='Password', dest="pwd")
    parser.add_argument('-serverip', type=str, help='Local SOCK5 server IP address (default: 127.0.0.1)', dest='serverip', default='127.0.0.1')
    parser.add_argument('-serverport', type=int, help='Local SOCK5 server port (default: 1080)', dest='serverport', default=1080)

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        IPADDR = args.ipaddr
        HOST = args.ipaddr
        PORT = args.remote_port
        PROTO = args.proto
        VERBOSE = args.verbose
        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2
        USER = args.user
        PWD = args.pwd
        SERVERIP = args.serverip
        SERVERPORT = args.serverport

        return IPADDR, HOST, PORT, PROTO, VERBOSE, USER, PWD, SERVERIP, SERVERPORT
    except ValueError:
        sys.exit(1)

def get_sniff_args():
    parser = argparse.ArgumentParser(
        formatter_class=lambda prog: argparse.RawDescriptionHelpFormatter(
            prog, max_help_position=50),
        description= RED + u'''☎️  STUNCHECK''' + WHITE + ''' BY ''' + GREEN + '''🅿 🅴 🅿 🅴 🅻 🆄 🆇''' + YELLOW + '''

██████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█▄─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─██─█▄▀─███─███─▄████─▄███
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▀▀▀

''' + GREEN + '''💾 https://github.com/Pepelux/stuncheck''' + WHITE + '''
''' + YELLOW + '''🐦 https://twitter.com/pepeluxx''' + WHITE + '''

''' + BLUE + ''' -= STUN Network sniffing =-''' + WHITE,
        epilog=BWHITE + '''
Sniffer for the STUN protocol. When starting a conference it will show all IP addresses involved in the conversation. It verifies the attributes of the messages received from the STUN/TURN server and also the communication using the RTP protocol.
 
''')

    # Add arguments
    parser.add_argument('-d', '--dev', help='Set Device (by default try to get it)', dest='dev', default="")
    parser.add_argument('-r', '--remote_port', type=str, help='Remote port (default: 3478 for udp/tcp and 5349 for tls). ALL for all ports', dest='remote_port', default=3478)
    parser.add_argument('-o', '--output_file', type=str, help='Save output into a PCAP file', dest='ofile', default="")
    parser.add_argument('-f', '--_file', type=str, help='Save output into a TXT file', dest='file', default="")
    parser.add_argument('-proto', help='Protocol to sniff: udp|tcp|tls|all', dest='proto', default="all")
    parser.add_argument('-rtp', help='Filter only RTP traffic', dest='rtp', action="count")
    parser.add_argument('-v', '--verbose', help='Increase verbosity (no data displayed by default)', dest='verbose', action="count")
    parser.add_argument('-vv', '--more_verbose', help='Increase more verbosity', dest='more_verbose', action="count")
    parser.add_argument('-w', '--whois', help='Do a whois', dest='whois', action="count")

    # Array for all arguments passed to script
    args = parser.parse_args()

    try:
        DEV = args.dev
        RPORT = args.remote_port
        FILE = args.file
        OFILE = args.ofile
        PROTO = args.proto
        RTP = args.rtp
        VERBOSE = args.verbose
        WHOIS = args.whois

        MORE_VERBOSE = args.more_verbose
        if MORE_VERBOSE == 1:
            VERBOSE = 2

        return DEV, RPORT, FILE, OFILE, VERBOSE, PROTO, RTP, WHOIS
    except ValueError:
        print('[-] Error')
        sys.exit(1)

