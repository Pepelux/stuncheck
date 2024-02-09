StunCheck is a set of tools for scanning, testing and exploiting STUN and TURN servers.

Some of the implemented utilities are based on the fantastic Stunner application (https://github.com/firefart/stunner)

# StunScan #

Multithread STUN/TURN server scanner. It can scan large ranges of networks.

```
 -= STUN scan =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Host/IP address/network (ex: mystunserver.com | 192.168.0.10 | 192.168.0.0/24)
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Ports to scan. Ex: 3478 | 3478,5349 | 3400-3500 | 3470,5000,5300-5400 | ALL for 1-65536 (default: 3478/udp or 5349/tcp)
  -p PROTO, --proto PROTO                    Protocol: udp|tcp|tls|all (default: udp)
  -th THREADS, --threads THREADS             Number of threads (default: 200)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
  -nocolor                                   Show result without colors
  -f FILE, --file FILE                       File with several IPs or network ranges
  -o OFILE, --output_file OFILE              Save data into a log file
  -random                                    Randomize target hosts
```

# StunInfo #

Gets info about the stun or turn server like used software, listening interface and supported protocols.

```
 -= STUN info =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: udp|tcp|tls (default: udp)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
```

Example:

```
$ ./stuninfo.py -i 185.X.X.11

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇

███████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─█▄▀─███─▄███─██─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Port: 3478
[✓] Protocol: UDP

[+] Headers:
  [-]  Message Type: Binding Response
  [-]  Message Cookie: 482112a4
  [-]  Transaction ID: 422cb0fa30c04c71f3dd3264e4
[+] Attributes:
  [-]  XOR-MAPPED-ADDRESS: 193.X.X.9:55878
  [-]  MAPPED-ADDRESS: 193.X.X.9:55878
  [-]  RESPONSE-ORIGIN: 185.X.X.11:3478
  [-]  SOFTWARE: Coturn-4.5.2 'dan Eider'
  [-]  FINGERPRINT: 848d1fa8

Transport ... UDP
[+] Headers:
  [-]  Message Type: Allocate Error Response
  [-]  Message Cookie: 682112a4
  [-]  Transaction ID: 42ffd9da6b9f98f06077f2ca56
[+] Attributes:
  [-]  ERROR-CODE: 401 Unauthorized
  [-]  NONCE: 7eb2371b7c103283
  [-]  REALM: mydomain.com
  [-]  SOFTWARE: Coturn-4.5.2 'dan Eider'
  [-]  FINGERPRINT: 27227d9d

Transport ... TCP
[+] Headers:
  [-]  Message Type: Allocate Error Response
  [-]  Message Cookie: 682112a4
  [-]  Transaction ID: 423ef44c68a1e7ec22f3b1d076
[+] Attributes:
  [-]  ERROR-CODE: 34303120 401 Unauthorized
  [-]  NONCE: 7b2d5efff9a9f2b5
  [-]  REALM: mydomain.com
  [-]  SOFTWARE: Coturn-4.5.2 'dan Eider'
  [-]  FINGERPRINT: dd4a9f0e
```

# StunSniff #

Sniffer for the STUN protocol. When starting a conference it will show all IP addresses involved in the conversation. It verifies the attributes of the messages received from the STUN/TURN server and also the communication using the RTP protocol.

```
 -= STUN Network sniffing =-

options:
  -h, --help                                 show this help message and exit
  -d DEV, --dev DEV                          Set Device (by default try to get it)
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478 for udp/tcp and 5349 for tls). ALL for all ports
  -o OFILE, --output_file OFILE              Save output into a PCAP file
  -f FILE, --_file FILE                      Save output into a TXT file
  -p PROTO, --proto PROTO                    Protocol to sniff: udp|tcp|tls|all
  -rtp                                       Filter only RTP traffic
  -v, --verbose                              Increase verbosity (no data displayed by default)
  -vv, --more_verbose                        Increase more verbosity
  -w, --whois                                Do a whois
```

# StunLogin #

Using the TURN protocol verifies the authentication of a given username and password.

```
 -= STUN login =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: udp|tcp|tls (default: udp)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
  -user USER                                 Username
  -pass PWD                                  Password
```

Example:

You can obtain TURN_USER and TURN_PASS, for example, using Burp.

```
$ ./stunlogin.py -i 185.X.X.11 -user TURN_USER -pass TURN_PASS

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇

███████████████████████████████████████████▀█████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄███─▄▄─█─▄▄▄▄█▄─▄█▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─██▀█─██─█─██▄─██─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▄▀▄▄▄▀▀▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Remote port: 3478
[✓] Protocol: UDP

[+] Allocate Request
[-] Allocate Error Response
[-] 401 Unauthorized
[+] Allocate Request
[-] Allocate Success Response
[✓] Connection successful
```

# StunTransports #

Bruteforce transports of a TURN server.

```
  -= STUN transports =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: udp|tcp|tls (default: udp)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
  -user USER                                 Username
  -pass PWD                                  Password
```

Example:

```
$ ./stuntransports.py -i 185.X.X.11 -user TURN_USER -pass TURN_PASS

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇

█████████████████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄─▄─█▄─▄▄▀██▀▄─██▄─▀█▄─▄█─▄▄▄▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─████─████─▄─▄██─▀─███─█▄▀─██▄▄▄▄─██─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▀▄▄▄▀▀▄▄▀▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Port range: 3478
[✓] Protocol: UDP

[✓] Proto 06 Connection successful
[✓] Proto 11 Connection successful
```

# StunIpScan #

Tries to access to several pre-established IP addresses (or a specific IP address) over TURN connection.

```
 -= STUN IP scan =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: tcp|tls (default: tcp)
  -v, --verbose                              Increase verbosity
  -user USER                                 Username
  -pass PWD                                  Password
  -dip DESTIP, --dest-ip DESTIP              IP address to check connection
```

Example:

```
$ ./stunipscan.py -i 185.X.X.11 -user TURN_USER -pass TURN_PASS

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇


████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄█▄─▄▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─███─▄▄▄█▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▄▄▄▀▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Port range: 3478
[✓] Protocol: TCP

[✓] 192.168.0.1/UDP: Successfully connected
[✓] 192.88.99.0/UDP: Successfully connected
[✓] 198.18.0.1/UDP: Successfully connected
[✓] 192.0.2.254/UDP: Successfully connected
[✓] 198.19.255.254/UDP: Successfully connected
[x] 224.0.0.1/UDP: Create Perm Error Response (Forbidden IP)
[x] 255.255.255.255/UDP: Create Perm Error Response (Forbidden IP)
[✓] 100.127.255.254/UDP: Successfully connected
[✓] 192.0.0.254/UDP: Successfully connected
[✓] 169.254.254.255/UDP: Successfully connected
[x] 240.0.0.1/UDP: Create Perm Error Response (Forbidden IP)
[✓] 203.0.113.254/UDP: Successfully connected
[✓] 203.0.113.1/UDP: Successfully connected
[x] 239.255.255.254/UDP: Create Perm Error Response (Forbidden IP)
[x] ::/UDP: Create Perm Error Response (Forbidden IP)
[✓] 10.255.255.254/UDP: Successfully connected
[✓] 127.0.0.1/UDP: Successfully connected
[✓] 169.254.0.1/UDP: Successfully connected
[✓] 169.254.169.254/UDP: Successfully connected
[x] ::1/UDP: Create Perm Error Response (Forbidden IP)
[✓] 172.31.255.254/UDP: Successfully connected
[✓] 192.0.2.1/UDP: Successfully connected
[✓] 10.0.0.1/UDP: Successfully connected
[✓] 198.51.100.1/UDP: Successfully connected
[✓] 192.168.255.254/UDP: Successfully connected
[✓] 172.16.0.1/UDP: Successfully connected
[✓] 198.51.100.254/UDP: Successfully connected
[x] 0.0.0.0/UDP: Create Perm Error Response (Forbidden IP)
[✓] 127.0.0.8/UDP: Successfully connected
[✓] 100.64.0.0/UDP: Successfully connected
[✓] 192.0.0.1/UDP: Successfully connected
[✓] 127.255.255.254/UDP: Successfully connected
[✓] 192.168.0.1/TCP: Successfully connected
[✓] 192.88.99.0/TCP: Successfully connected
[✓] 198.18.0.1/TCP: Successfully connected
[✓] 192.0.2.254/TCP: Successfully connected
[✓] 198.19.255.254/TCP: Successfully connected
[x] 224.0.0.1/TCP: Create Perm Error Response (Forbidden IP)
[x] 255.255.255.255/TCP: Create Perm Error Response (Forbidden IP)
[✓] 100.127.255.254/TCP: Successfully connected
[✓] 192.0.0.254/TCP: Successfully connected
[✓] 169.254.254.255/TCP: Successfully connected
[x] 240.0.0.1/TCP: Create Perm Error Response (Forbidden IP)
[✓] 203.0.113.254/TCP: Successfully connected
[✓] 203.0.113.1/TCP: Successfully connected
[x] 239.255.255.254/TCP: Create Perm Error Response (Forbidden IP)
[x] ::/TCP: Create Perm Error Response (Forbidden IP)
[✓] 10.255.255.254/TCP: Successfully connected
[✓] 127.0.0.1/TCP: Successfully connected
[✓] 169.254.0.1/TCP: Successfully connected
[✓] 169.254.169.254/TCP: Successfully connected
[x] ::1/TCP: Create Perm Error Response (Forbidden IP)
[✓] 172.31.255.254/TCP: Successfully connected
[✓] 192.0.2.1/TCP: Successfully connected
[✓] 10.0.0.1/TCP: Successfully connected
[✓] 198.51.100.1/TCP: Successfully connected
[✓] 192.168.255.254/TCP: Successfully connected
[✓] 172.16.0.1/TCP: Successfully connected
[✓] 198.51.100.254/TCP: Successfully connected
[x] 0.0.0.0/TCP: Create Perm Error Response (Forbidden IP)
[✓] 127.0.0.8/TCP: Successfully connected
[✓] 100.64.0.0/TCP: Successfully connected
[✓] 192.0.0.1/TCP: Successfully connected
[✓] 127.255.255.254/TCP: Successfully connected
```

# StunPortScan #

Port scanner via TURN connection. It is possible to scan remote computers, from the internal network or the machine itself if it allows localhost connections.

```
 -= STUN portscan =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: tcp|tls (default: tcp)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
  -vvv, --much_more_verbose                  Increase more verbosity
  -user USER                                 Username
  -pass PWD                                  Password
  -ipdst IPDST                               IP to scan (default: 127.0.0.1)
  -ports PORTS                               Ports to scan. Ex: 80 | 80,8080 | 1-1000 | 21,22,80,1000-2000 | ALL for 1-65536 (default: ALL)
  -fp, --fingerprinting                      Fingerprinting
```

Example:

```
$ ./stunportscan.py -i 185.X.X.11 -user TURN_USER -pass TURN_PASS -ports 80,22,443,3306 -v

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇

█████████████████████████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█▄─▄▄─█─▄▄─█▄─▄▄▀█─▄─▄─█─▄▄▄▄█─▄▄▄─██▀▄─██▄─▀█▄─▄█
█▄▄▄▄─███─████─██─███─█▄▀─███─▄▄▄█─██─██─▄─▄███─███▄▄▄▄─█─███▀██─▀─███─█▄▀─██
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▀▀▀▄▄▄▄▀▄▄▀▄▄▀▀▄▄▄▀▀▄▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▀▀▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Remote port: 3478
[✓] Port range: 80,22,443,3306
[✓] Protocol: TCP

[✓] Port : 22 open
[✓] Port : 3306 open
[x] Port : 443 closed
[✓] Port : 80 open
```

The port scan is executed from the TURN server itself. If we scan from outside and there is a firewall, we see that some ports are not accessible.

```
$ nmap 185.X.X.11 -p80,22,443,3306 -Pn
Starting Nmap 7.94 ( https://nmap.org ) at 2024-02-08 18:01 CET
Nmap scan report for webrtc (185.X.X.11)
Host is up (0.020s latency).
rDNS record for 185.99.186.211: webrtc.seguridadvoip.com

PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
443/tcp  filtered https
3306/tcp filtered mysql

Nmap done: 1 IP address (1 host up) scanned in 1.25 seconds
```

# StunSocks #

Relay traffic over TURN server using a Socks5 TCP proxy.

```
 -= STUN socks =-

options:
  -h, --help                                 show this help message and exit
  -i IPADDR, --ip IPADDR                     Target IP address
  -r REMOTE_PORT, --remote_port REMOTE_PORT  Remote port (default: 3478)
  -p PROTO, --proto PROTO                    Protocol: tcp|tls (default: tcp)
  -v, --verbose                              Increase verbosity
  -vv, --more_verbose                        Increase more verbosity
  -user USER                                 Username
  -pass PWD                                  Password
  -serverip SERVERIP                         Local SOCK5 server IP address (default: 127.0.0.1)
  -serverport SERVERPORT                     Local SOCK5 server port (default: 1080)
```

Example:

```
$ ./stunsocks.py -i 185.X.X.11 -user TURN_USER -pass TURN_PASS

☎️  STUNCHECK BY 🅿 🅴 🅿 🅴 🅻 🆄 🆇


█████████████████████████████████████████████████████████
█─▄▄▄▄█─▄─▄─█▄─██─▄█▄─▀█▄─▄█─▄▄▄▄█─▄▄─█─▄▄▄─█▄─█─▄█─▄▄▄▄█
█▄▄▄▄─███─████─██─███─█▄▀─██▄▄▄▄─█─██─█─███▀██─▄▀██▄▄▄▄─█
▀▄▄▄▄▄▀▀▄▄▄▀▀▀▄▄▄▄▀▀▄▄▄▀▀▄▄▀▄▄▄▄▄▀▄▄▄▄▀▄▄▄▄▄▀▄▄▀▄▄▀▄▄▄▄▄▀

💾 https://github.com/Pepelux/stuncheck
🐦 https://twitter.com/pepeluxx

[✓] IP/Network: 185.X.X.11
[✓] Port range: 3478
[✓] Protocol: TCP

Sock5 server started on 127.0.0.1:1080

[✓] Destination: 34.117.118.44:80
[✓] Connection established to: webrtc:3478
[✓] Connect Request: 34.117.118.44:80
[✓] Destination accepted
[✓] Connection successfully linked
```

On another console:

```
$ curl -x socks5://127.0.0.1:1080 http://ifconfig.me
185.X.X.11

$ proxychains4 curl http://ifconfig.me
[proxychains] config file found: /usr/local/etc/proxychains.conf
[proxychains] preloading /usr/local/Cellar/proxychains-ng/4.16/lib/libproxychains4.dylib
[proxychains] DLL init: proxychains-ng 4.16
[proxychains] Strict chain  ...  127.0.0.1:1080  ...  ifconfig.me:80  ...  OK
185.X.X.11
```

To access the local web of the TURN server:

```
$ curl -x socks5://127.0.0.1:1080 http://localhost

$ proxychains4 curl http://localhost
```

# Requirements #
* Python 3


# Instalation #

```
$ git clone https://github.com/Pepelux/stuncheck.git
$ cd stuncheck
$ pip3 install -r requirements.txt
```
