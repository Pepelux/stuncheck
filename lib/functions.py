import hmac
import socket
import struct
from bitstring import Bits
import hashlib
import netifaces


# STUN Message Header
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |0 0|     STUN Message Type     |         Message Length        |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |                         Magic Cookie                          |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                             Transaction ID
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#                                                                    |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# STUN Attribute Header
#
#     0                   1                   2                   3
#     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#    |         Type                  |            Length             |
#    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


def ip2long(ip):
    """
    Convert an IP string to long
    """
    packedIP = socket.inet_aton(ip)
    return struct.unpack("!L", packedIP)[0]


def long2ip(ip):
    return str(socket.inet_ntoa(struct.pack('!L', ip)))


def format_time(value):
    if value < 60:
        return str(value) + ' sec(s)'

    m = int(value/60)
    s = value % 60

    if m < 60:
        return str(m) + ' min(s) ' + str(s) + ' sec(s)'

    h = int(m/60)
    m = m % 60

    return str(h) + ' hour(s) ' + str(m) + ' min(s) ' + str(s) + ' sec(s)'


def address_parse(value):
    ip_address = {"port": bin2int(value[16:32]),
                  "ip": str(bin2int(value[32:40])) + "." + str(bin2int(value[40:48])) + "." + str(
        bin2int(value[48:56])) + "." + str(bin2int(value[56:64]))}
    return ip_address


def xor_address_parse(value):
    magicCookie = Bits(hex="0x2112A442")
    return address_parse(((Bits(bin=value[0:16])) +
                          (Bits(bin=value[16:32]) ^ Bits(bin=magicCookie.bin[0:16])) +
                          (Bits(bin=value[32:64]) ^ magicCookie)).bin)


def xor_address_parse2(value):
    magicCookie = Bits(hex="0x2112A442")
    xor_code = ((Bits(bin=value[0:16])) +
                (Bits(bin=value[16:32]) ^ Bits(bin=magicCookie.bin[0:16])) +
                (Bits(bin=value[32:64]) ^ magicCookie)).bin
    return (hex(int(xor_code, base=2)))


def parse_address(data, xor=False):
    (family, port) = struct.unpack_from("!HH", data, 0)

    if xor:
        port ^= 0x2112

    if family == 0x0001:  # IPv4
        (addr,) = struct.unpack_from("!I", data, 4)

        if xor:
            addr ^= 0x2112A442

        addr = socket.inet_ntoa(struct.pack("!I", addr))
    elif family == 0x0002:  # IPv6
        raise NotImplementedError("IPv6 parsing not implemented")
    else:
        raise ValueError("Unknown address family")

    return (addr, port)


attributesValues = {"UDP": "11", "TCP": "06", "UNKNOWN": "00"}

attributesTypes = {"0000": "",
                   "0001": "MAPPED-ADDRESS",
                   "0002": "RESPONSE-ADDRESS",
                   "0003": "CHANGE-ADDRESS",
                   "0004": "SOURCE-ADDRESS (Deprecated)",
                   "0005": "CHANGED-ADDRESS (Deprecated)",
                   "0006": "USERNAME",
                   "0007": "PASSWORD",
                   "0008": "MESSAGE-INTEGRITY",
                   "0009": "ERROR-CODE",
                   "000a": "UNKNOWN-ATTRIBUTES",
                   "000b": "REFLECTED-FROM",
                   "000c": "CHANNEL-NUMBER",
                   "000d": "LIFETIME",
                   "0012": "XOR-PEER-ADDRESS",
                   "0013": "DATA",
                   "0014": "REALM",
                   "0015": "NONCE",
                   "0016": "XOR-RELAYED-ADDRESS",
                   "0017": "REQUESTED-ADDRESS-FAMILY",
                   "0018": "EVEN-PORT",
                   "0019": "REQUESTED-TRANSPORT",
                   "001a": "DONT-FRAGMENT",
                   "001b": "ACCESS-TOKEN",
                   "001d": "PASSWORD-ALGORITHM",
                   "001c": "MESSAGE-INTEGRITY-SHA256",
                   "001e": "USERHASH",
                   "0020": "XOR-MAPPED-ADDRESS",
                   "0022": "RESERVATION-TOKEN",
                   "0024": "PRIORITY",
                   "0025": "USE-CANDIDATE",
                   "0026": "PADDING",
                   "0027": "RESPONSE-PORT",
                   "002a": "CONNECTION-ID",
                   "8000": "ADDITIONAL-ADDRESS-FAMILY",
                   "8001": "ADDRESS-ERROR-CODE",
                   "8002": "PASSWORD-ALGORITHMS",
                   "8003": "ALTERNATE-DOMAIN",
                   "8004": "ICMP",
                   "8022": "SOFTWARE",
                   "8023": "ALTERNATE-SERVER",
                   "8025": "TRANSACTION_TRANSMIT_COUNTER",
                   "8027": "CACHE-TIMEOUT",
                   "8028": "FINGERPRINT",
                   "8029": "ICE-CONTROLLED",
                   "802a": "ICE-CONTROLLING",
                   "802b": "RESPONSE-ORIGIN",
                   "802c": "OTHER-ADDRESS",
                   "802d": "ECN-CHECK STUN",
                   "802e": "THIRD-PARTY-AUTHORIZATION",
                   "8030": "MOBILITY-TICKET",
                   "c000": "CISCO-STUN-FLOWDATA",
                   "c001": "ENF-FLOW-DESCRIPTION",
                   "c002": "ENF-NETWORK-STATUS",
                   "c057": "GOOG-NETWORK-INFO",
                   "c058": "GOOG-LAST-ICE-CHECK-RECEIVED",
                   "c059": "GOOG-MISC-INFO",
                   "c05a": "GOOG-OBSOLETE-1",
                   "c05b": "GOOG-CONNECTION-ID",
                   "c05c": "GOOG-DELTA",
                   "c05d": "GOOG-DELTA-ACK",
                   "c05e": "GOOG-DELTA-SYNC-REQ",
                   "c060": "GOOG-MESSAGE-INTEGRITY-32"}

headersTypes = {"0001": "Binding Request",
                "0002": "Shared Secret Request",
                "0003": "Allocate Request",
                "0004": "Refresh Request",
                "0006": "Send Request",
                "0007": "Data Request",
                "0008": "Create Perm Request",
                "0009": "Channel Bind Request",
                "000a": "Connect Request",
                "000b": "ConnectionBind Request",
                "000c": "ConnectionAttempt Request",
                "0011": "Binding Indication",
                "0016": "Send Indication",
                "0017": "Data Indication",

                "0101": "Binding Response",
                "0102": "Shared Secret Response",
                "0103": "Allocate Success Response",
                "0104": "Refresh Response",
                "0106": "Send Response",
                "0107": "Data Response",
                "0108": "Create Perm Response",
                "0109": "Channel Bind Response",
                "010a": "Connect Success Response",
                "010b": "ConnectionBind Success Response",

                "0111": "Binding Error Response",
                "0112": "Shared Secret Error Response",
                "0113": "Allocate Error Response",
                "0114": "Refresh Error Response",
                "0116": "Send Error Response",
                "0117": "Data Error Response",
                "0118": "Create Perm Error Response",
                "0119": "Channel Bind Error Response",
                "011a": "Connect Error Response",
                "011b": "ConnectionBind Error Response"}


def bin2hex(binary):
    return Bits(bin=binary).hex


def bin2int(binary):
    return Bits(bin=binary).uint


# def generateUserPass(secret):
#     t = int(time.time())
#     expiry = 8400
#     username = str(t + expiry)

#     hmac_sha1 = calculate_message_integrity(username.encode(), secret.encode())
#     password = base64.b64encode(hmac_sha1).decode()

#     return (username, password)

def add_stun_attribute(attr_type, attr_value):
    attr_length = len(attr_value)
    padding = (4 - (attr_length % 4)) % 4
    padded_attr_value = attr_value + b'\x00' * padding
    return struct.pack('!HH', attr_type, attr_length) + padded_attr_value


def calculate_message_integrity(message, key):
    hashed_message = hmac.new(key, message, hashlib.sha1).digest()
    return hashed_message


def xor_address_to_bits(xor_address):
    total = xor_address.count(':')

    if total > 1:
        pos = xor_address.rfind(':')
        ip = xor_address[0:pos]
        ip = socket.inet_pton(socket.AF_INET6, ip)
        port = xor_address[pos+1:]
    else:
        ip, port = xor_address.split(':')
        ip = socket.inet_aton(ip)

    port = '0x'+hex(int(port))[2:].zfill(4)
    addr = b'\x00\x00' + Bits(port) + ip

    return Bits(addr)


def build_request(message_type, transaction_id, protocol, force_tcp, xor_address, username=None, realm=None, nonce=None, password=None, connectionid=None):
    message_length = 0
    attributes = b""

    bytes_proto = bytes.fromhex(protocol) + b'\x00\x00\x00'

    if username and realm and nonce:
        # Add attributes: REQUESTED-TRANSPORT, USERNAME, REALM, and NONCE
        if message_type == 11:
            try:
                attributes += add_stun_attribute(0x2a, connectionid.encode())
            except:
                attributes += add_stun_attribute(0x2a, connectionid)

        if xor_address != '':
            # Add attribute: XOR-PEER-ADDRESS
            input_bits = xor_address_to_bits(xor_address)
            result = xor_address_parse2(input_bits.bin)
            result_bits = b""
            result_bits += b"\x00"  # reserved
            result_bits += b"\x01"  # protocol family (IPv4)
            result_bits += bytearray.fromhex(result[2:].zfill(12))
            attributes += add_stun_attribute(0x12, result_bits)
        else:
            if message_type != 11:
                attributes += add_stun_attribute(0x19, bytes_proto)
        attributes += add_stun_attribute(0x06, username.encode('utf-8'))
        attributes += add_stun_attribute(0x14, realm.encode('utf-8'))
        attributes += add_stun_attribute(0x15, nonce.encode('utf-8'))
    elif force_tcp == True:
        attributes += add_stun_attribute(0x19, bytes_proto)

    message_length = len(attributes)
    message = struct.pack('!HHI12s', message_type, message_length,
                          0x2112A442, transaction_id.to_bytes(12, byteorder='big'))
    message += attributes

    if username and realm and nonce:
        message_length = len(attributes)+24
        message = struct.pack('!HHI12s', message_type, message_length, 0x2112A442,
                              transaction_id.to_bytes(12, byteorder='big')) + attributes

        key = hashlib.md5((username + ":" + realm + ":" +
                          password).encode('utf-8')).digest()

        # Calculate HMAC
        message_integrity = calculate_message_integrity(message, key)

        # Add MESSAGE-INTEGRITY attribute
        message = message + add_stun_attribute(0x08, message_integrity)

    return message


def header_parse(buf):
    header = {}

    value = buf[0:4]
    header['MESSAGE_TYPE'] = headersTypes[value]
    value = buf[6:14]
    header['COOKIE'] = value
    value = buf[14:]
    header['TRANSACTION_ID'] = value

    return header


def attributes_parse(buf):
    i = 0
    length = len(buf)
    attribute = {}
    cont = 1

    while i < length:
        # while buf[i + 0:i + 4] not in attributesTypes and i < length:
        #     i += 2

        while buf[i + 0:i + 4] in attributesTypes and attributesTypes[buf[i + 0:i + 4]] == '' and i < length:
            i += 4

        if i < length:
            if buf[i + 0:i + 4] in attributesTypes:
                attribute_type = attributesTypes[buf[i + 0:i + 4]]
            else:
                attribute_type = 'unknown attribute %s' % str(cont)
                cont += 1

            attribute_length = int(buf[i + 4:i + 8], base=16)
            if attribute_length % 2 != 0:
                attribute_length += 1
            attribute_length *= 2

            attribute_value = buf[i + 8:i + 8 + attribute_length]
            # print(buf[i + 0:i + 4])
            # print(buf[i + 4:i + 8])
            # print(attribute_length)
            # print(attribute_value)
            # print(attribute_type)

            try:
                if attribute_type == 'CONNECTION-ID':
                    attribute[attribute_type] = bytes.fromhex(attribute_value)
                else:
                    attribute[attribute_type] = bytes.fromhex(
                        attribute_value).decode("ascii")
            except:
                # if attribute_type == 'XOR-MAPPED-ADDRESS' or attribute_type == 'MAPPED-ADDRESS' or attribute_type == 'RESPONSE-ORIGIN':
                if attribute_type[0:3] == 'XOR':
                    (ip, port) = parse_address(
                        bytes.fromhex(attribute_value), True)
                    attribute_value = ip+':'+str(port)
                else:
                    try:
                        (ip, port) = parse_address(
                            bytes.fromhex(attribute_value), False)
                        attribute_value = ip+':'+str(port)
                    except:
                        pass

                byte_data = attribute_value.encode('utf-8')
                hex_string = byte_data.hex()
                attribute[attribute_type] = bytes.fromhex(
                    hex_string).decode("ascii")

            i += 8 + attribute_length

    return attribute


def searchInterface():
    ifaces = netifaces.interfaces()
    local_ip = get_machine_default_ip()
    networkInterface = ''

    for iface in ifaces:
        data = netifaces.ifaddresses(iface)
        if str(data).find(local_ip) != -1:
            networkInterface = iface

    return networkInterface


def get_machine_default_ip(type='ip'):
    """Return the default gateway IP for the machine."""
    gateways = netifaces.gateways()
    defaults = gateways.get("default")
    if not defaults:
        return

    def default_ip(family):
        gw_info = defaults.get(family)
        if not gw_info:
            return
        addresses = netifaces.ifaddresses(gw_info[1]).get(family)
        if addresses:
            if type == 'mask':
                return addresses[0]["netmask"]
            else:
                return addresses[0]["addr"]

    return default_ip(netifaces.AF_INET) or default_ip(netifaces.AF_INET6)
