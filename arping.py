import socket
import struct
import sys
from time import sleep
from uuid import getnode as get_mac
import fcntl
import ipaddress

def getHwAddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])




def make_ether(d_mac, s_mac):
    ether_frame = [
        struct.pack('!6B', *d_mac),
        struct.pack('!6B', *s_mac),
        struct.pack('!H', 0x0806), # ARP

    ]
    return b''.join(ether_frame)

def main():
    # ip, source_mac を添付してARPパケットをブロードキャスト

    ETH_P_ALL = 3
    ifname = "enp0s4"
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    soc.bind((ifname, 0))

    local_mac = [int(x, 16) for x in getHwAddr(ifname).split(":")]
    local_ip = [int(x) for x in socket.gethostbyname(socket.gethostname()).split(".")]
    dest_ip = map(int, sys.argv[1].split('.'))
    dest_mac = [0, 0, 0, 0, 0, 0]

    ARP_FRAME = [
        struct.pack('!H', 0x0001), # HRD
        struct.pack('!H', 0x0800), # PRO
        struct.pack('!B', 0x06), # HLN
        struct.pack('!B', 0x04), # PLN
        struct.pack('!H', 0x0001), # OP
        struct.pack('!6B', *local_mac), # SHA
        struct.pack('!4B', *local_ip), # SPA
        struct.pack('!6B', *(0x00,)*6), # THA
        struct.pack('!4B', *dest_ip), # TPA
    ]
    payload = make_ether(dest_mac, local_mac) + b''.join(ARP_FRAME)
    print("ARP sent....")

    soc.send(payload)

    while True:
        d = soc.recv(4086)

        dest = list(map(int, struct.unpack("!6B", d[:6])))
        src = list(map(int, struct.unpack("!6B", d[6:12])))
        protocol_type = struct.unpack("!H", d[12:14])[0]
        if(protocol_type == 0x0806 and dest == local_mac):
            print(":".join(["%02x" % x for x in src]))
            break
        sleep(1)
    
    soc.close()




if __name__=="__main__":
    main()
