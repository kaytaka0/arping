import socket
import struct
from uuid import getnode as get_mac

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
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    soc.bind(("enp0s4", 0))

    #local_mac = [int((f"{get_mac()}"[i:i+2]), 16) for i in range(0, 12, 2)]
    local_mac = [int("ee:e2:1d:9c:b1:cb"[i:i+2], 16) for i in range(0, 17, 3)]
    local_ip = [int(x) for x in socket.gethostbyname(socket.gethostname()).split(".")]
    dest_ip = [10, 0, 2, 3]
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
    print(payload)
    print("=" * 50)

    soc.send(payload)
    d = soc.recv(4086)
    print(d)
    dest_mac =  d[:6].hex()
    result = ":".join([ dest_mac[i:i+2] for i in range(0, 12, 2)])
    print(result)
    soc.close()




if __name__=="__main__":
    main()