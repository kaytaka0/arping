import socket
import struct
import sys
from time import sleep
from uuid import getnode as get_mac
import fcntl
import ipaddress
import netifaces as ni
from typing import List


def get_hw_addr(ifname: str) -> str:
    """MACアドレスを取得

    Args:
        ifname(str): インタフェース名
    Returns:
        str: MACアドレス("xx:xx:xx:xx"のような形式)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', bytes(ifname, 'utf-8')[:15]))
    return ':'.join('%02x' % b for b in info[18:24])


def guess_nw_if() -> str:
    """ネットワークインタフェースの推測

     ローカルループバック, dockerのブリッジネットワークを除いたものからインターフェースを選択する
    
    Returns:
        str: インタフェース名
    """
    exclude_ifname = ['docker0', 'lo']
    ifs = ni.interfaces()
    ifs = [ifname for ifname in ifs if ifname not in exclude_ifname]
    return ifs[0]


def make_ether(d_mac: List[int], s_mac: List[int]) -> bytes:
    """Ethernetヘッダの作成
    
    Returns:
        bytes: Ethernetヘッダのバイト列
    """
    ether_frame = [
        struct.pack('!6B', *d_mac), # 宛先MACアドレス
        struct.pack('!6B', *s_mac), # 送信元MACアドレス
        struct.pack('!H', 0x0806), # ARP
    ]
    return b''.join(ether_frame)

def unpack_arp_packet(payload: bytes, local_mac: List[int]) -> List[int]:
    """レスポンスのバイト列からMACアドレスを抽出する

    ARPリクエストの場合にレスポンス送信元のMACアドレスを返却する。
    ARP以外のプロトコルによるレスポンスの場合は、False

    Returns:
        List[int] | False: レスポンス送信元のMACアドレス, またはNone
    """
    
    d_mac = [int(x) for x in struct.unpack('!6B', payload[:6])]
    s_mac = [int(x) for x in struct.unpack('!6B', payload[6:12])]
    protocol_type = int(struct.unpack('!H', payload[12:14])[0])

    if(d_mac == local_mac and protocol_type == 0x0806):
        struct.unpack('!H', payload[14:16]) # HRD
        struct.unpack('!H', payload[16:18]) # PRO
        struct.unpack('!H', payload[20:22]) # OP
        a_src_mac = struct.unpack('!6B', payload[22:28]) # SHA
        struct.unpack('!4B', payload[28:32]) # SPA
        struct.unpack('!6B', payload[32:38]) # THA
        struct.unpack('!4B', payload[38:42]) # TPA
        return a_src_mac
    else:
        return None


def main():
    # ## ソケットの作成 ###
    ETH_P_ALL = 3
    ifname = guess_nw_if()
    soc = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    soc.bind((ifname, 0))

    # 宛先、送信元のIP, MACアドレス
    local_mac: List[int] = [int(x, 16) for x in get_hw_addr(ifname).split(":")]
    local_ip: List[int]  = [int(x) for x in socket.gethostbyname(socket.gethostname()).split(".")]
    dest_ip: List[int]   = [int(x) for x in sys.argv[1].split('.')]
    dest_mac: List[int]  = [0, 0, 0, 0, 0, 0] # 送信先のMACアドレスはわからないため、ダミーのアドレスを入れる

    # ARPパケットの作成
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
    # 送信パケット作成
    payload: bytes = make_ether(dest_mac, local_mac) + b''.join(ARP_FRAME)

    # 作成したARPパケットの送信
    soc.send(payload)

    while True:
        # ARPレスポンスの受信処理
        d = soc.recv(4086)
        print(f"[DEV] ARPING {sys.argv[1]} {ifname}")

        target_mac = unpack_arp_packet(d, local_mac)
        if target_mac is not None:
            # ARPレスポンスが受信された場合に、MACアドレスを表示する
            ip_str = ".".join([str(x) for x in dest_ip])
            mac_str = ":".join(["%02x" % x for x in target_mac])
            print(f"IP {ip_str}   MAC {mac_str}")
            break

        sleep(1)
    
    soc.close()


if __name__=="__main__":
    main()
