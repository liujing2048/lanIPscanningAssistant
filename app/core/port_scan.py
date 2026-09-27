"""TCP SYN 端口探测：以牺牲 IP 为源发 SYN，嗅探 SYN-ACK 判定开放。

不用 connect 的原因：connect 用本机真实 IP 做源，目标网段与本机 IP
不匹配时 SYN-ACK 要走路由，不可靠；SYN 扫描复用牺牲 IP + ARP 应答器 +
统一嗅探架构，与 ARP 扫描同一条代码路径。

sport 编码反查：为每个 (主机, 端口) 分配唯一源端口，收到 SYN-ACK 时按
目标端口 O(1) 反查归属，无需会话表。
"""
import random

from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

# 常见服务端口（用于设备类型推断）
COMMON_PORTS = [
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    139,   # NetBIOS
    143,   # IMAP
    443,   # HTTPS
    445,   # SMB
    515,   # LPD（打印机）
    554,   # RTSP（摄像头）
    631,   # IPP（打印机）
    1433,  # SQL Server
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
    8080,  # HTTP 备用
    9100,  # 打印机 RAW
]

SPORT_BASE = 40000
SPORT_MAX = 65500
BATCH_SIZE = SPORT_MAX - SPORT_BASE  # 单批最多探测数，超出分批发送


def build_syn_packets(hosts: list[tuple[str, str]], sacrifice_ip: str,
                       iface_mac: str):
    """为已发现的主机构造全端口 SYN 包。

    :param hosts: [(ip, mac), ...] 主机发现阶段已知 MAC，直接填二层目的地址
    :return: (packets, sport_map)  sport_map: sport → (ip, port)
    """
    packets = []
    sport_map = {}
    sport = SPORT_BASE
    for ip, mac in hosts:
        for port in COMMON_PORTS:
            if sport > SPORT_MAX:
                break
            pkt = (
                Ether(src=iface_mac, dst=mac)
                / IP(src=sacrifice_ip, dst=ip)
                / TCP(sport=sport, dport=port, flags="S",
                      seq=random.randint(1 << 20, 1 << 30))
            )
            packets.append(pkt)
            sport_map[sport] = (ip, port)
            sport += 1
    return packets, sport_map
