"""ARP 扫描核心：牺牲 IP 选取、who-has 包构造、ARP 代理应答器。

原理：对目标子网内每个 IP 发送 ARP who-has 请求，ARP 层的发送方 IP（psrc）
填"目标子网内的牺牲地址"而非本机真实 IP。目标主机收到后会把 ARP is-at
应答回给以太网帧的源 MAC（即本机网卡），由嗅探器捕获完成发现。
这样即使本机网卡完全没配置目标网段（如 192.168.1.8/29 场景），只要
物理上同一局域网就能发现设备，且全程不改动网卡配置。

牺牲 IP 选目标子网的网络地址（如 192.168.3.0/24 → 192.168.3.0）：
- 网络地址永远不会分配给真实主机，即使被写入目标 ARP 缓存也无害；
- 不能用 .1/.254（可能撞网关）、广播地址（协议栈会丢弃）、
  sender == 被扫 IP（RFC 5227 视为地址声明，不会回复）、
  0.0.0.0（部分打印机/嵌入式设备不回复，漏扫率高）。
"""
import ipaddress

from scapy.layers.l2 import ARP, Ether


def pick_sacrifice_ip(net: ipaddress.IPv4Network, local_ips: set[str],
                      mode: str = "auto") -> str:
    """为目标子网选取 ARP 探测的源 IP（牺牲 IP）。

    :param net: 目标子网
    :param local_ips: 本机所有网卡的 IPv4 集合
    :param mode: auto=本机 IP 在子网内则用真实 IP，否则用网络地址；
                 network=强制网络地址；zero=强制 0.0.0.0
    """
    if mode == "zero":
        return "0.0.0.0"
    if mode == "network":
        return str(net.network_address)
    # auto：本机 IP 确实落在目标子网主机范围内时用真实 IP（零副作用）
    for ip in local_ips:
        addr = ipaddress.ip_address(ip)
        if addr in net and addr != net.network_address \
                and addr != net.broadcast_address:
            return ip
    return str(net.network_address)


def build_arp_requests(net: ipaddress.IPv4Network, iface_mac: str,
                       src_ip: str) -> list:
    """构造子网内全部主机的 ARP who-has 请求包（双探测）。

    每个目标发两帧，任一应答即完成发现：
    - psrc=src_ip（子网内牺牲地址，通常为网络地址）：兼容绝大多数协议栈；
    - psrc=0.0.0.0（RFC 5227 ACD 探针语义）：部分设备（实测 OpenWrt）
      会忽略非常规 sender 的普通请求，但会回应探针。

    以太网源 MAC 必须用本机网卡真实 MAC（应答回给这个 MAC）。
    """
    pkts = []
    for ip in net.hosts():
        for psrc in (src_ip, "0.0.0.0"):
            if psrc == "0.0.0.0" and src_ip == "0.0.0.0":
                continue  # 避免重复
            pkts.append(
                Ether(src=iface_mac, dst="ff:ff:ff:ff:ff:ff")
                / ARP(op="who-has", hwsrc=iface_mac, psrc=psrc,
                      pdst=str(ip))
            )
    return pkts


def build_arp_reply(iface_mac: str, target_mac: str, target_ip: str,
                    sacrifice_ip: str):
    """构造 ARP 代理应答：告诉 target，牺牲 IP 在本机 MAC 上。

    目标主机要向牺牲 IP 回 TCP SYN-ACK / NBNS / mDNS 应答前，会先 ARP
    解析牺牲 IP；没有这个应答器，目标解析不出牺牲 IP 会直接丢包，
    端口扫描和主机名解析将全部静默失败。
    """
    return (
        Ether(src=iface_mac, dst=target_mac)
        / ARP(op="is-at", hwsrc=iface_mac, psrc=sacrifice_ip,
              pdst=target_ip, hwdst=target_mac)
    )
