"""主机名解析：NetBIOS(UDP 137) + mDNS(UDP 5353) + DNS PTR 三路并行。

NBNS / mDNS 必须走 scapy 二层路径（以牺牲 IP 为源），因为系统 socket
的源 IP 必须可路由；本机没有目标网段 IP 的场景下系统 socket 不可用。
zeroconf 库需要加入多播组并绑定接口 IP，同样不适用，故手工构造。
"""
import struct

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

MDNS_GROUP = "224.0.0.251"
MDNS_MAC = "01:00:5e:00:00:fb"

# 通配名 "*" 的 NBNS 一级编码（0x2A 展开为 'C''K'，其余 0x00 展开为 'A'）
_NBNS_WILDCARD = b"CK" + b"A" * 30


def build_nbns_query(host_ip: str, sacrifice_ip: str, iface_mac: str,
                      txn_id: int):
    """构造 NBNS Node Status 查询（UDP 137），查询目标的主机名。"""
    payload = (
        struct.pack(">HHHHHH", txn_id, 0x0010, 1, 0, 0, 0)  # 事务ID/标志/计数
        + _NBNS_WILDCARD + b"\x00"                          # 编码名 + 根标签
        + struct.pack(">HH", 0x21, 0x01)                    # QTYPE=NBSTAT QCLASS=IN
    )
    return (
        Ether(src=iface_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=sacrifice_ip, dst=host_ip)
        / UDP(sport=137, dport=137)
        / payload
    )


def parse_nbns_response(data: bytes) -> str:
    """解析 NBSTAT 应答中的主机名，取第一个唯一名（工作站服务优先）。

    :param data: UDP 137 应答的完整净荷
    :return: 主机名，解析失败返回空串
    """
    try:
        if len(data) < 12:
            return ""
        qd, an = struct.unpack(">HH", data[4:8])
        off = 12
        # 跳过问题段（每问 33 字节名 + 4 字节类型/类）
        off += qd * (33 + 4)
        if an == 0 or off >= len(data):
            return ""
        # 跳过应答 RR 的名字(33) + 类型(2) + 类(2) + TTL(4) + 长度(2)
        off += 33 + 2 + 2 + 4 + 2
        num_names = data[off]
        off += 1
        candidates = []  # (suffix, name)
        for _ in range(num_names):
            if off + 17 > len(data):
                break
            raw = data[off:off + 15]
            flags = struct.unpack(">H", data[off + 15:off + 17])[0]
            off += 17
            if flags & 0x8000:      # 组名（如工作组名）跳过
                continue
            name = raw.rstrip(b"\x00 ").decode("latin-1", "ignore").strip()
            if name and name != "*":
                candidates.append((flags >> 8, name))
        if not candidates:
            return ""
        # 优先取 suffix=0x00（工作站服务名）
        for suffix, name in candidates:
            if suffix == 0x00:
                return name
        return candidates[0][1]
    except (struct.error, IndexError):
        return ""


def build_mdns_query(host_ip: str, sacrifice_ip: str, iface_mac: str):
    """构造 mDNS 反向解析查询（PTR X.X.X.X.in-addr.arpa）。"""
    rev = ".".join(reversed(host_ip.split(".")))
    return (
        Ether(src=iface_mac, dst=MDNS_MAC)
        / IP(src=sacrifice_ip, dst=MDNS_GROUP, ttl=1)
        / UDP(sport=5353, dport=5353)
        / DNS(id=0, rd=0, qdcount=1,
              qd=DNSQR(qname=f"{rev}.in-addr.arpa", qtype="PTR"))
    )


def parse_mdns_response(frame) -> list[tuple[str, str]]:
    """解析 mDNS 应答，提取 (IP, 主机名) 列表。

    应答中 rrname 形如 "4.3.2.1.in-addr.arpa[.local]"，
    其 PTR 记录的 rdata 即主机名。
    """
    results = []
    try:
        if DNS not in frame or UDP not in frame:
            return results
        dns = frame[DNS]
        for rr in (dns.an or [])[:]:
            name = rr.rrname
            if isinstance(name, bytes):
                name = name.decode("latin-1", "ignore")
            name = name.rstrip(".")
            if "in-addr.arpa" not in name:
                continue
            # 从 "4.3.2.1.in-addr.arpa[.local]" 提取 IP
            labels = name.split(".")
            arpa_idx = labels.index("in-addr")
            octets = labels[:arpa_idx]
            if len(octets) != 4:
                continue
            try:
                ip = ".".join(reversed(octets))
                int(ip.replace(".", ""))  # 粗校验
            except ValueError:
                continue
            rdata = rr.rdata
            if isinstance(rdata, bytes):
                rdata = rdata.decode("latin-1", "ignore")
            hostname = str(rdata).rstrip(".").strip()
            if hostname:
                results.append((ip, hostname))
    except Exception:
        pass
    return results


def dns_ptr_lookup(ip: str, lifetime: float = 1.5) -> str:
    """通过系统 DNS 做 PTR 反查（dnspython，带超时）。

    不要用 socket.gethostbyaddr——无超时参数，可能拖死线程池。
    """
    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.lifetime = lifetime
        answer = resolver.resolve(dns.reversename.from_address(ip), "PTR")
        return str(answer[0]).rstrip(".").strip()
    except Exception:
        return ""
