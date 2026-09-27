"""物理网卡枚举与虚拟网卡过滤。

本机存在 docker0、br-*、veth*、tun0 等虚拟网卡（Windows 下为 VMware/
VirtualBox/Hyper-V/TAP 等），扫描时必须排除，否则会出现大量无效发送。

双平台实现：
- Linux：scapy get_if_list 枚举 + ioctl 读网卡掩码
- Windows：scapy conf.ifaces 枚举（网卡名/适配器描述过滤虚拟网卡），
  掩码从 scapy 路由表反查（scapy 未提供现成接口）
"""
import ipaddress
import socket
import struct
import sys

from scapy.config import conf
from scapy.error import Scapy_Exception
from scapy.interfaces import get_if_list

IS_WINDOWS = sys.platform == "win32"

if not IS_WINDOWS:
    import fcntl
    from scapy.arch import get_if_addr, get_if_hwaddr

# 虚拟网卡名称前缀（或精确名），这些网卡不参与扫描（Linux）
VIRTUAL_NAMES = ("lo", "any", "npcap", "usbmon", "nflog", "nfqueue")
VIRTUAL_PREFIXES = ("docker", "br-", "veth", "tun", "tap", "virbr", "vmnet",
                    "zt", "wg", "ovs", "cali", "flannel", "cni", "dummy", "ifb")

# Windows 虚拟网卡特征（匹配网卡友好名/适配器描述，不区分大小写）
VIRTUAL_KEYWORDS_WIN = ("loopback", "vmware", "virtualbox", "hyper-v",
                        "vethernet", "tap-", "wan miniport", "bluetooth",
                        "wi-fi direct", "wsl", "kernel debug")

SIOCGIFNETMASK = 0x891B


def is_virtual(name: str) -> bool:
    """判断网卡名是否属于虚拟网卡（Linux 命名规则）。"""
    low = name.lower()
    if low in VIRTUAL_NAMES:
        return True
    return low.startswith(VIRTUAL_PREFIXES)


def _is_virtual_win(name: str, description: str) -> bool:
    """按友好名 + 适配器描述判断 Windows 虚拟网卡。"""
    text = f"{name} {description}".lower()
    return any(k in text for k in VIRTUAL_KEYWORDS_WIN)


def _get_netmask(ifname: str) -> str | None:
    """通过 ioctl 读取网卡掩码（scapy 没有现成接口，仅 Linux）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", ifname[:15].encode())
        mask = fcntl.ioctl(s.fileno(), SIOCGIFNETMASK, packed)[20:24]
        return socket.inet_ntoa(mask)
    except OSError:
        return None
    finally:
        s.close()


def _win_prefix_for(ip: str) -> int:
    """Windows：从 scapy 路由表反查该 IP 所在网段的掩码位数。

    路由表项格式: (dest:int, mask:int, 网关, 网卡, 网卡IP, metric)；
    取覆盖该 IP 的最长掩码（排除默认路由 0 和本机 /32 主机路由），
    查不到回退 /24。
    """
    try:
        addr = struct.unpack(">I", socket.inet_aton(ip))[0]
    except OSError:
        return 24
    best = 0
    for route in conf.route.routes:
        try:
            dest, mask, _, _, dev_ip, _ = route
        except ValueError:
            continue
        if not isinstance(mask, int) or mask in (0, 0xFFFFFFFF):
            continue
        if dev_ip == ip and (addr & mask) == dest and mask > best:
            best = mask
    return bin(best).count("1") if best else 24


def _get_physical_ifaces_win() -> list[dict]:
    """Windows：枚举配置了 IPv4 的物理网卡（走 scapy conf.ifaces）。

    用友好名作为 "name"——scapy 的 resolve_iface 会先按友好名解析，
    引擎可直接使用。
    """
    result = []
    seen: set[tuple[str, str]] = set()
    for iface in conf.ifaces.values():
        ip = (iface.ip or "").strip()
        mac = (iface.mac or "").strip()
        if not ip or ip == "0.0.0.0" or not mac or mac == "00:00:00:00:00:00":
            continue
        if (ip, mac) in seen:
            continue  # 同一网卡可能以多个名字出现
        if _is_virtual_win(iface.name, getattr(iface, "description", "") or ""):
            continue
        seen.add((ip, mac))
        net = ipaddress.ip_network(f"{ip}/{_win_prefix_for(ip)}", strict=False)
        result.append({
            "name": iface.name,
            "mac": mac,
            "ip": ip,
            "net": str(net),
        })
    return result


def get_physical_ifaces() -> list[dict]:
    """枚举所有配置了 IPv4 的物理网卡。

    返回: [{"name", "mac", "ip", "net"(CIDR)}, ...]
    """
    if IS_WINDOWS:
        return _get_physical_ifaces_win()

    result = []
    for name in get_if_list():
        if is_virtual(name):
            continue
        try:
            ip = get_if_addr(name)
            mac = get_if_hwaddr(name)
        except (OSError, ValueError, Scapy_Exception):
            continue
        if not ip or ip == "0.0.0.0" or not mac or mac == "00:00:00:00:00:00":
            continue
        mask = _get_netmask(name)
        # 掩码转前缀长度，并归一化到网络地址（如 .102/24 → .0/24）
        prefix = _mask_to_prefix(mask) if mask else 24
        net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
        result.append({
            "name": name,
            "mac": mac,
            "ip": ip,
            "net": str(net),
        })
    return result


def _mask_to_prefix(mask: str) -> int:
    """点分十进制掩码转前缀长度，非法时返回 24。"""
    try:
        bits = bin(int.from_bytes(socket.inet_aton(mask), "big")).count("1")
        return bits if 0 <= bits <= 32 else 24
    except OSError:
        return 24
