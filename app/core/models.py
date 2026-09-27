"""数据模型定义。"""
from dataclasses import dataclass, field


@dataclass
class HostResult:
    """一台被发现的主机的扫描结果。"""

    ip: str
    mac: str
    vendor: str = ""              # MAC 厂商（OUI 查询）
    hostname: str = ""            # 主机名（NBNS / mDNS / DNS PTR）
    open_ports: list = field(default_factory=list)  # 开放端口列表
    device_type: str = ""         # 推断的设备类型
    subnet: str = ""              # 所属扫描网段（CIDR）
    iface: str = ""               # 经由哪块网卡发现
    note: str = ""                # 用户备注（按 MAC 持久化，重扫自动回显）

    def as_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostname": self.hostname,
            "open_ports": list(self.open_ports),
            "device_type": self.device_type,
            "subnet": self.subnet,
            "iface": self.iface,
            "note": self.note,
        }
