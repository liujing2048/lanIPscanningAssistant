"""设备类型推断：端口指纹 + 厂商启发式。"""


# 端口指纹规则（按匹配度从上到下，要求端口集合包含 rules 中的全部端口）
_PORT_RULES = [
    ({631, 9100}, "打印机"),
    ({515, 631}, "打印机"),
    ({9100}, "打印机"),
    ({445, 3389}, "Windows 主机"),
    ({445, 139}, "Windows 主机"),
    ({554}, "摄像头"),
    ({80, 554}, "摄像头"),
    ({23}, "网络设备/嵌入式"),
    ({3306, 22}, "Linux 服务器"),
    ({1433}, "Windows 服务器"),
    ({5900}, "远程管理主机"),
    ({22, 80}, "Linux/网络设备"),
    ({22}, "Linux/网络设备"),
    ({80}, "Web 设备"),
    ({443}, "Web 设备"),
]

# 厂商关键字启发式（端口指纹无法判断时使用）
_VENDOR_RULES = [
    ("hikvision", "摄像头"),
    ("dahua", "摄像头"),
    ("axis", "摄像头"),
    ("uniview", "摄像头"),
    ("espressif", "物联网设备"),
    ("tuya", "物联网设备"),
    ("xiaomi", "小米设备"),
    ("cisco", "网络设备"),
    ("huawei", "网络设备"),
    ("tp-link", "网络设备"),
    ("ruijie", "网络设备"),
    ("mikrotik", "网络设备"),
    ("router", "网络设备"),
    ("vmware", "虚拟机"),
    ("virtual", "虚拟机"),
    ("apple", "苹果设备"),
    ("samsung", "三星设备"),
    ("raspberry", "树莓派"),
    ("printer", "打印机"),
    ("hp inc", "惠普设备"),
    ("hewlett", "惠普设备"),
    ("dell", "戴尔设备"),
    ("intel", "PC/笔记本"),
    ("realtek", "PC/笔记本"),
]


# 主机名关键字启发式（优先级最高，mDNS/NBNS 名称往往直接暴露设备身份）
_HOSTNAME_RULES = [
    ("openwrt", "路由器"),
    ("router", "路由器"),
    ("gateway", "路由器"),
    ("miwifi", "路由器"),
    ("nas", "NAS 存储"),
    ("synology", "NAS 存储"),
    ("printer", "打印机"),
    ("hikvision", "摄像头"),
    ("nvr", "录像机"),
    ("camera", "摄像头"),
    ("raspberrypi", "树莓派"),
    ("appletv", "苹果设备"),
    ("homekit", "物联网设备"),
    ("esp", "物联网设备"),
    ("android", "安卓设备"),
    ("iphone", "苹果设备"),
    ("ipad", "苹果设备"),
    ("macbook", "苹果设备"),
    ("desktop", "PC/笔记本"),
    ("pc", "PC/笔记本"),
]


def classify_device(open_ports: list[int], vendor: str = "",
                    hostname: str = "") -> str:
    """根据主机名/开放端口/厂商推断设备类型，推断不出返回空串。"""
    h = hostname.lower()
    for keyword, label in _HOSTNAME_RULES:
        if keyword in h:
            return label
    ports = set(open_ports)
    for required, label in _PORT_RULES:
        if required.issubset(ports):
            return label
    v = vendor.lower()
    for keyword, label in _VENDOR_RULES:
        if keyword in v:
            return label
    return ""
