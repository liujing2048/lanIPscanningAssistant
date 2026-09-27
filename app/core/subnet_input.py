"""网段输入解析：支持多种写法与批量展开。

支持的写法（每行一个，逗号/空白分隔也可以）：
    192.168.1.0/24              标准 CIDR
    192.168.1.9/29               任意掩码（自动归一到 192.168.1.8/29）
    192.168.1.0                  无掩码且以 .0 结尾 → 按 /24 处理
    192.168.1.100                无掩码的单个 IP → 按 /32 处理
    192.168.1-3.0/24             第三段范围展开 → 3 个 /24 网段
    192.168.1,2,3.0/24           第三段枚举展开
"""
import ipaddress
import re

_RANGE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+(?:-\d+|,\d+)*)\.(\d+)(/\d+)?$")


def parse_input(text: str) -> list[str]:
    """把多行/逗号分隔的输入解析为标准 CIDR 字符串列表。

    :raises ValueError: 存在无法解析的行时
    """
    results: list[str] = []
    for token in re.split(r"[\s,，;；]+", text.strip()):
        if not token:
            continue
        results.extend(_parse_token(token))
    # 去重保序
    seen, unique = set(), []
    for s in results:
        if s not in seen:
            seen.add(s)
            unique.append(s)
    return unique


def _parse_token(token: str) -> list[str]:
    m = _RANGE_RE.match(token)
    if m and ("-" in m.group(3) or "," in m.group(3)):
        return _expand_range(m)
    try:
        if "/" in token:
            net = ipaddress.ip_network(token, strict=False)
            return [str(net)]
        ip = ipaddress.ip_address(token)
        # 无掩码：以 .0 结尾视为 /24 网段，否则视为单机
        if str(ip).endswith(".0"):
            return [str(ipaddress.ip_network(f"{ip}/24", strict=False))]
        return [str(ipaddress.ip_network(f"{ip}/32"))]
    except ValueError as e:
        raise ValueError(f"无法解析「{token}」：{e}") from e


def _expand_range(m) -> list[str]:
    """展开第三段的范围/枚举写法。"""
    a, b, seg3, host, mask = m.groups()
    mask = mask or "/24"
    parts = []
    if "-" in seg3:
        lo, hi = seg3.split("-", 1)
        lo, hi = int(lo), int(hi)
        if lo > hi:
            raise ValueError(f"范围写反了「{seg3}」")
        parts = list(range(lo, hi + 1))
    else:
        parts = [int(x) for x in seg3.split(",")]
    if len(parts) > 64:
        raise ValueError(f"一次最多展开 64 个网段（当前 {len(parts)} 个）")
    out = []
    for p in parts:
        if not 0 <= p <= 255:
            raise ValueError(f"第三段超出范围：{p}")
        out.extend(_parse_token(f"{a}.{b}.{p}.{host}{mask}"))
    return out
