"""MAC OUI 厂商查询。

数据源优先级：
1. 本机 ieee-data 包（/usr/share/ieee-data/*.csv，nmap 依赖）
2. 项目内置 data/oui_min.json 快照（从 ieee-data 生成，约 4 万条）
"""
import csv
import json
import os
import sys
import threading

_DATA_DIRS = [
    "/var/lib/ieee-data",
    "/usr/share/ieee-data",
]


def _builtin_path() -> str:
    """内置 JSON 快照路径：PyInstaller 打包后从解包目录取，源码运行取项目 data/。"""
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, "data", "oui_min.json")
    return os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "data", "oui_min.json")


_BUILTIN = _builtin_path()

_oui_24: dict[str, str] = {}   # 6 位十六进制前缀（MA-L）
_oui_28: dict[str, str] = {}   # 7 位十六进制前缀（MA-S / MA-M）
_oui_36: dict[str, str] = {}   # 9 位十六进制前缀（IAB）
_loaded = False
_lock = threading.Lock()


def _load_csv(path: str) -> None:
    """解析 ieee-data 的 CSV（格式: Registry,Assignment,Org Name,Address）。"""
    with open(path, newline="", encoding="utf-8", errors="ignore") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0] == "Registry":
                continue
            prefix, org = row[1].strip().upper(), row[2].strip()
            if not prefix or not org:
                continue
            if len(prefix) <= 6:
                _oui_24[prefix] = org
            elif len(prefix) == 7:
                _oui_28[prefix] = org
            else:
                _oui_36[prefix] = org


def _load_builtin() -> bool:
    """加载内置 JSON 快照，返回是否成功。"""
    if not os.path.isfile(_BUILTIN):
        return False
    with open(_BUILTIN, encoding="utf-8") as f:
        data = json.load(f)
    _oui_24.update(data.get("p24", {}))
    _oui_28.update(data.get("p28", {}))
    _oui_36.update(data.get("p36", {}))
    return True


def ensure_loaded() -> None:
    """加载数据源（幂等，线程安全）。约 0.3~0.5 秒，建议启动时后台调用。"""
    global _loaded
    with _lock:
        if _loaded:
            return
        for d in _DATA_DIRS:
            for name in ("oui.csv", "oui36.csv", "mam.csv", "iab.csv"):
                path = os.path.join(d, name)
                if os.path.isfile(path):
                    try:
                        _load_csv(path)
                    except OSError:
                        pass
        if not _oui_24:
            _load_builtin()
        _loaded = True


def lookup_vendor(mac: str) -> str:
    """查询 MAC 对应厂商，查不到返回空串。"""
    ensure_loaded()
    key = mac.replace(":", "").replace("-", "").upper()
    if len(key) < 6:
        return ""
    for table, n in ((_oui_36, 9), (_oui_28, 7), (_oui_24, 6)):
        v = table.get(key[:n])
        if v:
            return v
    return ""


def stats() -> dict:
    """返回已加载的条目数（用于 UI 显示数据源状态）。"""
    ensure_loaded()
    return {"p24": len(_oui_24), "p28": len(_oui_28), "p36": len(_oui_36)}
