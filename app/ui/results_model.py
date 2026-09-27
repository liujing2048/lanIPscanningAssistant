"""扫描结果表格模型：QAbstractTableModel + 排序/筛选代理。

行以 IP 为主键：主机发现时 insertRow，端口/主机名/类型等后续到达时
dataChanged 原地更新——支持"先出 IP/MAC，几秒后端口和主机名陆续补全"
的渐进式体验。
"""
from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, Signal
from PySide6.QtGui import QBrush, QColor, QFont

from app.core.models import HostResult

COL_IP, COL_MAC, COL_VENDOR, COL_HOSTNAME, COL_PORTS, COL_TYPE, \
    COL_SUBNET, COL_IFACE, COL_NOTE = range(9)

COLUMNS = ["IP 地址", "MAC 地址", "厂商", "主机名", "开放端口",
           "设备类型", "网段", "经由网卡", "备注"]

# 深色主题下几种设备类型的柔和着色
_TYPE_COLORS = {
    "路由器": "#e0a34f",
    "Windows 主机": "#4f8cff",
    "Windows 服务器": "#4f8cff",
    "Linux 服务器": "#5fb878",
    "Linux/网络设备": "#5fb878",
    "打印机": "#c98bdb",
    "摄像头": "#e07a5f",
    "NAS 存储": "#e0c04f",
}


class ResultsModel(QAbstractTableModel):
    """扫描结果模型。所有方法必须在 UI 线程调用（信号已保证）。"""

    note_edited = Signal(str, str, str)  # (mac, note, ip) → 持久化

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: list[HostResult] = []
        self._row_by_ip: dict[str, int] = {}

    # ---------------- 基础协议 ---------------- #

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return COLUMNS[section]
        return None

    def flags(self, index):
        base = Qt.ItemIsEnabled | Qt.ItemIsSelectable
        if index.column() == COL_NOTE:
            base |= Qt.ItemIsEditable
        return base

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        col = index.column()

        if role == Qt.DisplayRole or role == Qt.EditRole:
            if col == COL_IP:
                return row.ip
            if col == COL_MAC:
                return row.mac
            if col == COL_VENDOR:
                return row.vendor
            if col == COL_HOSTNAME:
                return row.hostname
            if col == COL_PORTS:
                return ", ".join(str(p) for p in row.open_ports)
            if col == COL_TYPE:
                return row.device_type
            if col == COL_SUBNET:
                return row.subnet
            if col == COL_IFACE:
                return row.iface
            if col == COL_NOTE:
                return row.note
        elif role == Qt.TextAlignmentRole:
            if col in (COL_IP, COL_PORTS, COL_SUBNET):
                return int(Qt.AlignCenter)
        elif role == Qt.FontRole:
            if col in (COL_IP, COL_MAC):
                f = QFont("JetBrains Mono")
                f.setFamilies(["JetBrains Mono", "Noto Sans Mono CJK SC",
                              "DejaVu Sans Mono"])
                f.setStyleHint(QFont.Monospace)
                return f
        elif role == Qt.ForegroundRole:
            if col == COL_TYPE and row.device_type:
                color = _TYPE_COLORS.get(row.device_type, "#9aa3b5")
                return QBrush(QColor(color))
            if col == COL_IP:
                return QBrush(QColor("#eef1f7"))
        elif role == Qt.ToolTipRole:
            if col == COL_PORTS and row.open_ports:
                names = {21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
                         53: "DNS", 80: "HTTP", 110: "POP3", 139: "NetBIOS",
                         143: "IMAP", 443: "HTTPS", 445: "SMB",
                         515: "LPD", 554: "RTSP", 631: "IPP",
                         1433: "SQL Server", 3306: "MySQL", 3389: "RDP",
                         5900: "VNC", 8080: "HTTP-alt", 9100: "RAW 打印"}
                return "\n".join(
                    f"{p}  {names.get(p, '')}".rstrip() for p in row.open_ports)
        return None

    def setData(self, index, value, role=Qt.EditRole):
        if role != Qt.EditRole or index.column() != COL_NOTE:
            return False
        row = self._rows[index.row()]
        note = value.strip()
        if note == row.note:
            return False
        row.note = note
        self.note_edited.emit(row.mac, note, row.ip)
        self.dataChanged.emit(index, index, [Qt.DisplayRole])
        return True

    # ---------------- 增量更新 ---------------- #

    def add_host(self, data: dict) -> None:
        """新主机被发现（data 为 HostResult.as_dict）。"""
        if data["ip"] in self._row_by_ip:
            return
        row = len(self._rows)
        self.beginInsertRows(QModelIndex(), row, row)
        host = HostResult(
            ip=data["ip"], mac=data["mac"], vendor=data.get("vendor", ""),
            hostname=data.get("hostname", ""),
            open_ports=list(data.get("open_ports", [])),
            device_type=data.get("device_type", ""),
            subnet=data.get("subnet", ""), iface=data.get("iface", ""),
            note=data.get("note", ""))
        self._rows.append(host)
        self._row_by_ip[host.ip] = row
        self.endInsertRows()

    def update_host(self, ip: str, fields: dict) -> None:
        """主机的部分字段更新（端口/主机名/类型陆续补全）。"""
        row = self._row_by_ip.get(ip)
        if row is None:
            return
        host = self._rows[row]
        changed_cols = []
        col_map = {"hostname": COL_HOSTNAME, "open_ports": COL_PORTS,
                   "device_type": COL_TYPE, "vendor": COL_VENDOR,
                   "note": COL_NOTE}
        for key, value in fields.items():
            if hasattr(host, key) and getattr(host, key) != value:
                setattr(host, key, value)
                changed_cols.append(col_map.get(key, -1))
        if not changed_cols:
            return
        lo = self.index(row, min(changed_cols))
        hi = self.index(row, max(changed_cols))
        self.dataChanged.emit(lo, hi, [Qt.DisplayRole])

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self._row_by_ip.clear()
        self.endResetModel()

    def rows(self) -> list[HostResult]:
        return list(self._rows)

    def host_at(self, row: int) -> HostResult:
        return self._rows[row]
