"""网段芯片编辑器：以标签芯片方式管理目标网段。

替代原先的多行文本框：已添加的网段显示为可删除的圆角芯片，
底部一行输入框负责添加（带校验与快捷按钮）。
"""
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame, QHBoxLayout, QLabel, QLineEdit, QPushButton, QToolButton,
    QVBoxLayout, QWidget,
)

from app.core.subnet_input import parse_input


class _Chip(QFrame):
    """单个网段芯片。"""

    removed = Signal(str)

    def __init__(self, text: str, parent=None):
        super().__init__(parent)
        self.setObjectName("chip")
        self.setFixedHeight(30)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 0, 4, 0)
        lay.setSpacing(6)
        label = QLabel(text, objectName="chipText")
        lay.addWidget(label)
        close = QToolButton(objectName="chipClose")
        close.setText("✕")
        close.setFixedSize(22, 22)
        close.setCursor(Qt.CursorShape.PointingHandCursor)
        close.setToolTip("移除此网段")
        close.clicked.connect(lambda: self.removed.emit(text))
        lay.addWidget(close)


class SubnetEditor(QWidget):
    """网段芯片编辑器。"""

    subnets_changed = Signal()   # 芯片增删后触发
    add_rejected = Signal(str)   # 输入不合法时触发（提示用）

    def __init__(self, parent=None):
        super().__init__(parent)
        self._subnets: list[str] = []
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(8)

        # 芯片区：chip_panel 必须有自己的布局来管理 holder，
        # 否则 holder 保持 0x0 几何，芯片全被裁剪不可见
        self.chip_panel = QFrame(objectName="chipPanel")
        panel_lay = QVBoxLayout(self.chip_panel)
        panel_lay.setContentsMargins(8, 8, 8, 8)
        self.flow = FlowLayoutHolder()
        panel_lay.addWidget(self.flow)
        self.chip_panel.setVisible(False)
        outer.addWidget(self.chip_panel)

        # 输入行
        entry = QHBoxLayout()
        entry.setSpacing(8)
        self.entry_edit = QLineEdit()
        self.entry_edit.setPlaceholderText(
            "输入网段后回车添加，如 192.168.2.0/24、192.168.1.9/29、192.168.1-3.0/24")
        self.entry_edit.returnPressed.connect(self._add_from_entry)
        entry.addWidget(self.entry_edit, 1)
        self.add_btn = QPushButton("＋ 添加")
        self.add_btn.setObjectName("ghostBtn")
        self.add_btn.clicked.connect(self._add_from_entry)
        entry.addWidget(self.add_btn)
        self.local_btn = QPushButton("⌂ 本机网段")
        self.local_btn.setObjectName("ghostBtn")
        self.local_btn.setToolTip("把本机所有物理网卡所在网段加入")
        entry.addWidget(self.local_btn)
        outer.addLayout(entry)

    # ---------------- 对外接口 ---------------- #

    def subnets(self) -> list[str]:
        return self._subnets

    def set_subnets(self, items: list[str]) -> None:
        self._subnets = list(items)
        self._refresh()

    def add_subnet(self, text: str) -> bool:
        """解析并添加网段（支持一条输入展开为多个网段）。"""
        try:
            nets = parse_input(text)
        except ValueError as e:
            self.add_rejected.emit(str(e))
            return False
        if not nets:
            self.add_rejected.emit("请输入网段")
            return False
        added = False
        for n in nets:
            if n not in self._subnets:
                self._subnets.append(n)
                added = True
        if added:
            self._refresh()
        return added

    def add_local_subnets(self) -> None:
        from app.core.netinfo import get_physical_ifaces
        for i in get_physical_ifaces():
            n = i["net"]
            if n not in self._subnets:
                self._subnets.append(n)
        self._refresh()

    # ---------------- 内部 ---------------- #

    def _add_from_entry(self):
        text = self.entry_edit.text().strip()
        if not text:
            return
        if self.add_subnet(text):
            self.entry_edit.clear()
            self.subnets_changed.emit()

    def _remove(self, text: str):
        if text in self._subnets:
            self._subnets.remove(text)
            self._refresh()

    def _refresh(self):
        self.flow.clear()
        for s in self._subnets:
            chip = _Chip(s)
            chip.removed.connect(self._on_removed)
            self.flow.addWidget(chip)
        self.chip_panel.setVisible(bool(self._subnets))
        self.subnets_changed.emit()

    def _on_removed(self, text: str):
        self._remove(text)


class FlowLayoutHolder(QFrame):
    """持有 FlowLayout 的容器。"""

    def __init__(self, parent=None):
        super().__init__(parent)
        from .flowlayout import FlowLayout
        self._flow = FlowLayout(self, margin=0, spacing=6)

    def addWidget(self, w: QWidget):
        self._flow.addWidget(w)

    def clear(self):
        self._flow.clear()
