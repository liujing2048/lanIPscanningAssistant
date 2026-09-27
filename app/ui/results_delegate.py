"""结果表格绘制代理：设备类型列画彩色徽章，IP 列强调显示。"""
from PySide6.QtCore import QRect, Qt
from PySide6.QtGui import QColor, QFont, QPainter, QPen
from PySide6.QtWidgets import QStyle, QStyledItemDelegate, QStyleOptionViewItem

from .results_model import COL_IP, COL_MAC, COL_TYPE
from .theme import current as current_theme

# 设备类型徽章配色（浅色文字 + 同色低透明度底）
_TYPE_STYLE = {
    "路由器":           "#e8b45a",
    "Windows 主机":     "#5b8cff",
    "Windows 服务器":   "#5b8cff",
    "Linux 服务器":     "#3ecf8e",
    "Linux/网络设备":    "#3ecf8e",
    "打印机":           "#c98bdb",
    "摄像头":           "#ff8f6b",
    "NAS 存储":         "#e8d45a",
    "物联网设备":       "#7bdff0",
    "虚拟机":           "#9aa3b5",
    "苹果设备":         "#d4d9e8",
    "安卓设备":         "#7bdff0",
    "树莓派":           "#ff8f6b",
    "网络设备/嵌入式":    "#e8b45a",
    "Web 设备":         "#8a90a6",
    "PC/笔记本":        "#5b8cff",
    "远程管理主机":       "#c98bdb",
    "小米设备":         "#ff8f6b",
    "三星设备":         "#5b8cff",
    "惠普设备":         "#7bdff0",
    "戴尔设备":         "#5b8cff",
    "录像机":           "#ff8f6b",
}

_MONO = ["JetBrains Mono", "Noto Sans Mono CJK SC", "DejaVu Sans Mono"]


class ResultsDelegate(QStyledItemDelegate):
    """结果表绘制：类型徽章 / IP·MAC 等宽字体高亮。"""

    def paint(self, painter: QPainter, option, index):
        col = index.column()
        if col == COL_TYPE:
            self._paint_badge(painter, option, index)
        elif col in (COL_IP, COL_MAC):
            self._paint_mono(painter, option, index, bold=(col == COL_IP))
        else:
            super().paint(painter, option, index)

    # ---------------- 各列绘制 ---------------- #

    def _paint_badge(self, painter, option: QStyleOptionViewItem, index):
        text = index.data(Qt.DisplayRole) or ""
        palette = current_theme()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(palette.selection))
        if text:
            color = QColor(_TYPE_STYLE.get(text, palette.muted))
            if palette.is_light:
                color = color.darker(155)  # 浅色主题下加深保证对比度
            fm = painter.fontMetrics()
            w = fm.horizontalAdvance(text) + 22
            h = 20
            x = option.rect.x() + (option.rect.width() - w) // 2
            y = option.rect.y() + (option.rect.height() - h) // 2
            rect = QRect(x, y, w, h)
            bg = QColor(color)
            bg.setAlpha(30)
            painter.setPen(Qt.NoPen)
            painter.setBrush(bg)
            painter.drawRoundedRect(rect, h // 2, h // 2)
            painter.setPen(QPen(color))
            f = painter.font()
            f.setPointSizeF(9.5)
            f.setBold(True)
            painter.setFont(f)
            painter.drawText(option.rect, Qt.AlignCenter, text)
        painter.restore()

    def _paint_mono(self, painter, option, index, bold=False):
        text = index.data(Qt.DisplayRole) or ""
        palette = current_theme()
        painter.save()
        painter.setRenderHint(QPainter.Antialiasing)
        if option.state & QStyle.StateFlag.State_Selected:
            painter.fillRect(option.rect, QColor(palette.selection))
        f = QFont()
        f.setFamilies(_MONO)
        f.setPointSizeF(10.5)
        f.setBold(bold)
        painter.setFont(f)
        painter.setPen(QPen(QColor(palette.textBright if bold
                                   else palette.muted)))
        rect = option.rect.adjusted(10, 0, -10, 0)
        painter.drawText(rect, Qt.AlignVCenter | Qt.AlignLeft, text)
        painter.restore()
