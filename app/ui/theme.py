"""主题系统：深色 / 浅色双主题，运行时可切换。

QSS 由调色板模板生成（string.Template，$变量），避免 f-string 与
CSS 花括号冲突。当前调色板全局可查，供表格绘制代理等需要按主题
取色的模块使用。
"""
import os
import tempfile
from string import Template

# ------------------------------------------------------------------ #
# 调色板
# ------------------------------------------------------------------ #

DARK = {
    "light": "0",
    "bg": "#0f1014", "card": "#171922", "chipPanel": "#12141b",
    "border": "#2a2e3c", "borderLight": "#34394c",
    "input": "#12141b", "table": "#12141b", "tableAlt": "#151823",
    "header": "#171a24", "selection": "#2c4266",
    "text": "#e8ebf4", "textBright": "#f0f3fa",
    "muted": "#8a90a6", "faint": "#626879",
    "accent": "#5b8cff", "accentHover": "#6d9aff",
    "accentDisabledBg": "#232a3d", "accentDisabledText": "#556077",
    "green": "#3ecf8e", "greenBg": "rgba(62, 207, 142, 0.13)",
    "red": "#ff5c5c", "redBg": "rgba(255, 92, 92, 0.14)",
    "redBorder": "rgba(255, 92, 92, 0.35)",
    "redBgHover": "rgba(255, 92, 92, 0.22)",
    "redDisabledBg": "#221a1e", "redDisabledText": "#5e4a4d",
    "chipBg": "#1b2233", "chipBorder": "#32405f", "chipText": "#a9c1ff",
    "chipCloseHover": "rgba(255, 92, 92, 0.12)",
    "chipClose": "#626879",
    "button": "#1d202b", "buttonHover": "#242836",
    "ghostText": "#8a90a6", "ghostBorder": "#2a2e3c",
    "ghostHoverText": "#a9c1ff", "ghostHoverBorder": "#32405f",
    "logText": "#79809a",
    "menuSel": "#5b8cff",
    "scrollHandle": "#2a2e3c", "scrollHandleHover": "#3a4157",
    "disabledText": "#4b4f60", "disabledBg": "#181a22",
}

LIGHT = {
    "light": "1",
    "bg": "#eef0f5", "card": "#ffffff", "chipPanel": "#f4f6fa",
    "border": "#e0e4ee", "borderLight": "#ccd2e0",
    "input": "#f7f8fc", "table": "#ffffff", "tableAlt": "#f6f7fb",
    "header": "#f2f4f9", "selection": "#dbe6fb",
    "text": "#262a3d", "textBright": "#171a28",
    "muted": "#5d6474", "faint": "#8b91a3",
    "accent": "#3a6df0", "accentHover": "#4d7cf5",
    "accentDisabledBg": "#d8dded", "accentDisabledText": "#a0a8bd",
    "green": "#17995c", "greenBg": "rgba(23, 153, 92, 0.10)",
    "red": "#d43c41", "redBg": "rgba(212, 60, 65, 0.08)",
    "redBorder": "rgba(212, 60, 65, 0.35)",
    "redBgHover": "rgba(212, 60, 65, 0.14)",
    "redDisabledBg": "#f0e3e4", "redDisabledText": "#b08c8e",
    "chipBg": "#e7edfc", "chipBorder": "#c3d2f2", "chipText": "#33508f",
    "chipCloseHover": "rgba(212, 60, 65, 0.10)",
    "chipClose": "#9aa1b3",
    "button": "#f0f2f8", "buttonHover": "#e6e9f2",
    "ghostText": "#5d6474", "ghostBorder": "#e0e4ee",
    "ghostHoverText": "#33508f", "ghostHoverBorder": "#c3d2f2",
    "logText": "#7a8095",
    "menuSel": "#3a6df0",
    "scrollHandle": "#cdd3e0", "scrollHandleHover": "#b6bdd0",
    "disabledText": "#9aa1b3", "disabledBg": "#f0f1f6",
}

_QSS = Template("""
* {
    font-family: "Noto Sans CJK SC", "Source Han Sans SC", "PingFang SC",
                 "Microsoft YaHei", "Sans-serif";
    font-size: 13px;
    color: $text;
    outline: none;
}

QMainWindow, QWidget#root { background-color: $bg; }

/* ---------- 卡片 ---------- */
QFrame#card {
    background-color: $card;
    border: 1px solid $border;
    border-radius: 14px;
}
QFrame#chipPanel {
    background-color: $chipPanel;
    border: 1px solid $border;
    border-radius: 10px;
}

QLabel#cardTitle { color: $muted; font-weight: 600; }
QLabel#cardHint  { color: $faint; font-size: 12px; }
QLabel#appTitle  { font-size: 18px; font-weight: 700; color: $textBright; }
QLabel#appSub    { color: $faint; font-size: 12px; }
QLabel#phaseLabel{ color: $muted; font-size: 12.5px; }

QLabel#statPill {
    background-color: $greenBg;
    color: $green;
    border-radius: 13px;
    padding: 4px 14px;
    font-weight: 600;
}
QLabel#infoLabel { color: $faint; font-size: 12px; }

/* ---------- 芯片 ---------- */
QFrame#chip {
    background-color: $chipBg;
    border: 1px solid $chipBorder;
    border-radius: 15px;
}
QLabel#chipText { color: $chipText; font-size: 12.5px; }
QToolButton#chipClose {
    background: transparent; border: none; border-radius: 8px;
    color: $chipClose; font-size: 12px;
}
QToolButton#chipClose:hover { color: $red; background: $chipCloseHover; }

/* ---------- 按钮 ---------- */
QPushButton {
    background-color: $button;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 7px 16px;
    color: $text;
}
QPushButton:hover { background-color: $buttonHover; border-color: $borderLight; color: $textBright; }
QPushButton:pressed { background-color: $button; }
QPushButton:disabled { color: $disabledText; background-color: $disabledBg; }

QPushButton#ghostBtn {
    background: transparent; border: 1px solid $ghostBorder;
    color: $ghostText; padding: 6px 13px;
}
QPushButton#ghostBtn:hover { color: $ghostHoverText; border-color: $ghostHoverBorder; }

QPushButton#startBtn {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 $accent, stop:1 #7b6cff);
    color: #ffffff; font-weight: 700; border: none;
    padding: 9px 30px; border-radius: 9px; font-size: 13.5px;
}
QPushButton#startBtn:hover { background-color: $accentHover; }
QPushButton#startBtn:disabled { background-color: $accentDisabledBg; color: $accentDisabledText; }

QPushButton#stopBtn {
    background-color: $redBg;
    color: $red; font-weight: 700; border: 1px solid $redBorder;
    padding: 8px 30px; border-radius: 9px;
}
QPushButton#stopBtn:hover { background-color: $redBgHover; }
QPushButton#stopBtn:disabled { background-color: $redDisabledBg; color: $redDisabledText;
    border-color: $border; }

/* ---------- 输入控件 ---------- */
QLineEdit, QComboBox, QSpinBox {
    background-color: $input;
    border: 1px solid $border;
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: $accent;
    selection-color: #ffffff;
}
QLineEdit:focus, QComboBox:focus { border-color: $accent; }
QLineEdit:disabled, QComboBox:disabled { color: $disabledText; }
QLineEdit#filterEdit {
    border-radius: 15px; padding: 5px 14px 5px 30px;
    background-color: $input;
}

QComboBox::drop-down { border: none; width: 24px; }
QComboBox QAbstractItemView {
    background-color: $card;
    border: 1px solid $borderLight;
    border-radius: 8px;
    selection-background-color: $menuSel;
    selection-color: #ffffff;
    padding: 4px;
}

QCheckBox { spacing: 7px; color: $muted; }
QCheckBox::indicator {
    width: 16px; height: 16px;
    border: 1px solid $borderLight; border-radius: 5px;
    background-color: $input;
}
QCheckBox::indicator:checked {
    background-color: $accent; border-color: $accent;
    image: url($checkImg);
}
QCheckBox::indicator:checked:hover {
    background-color: $accentHover; border-color: $accentHover;
    image: url($checkImg);
}
QCheckBox::indicator:hover { border-color: $accent; }
QCheckBox::indicator:disabled { background-color: $disabledBg; border-color: $border; }
QCheckBox:disabled { color: $disabledText; }

/* ---------- 表格 ---------- */
QTableView {
    background-color: $table;
    border: 1px solid $border;
    border-radius: 10px;
    gridline-color: $border;
    alternate-background-color: $tableAlt;
}
QTableView::item {
    padding: 6px 10px;
    border: none;
    background-color: $table;
    color: $text;
}
QTableView::item:selected { background-color: $selection; color: $textBright; }
QTableView::item:hover { background-color: $selection; color: $textBright; }
QTableView:focus { border-color: $border; }

QHeaderView { background-color: transparent; }
QHeaderView::section {
    background-color: $header;
    color: $muted;
    border: none;
    border-right: 1px solid $border;
    border-bottom: 1px solid $border;
    padding: 8px 10px;
    font-weight: 600;
}
QTableCornerButton::section { background-color: $header; border: none; }

/* ---------- 进度条 ---------- */
QProgressBar {
    background-color: $input;
    border: none;
    border-radius: 5px;
    max-height: 10px; min-height: 10px;
    text-align: center;
}
QProgressBar::chunk {
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 $accent, stop:1 #7b6cff);
    border-radius: 5px;
}

/* ---------- 日志 ---------- */
QPlainTextEdit#logView {
    background-color: $table;
    border: 1px solid $border;
    border-radius: 10px;
    color: $logText;
    padding: 6px;
}

/* ---------- 分割器 / 滚动条 ---------- */
QSplitter::handle { background-color: transparent; height: 4px; }
QSplitter::handle:hover { background-color: $border; }

QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
QScrollBar::handle:vertical {
    background: $scrollHandle; border-radius: 5px; min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: $scrollHandleHover; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
QScrollBar::handle:horizontal {
    background: $scrollHandle; border-radius: 5px; min-width: 30px;
}
QScrollBar::add-page, QScrollBar::sub-page { background: none; }

/* ---------- 菜单 / 状态栏 / 提示 ---------- */
QMenuBar {
    background-color: $bg;
    border-bottom: 1px solid $border;
}
QMenuBar::item {
    padding: 5px 12px;
    border-radius: 6px;
    background-color: transparent;
    color: $text;
}
QMenuBar::item:selected { background-color: $button; color: $textBright; }
QMenuBar::item:pressed { background-color: $buttonHover; color: $textBright; }
QMenu {
    background-color: $card;
    border: 1px solid $borderLight;
    border-radius: 10px;
    padding: 6px;
}
QMenu::item { padding: 7px 26px; border-radius: 6px; color: $text; }
QMenu::item:selected { background-color: $menuSel; color: #ffffff; }
QMenu::item:disabled { color: $disabledText; }

QStatusBar { background-color: transparent; color: $faint; }
QStatusBar::item { border: none; }

QToolTip {
    background-color: $card;
    border: 1px solid $accent;
    border-radius: 6px;
    padding: 5px 9px;
    color: $text;
}
""")

# ------------------------------------------------------------------ #
# 全局当前调色板
# ------------------------------------------------------------------ #


class _Palette:
    """当前主题调色板（属性访问 + light 标志）。"""

    def __init__(self, d: dict):
        self.__dict__.update(d)

    @property
    def is_light(self) -> bool:
        return bool(int(self.__dict__["light"]))


_current: _Palette | None = None


def _check_image() -> str:
    """生成白色对钩图片（QSS 自绘指示器后 Fusion 不再画原生对钩，
    需用图片补回），返回文件路径。两个主题通用（勾画在强调色底上）。"""
    from PySide6.QtCore import QPointF, Qt
    from PySide6.QtGui import QColor, QImage, QPainter, QPen, QPolygonF

    path = os.path.join(tempfile.gettempdir(), "lanscan_checkmark.png")
    img = QImage(16, 16, QImage.Format_ARGB32_Premultiplied)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    pen = QPen(QColor("#ffffff"), 2.4)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPolyline(QPolygonF([QPointF(3.5, 8.8), QPointF(6.9, 12.2),
                              QPointF(12.6, 4.4)]))
    p.end()
    img.save(path, "PNG")
    return path


def apply_theme(app, name: str = "dark") -> None:
    """为 QApplication 应用主题（dark / light）。"""
    global _current
    from PySide6.QtGui import QColor, QPalette

    palette = dict(LIGHT if name == "light" else DARK)
    # QSS url() 里必须用正斜杠，否则 Windows 路径中的反斜杠会被当成转义符。
    palette["checkImg"] = _check_image().replace("\\", "/")
    _current = _Palette(palette)

    app.setStyle("Fusion")
    qss = _QSS.substitute(palette)
    # 先清空再设置，确保运行时切换主题不会残留旧样式。
    app.setStyleSheet("")
    app.setStyleSheet(qss)

    # 同步 QPalette：确保菜单栏、表格项等依赖调色板的控件也能跟随主题，
    # 尤其在 Windows 的 Fusion 风格下避免原生浅色调盘残留。
    p = QPalette()
    c = _current
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Window, QColor(c.bg))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.WindowText, QColor(c.text))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Base, QColor(c.table))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.AlternateBase, QColor(c.tableAlt))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Text, QColor(c.text))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Button, QColor(c.button))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.ButtonText, QColor(c.text))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Highlight, QColor(c.selection))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.ToolTipBase, QColor(c.card))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.ToolTipText, QColor(c.text))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.PlaceholderText, QColor(c.faint))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.Link, QColor(c.accent))
    p.setColor(QPalette.ColorGroup.All, QPalette.ColorRole.LinkVisited, QColor(c.accentHover))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor(c.disabledText))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor(c.disabledText))
    p.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Base, QColor(c.disabledBg))
    app.setPalette(p)

    # 强制重新 polish 所有已创建控件，否则运行时切换主题后部分区域会残留旧颜色。
    style = app.style()
    style.unpolish(app)
    style.polish(app)
    for widget in app.allWidgets():
        style.unpolish(widget)
        style.polish(widget)
        widget.update()


def current() -> _Palette:
    """获取当前调色板（未初始化时按深色处理）。"""
    global _current
    if _current is None:
        _current = _Palette(DARK)
    return _current
