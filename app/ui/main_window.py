"""主窗口 v2：卡片式布局 + 芯片网段编辑 + 徽章结果表。"""
import csv
import datetime
import json
import os

from PySide6.QtCore import QSortFilterProxyModel, Qt, QThread
from PySide6.QtGui import QAction, QActionGroup, QGuiApplication
from PySide6.QtWidgets import (
    QAbstractItemView, QApplication, QCheckBox, QComboBox, QFileDialog,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton,
    QSplitter, QTableView, QVBoxLayout, QWidget,
)

from app.core.netinfo import get_physical_ifaces
from app.core.oui import stats as oui_stats
from app.storage.store import DeviceStore
from .results_delegate import ResultsDelegate
from .results_model import ResultsModel
from .scan_worker import ScanWorker
from .subnet_editor import SubnetEditor
from .theme import apply_theme


class MainWindow(QMainWindow):
    def __init__(self, data_dir: str, uid=None, gid=None):
        super().__init__()
        self.setWindowTitle("局域网 IP 地址扫描助手")
        self.setMinimumSize(1080, 720)
        self.resize(1280, 840)

        self._data_dir = data_dir
        self.store = DeviceStore(
            os.path.join(data_dir, "devices.db"), uid=uid, gid=gid)
        self._notes_cache = self.store.get_notes()
        self._subnet_file = os.path.join(data_dir, "subnets.json")
        self._settings_file = os.path.join(data_dir, "settings.json")
        self._uid, self._gid = uid, gid
        self._thread = None
        self._worker = None
        self._scanning = False
        self._theme = self._load_settings().get("theme", "dark")
        apply_theme(QApplication.instance(), self._theme)

        self._build_menu()
        self._build_ui()
        self._load_subnets()
        self.statusBar().showMessage("就绪")

    # ------------------------------------------------------------------ #
    # UI 构建
    # ------------------------------------------------------------------ #

    def _build_menu(self):
        m_file = self.menuBar().addMenu("文件")
        for text, slot in (("导出 CSV …", self._export_csv),
                           ("导出 JSON …", self._export_json)):
            act = QAction(text, self)
            act.triggered.connect(slot)
            m_file.addAction(act)
        m_file.addSeparator()
        act_quit = QAction("退出", self)
        act_quit.triggered.connect(self.close)
        m_file.addAction(act_quit)

        # 视图菜单：主题切换（互斥可选，记住选择）
        m_view = self.menuBar().addMenu("视图")
        group = QActionGroup(self)
        group.setExclusive(True)
        self._theme_actions = {}
        for name, label in (("dark", "深色主题"), ("light", "浅色主题")):
            act = QAction(label, self, checkable=True)
            act.setActionGroup(group)
            act.setChecked(name == self._theme)
            act.triggered.connect(lambda checked, n=name: self._set_theme(n))
            m_view.addAction(act)
            self._theme_actions[name] = act

        m_help = self.menuBar().addMenu("帮助")
        act_about = QAction("关于", self)
        act_about.triggered.connect(self._about)
        m_help.addAction(act_about)

    def _card(self) -> tuple[QFrame, QVBoxLayout]:
        """创建卡片并返回 (卡片, 内容布局)。"""
        card = QFrame(objectName="card")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(18, 14, 18, 16)
        lay.setSpacing(10)
        return card, lay

    def _build_ui(self):
        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)
        layout.setContentsMargins(16, 10, 16, 12)
        layout.setSpacing(12)

        # ================= 顶部标题栏 ================= #
        head = QHBoxLayout()
        title_col = QVBoxLayout()
        title_col.setSpacing(1)
        title_col.addWidget(QLabel("⦿ 局域网 IP 地址扫描助手",
                                   objectName="appTitle"))
        title_col.addWidget(QLabel("多网段并发 · 无需改网卡配置 · 任意掩码",
                                   objectName="appSub"))
        head.addLayout(title_col)
        head.addStretch(1)
        oui = oui_stats()
        info = QLabel(f"OUI 厂商库 {oui['p24'] + oui['p28'] + oui['p36']} 条"
                      f"　·　{self._data_dir}",
                      objectName="infoLabel")
        head.addWidget(info, 0, Qt.AlignBottom)
        layout.addLayout(head)

        # ================= 扫描配置卡片 ================= #
        cfg_card, cfg = self._card()
        cfg_row = QHBoxLayout()
        cfg_row.addWidget(QLabel("目标网段", objectName="cardTitle"))
        cfg_row.addSpacing(8)
        cfg_row.addWidget(QLabel("回车添加 · 点 ✕ 移除 · 支持 192.168.1-3.0/24 范围写法",
                                 objectName="cardHint"))
        cfg_row.addStretch(1)
        cfg.addLayout(cfg_row)

        self.subnet_editor = SubnetEditor()
        self.subnet_editor.add_rejected.connect(
            lambda m: self.statusBar().showMessage(m, 4000))
        self.subnet_editor.subnets_changed.connect(self._save_subnets)
        cfg.addWidget(self.subnet_editor)

        # 选项行
        opts = QHBoxLayout()
        opts.setSpacing(16)
        opts.addWidget(QLabel("网卡", objectName="cardTitle"))
        self.iface_combo = QComboBox()
        self.iface_combo.addItem("自动（全部物理网卡）", "auto")
        for ifn in get_physical_ifaces():
            self.iface_combo.addItem(f"{ifn['name']}（{ifn['ip']}）",
                                     ifn["name"])
        self.iface_combo.setToolTip(
            "自动模式下：目标子网与某网卡匹配则只走该网卡；\n"
            "都不匹配则在所有物理网卡上各发一轮")
        opts.addWidget(self.iface_combo)
        opts.addSpacing(10)
        self.port_check = QCheckBox("探测端口")
        self.port_check.setChecked(False)
        self.port_check.setToolTip("TCP SYN 探测常见端口，用于识别设备类型")
        opts.addWidget(self.port_check)
        self.name_check = QCheckBox("解析主机名")
        self.name_check.setChecked(False)
        self.name_check.setToolTip("NetBIOS / mDNS / DNS PTR 三路解析")
        opts.addWidget(self.name_check)
        self.clear_check = QCheckBox("扫描前清空结果")
        self.clear_check.setChecked(True)
        opts.addWidget(self.clear_check)
        opts.addStretch(1)
        cfg.addLayout(opts)

        # 控制行
        ctrl = QHBoxLayout()
        ctrl.setSpacing(12)
        self.start_btn = QPushButton("▶  开始扫描", objectName="startBtn")
        self.start_btn.clicked.connect(self._start_scan)
        self.stop_btn = QPushButton("■ 停止", objectName="stopBtn")
        self.stop_btn.clicked.connect(self._stop_scan)
        self.stop_btn.setEnabled(False)
        ctrl.addWidget(self.start_btn)
        ctrl.addWidget(self.stop_btn)
        ctrl.addSpacing(10)
        self.phase_label = QLabel("", objectName="phaseLabel")
        ctrl.addWidget(self.phase_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setValue(0)
        ctrl.addWidget(self.progress_bar, 1)
        cfg.addLayout(ctrl)
        layout.addWidget(cfg_card)

        # ================= 结果 + 日志（可拖分栏） ================= #
        splitter = QSplitter(Qt.Vertical)
        splitter.setChildrenCollapsible(False)
        layout.addWidget(splitter, 1)

        # ---- 结果卡片 ---- #
        res_card, res = self._card()
        res_head = QHBoxLayout()
        res_head.addWidget(QLabel("扫描结果", objectName="cardTitle"))
        res_head.addStretch(1)
        res_head.addWidget(QLabel("⌕"))
        self.filter_edit = QLineEdit(objectName="filterEdit")
        self.filter_edit.setPlaceholderText("筛选：IP / MAC / 厂商 / 主机名 / 备注 …")
        self.filter_edit.setFixedWidth(300)
        self.filter_edit.textChanged.connect(
            lambda t: self.proxy.setFilterFixedString(t.strip()))
        res_head.addWidget(self.filter_edit)
        self.stat_label = QLabel("已发现 0 台", objectName="statPill")
        res_head.addWidget(self.stat_label)
        btn_csv = QPushButton("⇩ CSV", objectName="ghostBtn")
        btn_csv.clicked.connect(self._export_csv)
        res_head.addWidget(btn_csv)
        btn_json = QPushButton("⇩ JSON", objectName="ghostBtn")
        btn_json.clicked.connect(self._export_json)
        res_head.addWidget(btn_json)
        res.addLayout(res_head)

        self.model = ResultsModel()
        self.model.note_edited.connect(self._save_note)
        self.proxy = ResultsProxy()
        self.proxy.setSourceModel(self.model)
        self.proxy.setFilterKeyColumn(-1)
        self.proxy.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setItemDelegate(ResultsDelegate(self.table))
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.setSortingEnabled(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setWordWrap(False)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._table_menu)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(True)
        header.setDefaultAlignment(Qt.AlignCenter)
        header.setSectionResizeMode(QHeaderView.Interactive)
        for col, w in enumerate((140, 170, 150, 140, 170, 120, 140, 100, 170)):
            self.table.setColumnWidth(col, w)
        res.addWidget(self.table)
        splitter.addWidget(res_card)

        # ---- 日志卡片 ---- #
        log_card, log = self._card()
        log_head = QHBoxLayout()
        log_head.addWidget(QLabel("运行日志", objectName="cardTitle"))
        log_head.addStretch(1)
        log.addLayout(log_head)
        self.log_view = QPlainTextEdit(objectName="logView")
        self.log_view.setReadOnly(True)
        log.addWidget(self.log_view)
        splitter.addWidget(log_card)
        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([640, 140])

    # ------------------------------------------------------------------ #
    # 扫描控制
    # ------------------------------------------------------------------ #

    def _start_scan(self):
        subnets = self.subnet_editor.subnets()
        if not subnets:
            QMessageBox.information(
                self, "请先添加网段",
                "在上方输入目标网段（如 192.168.1.0/24）并回车添加。")
            return
        total_hosts = sum(_count_hosts(s) for s in subnets)
        if total_hosts > 16384:
            r = QMessageBox.question(
                self, "网段较大",
                f"共 {total_hosts} 个地址，扫描可能较久。继续吗？")
            if r != QMessageBox.Yes:
                return

        if self.clear_check.isChecked():
            self.model.clear()
        self._notes_cache = self.store.get_notes()
        self.log_view.clear()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self._set_scanning(True)

        self._thread = QThread()
        self._worker = ScanWorker()
        self._worker.moveToThread(self._thread)
        self._worker.params = {
            "subnet_strs": subnets,
            "iface_name": self.iface_combo.currentData(),
            "probe_ports": self.port_check.isChecked(),
            "resolve_names": self.name_check.isChecked(),
        }
        self._worker.host_found.connect(self._on_host_found)
        self._worker.host_updated.connect(self.model.update_host)
        self._worker.progress.connect(self._on_progress)
        self._worker.log.connect(self._on_log)
        self._worker.scan_finished.connect(self._on_finished)
        self._worker.scan_failed.connect(
            lambda m: QMessageBox.warning(self, "扫描失败", m))
        self._thread.started.connect(self._worker.run)
        self._thread.start()
        self.statusBar().showMessage(f"扫描中：{', '.join(subnets)}")

    def _stop_scan(self):
        if self._worker:
            self._worker.request_stop()
            self._on_log("正在停止 …")

    def _set_scanning(self, scanning: bool):
        self._scanning = scanning
        self.start_btn.setEnabled(not scanning)
        self.stop_btn.setEnabled(scanning)
        self.subnet_editor.setEnabled(not scanning)
        self.iface_combo.setEnabled(not scanning)

    def _on_finished(self, count: int):
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(100)
        self.phase_label.setText("")
        self._set_scanning(False)
        self.statusBar().showMessage(f"扫描完成，发现 {count} 台主机")
        self._update_stat()
        for h in self.model.rows():
            self.store.touch(h.mac, h.ip, h.hostname)
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
            self._thread = None
            self._worker = None

    # ------------------------------------------------------------------ #
    # 结果 / 日志 / 进度
    # ------------------------------------------------------------------ #

    def _on_host_found(self, data: dict):
        # 按 MAC 回填历史备注
        saved = self._notes_cache.get(data["mac"])
        if saved:
            data["note"] = saved["note"]
        self.model.add_host(data)
        self._update_stat()

    def _update_stat(self):
        self.stat_label.setText(f"已发现 {self.model.rowCount()} 台")

    def _on_progress(self, cur, total, text):
        self.phase_label.setText(text)
        if total > 0:
            self.progress_bar.setRange(0, total)
            self.progress_bar.setValue(cur)
        else:
            self.progress_bar.setRange(0, 0)  # 忙碌指示

    def _on_log(self, msg):
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.log_view.appendPlainText(f"[{stamp}] {msg}")

    def _save_note(self, mac, note, ip):
        self.store.save_note(mac, note, ip)

    # ------------------------------------------------------------------ #
    # 主题 / 设置持久化
    # ------------------------------------------------------------------ #

    def _set_theme(self, name: str):
        self._theme = name
        apply_theme(QApplication.instance(), name)
        self.table.viewport().update()  # 绘制代理的颜色需要重绘
        self._save_settings()

    def _load_settings(self) -> dict:
        try:
            with open(self._settings_file, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_settings(self):
        try:
            with open(self._settings_file, "w", encoding="utf-8") as f:
                json.dump({"theme": self._theme}, f, ensure_ascii=False)
            if self._uid is not None:
                os.chown(self._settings_file, self._uid,
                         self._gid if self._gid is not None else -1)
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # 网段持久化
    # ------------------------------------------------------------------ #

    def _save_subnets(self):
        try:
            with open(self._subnet_file, "w", encoding="utf-8") as f:
                json.dump(self.subnet_editor.subnets(), f,
                          ensure_ascii=False, indent=1)
            if self._uid is not None:
                os.chown(self._subnet_file, self._uid,
                         self._gid if self._gid is not None else -1)
        except OSError:
            pass

    def _load_subnets(self):
        try:
            with open(self._subnet_file, encoding="utf-8") as f:
                nets = json.load(f)
            if isinstance(nets, list):
                self.subnet_editor.set_subnets(nets)
        except (OSError, json.JSONDecodeError):
            pass

    # ------------------------------------------------------------------ #
    # 表格右键菜单 / 导出 / 关于
    # ------------------------------------------------------------------ #

    def _table_menu(self, pos):
        index = self.table.indexAt(pos)
        if not index.isValid():
            return
        row = self.proxy.mapToSource(index).row()
        h = self.model.host_at(row)
        menu = QMenu(self)
        for text, value in (("复制 IP", h.ip), ("复制 MAC", h.mac),
                            ("复制主机名", h.hostname),
                            ("复制备注", h.note)):
            act = QAction(text, self)
            act.setEnabled(bool(value))
            act.triggered.connect(
                lambda _, v=value: QGuiApplication.clipboard().setText(v))
            menu.addAction(act)
        menu.addSeparator()
        act_note = QAction("编辑备注 …", self)
        act_note.triggered.connect(
            lambda: self.table.edit(self.proxy.index(row, 8)))
        menu.addAction(act_note)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 CSV", "扫描结果.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        rows = [h.as_dict() for h in self.model.rows()]
        with open(path, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(["IP 地址", "MAC 地址", "厂商", "主机名", "开放端口",
                        "设备类型", "网段", "经由网卡", "备注"])
            for r in rows:
                w.writerow([r["ip"], r["mac"], r["vendor"], r["hostname"],
                            " ".join(map(str, r["open_ports"])),
                            r["device_type"], r["subnet"], r["iface"],
                            r["note"]])
        self.statusBar().showMessage(f"已导出 {len(rows)} 条到 {path}")

    def _export_json(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "导出 JSON", "扫描结果.json", "JSON 文件 (*.json)")
        if not path:
            return
        data = [h.as_dict() for h in self.model.rows()]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.statusBar().showMessage(f"已导出 {len(data)} 条到 {path}")

    def _about(self):
        QMessageBox.about(
            self, "关于",
            "<b>局域网 IP 地址扫描助手</b><br><br>"
            "多网段并发的局域网设备发现工具：<br>"
            "• ARP 二层扫描 + 牺牲 IP 机制，本机网卡无需配置目标网段<br>"
            "• 支持任意掩码（如 /29），可跨子网发现设备<br>"
            "• 端口探测 / MAC 厂商识别 / 主机名解析 / 设备类型推断<br>"
            "• 设备备注按 MAC 持久化，重扫自动回显<br><br>"
            "<span style='color:#626879'>仅用于自有网络的设备排查。</span>")

    def closeEvent(self, event):
        if self._scanning:
            r = QMessageBox.question(
                self, "扫描进行中", "扫描正在进行，确定退出吗？")
            if r != QMessageBox.Yes:
                event.ignore()
                return
            if self._worker:
                self._worker.request_stop()
        if self._thread:
            self._thread.quit()
            self._thread.wait(3000)
        event.accept()


class ResultsProxy(QSortFilterProxyModel):
    """结果代理：IP 列按数值排序（避免 192.168.1.10 < 192.168.1.9 的字典序）。"""

    def lessThan(self, left, right):
        if left.column() == 0 and right.column() == 0:
            try:
                a = tuple(int(x) for x in left.data().split("."))
                b = tuple(int(x) for x in right.data().split("."))
                return a < b
            except (AttributeError, ValueError):
                pass
        return super().lessThan(left, right)


def _count_hosts(cidr: str) -> int:
    """计算网段地址总数（用于大网段提醒）。"""
    import ipaddress
    return ipaddress.ip_network(cidr).num_addresses
