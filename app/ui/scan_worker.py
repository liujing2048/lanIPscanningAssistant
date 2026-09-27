"""扫描工作线程桥接：引擎回调 → Qt 信号 → UI 线程。

引擎在工作线程运行，回调（可能来自嗅探线程）在这里立即转成信号，
Qt 自动以队列连接投递到 UI 线程，model 更新全部发生在 UI 线程，无锁。
"""
from PySide6.QtCore import QObject, Signal, Slot

from app.core.engine import ScanEngine


class ScanWorker(QObject):
    host_found = Signal(dict)      # 新主机（as_dict）
    host_updated = Signal(str, dict)  # (ip, 变更字段)
    progress = Signal(int, int, str)  # (cur, total, 阶段文本)
    log = Signal(str)
    scan_finished = Signal(int)   # 发现主机总数
    scan_failed = Signal(str)     # 启动参数错误等

    def __init__(self, parent=None):
        super().__init__(parent)
        self.engine = ScanEngine(
            on_host_found=lambda h: self.host_found.emit(h),
            on_host_update=lambda ip, f: self.host_updated.emit(ip, f),
            on_progress=lambda c, t, x: self.progress.emit(c, t, x),
            on_log=lambda m: self.log.emit(m),
            on_finished=lambda n: self.scan_finished.emit(n),
        )
        self.params = {}  # 由主窗口在启动前填好

    @Slot()
    def run(self):
        """线程入口：执行扫描（阻塞直到完成或被停止）。"""
        try:
            self.engine.start(**self.params)
        except Exception as e:
            self.scan_failed.emit(str(e))
            self.scan_finished.emit(0)

    def request_stop(self):
        """线程安全的停止请求（可从 UI 线程直接调用）。"""
        self.engine.stop()
