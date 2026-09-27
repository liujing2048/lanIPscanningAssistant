"""应用入口：root 权限检查、sudo 下数据目录还原、QApplication 启动。

双平台支持：
- Linux：raw socket 需 root（sudo -E），数据目录 ~/.local/share/LanScanAssistant
- Windows：需管理员（Npcap 发原始帧），数据目录 %APPDATA%/LanScanAssistant
"""
import os
import sys

IS_WINDOWS = sys.platform == "win32"

if not IS_WINDOWS:
    import pwd


def real_user() -> tuple[int | None, int | None]:
    """sudo 运行时返回真实用户的 (uid, gid)，否则 (None, None)。Windows 恒为 (None, None)。"""
    if IS_WINDOWS:
        return None, None
    if "SUDO_USER" in os.environ and os.geteuid() == 0:
        try:
            pw = pwd.getpwnam(os.environ["SUDO_USER"])
            return pw.pw_uid, pw.pw_gid
        except KeyError:
            pass
    return None, None


def is_elevated() -> bool:
    """是否以管理员（Windows）/ root（Linux）身份运行。"""
    if IS_WINDOWS:
        import ctypes
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return os.geteuid() == 0


def data_dir() -> str:
    """计算数据目录：Windows 用 %APPDATA%；Linux sudo 下还原真实用户家目录。"""
    uid, gid = real_user()
    if IS_WINDOWS:
        d = os.path.join(os.environ.get("APPDATA") or os.path.expanduser("~"),
                         "LanScanAssistant")
    else:
        if uid is not None:
            home = pwd.getpwuid(uid).pw_dir
        else:
            home = os.path.expanduser("~")
        d = os.path.join(home, ".local", "share", "LanScanAssistant")
    os.makedirs(d, exist_ok=True)
    # root 创建的目录归还给真实用户，避免普通权限下无法读写（仅 Linux）
    if uid is not None:
        for root, dirs, files in os.walk(d):
            for name in dirs + files:
                try:
                    os.chown(os.path.join(root, name), uid, gid)
                except OSError:
                    pass
    return d


def _elevate_hint() -> str:
    """未提权时的启动提示文案（按平台 / 打包形态区分）。"""
    if IS_WINDOWS:
        return "请关闭程序，右键选择「以管理员身份运行」。"
    if getattr(sys, "frozen", False):
        # PyInstaller 打包后的启动提示
        return ("请在终端执行：\n"
                "    sudo -E env QT_WAYLAND_DECORATION=bradient ./LanScanAssistant")
    return ("请在终端执行：\n"
            "    sudo -E /home/piter/project/python/venv/bin/python main.py\n"
            "或直接运行 ./run.sh")


def main():
    app = None
    if not is_elevated():
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication(sys.argv)
        if IS_WINDOWS:
            # Windows + Npcap 存在非管理员可用的安装方式，允许用户选择继续
            ret = QMessageBox.question(
                None, "未以管理员身份运行",
                "ARP 扫描需要发送原始以太网帧（raw socket），通常需要管理员权限。\n\n"
                + _elevate_hint() + "\n\n是否仍要继续？",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if ret != QMessageBox.Yes:
                sys.exit(1)
        else:
            QMessageBox.warning(
                None, "需要 root 权限",
                "ARP 扫描需要发送原始以太网帧（raw socket），必须以 root 运行。\n\n"
                + _elevate_hint())
            sys.exit(1)

    from PySide6.QtWidgets import QApplication
    if app is None:
        app = QApplication(sys.argv)

    from app.ui.theme import apply_theme
    from app.ui.main_window import MainWindow
    apply_theme(app)
    window = MainWindow(data_dir(), uid=real_user()[0], gid=real_user()[1])
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
