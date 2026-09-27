"""引擎 CLI 冒烟测试（不经 GUI 直接验证扫描核心）。

用法（需要 root）：
    sudo /home/piter/project/python/venv/bin/python cli_test.py 192.168.1.0/24 192.168.1.8/29
"""
import sys
import threading

from app.core.engine import ScanEngine
from app.core.netinfo import get_physical_ifaces
from app.core.oui import stats


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    subnets = sys.argv[1:]

    print("物理网卡：")
    for i in get_physical_ifaces():
        print(f"  {i['name']}: {i['ip']}  MAC={i['mac']}  ({i['net']})")
    print(f"OUI 库：{stats()}")

    found = []
    lock = threading.Lock()

    def on_host_found(h):
        with lock:
            found.append(h)
        print(f"  [发现] {h['ip']:<16} {h['mac']:<20} {h['vendor']:<24}"
              f" 网段={h['subnet']:<18} 网卡={h['iface']}")

    def on_host_update(ip, fields):
        print(f"  [更新] {ip}: {fields}")

    def on_progress(cur, total, text):
        print(f"  [进度] {text} {cur}/{total}")

    def on_log(msg):
        print(f"  [日志] {msg}")

    engine = ScanEngine(on_host_found=on_host_found, on_host_update=on_host_update,
                        on_progress=on_progress, on_log=on_log, on_finished=None)
    print(f"\n开始扫描：{subnets}\n")
    engine.start(subnets)
    print(f"\n扫描完成，共发现 {len(engine.results)} 台主机")


if __name__ == "__main__":
    main()
