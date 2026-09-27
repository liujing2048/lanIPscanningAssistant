#!/bin/bash
# 以 root 权限启动局域网 IP 地址扫描助手（保留图形环境变量）
cd "$(dirname "$0")"
# 避免 sudo 运行时在项目目录写入 root 属主的 __pycache__
export PYTHONDONTWRITEBYTECODE=1
# root 下 GNOME Wayland 的 adwaita 装饰拿不到用户会话主题，标题栏按钮不显示；
# 强制 Qt 自绘基础装饰（bradient），保证最小化/最大化/关闭按钮可用
export QT_WAYLAND_DECORATION=bradient
exec sudo -E env PYTHONDONTWRITEBYTECODE=1 QT_WAYLAND_DECORATION=bradient \
    /home/piter/project/python/venv/bin/python main.py "$@"
