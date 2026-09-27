"""设备备注持久化（sqlite，按 MAC 地址关联，重新扫描自动回显）。"""
import datetime
import os
import sqlite3
import threading


class DeviceStore:
    """设备备注存储。线程安全（内部加锁）。"""

    def __init__(self, db_path: str, uid: int | None = None,
                 gid: int | None = None):
        self._path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS devices (
                mac        TEXT PRIMARY KEY,
                note       TEXT DEFAULT '',
                name_hint  TEXT DEFAULT '',
                first_seen TEXT,
                last_seen  TEXT,
                last_ip    TEXT DEFAULT ''
            )"""
        )
        self._conn.commit()
        # sudo 下 root 创建的数据库归还给真实用户，避免普通权限时无法更新
        if uid is not None:
            for p in (db_path, db_path + "-wal", db_path + "-shm",
                      db_path + "-journal"):
                if os.path.exists(p):
                    try:
                        os.chown(p, uid, gid if gid is not None else -1)
                    except OSError:
                        pass

    def get_notes(self) -> dict[str, dict]:
        """返回 {mac: {note, name_hint}}。"""
        with self._lock:
            rows = self._conn.execute(
                "SELECT mac, note, name_hint FROM devices").fetchall()
        return {mac: {"note": note or "", "name_hint": hint or ""}
                for mac, note, hint in rows}

    def save_note(self, mac: str, note: str, ip: str = "") -> None:
        """新增或更新设备备注。"""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """INSERT INTO devices (mac, note, first_seen, last_seen, last_ip)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(mac) DO UPDATE SET
                       note = excluded.note,
                       last_seen = excluded.last_seen,
                       last_ip = excluded.last_ip""",
                (mac, note, now, now, ip))
            self._conn.commit()

    def touch(self, mac: str, ip: str, name_hint: str = "") -> None:
        """记录设备的最后发现时间 / IP（不改备注）。"""
        now = datetime.datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self._conn.execute(
                """INSERT INTO devices (mac, note, name_hint, first_seen, last_seen, last_ip)
                   VALUES (?, '', ?, ?, ?, ?)
                   ON CONFLICT(mac) DO UPDATE SET
                       last_seen = excluded.last_seen,
                       last_ip = excluded.last_ip""",
                (mac, name_hint, now, now, ip))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
