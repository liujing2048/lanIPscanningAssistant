"""扫描引擎编排器：多网段调度、统一嗅探分发、停止控制。

架构：所有探测（ARP who-has / TCP SYN / NBNS / mDNS）都以目标子网内的
牺牲 IP 为源、本机真实网卡 MAC 为源 MAC 从二层发出；每块物理网卡一个
AsyncSniffer（BPF 内核过滤 + store=0），一个帧分发器分类处理应答。
目标网段与本机 IP 完全不匹配时，一切应答也不依赖三层路由。
"""
import ipaddress
import random
import struct
import threading
import time

from scapy.layers.dns import DNS
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import AsyncSniffer, sendp

from .arp_scan import build_arp_reply, build_arp_requests, pick_sacrifice_ip
from .classify import classify_device
from .hostname import (build_mdns_query, build_nbns_query, dns_ptr_lookup,
                       parse_mdns_response, parse_nbns_response)
from .models import HostResult
from .netinfo import get_physical_ifaces
from .oui import lookup_vendor
from .port_scan import build_syn_packets

SEND_CHUNK = 200        # 发送分块大小（块间可检查停止事件）
ARP_WAIT = 2.5          # ARP 阶段收尾等待（秒）
PORT_WAIT = 3.0         # 端口阶段收尾等待（秒）
NAME_WAIT = 3.0         # 主机名阶段收尾等待（秒）


class ScanEngine:
    """多网段并发扫描引擎。start() 阻塞运行，应在 GUI 工作线程中调用。

    回调（on_host_found 等）可能在嗅探线程中触发，GUI 侧需通过信号
    投递到 UI 线程。
    """

    def __init__(self, on_host_found=None, on_host_update=None,
                 on_progress=None, on_log=None, on_finished=None):
        self._on_host_found = on_host_found or (lambda h: None)
        self._on_host_update = on_host_update or (lambda ip, f: None)
        self._on_progress = on_progress or (lambda cur, total, text: None)
        self._on_log = on_log or (lambda msg: None)
        self._on_finished = on_finished or (lambda n: None)

        self.stop_event = threading.Event()
        self._lock = threading.RLock()
        self._hosts: dict[str, HostResult] = {}
        self._pending: set[str] = set()      # ARP 探测目标集合
        self._sacrifices: set[str] = set()   # 全部牺牲 IP（ARP 应答器守护）
        self._sport_map: dict[int, tuple] = {}  # sport → (ip, port)
        self._nbns_txn: dict[int, str] = {}  # NBNS 事务 ID → 查询的 IP
        self._sniffers: list[AsyncSniffer] = []
        self._iface_mac: dict[str, str] = {}
        self._local_ips: set[str] = set()
        self._send_interval = 0.0025
        self._running = False
        self._nets = []

    # ------------------------------------------------------------------ #
    # 对外接口
    # ------------------------------------------------------------------ #

    def stop(self) -> None:
        """请求停止（线程安全，可从 UI 线程调用）。"""
        self.stop_event.set()

    @property
    def running(self) -> bool:
        return self._running

    @property
    def results(self) -> list[HostResult]:
        with self._lock:
            return list(self._hosts.values())

    def start(self, subnet_strs: list[str], iface_name: str = "auto",
              probe_ports: bool = True, resolve_names: bool = True,
              send_interval: float = 0.0025):
        """执行一次完整扫描（阻塞）。

        ARP 发现阶段自动双探测（网络地址 + 0.0.0.0 探针）；
        端口/主机名阶段以"本机真实 IP（若在子网内）或网络地址"为源。
        """
        self.stop_event.clear()
        self._running = True
        self._send_interval = send_interval
        with self._lock:
            self._hosts.clear()
            self._pending.clear()
            self._sacrifices.clear()
            self._sport_map.clear()
            self._nbns_txn.clear()
        try:
            nets = self._parse_subnets(subnet_strs)
            self._nets = nets  # 供 _subnet_of / _in_scanned_subnets 使用
            ifaces = self._select_ifaces(iface_name)
            self._local_ips = {i["ip"] for i in ifaces}
            # ARP 目标集合（多网段重叠时自动去重）
            for net in nets:
                self._pending.update(str(ip) for ip in net.hosts())

            # 任务 = (net, iface) 组合；并确定每个任务的牺牲 IP
            tasks = self._build_tasks(nets, ifaces)
            if not tasks:
                raise ValueError("没有可用的物理网卡")

            # 启动每块网卡的嗅探器
            self._start_sniffers({ifname for _, ifname, _ in tasks})

            # 阶段 1：ARP 主机发现
            self._phase_arp(tasks)

            # 阶段 2：TCP SYN 端口探测
            if probe_ports:
                self._phase_ports(tasks)

            # 阶段 3：主机名解析（NBNS / mDNS / DNS PTR）
            if resolve_names:
                self._phase_names(tasks)

            # 收尾：设备类型推断
            self._finish_classify()
        except Exception as e:  # 引擎在工作线程中运行，异常必须带回
            self._on_log(f"扫描出错：{e}")
        finally:
            self._stop_sniffers()
            self._running = False
            self._on_finished(len(self._hosts))

    # ------------------------------------------------------------------ #
    # 准备阶段
    # ------------------------------------------------------------------ #

    def _parse_subnets(self, subnet_strs: list[str]) -> list:
        """解析网段字符串（如 192.168.1.0/24、192.168.1.9/29）。"""
        nets = []
        for s in subnet_strs:
            s = s.strip()
            if not s:
                continue
            try:
                net = ipaddress.ip_network(s, strict=False)
            except ValueError as e:
                raise ValueError(f"无效网段「{s}」：{e}")
            if net.num_addresses > 65536:
                raise ValueError(f"网段「{s}」过大（> /16），请缩小范围")
            nets.append(net)
        if not nets:
            raise ValueError("请至少指定一个网段")
        # 去掉完全相同的网段
        seen, unique = set(), []
        for n in nets:
            if str(n) not in seen:
                seen.add(str(n))
                unique.append(n)
        return unique

    def _select_ifaces(self, iface_name: str) -> list[dict]:
        """选择参与扫描的网卡。auto=全部物理网卡。"""
        physical = get_physical_ifaces()
        if not physical:
            raise ValueError("未找到可用的物理网卡")
        if iface_name and iface_name != "auto":
            for p in physical:
                if p["name"] == iface_name:
                    return [p]
            raise ValueError(f"网卡 {iface_name} 不存在或非物理网卡")
        return physical

    def _build_tasks(self, nets, ifaces) -> list:
        """生成 (net, iface, sacrifice_ip) 任务组合。

        自动模式：目标子网与某网卡 IP 匹配则只走该网卡；都不匹配则
        在全部物理网卡上各发一轮（只有直连网卡会有应答）。
        """
        tasks = []
        for net in nets:
            matched = [i for i in ifaces
                       if ipaddress.ip_address(i["ip"]) in net]
            chosen = matched if matched else ifaces
            for ifinfo in chosen:
                sac = pick_sacrifice_ip(net, {ifinfo["ip"]})
                tasks.append((net, ifinfo["name"], sac))
                with self._lock:
                    self._sacrifices.add(sac)
        return tasks

    # ------------------------------------------------------------------ #
    # 嗅探与分发
    # ------------------------------------------------------------------ #

    def _bpf_filter(self, mac: str) -> str:
        """每网卡的 BPF 过滤器：ARP / TCP SYN-ACK·RST / UDP 137·5353，
        并排除自己发出的帧（内核态预过滤，减轻 Python 收包压力）。"""
        tcp_part = ("(tcp and ((tcp[tcpflags] & (tcp-syn|tcp-ack) "
                    "== (tcp-syn|tcp-ack)) or (tcp[tcpflags] & tcp-rst != 0)))")
        udp_part = "(udp and (src port 137 or src port 5353))"
        return f"(arp or {tcp_part} or {udp_part}) and not ether src {mac}"

    def _start_sniffers(self, iface_names: set[str]) -> None:
        for ifname in iface_names:
            mac = next((i["mac"] for i in get_physical_ifaces()
                        if i["name"] == ifname), None)
            if not mac:
                continue
            self._iface_mac[ifname] = mac
            sniffer = AsyncSniffer(
                iface=ifname,
                filter=self._bpf_filter(mac),
                store=False,
                prn=self._make_dispatcher(ifname, mac),
            )
            sniffer.start()
            self._sniffers.append(sniffer)
            self._on_log(f"嗅探器已启动：{ifname}")

    def _stop_sniffers(self) -> None:
        for sniffer in self._sniffers:
            try:
                sniffer.stop()
            except Exception:
                pass
        self._sniffers.clear()

    def _make_dispatcher(self, ifname: str, my_mac: str):
        """构造某网卡的帧分发器（在嗅探线程中执行，注意线程安全）。"""

        def dispatch(frame):
            try:
                if Ether not in frame:
                    return
                if frame[Ether].src == my_mac:
                    return
                if ARP in frame:
                    self._dispatch_arp(frame, ifname)
                elif TCP in frame and IP in frame:
                    self._dispatch_tcp(frame)
                elif UDP in frame and IP in frame:
                    self._dispatch_udp(frame)
            except Exception:
                pass  # 嗅探线程绝不向上抛异常

        return dispatch

    def _dispatch_arp(self, frame, ifname: str) -> None:
        arp = frame[ARP]
        if arp.op == 2:  # is-at 应答 → 发现主机
            ip = str(arp.psrc)
            mac = str(arp.hwsrc)
            if mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                return
            with self._lock:
                if ip not in self._pending or ip in self._hosts:
                    return
                host = HostResult(ip=ip, mac=mac, iface=ifname,
                                  subnet=self._subnet_of(ip))
                self._hosts[ip] = host
                host.vendor = lookup_vendor(mac)
            self._on_host_found(host.as_dict())
        elif arp.op == 1:  # who-has → ARP 代理应答器
            asked = str(arp.pdst)
            asker = str(arp.psrc)
            if asked not in self._sacrifices or asked in self._local_ips:
                return
            # 只回应我们扫描网段内主机的询问
            if not self._in_scanned_subnets(asker):
                return
            reply = build_arp_reply(self._iface_mac.get(ifname, ""),
                                    frame[Ether].src, asker, asked)
            sendp(reply, iface=ifname, verbose=0)

    def _dispatch_tcp(self, frame) -> None:
        tcp = frame[TCP]
        target = self._sport_map.get(int(tcp.dport))
        if not target:
            return
        ip, port = target
        if str(frame[IP].src) != ip:
            return
        flags = int(tcp.flags)
        if flags & 0x12 == 0x12:  # SYN+ACK → 端口开放
            with self._lock:
                host = self._hosts.get(ip)
                if host is None or port in host.open_ports:
                    return
                host.open_ports.append(port)
                host.open_ports.sort()
            self._on_host_update(ip, {"open_ports": host.open_ports})

    def _dispatch_udp(self, frame) -> None:
        udp = frame[UDP]
        sport = int(udp.sport)
        if sport == 137:  # NBNS 应答
            data = bytes(udp.payload)
            if len(data) < 2:
                return
            txn = struct.unpack(">H", data[:2])[0]
            with self._lock:
                ip = self._nbns_txn.get(txn)
            if not ip:
                return
            name = parse_nbns_response(data)
            if not name:
                return
            with self._lock:
                host = self._hosts.get(ip)
                if host is None or host.hostname == name:
                    return
                host.hostname = name
            self._on_host_update(ip, {"hostname": name})
        elif sport == 5353:  # mDNS 应答
            for ip, hostname in parse_mdns_response(frame):
                with self._lock:
                    host = self._hosts.get(ip)
                    if host is None or host.hostname:
                        continue
                    host.hostname = hostname
                self._on_host_update(ip, {"hostname": hostname})

    def _subnet_of(self, ip: str) -> str:
        """返回包含该 IP 的扫描网段标签（取第一个匹配的）。"""
        addr = ipaddress.ip_address(ip)
        for net in getattr(self, "_nets", []):
            if addr in net:
                return str(net)
        return ""

    def _in_scanned_subnets(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in n for n in getattr(self, "_nets", []))

    # ------------------------------------------------------------------ #
    # 扫描阶段
    # ------------------------------------------------------------------ #

    def _send_chunks(self, pkts: list, ifname: str) -> None:
        """分块发包，块间检查停止事件。"""
        for i in range(0, len(pkts), SEND_CHUNK):
            if self.stop_event.is_set():
                return
            sendp(pkts[i:i + SEND_CHUNK], iface=ifname,
                  inter=self._send_interval, verbose=0)

    def _wait(self, seconds: float) -> None:
        """收尾等待窗口（可被停止事件打断）。"""
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            if self.stop_event.is_set():
                return
            time.sleep(0.05)

    def _phase_arp(self, tasks) -> None:
        self._on_progress(0, len(self._pending), "ARP 主机发现")
        self._on_log("阶段 1/3：ARP 主机发现 …")
        total = len(self._pending) * 2  # 每个目标双探测（两帧）
        sent = 0
        for net, ifname, sac in tasks:
            if self.stop_event.is_set():
                return
            mac = self._iface_mac[ifname]
            pkts = build_arp_requests(net, mac, sac)
            self._send_chunks(pkts, ifname)
            sent = min(sent + len(pkts), total)
            self._on_progress(sent, total, "ARP 主机发现")
        self._on_log(f"ARP 请求已全部发出（{total} 个地址），等待应答 …")
        self._wait(ARP_WAIT)
        # 对无应答的目标补发两轮（丢包/瞬时不响应兜底）
        for attempt in (1, 2):
            if self.stop_event.is_set():
                return
            with self._lock:
                missing = self._pending - set(self._hosts)
            if not missing:
                return
            self._on_log(f"对 {len(missing)} 个未应答地址补发第 {attempt} 轮探测 …")
            for net, ifname, sac in tasks:
                if self.stop_event.is_set():
                    return
                mac = self._iface_mac[ifname]
                pkts = [p for p in build_arp_requests(net, mac, sac)
                        if str(p[ARP].pdst) in missing]
                if pkts:
                    self._send_chunks(pkts, ifname)
            self._wait(1.2)

    def _phase_ports(self, tasks) -> None:
        if self.stop_event.is_set():
            return
        with self._lock:
            hosts = list(self._hosts.values())
        if not hosts:
            return
        self._on_log("阶段 2/3：TCP SYN 端口探测 …")
        # 按任务（网段+网卡）分组发 SYN
        sac_map = {(str(net), ifname): sac for net, ifname, sac in tasks}
        total_pkts = 0
        for (net, ifname, _sac) in tasks:
            if self.stop_event.is_set():
                return
            with self._lock:
                group = [h for h in self._hosts.values()
                         if h.subnet == str(net) and h.iface == ifname]
            if not group:
                continue
            sac = sac_map[(str(net), ifname)]
            mac = self._iface_mac[ifname]
            pkts, smap = build_syn_packets(
                [(h.ip, h.mac) for h in group], sac, mac)
            with self._lock:
                self._sport_map.update(smap)
            self._send_chunks(pkts, ifname)
            total_pkts += len(pkts)
        self._on_progress(0, 0, "端口探测")
        self._on_log(f"SYN 探测包已全部发出（{total_pkts} 个），等待应答 …")
        self._wait(PORT_WAIT)

    def _phase_names(self, tasks) -> None:
        if self.stop_event.is_set():
            return
        self._on_log("阶段 3/3：主机名解析（NBNS / mDNS / DNS PTR）…")
        with self._lock:
            hosts = list(self._hosts.values())
        if not hosts:
            return
        sac_map = {(str(net), ifname): sac for net, ifname, sac in tasks}

        def sac_of(host):
            return sac_map.get((host.subnet, host.iface)) or "0.0.0.0"

        # NBNS + mDNS（scapy 二层路径）
        nbns_pkts, mdns_pkts = [], []
        used_txn = set()
        for h in hosts:
            sac = sac_of(h)
            mac = self._iface_mac.get(h.iface)
            if not mac:
                continue
            # 生成不重复的事务 ID
            txn = random.randint(1, 0xFFFF)
            while txn in used_txn:
                txn = random.randint(1, 0xFFFF)
            used_txn.add(txn)
            with self._lock:
                self._nbns_txn[txn] = h.ip
            nbns_pkts.append((build_nbns_query(h.ip, sac, mac, txn), h.iface))
            mdns_pkts.append((build_mdns_query(h.ip, sac, mac), h.iface))

        for pkt, ifname in nbns_pkts:
            if self.stop_event.is_set():
                break
            sendp(pkt, iface=ifname, verbose=0)
        for pkt, ifname in mdns_pkts:
            if self.stop_event.is_set():
                break
            sendp(pkt, iface=ifname, verbose=0)

        # DNS PTR（系统 socket，线程池并发，带超时）
        ptr_results = {}

        def do_ptr(ip):
            name = dns_ptr_lookup(ip, lifetime=1.5)
            if name:
                ptr_results[ip] = name

        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(do_ptr, h.ip) for h in hosts]
            for f in futures:
                f.result(timeout=NAME_WAIT + 2)

        self._wait(NAME_WAIT)
        # PTR 结果只填充仍无主机名的设备
        for ip, name in ptr_results.items():
            with self._lock:
                host = self._hosts.get(ip)
                if host is None or host.hostname:
                    continue
                host.hostname = name
            self._on_host_update(ip, {"hostname": name})

    def _finish_classify(self) -> None:
        """端口探测完成后推断设备类型并推送更新。"""
        with self._lock:
            hosts = list(self._hosts.values())
        for h in hosts:
            t = classify_device(h.open_ports, h.vendor, h.hostname)
            if t and t != h.device_type:
                h.device_type = t
                self._on_host_update(h.ip, {"device_type": t})
