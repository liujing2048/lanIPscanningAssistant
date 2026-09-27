# 局域网 IP 地址扫描助手

带美观深色 GUI 的局域网设备发现工具。核心特性是 **ARP 二层扫描 + 牺牲 IP 机制**：
本机网卡**无需配置目标网段 IP**，就能同时扫描多个互不相关的网段（包括任意掩码如
/29），解决了"设备 IP 忘了、网段不确定、掩码很偏"的排查难题。

## 功能

- **多网段并发扫描**：如 `192.168.1.0/24` + `192.168.2.0/24` + `192.168.3.0/24` 同时扫
- **任意掩码**：`192.168.1.9/29` 自动归一到所在子网 `192.168.1.8/29` 并扫描
- **无需改网卡配置**：所有探测以"目标子网内牺牲 IP"为源从二层发出，
  网卡上完全不用添加目标网段
- **端口探测**：TCP SYN 探测 20 个常见端口（不完成握手，不留连接）
- **MAC 厂商识别**：内置 4 万+ OUI 记录（有 ieee-data 时优先用系统库）
- **主机名解析**：NetBIOS(137) / mDNS(5353) / DNS PTR 三路并行
- **设备类型推断**：端口指纹 + 主机名 + MAC 厂商综合判断（路由器/打印机/摄像头…）
- **设备备注**：按 MAC 地址持久化（sqlite），重新扫描自动回显
- **导出**：CSV（Excel 友好，utf-8-sig）/ JSON
- 渐进式结果展示：先出 IP/MAC，端口和主机名陆续补全；可排序、关键字筛选
- **深色 / 浅色主题**：菜单「视图」切换，自动记住选择

## 运行

```bash
# 需要 root（发送原始以太网帧）：
./run.sh
# 或
sudo -E env QT_WAYLAND_DECORATION=bradient /home/piter/project/python/venv/bin/python main.py
```

> GNOME Wayland 下以 root 运行时必须带 `QT_WAYLAND_DECORATION=bradient`，
> 否则窗口没有最小化/最大化/关闭按钮（root 拿不到用户会话主题）。
> `./run.sh` 已自动处理。

### Windows 运行

1. 安装 [Npcap](https://npcap.com/)（scapy 在 Windows 发送/嗅探原始以太网帧的依赖）
2. `pip install -r requirements.txt`
3. 以管理员身份运行：`python main.py`（未提权时会弹窗询问是否继续）

- 数据目录：`%APPDATA%\LanScanAssistant`
- 命令行快扫：`python cli_scan.py 192.168.1.0/24`
- 虚拟网卡（VMware/VirtualBox/Hyper-V/TAP 等）按适配器描述自动过滤

虚拟环境：`/home/piter/project/python/venv`（依赖见 requirements.txt）。

命令行快速扫描（不经 GUI）：

```bash
sudo /home/piter/project/python/venv/bin/python cli_scan.py 192.168.1.0/24 192.168.1.8/29
```

## 网段输入写法

| 写法 | 含义 |
|---|---|
| `192.168.1.0/24` | 标准 CIDR |
| `192.168.1.9/29` | 任意掩码（自动归一为 192.168.1.8/29） |
| `192.168.1.0` | 无掩码且以 .0 结尾，按 /24 处理 |
| `192.168.1.100` | 无掩码单 IP，按 /32 处理 |
| `192.168.1-3.0/24` | 范围展开 = 192.168.1.0/24 ~ 192.168.3.0/24 |
| `192.168.1,2,3.0/24` | 枚举展开 |

## 工作原理（为什么不需要改网卡配置）

对目标子网内每个 IP 发送 ARP who-has 请求，ARP 层发送方 IP 填**目标子网内的
牺牲地址**（通常为子网的网络地址，如 `192.168.3.0`），以太网源 MAC 用本机网卡
真实 MAC。目标主机收到后会向该 MAC 回 ARP is-at 应答，由嗅探器捕获完成发现。

配套一个 **ARP 应答器**：当目标主机需要向牺牲 IP 回包（TCP SYN-ACK、NBNS、mDNS
应答都要先 ARP 解析牺牲 IP）时，立即代答"牺牲 IP 在本机 MAC 上"，保证后续端口/
主机名探测的应答能顺利送回。

ARP 发现阶段采用**双探测**（网络地址 + 0.0.0.0 探针，兼容不同协议栈），并对
未应答地址自动补发两轮，降低偶发丢包造成的漏扫。

## ⚠️ 注意事项

- **仅用于自有网络**。牺牲 IP 机制会给目标主机 ARP 缓存写入一条无害记录（指向
  本机 MAC 的网络地址）；企业网络若开启 DAI（动态 ARP 检测）/端口安全可能拦截。
- 端口探测为半开 SYN：目标日志可能出现对 `x.x.x.0` 地址的未完成连接记录，无实际影响。
- sudo 运行时数据目录自动还原到真实用户家目录
  （`~/.local/share/LanScanAssistant/`），文件属主已修正，普通权限可读写。
- 交换机侧大量广播帧可能触发广播风暴抑制，发包间隔默认 2.5ms，扫 /24 约 1 秒。

## 项目结构

```
main.py                    入口（root 检查、sudo 下数据目录还原）
app/core/engine.py         扫描引擎：多网段调度、嗅探分发、停止控制
app/core/arp_scan.py       牺牲 IP 选取、ARP 双探测、ARP 应答器
app/core/port_scan.py      TCP SYN 探测（sport 编码反查）
app/core/hostname.py       NBNS / mDNS / DNS PTR 三路解析
app/core/oui.py            MAC 厂商查询（ieee-data + 内置快照兜底）
app/core/classify.py       设备类型推断
app/core/subnet_input.py   网段输入解析与范围展开
app/core/netinfo.py        物理网卡枚举（过滤 docker/br/veth 等虚拟网卡）
app/storage/store.py       设备备注 sqlite 持久化
app/ui/                    PySide6 GUI（深色主题、模型/视图、线程桥接）
```
