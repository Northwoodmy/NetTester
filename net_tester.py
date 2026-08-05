#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
net_tester.py — TCP/UDP 网络测试工具（GUI）

功能：
  - 三种工作模式：TCP Server / TCP Client / UDP
  - 发送随机数据包（自定义大小）、手动发送（文本/HEX）、定时循环发送
  - 接收数据显示（文本/HEX 切换、时间戳、来源地址）
  - 收发统计（字节数、包数、实时速率）

依赖：python3-tk（sudo apt install python3-tk）
"""

import errno
import os
import queue
import re
import socket
import subprocess
import sys
import threading
import time

try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox
except ModuleNotFoundError:                 # 允许无 GUI 环境仅使用网络层
    tk = None

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

UDP_MAX_PAYLOAD = 65507          # UDP 数据报最大载荷
RECV_BUF = 65536
MAX_RX_LINES = 2000              # 接收区最大行数，超出裁剪
MONO_FONT = "Consolas" if sys.platform == "win32" else "Monospace"
IS_WIN = sys.platform == "win32"


def format_hex(data: bytes) -> str:
    """字节串转空格分隔的十六进制显示。"""
    return " ".join(f"{b:02X}" for b in data)


def parse_hex(text: str) -> bytes:
    """解析十六进制输入（自动去空格/换行），非法输入抛 ValueError。"""
    cleaned = "".join(text.split())
    if len(cleaned) % 2 != 0:
        raise ValueError("HEX 长度必须为偶数")
    return bytes.fromhex(cleaned)


def pretty_bytes(n) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"


def _ip_sort_key(ip: str):
    """私网地址排最前，其次公网/TUN，再 link-local，最后回环。"""
    try:
        a, b = (int(x) for x in ip.split(".")[:2])
    except ValueError:
        return (9, ip)
    if a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168):
        return (0, ip)
    if a == 169 and b == 254:
        return (2, ip)
    if a == 127:
        return (3, ip)
    return (1, ip)


def detect_local_ips() -> list:
    """探测本机 IPv4 地址：私网 IP 在前，127.0.0.1 备选，0.0.0.0 垫底。"""
    ips = []
    try:                                   # 主出口 IP（UDP connect 不产生真实流量）
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ips.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:                                   # 主机名解析（跨平台，多数系统能列出网卡地址）
        for _f, _t, _p, _c, sa in socket.getaddrinfo(
                socket.gethostname(), None, socket.AF_INET):
            if sa[0] not in ips:
                ips.append(sa[0])
    except OSError:
        pass
    if not IS_WIN:                         # Linux 再用 ip 命令补全（多网卡/容器更准）
        try:
            out = subprocess.check_output(["ip", "-4", "-o", "addr", "show"],
                                          text=True, timeout=3)
            for line in out.splitlines():
                parts = line.split()
                if "inet" in parts:
                    ip = parts[parts.index("inet") + 1].split("/")[0]
                    if ip not in ips:
                        ips.append(ip)
        except (OSError, subprocess.SubprocessError):
            pass
    if "127.0.0.1" not in ips:
        ips.append("127.0.0.1")
    return sorted(ips, key=_ip_sort_key) + ["0.0.0.0"]


def _loopback(addr):
    """0.0.0.0 换成 127.0.0.1（Windows 对 0.0.0.0 作为目的地址支持不一致）。"""
    return ("127.0.0.1", addr[1]) if addr[0] == "0.0.0.0" else addr[:2]


# ---------------------------------------------------------------------------
# 网络层（不依赖 tkinter，可独立测试）
#
# 所有 worker 通过两个回调向外界通报：
#   on_data(source: str, data: bytes)  — 收到数据
#   on_event(text: str)                — 状态/错误事件
# 回调在后台线程中触发，GUI 层负责投递到主线程。
# ---------------------------------------------------------------------------

class BaseWorker:
    def __init__(self, on_data, on_event):
        self.on_data = on_data
        self.on_event = on_event
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def send(self, data: bytes):
        raise NotImplementedError


class UDPWorker(BaseWorker):
    """绑定本地端口收发 UDP。"""

    def __init__(self, on_data, on_event, local_host: str, local_port: int,
                 target_host: str, target_port: int):
        super().__init__(on_data, on_event)
        self.local = (local_host, local_port)
        self.target = (target_host, target_port)
        self.sock = None
        self._thread = None

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # 不加 SO_REUSEADDR：加了会允许多个窗口绑同一端口、静默分走数据包
        # SO_BROADCAST：允许向 255.255.255.255 等广播地址发包
        # 注意：收广播包必须把本地地址绑 0.0.0.0（绑具体 IP 只收单播）
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.bind(self.local)
        self.sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._thread.start()
        self.on_event(f"UDP 已绑定 {self.local[0]}:{self.local[1]}")

    def _recv_loop(self):
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(RECV_BUF)
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop.is_set():      # 被 stop() 的唤醒包打断
                break
            self.on_data(f"{addr[0]}:{addr[1]}", data)

    def send(self, data: bytes):
        if len(data) > UDP_MAX_PAYLOAD:
            data = data[:UDP_MAX_PAYLOAD]
            self.on_event(f"UDP 包过大，已截断为 {UDP_MAX_PAYLOAD} 字节")
        self.sock.sendto(data, self.target)

    def stop(self):
        super().stop()
        if not self.sock:
            return
        try:    # 给自己发个空包，唤醒阻塞中的 recvfrom，让端口立即释放
            self.sock.sendto(b"", _loopback(self.sock.getsockname()))
        except OSError:
            pass
        if self._thread:
            self._thread.join(timeout=1.0)
        try:
            self.sock.close()
        except OSError:
            pass


class TCPClientWorker(BaseWorker):
    """主动连接 TCP 服务端。"""

    def __init__(self, on_data, on_event, remote_host: str, remote_port: int):
        super().__init__(on_data, on_event)
        self.remote = (remote_host, remote_port)
        self.sock = None

    def start(self):
        self.sock = socket.create_connection(self.remote, timeout=5)
        self.sock.settimeout(0.5)
        threading.Thread(target=self._recv_loop, daemon=True).start()
        self.on_event(f"已连接到 {self.remote[0]}:{self.remote[1]}")

    def _recv_loop(self):
        src = f"{self.remote[0]}:{self.remote[1]}"
        while not self._stop.is_set():
            try:
                data = self.sock.recv(RECV_BUF)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                self.on_event("对方已断开连接")
                break
            self.on_data(src, data)

    def send(self, data: bytes):
        self.sock.sendall(data)

    def stop(self):
        super().stop()
        if self.sock:
            try:
                self.sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.sock.close()


class TCPServerWorker(BaseWorker):
    """监听本地端口，接受多客户端；send 时指定目标或广播。"""

    def __init__(self, on_data, on_event, local_host: str, local_port: int):
        super().__init__(on_data, on_event)
        self.local = (local_host, local_port)
        self.server = None
        self.clients = {}               # addr_str -> socket
        self._lock = threading.Lock()

    def start(self):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(self.local)
        self.server.listen(8)
        self.server.settimeout(0.5)
        threading.Thread(target=self._accept_loop, daemon=True).start()
        self.on_event(f"TCP Server 监听中 {self.local[0]}:{self.local[1]}")

    def _accept_loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            if self._stop.is_set():      # 被 stop() 的唤醒连接打断
                conn.close()
                break
            key = f"{addr[0]}:{addr[1]}"
            conn.settimeout(0.5)
            with self._lock:
                self.clients[key] = conn
            self.on_event(f"客户端接入 {key}")
            threading.Thread(target=self._client_loop, args=(key, conn),
                             daemon=True).start()

    def _client_loop(self, key: str, conn: socket.socket):
        while not self._stop.is_set():
            try:
                data = conn.recv(RECV_BUF)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            self.on_data(key, data)
        with self._lock:
            self.clients.pop(key, None)
        try:
            conn.close()
        except OSError:
            pass
        self.on_event(f"客户端断开 {key}")

    def client_keys(self):
        with self._lock:
            return list(self.clients.keys())

    def send(self, data: bytes, target: str = None):
        """target 为客户端地址串；None 或 '所有连接' 表示广播。"""
        with self._lock:
            items = list(self.clients.items())
        if not items:
            raise OSError("当前没有已连接的客户端")
        if target and target != "所有连接":
            items = [(k, v) for k, v in items if k == target]
            if not items:
                raise OSError(f"客户端 {target} 不存在")
        sent = 0
        for key, conn in items:
            try:
                conn.sendall(data)
                sent += 1
            except OSError:
                self.on_event(f"发送到 {key} 失败")
        return sent

    def stop(self):
        super().stop()
        if self.server:
            try:    # 连一下自己，唤醒阻塞中的 accept，让监听端口立即释放
                socket.create_connection(_loopback(self.server.getsockname()),
                                         timeout=0.5).close()
            except OSError:
                pass
            try:
                self.server.close()
            except OSError:
                pass
        with self._lock:
            conns = list(self.clients.values())
            self.clients.clear()
        for c in conns:
            try:
                c.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------
# GUI 层
# ---------------------------------------------------------------------------

class NetTesterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("TCP/UDP 网络测试工具")
        root.geometry("980x640")
        root.minsize(860, 560)

        self.worker: BaseWorker | None = None
        self.msg_queue: queue.Queue = queue.Queue()
        self._peers = []                 # UDP 模式下见过的来源地址

        # 统计
        self.tx_bytes = 0
        self.tx_pkts = 0
        self.rx_bytes = 0
        self.rx_pkts = 0
        self._last_rate_t = time.monotonic()
        self._last_tx = 0
        self._last_rx = 0

        self._timer_job = None

        self._build_ui()
        self._poll_queue()
        self._update_stats()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI 搭建 ----------------

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=6)
        main.pack(fill=tk.BOTH, expand=True)

        # 左侧设置面板
        left = ttk.LabelFrame(main, text=" 设置 ", padding=8)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))

        ttk.Label(left, text="工作模式").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.mode_var = tk.StringVar(value="TCP Server")
        self.mode_box = ttk.Combobox(left, textvariable=self.mode_var, state="readonly",
                                     values=["TCP Server", "TCP Client", "UDP"], width=14)
        self.mode_box.grid(row=1, column=0, columnspan=2, sticky=tk.EW, pady=2)
        self.mode_box.bind("<<ComboboxSelected>>", lambda _e: self._on_mode_change())

        ttk.Label(left, text="本地地址").grid(row=2, column=0, sticky=tk.W, pady=2)
        ips = detect_local_ips()
        self.local_host = ttk.Combobox(left, width=12, values=ips)
        self.local_host.set(ips[0])
        self.local_host.grid(row=3, column=0, sticky=tk.EW, pady=2)
        try:    # 下拉时刷新网卡地址（WiFi 切换等场景）
            self.local_host.config(postcommand=self._refresh_local_ips)
        except tk.TclError:
            pass
        self.local_port = ttk.Entry(left, width=7)
        self.local_port.insert(0, "9000")
        self.local_port.grid(row=3, column=1, sticky=tk.W, padx=(4, 0))

        ttk.Label(left, text="目标地址").grid(row=4, column=0, sticky=tk.W, pady=2)
        self.remote_host = ttk.Entry(left, width=12)
        self.remote_host.insert(0, "127.0.0.1")
        self.remote_host.grid(row=5, column=0, sticky=tk.EW, pady=2)
        self.remote_port = ttk.Entry(left, width=7)
        self.remote_port.insert(0, "9000")
        self.remote_port.grid(row=5, column=1, sticky=tk.W, padx=(4, 0))

        self.open_btn = ttk.Button(left, text="打开", command=self._toggle_open)
        self.open_btn.grid(row=6, column=0, columnspan=2, sticky=tk.EW, pady=(8, 2))

        self.client_lbl = ttk.Label(left, text="连接列表")
        self.client_lbl.grid(row=7, column=0, sticky=tk.W, pady=2)
        self.client_var = tk.StringVar(value="所有连接")
        self.client_box = ttk.Combobox(left, textvariable=self.client_var,
                                       state="readonly", values=["所有连接"], width=16)
        self.client_box.grid(row=8, column=0, columnspan=2, sticky=tk.EW, pady=2)
        self.client_box.bind("<<ComboboxSelected>>", self._on_client_pick)

        ttk.Separator(left).grid(row=9, column=0, columnspan=2, sticky=tk.EW, pady=8)

        self.stats_lbl = ttk.Label(left, text="发送: 0 B / 0 包\n接收: 0 B / 0 包",
                                   justify=tk.LEFT)
        self.stats_lbl.grid(row=10, column=0, columnspan=2, sticky=tk.W, pady=2)
        self.rate_lbl = ttk.Label(left, text="速率 ↑ 0 B/s  ↓ 0 B/s")
        self.rate_lbl.grid(row=11, column=0, columnspan=2, sticky=tk.W, pady=2)
        ttk.Button(left, text="统计清零", command=self._reset_stats).grid(
            row=12, column=0, columnspan=2, sticky=tk.EW, pady=(4, 0))

        left.columnconfigure(0, weight=1)

        # 右侧数据面板
        right = ttk.Frame(main)
        right.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 接收区
        rx_frame = ttk.LabelFrame(right, text=" 接收 ", padding=4)
        rx_frame.pack(fill=tk.BOTH, expand=True)
        self.rx_text = scrolledtext.ScrolledText(rx_frame, state=tk.DISABLED,
                                                 font=(MONO_FONT, 10), wrap=tk.NONE)
        self.rx_text.pack(fill=tk.BOTH, expand=True)

        rx_opt = ttk.Frame(rx_frame)
        rx_opt.pack(fill=tk.X, pady=(4, 0))
        self.rx_hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rx_opt, text="HEX 显示", variable=self.rx_hex_var).pack(side=tk.LEFT)
        self.rx_ts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rx_opt, text="时间戳", variable=self.rx_ts_var).pack(side=tk.LEFT, padx=6)
        self.rx_pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rx_opt, text="暂停显示", variable=self.rx_pause_var).pack(side=tk.LEFT)
        ttk.Button(rx_opt, text="清空", command=self._clear_rx).pack(side=tk.RIGHT)

        # 发送区
        tx_frame = ttk.LabelFrame(right, text=" 发送 ", padding=4)
        tx_frame.pack(fill=tk.X, pady=(6, 0))

        rand_row = ttk.Frame(tx_frame)
        rand_row.pack(fill=tk.X, pady=2)
        ttk.Label(rand_row, text="随机包大小").pack(side=tk.LEFT)
        self.rand_size = ttk.Entry(rand_row, width=8)
        self.rand_size.insert(0, "512")
        self.rand_size.pack(side=tk.LEFT, padx=4)
        ttk.Label(rand_row, text="字节").pack(side=tk.LEFT)
        self.rand_btn = ttk.Button(rand_row, text="发送随机包",
                                   command=lambda: self._send(random_pkt=True))
        self.rand_btn.pack(side=tk.LEFT, padx=10)

        ttk.Label(tx_frame, text="手动输入（填文本；勾选 HEX 发送则填十六进制，"
                                 "如 DE AD BE EF；Ctrl+Enter 快捷发送）:"
                  ).pack(anchor=tk.W, pady=(6, 0))
        self.tx_text = tk.Text(tx_frame, height=4, font=(MONO_FONT, 10))
        self.tx_text.pack(fill=tk.X, pady=2)
        self.tx_text.bind("<Control-Return>",
                          lambda _e: self._send(random_pkt=False))

        tx_opt = ttk.Frame(tx_frame)
        tx_opt.pack(fill=tk.X, pady=2)
        self.tx_hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tx_opt, text="HEX 发送", variable=self.tx_hex_var).pack(side=tk.LEFT)
        self.loop_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(tx_opt, text="定时发送", variable=self.loop_var,
                        command=self._toggle_loop).pack(side=tk.LEFT, padx=6)
        self.loop_ms = ttk.Entry(tx_opt, width=6)
        self.loop_ms.insert(0, "1000")
        self.loop_ms.pack(side=tk.LEFT)
        ttk.Label(tx_opt, text="ms").pack(side=tk.LEFT, padx=(2, 8))
        self.loop_rand_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(tx_opt, text="循环发随机包", variable=self.loop_rand_var).pack(side=tk.LEFT)
        self.send_btn = ttk.Button(tx_opt, text="发送",
                                   command=lambda: self._send(random_pkt=False))
        self.send_btn.pack(side=tk.RIGHT)

        # 状态栏
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN,
                  anchor=tk.W, padding=(6, 2)).pack(fill=tk.X, side=tk.BOTTOM)

        self._on_mode_change()

    # ---------------- 模式与连接管理 ----------------

    def _refresh_local_ips(self):
        cur = self.local_host.get()
        ips = detect_local_ips()
        self.local_host.config(values=ips)
        if cur and cur not in ips:         # 保留手动输入的地址
            self.local_host.config(values=ips + [cur])

    def _on_mode_change(self):
        mode = self.mode_var.get()
        is_server = mode == "TCP Server"
        is_client = mode == "TCP Client"
        # 服务器不需要目标地址；客户端不需要本地地址
        for w in (self.local_host, self.local_port):
            w.config(state=tk.DISABLED if is_client else tk.NORMAL)
        for w in (self.remote_host, self.remote_port):
            w.config(state=tk.DISABLED if is_server else tk.NORMAL)
        self.open_btn.config(text={"TCP Server": "开始监听", "TCP Client": "连接",
                                   "UDP": "打开"}[mode])
        if is_server:
            self.client_lbl.config(text="连接列表")
            self.client_box.config(state="readonly", values=["所有连接"])
            self.client_var.set("所有连接")
        elif mode == "UDP":
            # UDP 无连接，此框复用为"见过的来源地址"，点选即填入目标地址
            self.client_lbl.config(text="来源列表")
            self.client_box.config(state="readonly",
                                   values=["（手动目标）"] + self._peers)
            self.client_var.set("（手动目标）")
        else:
            self.client_lbl.config(text="连接列表")
            self.client_box.config(state=tk.DISABLED, values=[])
            self.client_var.set("")

    def _on_client_pick(self, _event=None):
        """UDP 模式：点选来源地址 -> 填入目标地址栏。"""
        if self.mode_var.get() != "UDP":
            return
        m = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)$", self.client_var.get())
        if m:
            for entry, val in ((self.remote_host, m.group(1)),
                               (self.remote_port, m.group(2))):
                entry.delete(0, tk.END)
                entry.insert(0, val)
            self.status_var.set(f"目标已设为 {m.group(0)}")

    def _add_peer(self, addr: str):
        if addr in self._peers:
            return
        self._peers.append(addr)
        if len(self._peers) > 50:
            self._peers = self._peers[-50:]
        if self.mode_var.get() == "UDP":
            self.client_box.config(values=["（手动目标）"] + self._peers)

    def _toggle_open(self):
        if self.worker:
            self._close_worker()
        else:
            self._open_worker()

    def _open_worker(self):
        mode = self.mode_var.get()
        try:
            if mode == "UDP":
                w = UDPWorker(self._q_data, self._q_event,
                              self.local_host.get().strip(),
                              int(self.local_port.get()),
                              self.remote_host.get().strip(),
                              int(self.remote_port.get()))
            elif mode == "TCP Client":
                w = TCPClientWorker(self._q_data, self._q_event,
                                    self.remote_host.get().strip(),
                                    int(self.remote_port.get()))
            else:
                w = TCPServerWorker(self._q_data, self._q_event,
                                    self.local_host.get().strip(),
                                    int(self.local_port.get()))
            w.start()
        except (ValueError, OSError) as e:
            msg = str(e)
            if isinstance(e, OSError) and e.errno == errno.EADDRINUSE:
                msg += "\n\n" + self._port_owner_hint(self.local_port.get())
            messagebox.showerror("打开失败", msg)
            self.status_var.set(f"错误: {e}")
            return
        self.worker = w
        self.open_btn.config(text="关闭")
        self.mode_box.config(state=tk.DISABLED)
        self.status_var.set(f"{mode} 运行中")

    @staticmethod
    def _port_owner_hint(port: str) -> str:
        """查出占用该端口的进程，附在报错后面。"""
        if IS_WIN:
            return (f"端口 {port} 已被占用。\n命令行执行  netstat -ano -p udp | findstr {port}  "
                    f"可查到占用进程的 PID。")
        try:
            out = subprocess.check_output(
                ["ss", "-ulpn"], text=True, timeout=3, stderr=subprocess.DEVNULL)
            for ln in out.splitlines():
                if f":{port}" not in ln:
                    continue
                m = re.search(r'users:\(\("([^"]+)",pid=(\d+)', ln)
                if m:
                    return (f"端口 {port} 被进程 {m.group(1)} (PID {m.group(2)}) 占用。\n"
                            f"可换个端口，或先关闭对应程序/窗口。")
                return (f"端口 {port} 被其他用户/root 进程占用（无权查看属主）。\n"
                        f"可执行  pkexec ss -ulpn | grep {port}  查看，或换个端口。")
        except (OSError, subprocess.SubprocessError):
            pass
        return f"端口 {port} 已被占用，可执行  ss -ulpn | grep {port}  查看占用进程。"

    def _close_worker(self):
        self.loop_var.set(False)
        self._toggle_loop()
        w, self.worker = self.worker, None
        if w:
            w.stop()
        self.open_btn.config(text="打开")
        self.mode_box.config(state="readonly")
        self._peers.clear()
        self._on_mode_change()
        self.status_var.set("已关闭")
        self._log_event("--- 连接已关闭 ---")

    # ---------------- 队列 <-> GUI ----------------

    def _q_data(self, source, data):
        self.msg_queue.put(("data", source, data))

    def _q_event(self, text):
        self.msg_queue.put(("event", text, None))

    def _poll_queue(self):
        buf = []                       # 批量拼接，每 50ms 只插一次，抗高包速
        try:
            while True:
                kind, a, b = self.msg_queue.get_nowait()
                if kind == "data":
                    self.rx_bytes += len(b)
                    self.rx_pkts += 1
                    if isinstance(self.worker, UDPWorker):
                        self._add_peer(a)
                    if not self.rx_pause_var.get():
                        buf.append(self._fmt_rx(a, b))
                else:
                    self.status_var.set(a)
                    buf.append(self._fmt_event(a))
        except queue.Empty:
            pass
        if buf:
            self._append_rx("".join(buf))
        if isinstance(self.worker, TCPServerWorker):
            self._refresh_client_list(self.worker.client_keys())
        self.root.after(50, self._poll_queue)

    def _ts(self):
        return time.strftime("[%H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}] " \
            if self.rx_ts_var.get() else ""

    def _fmt_rx(self, source: str, data: bytes):
        body = format_hex(data) if self.rx_hex_var.get() else data.decode("utf-8", "replace")
        return f"{self._ts()}[{source}] ({len(data)} 字节)\n{body}\n"

    def _fmt_event(self, text: str):
        return f"{self._ts()}* {text}\n"

    def _log_event(self, text: str):
        self._append_rx(self._fmt_event(text))
        self.status_var.set(text)

    def _append_rx(self, text: str):
        t = self.rx_text
        t.config(state=tk.NORMAL)
        t.insert(tk.END, text)
        if int(t.index("end-1c").split(".")[0]) > MAX_RX_LINES:
            t.delete("1.0", f"{MAX_RX_LINES // 2}.0")
        t.see(tk.END)
        t.config(state=tk.DISABLED)

    def _clear_rx(self):
        self.rx_text.config(state=tk.NORMAL)
        self.rx_text.delete("1.0", tk.END)
        self.rx_text.config(state=tk.DISABLED)

    def _refresh_client_list(self, keys):
        values = ["所有连接"] + keys
        cur = self.client_var.get()
        self.client_box.config(values=values)
        if cur not in values:
            self.client_var.set("所有连接")

    # ---------------- 发送 ----------------

    def _get_payload(self, random_pkt: bool) -> bytes:
        if random_pkt:
            size = int(self.rand_size.get())
            if size <= 0:
                raise ValueError("包大小必须为正整数")
            return os.urandom(min(size, 16 * 1024 * 1024))
        text = self.tx_text.get("1.0", tk.END).rstrip("\n")
        if self.tx_hex_var.get():
            return parse_hex(text)
        return text.encode("utf-8")

    def _send(self, random_pkt: bool) -> bool:
        if not self.worker:
            self.status_var.set("请先打开连接")
            return False
        try:
            payload = self._get_payload(random_pkt)
            if not payload:
                self.status_var.set("发送内容为空")
                return False
            if isinstance(self.worker, TCPServerWorker):
                self.worker.send(payload, self.client_var.get())
            else:
                if isinstance(self.worker, UDPWorker):
                    # 发送前同步目标地址（点选来源列表/手改后无需重开）
                    self.worker.target = (self.remote_host.get().strip(),
                                          int(self.remote_port.get()))
                self.worker.send(payload)
        except (ValueError, OSError) as e:
            self.status_var.set(f"发送失败: {e}")
            return False
        self.tx_bytes += len(payload)
        self.tx_pkts += 1
        tag = "随机包" if random_pkt else "数据"
        self.status_var.set(f"已发送{tag} {len(payload)} 字节")
        return True

    # ---------------- 定时发送 ----------------

    def _toggle_loop(self):
        if self._timer_job:
            self.root.after_cancel(self._timer_job)
            self._timer_job = None
        if self.loop_var.get():
            self._loop_tick()

    def _loop_tick(self):
        if not self.loop_var.get():
            return
        if not self._send(random_pkt=self.loop_rand_var.get()):
            self.loop_var.set(False)   # 发送失败自动停止
            return
        try:
            interval = max(10, int(self.loop_ms.get()))
        except ValueError:
            interval = 1000
        self._timer_job = self.root.after(interval, self._loop_tick)

    # ---------------- 统计 ----------------

    def _reset_stats(self):
        self.tx_bytes = self.tx_pkts = self.rx_bytes = self.rx_pkts = 0
        self._last_tx = self._last_rx = 0

    def _update_stats(self):
        now = time.monotonic()
        dt = now - self._last_rate_t
        if dt >= 1.0:
            tx_rate = (self.tx_bytes - self._last_tx) / dt
            rx_rate = (self.rx_bytes - self._last_rx) / dt
            self.rate_lbl.config(
                text=f"速率 ↑ {pretty_bytes(tx_rate)}/s  ↓ {pretty_bytes(rx_rate)}/s")
            self._last_rate_t = now
            self._last_tx = self.tx_bytes
            self._last_rx = self.rx_bytes
        self.stats_lbl.config(
            text=f"发送: {pretty_bytes(self.tx_bytes)} / {self.tx_pkts} 包\n"
                 f"接收: {pretty_bytes(self.rx_bytes)} / {self.rx_pkts} 包")
        self.root.after(500, self._update_stats)

    # ---------------- 退出 ----------------

    def _on_close(self):
        self.loop_var.set(False)
        if self._timer_job:
            self.root.after_cancel(self._timer_job)
        if self.worker:
            self.worker.stop()
        self.root.destroy()


def main():
    if tk is None:
        raise SystemExit("未找到 tkinter，请先安装: sudo apt install python3-tk")
    import argparse
    p = argparse.ArgumentParser(description="TCP/UDP 网络测试工具")
    p.add_argument("--mode", choices=["TCP Server", "TCP Client", "UDP"])
    p.add_argument("--local-host"); p.add_argument("--local-port", type=int)
    p.add_argument("--remote-host"); p.add_argument("--remote-port", type=int)
    p.add_argument("--open", action="store_true", help="启动后立即打开连接")
    args = p.parse_args()

    def set_entry(entry, val):
        entry.delete(0, tk.END)
        entry.insert(0, str(val))

    root = tk.Tk()
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:
        pass
    gui = NetTesterGUI(root)
    if args.mode:
        gui.mode_var.set(args.mode)
        gui._on_mode_change()
    if args.local_host:
        set_entry(gui.local_host, args.local_host)
    if args.local_port:
        set_entry(gui.local_port, args.local_port)
    if args.remote_host:
        set_entry(gui.remote_host, args.remote_host)
    if args.remote_port:
        set_entry(gui.remote_port, args.remote_port)
    if args.open:
        root.after(100, gui._open_worker)
    root.mainloop()


if __name__ == "__main__":
    main()
