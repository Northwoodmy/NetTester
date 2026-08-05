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
    from tkinter import font as tkfont
except ModuleNotFoundError:                 # 允许无 GUI 环境仅使用网络层
    tk = None

# ---------------------------------------------------------------------------
# 工具函数
# ---------------------------------------------------------------------------

UDP_MAX_PAYLOAD = 65507          # UDP 数据报最大载荷
RECV_BUF = 65536
MAX_RX_LINES = 2000              # 接收区最大行数，超出裁剪
MAX_CONVO_MSGS = 2000            # 每个会话最多保存的消息条数
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
    """主动连接多个 TCP 服务端；每个连接 = 一个会话，send 时指定目标。"""

    def __init__(self, on_data, on_event):
        super().__init__(on_data, on_event)
        self.conns = {}                 # addr_str -> socket
        self._lock = threading.Lock()

    def start(self):
        # 无需绑定/监听；连接通过 connect() 按需发起
        self.on_event("TCP Client 已就绪，添加目标即连接服务器")

    def connect(self, host: str, port: int) -> str:
        key = f"{host}:{port}"
        with self._lock:
            old = self.conns.pop(key, None)     # 重连同目标：先关旧连接
        if old:
            try:
                old.close()
            except OSError:
                pass
        sock = socket.create_connection((host, port), timeout=5)
        sock.settimeout(0.5)
        with self._lock:
            self.conns[key] = sock
        self.on_event(f"已连接到 {key}")
        threading.Thread(target=self._conn_loop, args=(key, sock),
                         daemon=True).start()
        return key

    def _conn_loop(self, key: str, sock: socket.socket):
        while not self._stop.is_set():
            try:
                data = sock.recv(RECV_BUF)
            except socket.timeout:
                continue
            except OSError:
                break
            if not data:
                break
            self.on_data(key, data)
        with self._lock:
            self.conns.pop(key, None)
        try:
            sock.close()
        except OSError:
            pass
        self.on_event(f"连接已断开 {key}")

    def conn_keys(self):
        with self._lock:
            return list(self.conns.keys())

    def send(self, data: bytes, target: str):
        with self._lock:
            sock = self.conns.get(target)
        if not sock:
            raise OSError(f"连接 {target} 不存在或已断开，可重新添加该会话")
        sock.sendall(data)

    def stop(self):
        super().stop()
        with self._lock:
            conns = list(self.conns.values())
            self.conns.clear()
        for s in conns:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()


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
# Google Material 浅色主题
# ---------------------------------------------------------------------------

PALETTE = {
    "bg":           "#F8F9FA",   # 主背景（Google 浅灰）
    "surface":      "#F1F3F4",   # 按钮/控件
    "field":        "#FFFFFF",   # 输入框/文本区
    "fg":           "#202124",   # 主文字
    "subtle":       "#5F6368",   # 次要文字
    "accent":       "#1A73E8",   # Google 蓝
    "accent_hi":    "#1967D2",
    "accent_press": "#174EA6",
    "green":        "#188038",   # Google 绿
    "green_hi":     "#1E8E3E",
    "green_press":  "#137333",
    "orange":       "#E8710A",   # Google 橙
    "border":       "#DADCE0",
    "select":       "#D2E3FC",
    "disabled_bg":  "#F1F3F4",
    "disabled_fg":  "#9AA0A6",
}
WINDOW_ALPHA = 1.0               # 浅色主题不用半透明


def _win_glass(root):
    """Windows 11 毛玻璃：Mica 背景（跟随系统明暗）。"""
    try:
        import ctypes
        hwnd = ctypes.windll.user32.GetAncestor(root.winfo_id(), 2)   # GA_ROOT
        dwm = ctypes.windll.dwmapi
        dwm.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(0)), 4)  # 浅色标题栏
        dwm.DwmSetWindowAttribute(hwnd, 38, ctypes.byref(ctypes.c_int(2)), 4)  # Mica
    except Exception:
        pass


def apply_modern_theme(root):
    p = PALETTE
    ui_font = "Segoe UI" if IS_WIN else "Noto Sans CJK SC"
    try:
        from tkinter import font as tkfont
        for name in ("TkDefaultFont", "TkTextFont", "TkMenuFont", "TkHeadingFont"):
            tkfont.nametofont(name).configure(family=ui_font, size=10)
    except tk.TclError:
        pass
    root.configure(bg=p["bg"])
    s = ttk.Style(root)
    try:
        s.theme_use("clam")
    except tk.TclError:
        pass

    s.configure(".", background=p["bg"], foreground=p["fg"],
                fieldbackground=p["field"], bordercolor=p["bg"],
                troughcolor=p["surface"], focuscolor=p["accent"])
    s.configure("TFrame", background=p["bg"])
    s.configure("TLabel", background=p["bg"], foreground=p["fg"])

    # 分区彩色标题（Google 蓝/绿/橙）
    s.configure("TLabelframe", background=p["bg"], bordercolor=p["border"])
    for name, color in (("Blue", p["accent"]), ("Green", p["green"]),
                        ("Orange", p["orange"])):
        s.configure(f"{name}.TLabelframe", background=p["bg"],
                    bordercolor=p["border"])
        s.configure(f"{name}.TLabelframe.Label", background=p["bg"],
                    foreground=color, font=(ui_font, 10, "bold"))

    # 普通按钮：Material 描边按钮 —— 白底灰框蓝字，与背景区分开
    s.configure("TButton", background="#FFFFFF", foreground=p["accent"],
                bordercolor=p["border"], borderwidth=1,
                padding=(16, 7), focusthickness=0)
    s.map("TButton",
          background=[("active", "#F1F3F4"), ("pressed", p["select"]),
                      ("disabled", p["disabled_bg"])],
          foreground=[("disabled", p["disabled_fg"])],
          bordercolor=[("active", p["subtle"]), ("disabled", p["border"])])
    s.configure("Accent.TButton", background=p["accent"], foreground="#FFFFFF",
                borderwidth=0, font=(ui_font, 10, "bold"))
    s.map("Accent.TButton",
          background=[("active", p["accent_hi"]), ("pressed", p["accent_press"]),
                      ("disabled", p["disabled_bg"])],
          foreground=[("disabled", p["disabled_fg"])])
    s.configure("Green.TButton", background=p["green"], foreground="#FFFFFF",
                borderwidth=0, font=(ui_font, 10, "bold"))
    s.map("Green.TButton",
          background=[("active", p["green_hi"]), ("pressed", p["green_press"]),
                      ("disabled", p["disabled_bg"])],
          foreground=[("disabled", p["disabled_fg"])])
    # 输入框：Material 文本框 —— 白底灰描边，聚焦描边变蓝
    s.configure("TEntry", fieldbackground=p["field"], foreground=p["fg"],
                insertcolor=p["fg"], bordercolor=p["border"],
                lightcolor=p["field"], darkcolor=p["field"], padding=6)
    s.map("TEntry",
          fieldbackground=[("disabled", p["disabled_bg"])],
          foreground=[("disabled", p["disabled_fg"])],
          bordercolor=[("focus", p["accent"]), ("active", p["subtle"])])
    # 下拉框：白底 + 箭头悬停加深，文字与箭头间留白
    s.configure("TCombobox", fieldbackground=p["field"], foreground=p["fg"],
                background=p["field"], arrowcolor=p["subtle"], arrowsize=13,
                bordercolor=p["border"], lightcolor=p["field"],
                darkcolor=p["field"], padding=(6, 6, 20, 6))
    s.map("TCombobox",
          fieldbackground=[("readonly", p["field"]), ("disabled", p["disabled_bg"])],
          foreground=[("readonly", p["fg"]), ("disabled", p["disabled_fg"])],
          bordercolor=[("focus", p["accent"]), ("active", p["subtle"])],
          arrowcolor=[("active", p["fg"]), ("disabled", p["disabled_fg"])])
    # 下拉弹层：扁平无描边，选中项浅蓝底深蓝字，无虚线框
    root.option_add("*TCombobox*Listbox.background", p["field"])
    root.option_add("*TCombobox*Listbox.foreground", p["fg"])
    root.option_add("*TCombobox*Listbox.selectBackground", p["select"])
    root.option_add("*TCombobox*Listbox.selectForeground", p["accent_press"])
    root.option_add("*TCombobox*Listbox.borderWidth", 0)
    root.option_add("*TCombobox*Listbox.highlightThickness", 0)
    root.option_add("*TCombobox*Listbox.relief", "flat")
    root.option_add("*TCombobox*Listbox.activeStyle", "none")
    # 复选框：Material 蓝底白勾（Tk 8.6 clam 只认 indicatorbackground /
    # indicatorforeground / upper/lowerbordercolor，不认 indicatorcolor）
    s.configure("TCheckbutton", background=p["bg"], foreground=p["fg"],
                indicatorsize=16,
                indicatorbackground="#FFFFFF", indicatorforeground="#FFFFFF",
                upperbordercolor=p["border"], lowerbordercolor=p["border"],
                indicatormargin=(0, 6, 0, 0))
    s.map("TCheckbutton",
          background=[("active", p["bg"])],
          indicatorbackground=[("pressed", p["accent_press"]),
                               ("selected", p["accent"]),
                               ("active", "#E8F0FE"),
                               ("!selected", "#FFFFFF")],
          upperbordercolor=[("selected", p["accent"]), ("active", p["subtle"]),
                            ("!selected", p["border"])],
          lowerbordercolor=[("selected", p["accent"]), ("active", p["subtle"]),
                            ("!selected", p["border"])])
    s.configure("TSeparator", background=p["border"])
    s.configure("Vertical.TScrollbar", background=p["border"], troughcolor=p["bg"],
                bordercolor=p["bg"], arrowcolor=p["subtle"], arrowsize=12)
    s.map("Vertical.TScrollbar",
          background=[("active", "#BDC1C6"), ("pressed", p["disabled_fg"])])
    s.configure("Status.TLabel", background=p["surface"], foreground=p["subtle"])

    # Windows 毛玻璃；Linux/X11 半透明（浅色主题默认关闭）
    if IS_WIN:
        _win_glass(root)
    elif WINDOW_ALPHA < 1.0:
        try:
            root.attributes("-alpha", WINDOW_ALPHA)
        except tk.TclError:
            pass


TEXT_STYLE = dict(bg="#FFFFFF", fg="#202124", insertbackground="#202124",
                  selectbackground="#D2E3FC", relief="flat", padx=8, pady=6,
                  highlightthickness=1, highlightbackground="#DADCE0",
                  highlightcolor="#1A73E8")


# ---------------------------------------------------------------------------
# GUI 层
# ---------------------------------------------------------------------------

class NetTesterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("TCP/UDP 网络测试工具")

        self.channels = {}               # 通道 cid -> worker；cid = 协议:地址:端口
        self.msg_queue: queue.Queue = queue.Queue()
        self._local_ips = set()          # 本机 IP 缓存（"忽略本机来源"用）

        # 会话（类微信：每个对端地址 = 一个联系人，各自一份聊天记录）
        # 会话挂在通道上：ckey = f"{cid}|{对端}"，"|*" 为该通道的群发会话。
        # 不同会话可属于不同协议、不同端口的通道。
        self._convos = {}                # ckey -> [(direction, data, time), ...]
        self._convo_keys = []            # 联系人列表行对应的 ckey
        self._unread = {}                # ckey -> 未读条数
        self._cstats = {}                # ckey -> [tx字节, tx包数, rx字节, rx包数]
        self._crate = {}                 # ckey -> [时间, tx字节, rx字节]（速率基线）
        self._drafts = {}                # ckey -> (输入框文本, HEX发送勾选)
        self.current_peer = None         # 当前选中的会话 ckey
        self._cli_cfg = {}               # CLI 参数（--open 建会话 & 对话框预填）
        self._last_visible = None        # 联系人列表变化检测缓存

        # 统计（全局总计；各会话的明细在 _cstats）
        self.tx_bytes = 0
        self.tx_pkts = 0
        self.rx_bytes = 0
        self.rx_pkts = 0

        self._timer_job = None
        self._loop_ckey = None           # 定时发送锁定的会话

        self._build_ui()
        # 按内容实际所需尺寸开窗（不同平台/字体下都不会裁掉控件）
        root.update_idletasks()
        root.geometry(f"{max(940, root.winfo_reqwidth())}x"
                      f"{max(600, root.winfo_reqheight())}")
        root.minsize(820, 480)
        self._poll_queue()
        self._update_stats()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI 搭建 ----------------

    def _build_ui(self):
        self._ui_font = "Segoe UI" if IS_WIN else "Noto Sans CJK SC"

        # 底部状态栏：仅状态文字（统计已并入各会话）
        status = ttk.Frame(self.root, padding=(8, 3))
        status.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel",
                  anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)

        main = ttk.Frame(self.root, padding=6)
        main.pack(fill=tk.BOTH, expand=True)

        # 左栏：会话联系人列表 + 发起新会话按钮（类微信）
        # 列表宽度按最长条目自适应（_fit_contact_width），无需横向滚动条
        contact_col = ttk.Frame(main)
        contact_col.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        self.contact_list = tk.Listbox(
            contact_col, width=22, bg="#FFFFFF", fg=PALETTE["fg"],
            selectbackground=PALETTE["select"],
            selectforeground=PALETTE["accent_press"],
            relief="flat", highlightthickness=1,
            highlightbackground=PALETTE["border"],
            highlightcolor=PALETTE["accent"],
            activestyle="none", exportselection=False)
        self.contact_list.pack(fill=tk.BOTH, expand=True)
        self.contact_list.bind("<<ListboxSelect>>", self._on_contact_pick)
        self.contact_list.bind("<Button-3>", self._on_contact_menu)
        ttk.Button(contact_col, text="＋ 发起新会话", style="Accent.TButton",
                   command=self._show_new_session_dialog).pack(fill=tk.X,
                                                               pady=(4, 0))
        ttk.Separator(main, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y,
                                                     padx=(0, 6))

        # 右栏对话面板：顶部标题+显示选项，中间气泡，底部输入区
        conv_col = ttk.Frame(main)
        conv_col.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # —— 底部输入区先按底打包（窗口变矮时优先保住，不被气泡区挤掉）——
        tx_opt = ttk.Frame(conv_col)
        tx_opt.pack(side=tk.BOTTOM, fill=tk.X, pady=(2, 0))
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
        self.send_btn = ttk.Button(tx_opt, text="发送", style="Accent.TButton",
                                   command=lambda: self._send(random_pkt=False))
        self.send_btn.pack(side=tk.RIGHT)

        self.tx_text = tk.Text(conv_col, height=4, font=(MONO_FONT, 10), **TEXT_STYLE)
        self.tx_text.pack(side=tk.BOTTOM, fill=tk.X, pady=2)
        self.tx_text.bind("<Control-Return>",
                          lambda _e: self._send(random_pkt=False))

        ui_font = "Segoe UI" if IS_WIN else "Noto Sans CJK SC"
        ttk.Label(conv_col, text="输入文本（HEX 发送则填十六进制，"
                                 "如 DE AD BE EF；Ctrl+Enter 发送）",
                  font=(ui_font, 8),
                  foreground=PALETTE["subtle"]).pack(side=tk.BOTTOM, anchor=tk.W)

        rand_row = ttk.Frame(conv_col)
        rand_row.pack(side=tk.BOTTOM, fill=tk.X, pady=(4, 2))
        ttk.Label(rand_row, text="随机包大小").pack(side=tk.LEFT)
        self.rand_size = ttk.Entry(rand_row, width=8)
        self.rand_size.insert(0, "512")
        self.rand_size.pack(side=tk.LEFT, padx=4)
        ttk.Label(rand_row, text="字节").pack(side=tk.LEFT)
        self.rand_btn = ttk.Button(rand_row, text="发送随机包", style="Green.TButton",
                                   command=lambda: self._send(random_pkt=True))
        self.rand_btn.pack(side=tk.LEFT, padx=10)

        # —— 顶部：当前会话标题 + 会话统计行 + 显示选项工具条 ——
        self.convo_title = ttk.Label(conv_col, text="未选择会话",
                                     font=(self._ui_font, 11, "bold"))
        self.convo_title.pack(fill=tk.X, pady=(0, 2))

        convo_stats_row = ttk.Frame(conv_col)
        convo_stats_row.pack(fill=tk.X, pady=(0, 2))
        self.convo_stats_tx = tk.Label(convo_stats_row, text="↑ 0 B / 0 包",
                                       fg=PALETTE["accent"], bg=PALETTE["bg"],
                                       font=(self._ui_font, 9))
        self.convo_stats_tx.pack(side=tk.LEFT)
        self.convo_stats_rx = tk.Label(convo_stats_row, text="↓ 0 B / 0 包",
                                       fg=PALETTE["green"], bg=PALETTE["bg"],
                                       font=(self._ui_font, 9))
        self.convo_stats_rx.pack(side=tk.LEFT, padx=(10, 0))
        self.convo_rate = ttk.Label(convo_stats_row, text="↑ 0 B/s ↓ 0 B/s",
                                    font=(self._ui_font, 9),
                                    foreground=PALETTE["subtle"])
        self.convo_rate.pack(side=tk.LEFT, padx=(10, 0))
        ttk.Button(convo_stats_row, text="清零", width=4,
                   command=self._reset_stats).pack(side=tk.RIGHT)

        rx_opt = ttk.Frame(conv_col)
        rx_opt.pack(fill=tk.X, pady=(0, 2))
        self.rx_hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rx_opt, text="HEX 显示", variable=self.rx_hex_var,
                        command=self._rerender).pack(side=tk.LEFT)
        self.rx_ts_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rx_opt, text="时间戳", variable=self.rx_ts_var,
                        command=self._rerender).pack(side=tk.LEFT, padx=6)
        self.rx_pause_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rx_opt, text="暂停显示", variable=self.rx_pause_var).pack(side=tk.LEFT)
        self.rx_ignore_local_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(rx_opt, text="忽略本机来源",
                        variable=self.rx_ignore_local_var,
                        command=self._refresh_ignore_cache).pack(side=tk.LEFT, padx=6)
        ttk.Button(rx_opt, text="清空", command=self._clear_rx).pack(side=tk.RIGHT)

        # —— 中间气泡聊天记录 ——
        self.rx_text = scrolledtext.ScrolledText(
            conv_col, state=tk.DISABLED, font=(MONO_FONT, 10), wrap=tk.CHAR,
            height=12, **{**TEXT_STYLE, "bg": "#F5F5F5"})
        self.rx_text.pack(fill=tk.BOTH, expand=True)
        t = self.rx_text
        # 气泡：收到=左白，发出=右绿（微信配色）；meta=灰小字；sys=居中灰字
        t.tag_configure("rx", background="#FFFFFF", lmargin1=6, lmargin2=6,
                        rmargin=90, justify=tk.LEFT, spacing3=2)
        t.tag_configure("tx", background="#95EC69", lmargin1=90, rmargin=6,
                        justify=tk.RIGHT, spacing3=2)
        t.tag_configure("rx_meta", foreground="#9AA0A6", font=(ui_font, 8),
                        lmargin1=6, justify=tk.LEFT, spacing1=8)
        t.tag_configure("tx_meta", foreground="#9AA0A6", font=(ui_font, 8),
                        rmargin=6, justify=tk.RIGHT, spacing1=8)
        t.tag_configure("sys", foreground="#9AA0A6", font=(ui_font, 8),
                        justify=tk.CENTER, spacing1=6)

        self._refresh_contacts()

    # ---------------- 通道管理（多通道并存：协议 + 本地端口） ----------------

    @staticmethod
    def _cid(proto: str, host: str, port) -> str:
        return f"{proto}:{host}:{port}"

    @staticmethod
    def _cid_tag(cid: str) -> str:
        proto, _h, p = cid.split(":", 2)
        return {"udp": f"UDP·{p}", "tcps": f"TCP·{p}", "tcpc": "TCP"}[proto]

    @staticmethod
    def _peer_of(ckey: str) -> str:
        return ckey.rsplit("|", 1)[1]

    @staticmethod
    def _chan_of(ckey: str) -> str:
        return ckey.rsplit("|", 1)[0]

    def _display(self, ckey: str) -> str:
        """联系人显示名：对端 [协议·端口]；通道已关闭则标注。"""
        cid, peer = ckey.rsplit("|", 1)
        tag = self._cid_tag(cid)
        if cid not in self.channels:
            tag += "·已关闭"
        return f"（群发）[{tag}]" if peer == "*" else f"{peer} [{tag}]"

    # ---------------- 发起新会话（对话框：协议 + 地址 + 端口） ----------------

    def _create_session(self, proto: str, lhost: str = "", lport: str = "",
                        thost: str = "", tport: str = "") -> bool:
        """统一建会话入口（对话框 / CLI / 测试共用）。

        proto: udp=绑定本地端口收发（thost 可留空仅监听，也可逗号分隔多个
        目标、共用 tport）；tcps=本地监听；tcpc=连接目标服务器。"""
        try:
            if proto == "tcpc":
                ckey = self._connect_tcp_client(thost, int(tport))
                if not ckey:
                    return False                # 连接失败，状态栏已提示
                self._select_convo(ckey)
                return True
            cid = self._open_channel(proto, lhost, str(int(lport)))
            if not cid:
                return False                    # 打开失败，错误已弹窗
            if proto == "udp" and thost:
                last = None
                for h in re.split(r"[,，;；\s]+", thost):
                    if h:
                        last = f"{cid}|{h}:{int(tport)}"
                        self._ensure_convo(last)
                if last:
                    self._select_convo(last)
                    return True
            self._select_convo(f"{cid}|*")      # 无目标：选中该通道群发项
            return True
        except (ValueError, OSError) as e:
            self.status_var.set(f"发起会话失败: {e}")
            return False

    def _show_new_session_dialog(self):
        """发起新会话对话框：协议 + 本地/目标地址端口，按协议启用对应字段。"""
        if getattr(self, "_dlg", None) is not None:
            try:
                if self._dlg.winfo_exists():
                    self._dlg.lift()            # 已打开则提到前面
                    return
            except tk.TclError:
                pass
        cfg = self._cli_cfg                     # CLI 参数作为默认值预填
        dlg = tk.Toplevel(self.root)
        self._dlg = dlg
        dlg.title("发起新会话")
        dlg.transient(self.root)
        dlg.resizable(False, False)
        body = ttk.Frame(dlg, padding=14)
        body.pack(fill=tk.BOTH, expand=True)

        ips = detect_local_ips()
        th_def, _, tp_def = (cfg.get("target") or "").rpartition(":")
        pvar = tk.StringVar(value=cfg.get("mode") or "UDP")

        ttk.Label(body, text="协议").grid(row=0, column=0, sticky=tk.W, pady=3)
        pbox = ttk.Combobox(body, textvariable=pvar, state="readonly",
                            values=["UDP", "TCP Server", "TCP Client"], width=12)
        pbox.grid(row=0, column=1, sticky=tk.W, pady=3)

        ttk.Label(body, text="本地地址").grid(row=1, column=0, sticky=tk.W, pady=3)
        lh = ttk.Combobox(body, values=ips, width=16)
        lh.set(cfg.get("lhost") or ips[0])
        lh.grid(row=1, column=1, sticky=tk.EW, pady=3)
        ttk.Label(body, text="本地端口").grid(row=2, column=0, sticky=tk.W, pady=3)
        lp = ttk.Entry(body, width=8)
        lp.insert(0, str(cfg.get("lport") or "9000"))
        lp.grid(row=2, column=1, sticky=tk.W, pady=3)

        ttk.Label(body, text="目标地址").grid(row=3, column=0, sticky=tk.W, pady=3)
        th = ttk.Entry(body, width=18)
        th.insert(0, th_def)
        th.grid(row=3, column=1, sticky=tk.EW, pady=3)
        ttk.Label(body, text="目标端口").grid(row=4, column=0, sticky=tk.W, pady=3)
        tp = ttk.Entry(body, width=8)
        if tp_def:
            tp.insert(0, tp_def)
        tp.grid(row=4, column=1, sticky=tk.W, pady=3)

        hint = ttk.Label(body, font=(self._ui_font, 8),
                         foreground=PALETTE["subtle"], justify=tk.LEFT)
        hint.grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=(2, 0))
        err = tk.StringVar()
        tk.Label(body, textvariable=err, fg="#D93025", bg=PALETTE["bg"],
                 anchor=tk.W, justify=tk.LEFT, wraplength=260).grid(
            row=6, column=0, columnspan=2, sticky=tk.EW)

        btns = ttk.Frame(body)
        btns.grid(row=7, column=0, columnspan=2, sticky=tk.E, pady=(10, 0))
        ttk.Button(btns, text="取消",
                   command=dlg.destroy).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(btns, text="确定", style="Accent.TButton",
                   command=lambda: self._dlg_confirm(
                       dlg, pvar, lh, lp, th, tp, err)).pack(side=tk.RIGHT)

        def sync_fields(*_):
            """按协议启用/禁用本地与目标字段，并更新提示。"""
            mode = pvar.get()
            st_local = tk.DISABLED if mode == "TCP Client" else tk.NORMAL
            lh.config(state=st_local)
            lp.config(state=st_local)
            st_tgt = tk.DISABLED if mode == "TCP Server" else tk.NORMAL
            th.config(state=st_tgt)
            tp.config(state=st_tgt)
            hint.config(text={
                "UDP": "绑定本地地址收发 UDP；目标可留空（仅监听），\n"
                       "多个目标用逗号分隔，共用同一目标端口",
                "TCP Server": "在本地地址监听，等待客户端连入",
                "TCP Client": "主动连接目标服务器（目标必填）"}[mode])
        pbox.bind("<<ComboboxSelected>>", sync_fields)
        sync_fields()

        dlg.bind("<Return>", lambda _e: self._dlg_confirm(
            dlg, pvar, lh, lp, th, tp, err))
        dlg.bind("<Escape>", lambda _e: dlg.destroy())
        dlg.update_idletasks()
        rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
        dlg.geometry(f"+{rx + (self.root.winfo_width() - dlg.winfo_reqwidth()) // 2}"
                     f"+{ry + (self.root.winfo_height() - dlg.winfo_reqheight()) // 2}")
        dlg.grab_set()                          # 模态
        pbox.focus_set()

    def _dlg_confirm(self, dlg, pvar, lh, lp, th, tp, err):
        """对话框确定：校验通过后调 _create_session，失败红字提示不关闭。"""
        proto = {"UDP": "udp", "TCP Server": "tcps",
                 "TCP Client": "tcpc"}[pvar.get()]
        lhost, lport = lh.get().strip(), lp.get().strip()
        thost, tport = th.get().strip(), tp.get().strip()

        def bad(msg):
            err.set(msg)
        if proto != "tcpc":
            if not lhost:
                return bad("请填写本地地址")
            if not lport.isdigit() or not 0 < int(lport) < 65536:
                return bad("本地端口应为 1-65535 的数字")
        if proto == "tcpc" and (not thost or not tport):
            return bad("TCP Client 需要填写目标地址和端口")
        if proto == "udp" and thost and not tport:
            return bad("填写了目标地址，请同时填写目标端口")
        if tport and (not tport.isdigit() or not 0 < int(tport) < 65536):
            return bad("目标端口应为 1-65535 的数字")
        if self._create_session(proto, lhost, lport, thost, tport):
            dlg.destroy()
        else:
            err.set(self.status_var.get())      # 失败原因已在状态栏

    # ---------------- 联系人右键菜单 ----------------

    def _on_contact_menu(self, event):
        """右键联系人：关闭所在通道 / 删除会话记录。"""
        idx = self.contact_list.nearest(event.y)
        if idx < 0 or idx >= len(self._convo_keys):
            return
        ckey = self._convo_keys[idx]
        self._select_convo(ckey)
        cid = self._chan_of(ckey)
        menu = tk.Menu(self.root, tearoff=0)
        if cid in self.channels:
            menu.add_command(label=f"关闭通道 {self._cid_tag(cid)}",
                             command=lambda: self._close_channel(cid))
        else:
            menu.add_command(label="通道已关闭", state=tk.DISABLED)
        menu.add_command(label="删除会话记录",
                         command=lambda: self._delete_convo(ckey))
        try:
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    def _delete_convo(self, ckey: str):
        """删除会话记录：清聊天记录并从列表移除（不影响通道）。"""
        self._convos.pop(ckey, None)
        self._unread.pop(ckey, None)
        self._cstats.pop(ckey, None)
        self._crate.pop(ckey, None)
        self._drafts.pop(ckey, None)
        if self.current_peer == ckey:
            self.current_peer = None
            self._clear_view()
        self._refresh_contacts()
        self._refresh_convo_stats()
        self.status_var.set(f"已删除会话 {self._display(ckey)}")

    def _cli_open(self):
        """CLI --open：按 _cli_cfg 建通道/会话。"""
        cfg = self._cli_cfg
        mode = cfg.get("mode") or "TCP Server"
        target = cfg.get("target")
        if mode == "TCP Client":
            if target:
                h, pt = target.rsplit(":", 1)
                self._create_session("tcpc", "", "", h, pt)
            return
        proto = "udp" if mode == "UDP" else "tcps"
        lhost = cfg.get("lhost") or detect_local_ips()[0]
        lport = str(cfg.get("lport") or "9000")
        thost = tport = ""
        if target and proto == "udp":
            thost, tport = target.rsplit(":", 1)
        self._create_session(proto, lhost, lport, thost, tport)

    def _open_channel(self, proto: str, lhost: str, lport: str):
        """打开一个通道（UDP 绑定 / TCP 监听）；多个通道可并存。"""
        cid = self._cid(proto, lhost, lport)
        if cid in self.channels:
            return cid
        cb_data = lambda s, d, c=cid: self._q_data(c, s, d)
        cb_evt = lambda t, c=cid: self._q_event(c, t)
        try:
            if proto == "udp":
                w = UDPWorker(cb_data, cb_evt, lhost, int(lport), "127.0.0.1", 9)
            else:
                w = TCPServerWorker(cb_data, cb_evt, lhost, int(lport))
            w.start()
        except (ValueError, OSError) as e:
            msg = str(e)
            if isinstance(e, OSError) and e.errno == errno.EADDRINUSE:
                msg += "\n\n" + self._port_owner_hint(lport)
            messagebox.showerror("打开失败", msg)
            self.status_var.set(f"错误: {e}")
            return None
        self.channels[cid] = w
        self._ensure_convo(f"{cid}|*")          # 该通道的群发会话
        self._refresh_contacts()
        self._refresh_ignore_cache()
        self.status_var.set(
            f"通道已打开 [{self._cid_tag(cid)}]，共 {len(self.channels)} 个")
        return cid

    def _close_channel(self, cid: str):
        w = self.channels.pop(cid, None)
        if not w:
            return
        w.stop()
        # 会话与聊天记录保留（类微信），群发项随通道消失、重开时恢复
        self._refresh_contacts()
        self._log_event(f"--- 通道已关闭 [{self._cid_tag(cid)}] ---")
        if not self.channels:
            self.status_var.set("全部通道已关闭")

    def _close_all_channels(self):
        for cid in list(self.channels):
            self._close_channel(cid)

    def _connect_tcp_client(self, host: str, port: int):
        """建立（或复用）到 host:port 的 TCP 通道并连接；成功返回会话 key。"""
        cid = self._cid("tcpc", host, port)
        w = self.channels.get(cid)
        if w is None:
            w = TCPClientWorker(lambda s, d, c=cid: self._q_data(c, s, d),
                                lambda t, c=cid: self._q_event(c, t))
            w.start()
            self.channels[cid] = w
            self.status_var.set(f"通道已打开 [TCP]，共 {len(self.channels)} 个")
        try:
            w.connect(host, port)
        except OSError as e:
            self.status_var.set(f"连接 {host}:{port} 失败: {e}")
            if not w.conn_keys():               # 空通道不留
                self.channels.pop(cid, None)
                w.stop()
            return None
        ckey = f"{cid}|{host}:{port}"
        self._ensure_convo(ckey)
        return ckey

    # ---------------- 会话（联系人）管理 ----------------

    def _all_convo_keys(self):
        """联系人列表：各通道群发项 -> 活跃连接 -> 历史会话（去重保序）。"""
        keys = [f"{cid}|*" for cid in self.channels
                if not cid.startswith("tcpc:")]
        for cid, w in self.channels.items():
            if isinstance(w, TCPServerWorker):
                cand = [f"{cid}|{k}" for k in w.client_keys()]
            elif isinstance(w, TCPClientWorker):
                cand = [f"{cid}|{k}" for k in w.conn_keys()]
            else:
                cand = []
            for k in cand:
                if k not in keys:
                    keys.append(k)
        for k in self._convos:
            if not k.endswith("|*") and k not in keys:
                keys.append(k)
        return keys

    def _fit_contact_width(self):
        """联系人列表宽度按最长条目自适应：用列表字体实测像素宽，
        换算成字符宽度，夹在 [22, 60] 之间。"""
        f = tkfont.Font(font=self.contact_list.cget("font"))
        unit = f.measure("0") or 7
        widest = 0
        for i in range(self.contact_list.size()):
            widest = max(widest, f.measure(self.contact_list.get(i)))
        chars = max(22, min(60, widest // unit + 2))
        if chars != int(self.contact_list.cget("width")):
            self.contact_list.config(width=chars)

    def _refresh_contacts(self):
        """重建联系人列表，保持当前选中态，并同步聊天区标题。"""
        keys = self._all_convo_keys()
        self._convo_keys = keys
        self.contact_list.delete(0, tk.END)
        for k in keys:
            n = self._unread.get(k, 0)
            disp = self._display(k)
            self.contact_list.insert(tk.END, f"{disp}  [{n}]" if n else disp)
        self._fit_contact_width()
        if self.current_peer in keys:
            idx = keys.index(self.current_peer)
            self.contact_list.selection_set(idx)
            self.contact_list.see(idx)
            self.convo_title.config(text=self._display(self.current_peer))
        else:
            self.convo_title.config(text="未选择会话（点击 ＋发起新会话 开始）")

    def _ensure_convo(self, ckey: str) -> bool:
        is_new = ckey not in self._convos
        self._convos.setdefault(ckey, [])
        return is_new

    def _on_contact_pick(self, _event=None):
        sel = self.contact_list.curselection()
        if not sel or sel[0] >= len(self._convo_keys):
            return
        self._select_convo(self._convo_keys[sel[0]])

    def _select_convo(self, peer: str):
        old = self.current_peer
        if old != peer:
            # 切换会话才动草稿：保存旧会话的（输入文本 + HEX 勾选），
            # 恢复新会话的；重复选中同一会话时保持输入框原样
            if old is not None:
                self._drafts[old] = (
                    self.tx_text.get("1.0", tk.END).rstrip("\n"),
                    self.tx_hex_var.get())
            text, hex_on = self._drafts.get(peer, ("", False))
            self.tx_text.delete("1.0", tk.END)
            if text:
                self.tx_text.insert("1.0", text)
            self.tx_hex_var.set(hex_on)
        self.current_peer = peer
        self._unread.pop(peer, None)
        self._refresh_contacts()
        self._render_chat(peer)
        self._refresh_convo_stats()

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

    # ---------------- 队列 <-> GUI ----------------

    def _q_data(self, cid, source, data):
        self.msg_queue.put(("data", cid, source, data))

    def _q_event(self, cid, text):
        self.msg_queue.put(("event", cid, text, None))

    def _refresh_ignore_cache(self):
        """刷新本机 IP 集合（勾选"忽略本机来源"时调用）。"""
        if self.rx_ignore_local_var.get():
            self._local_ips = set(detect_local_ips()) | {"127.0.0.1"}

    def _poll_queue(self):
        appends = []                   # 批量渲染，每 50ms 只刷一次，抗高包速
        try:
            while True:
                kind, cid, a, b = self.msg_queue.get_nowait()
                if kind == "data":
                    if self.rx_ignore_local_var.get() and \
                            a.rsplit(":", 1)[0] in self._local_ips:
                        continue     # 忽略本机发出的包（广播自发自收等场景）
                    self.rx_bytes += len(b)
                    self.rx_pkts += 1
                    ckey = f"{cid}|{a}"
                    st = self._cstats.setdefault(ckey, [0, 0, 0, 0])
                    st[2] += len(b)
                    st[3] += 1
                    if self._ensure_convo(ckey):
                        self._refresh_contacts()
                    self._store_msg(ckey, "rx", b)
                    if self.current_peer is None:
                        self._select_convo(ckey)   # 第一个会话自动选中
                    if ckey == self.current_peer:
                        if not self.rx_pause_var.get():
                            appends.append(("msg", "rx", ckey, b, time.time()))
                    else:
                        self._unread[ckey] = self._unread.get(ckey, 0) + 1
                        self._refresh_contacts()
                else:
                    self.status_var.set(a)
                    appends.append(("sys", f"* [{self._cid_tag(cid)}] {a}"))
        except queue.Empty:
            pass
        if appends:
            self._append_msgs(appends)
        keys = tuple(self._all_convo_keys())       # 连接接入/断开/通道变化
        if keys != self._last_visible:
            self._last_visible = keys
            self._refresh_contacts()
        self.root.after(50, self._poll_queue)

    # ---------------- 会话消息存储与气泡渲染 ----------------

    def _store_msg(self, peer: str, direction: str, data: bytes):
        msgs = self._convos.setdefault(peer, [])
        msgs.append((direction, data, time.time()))
        if len(msgs) > MAX_CONVO_MSGS:           # 每会话封顶，超出裁掉旧的一半
            del msgs[:MAX_CONVO_MSGS // 2]

    def _fmt_ts(self, t: float) -> str:
        if not self.rx_ts_var.get():
            return ""
        return time.strftime("[%H:%M:%S", time.localtime(t)) + \
            f".{int(t * 1000) % 1000:03d}] "

    def _fmt_body(self, data: bytes) -> str:
        return format_hex(data) if self.rx_hex_var.get() \
            else data.decode("utf-8", "replace")

    def _insert_msg(self, direction: str, ckey: str, data: bytes, t: float):
        """插一条气泡：meta 行（时间+对端）+ 正文。正文换行不带 tag，
        背景只包住文字，形成气泡效果。"""
        w = self.rx_text
        ts = self._fmt_ts(t)
        peer = self._peer_of(ckey)
        disp = "（群发）" if peer == "*" else peer
        if direction == "tx":
            w.insert(tk.END, f"{ts}我 → {disp}\n", "tx_meta")
            w.insert(tk.END, self._fmt_body(data), "tx")
        else:
            w.insert(tk.END, f"{ts}{disp}\n", "rx_meta")
            w.insert(tk.END, self._fmt_body(data), "rx")
        w.insert(tk.END, "\n\n")

    def _append_msgs(self, items):
        """items: ('msg', direction, peer, data, t) 或 ('sys', text)。"""
        w = self.rx_text
        w.config(state=tk.NORMAL)
        for it in items:
            if it[0] == "sys":
                w.insert(tk.END, it[1] + "\n\n", "sys")
            else:
                self._insert_msg(it[1], it[2], it[3], it[4])
        if int(w.index("end-1c").split(".")[0]) > MAX_RX_LINES:
            w.delete("1.0", f"{MAX_RX_LINES // 2}.0")
        w.see(tk.END)
        w.config(state=tk.DISABLED)

    def _render_chat(self, peer: str):
        w = self.rx_text
        w.config(state=tk.NORMAL)
        w.delete("1.0", tk.END)
        for direction, data, t in self._convos.get(peer, []):
            self._insert_msg(direction, peer, data, t)
        w.see(tk.END)
        w.config(state=tk.DISABLED)

    def _rerender(self):
        if self.current_peer is not None:
            self._render_chat(self.current_peer)

    def _log_event(self, text: str):
        self._append_msgs([("sys", f"* {text}")])
        self.status_var.set(text)

    def _clear_view(self):
        self.rx_text.config(state=tk.NORMAL)
        self.rx_text.delete("1.0", tk.END)
        self.rx_text.config(state=tk.DISABLED)

    def _clear_rx(self):
        """清空按钮：清掉当前会话的聊天记录和视图。"""
        if self.current_peer in self._convos:
            self._convos[self.current_peer].clear()
        self._clear_view()

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

    def _send(self, random_pkt: bool, ckey: str = None) -> bool:
        ckey = ckey or self.current_peer
        if ckey is None:
            self.status_var.set("请先添加或选择一个会话")
            return False
        cid, peer = ckey.rsplit("|", 1)
        w = self.channels.get(cid)
        if w is None:
            self.status_var.set(f"该会话所在通道已关闭 [{self._cid_tag(cid)}]，请重新打开")
            return False
        try:
            payload = self._get_payload(random_pkt)
            if not payload:
                self.status_var.set("发送内容为空")
                return False
            n = 0
            if isinstance(w, UDPWorker):
                if peer == "*":
                    # 群发：向该通道下每个已知来源各发一份；单个失败不影响其他
                    peers = [self._peer_of(k) for k in self._all_convo_keys()
                             if self._chan_of(k) == cid and not k.endswith("|*")]
                    if not peers:
                        self.status_var.set("该通道暂无已知来源，请先收到包或添加目标")
                        return False
                    failed = []
                    for p in peers:
                        h, pt = p.rsplit(":", 1)
                        try:
                            w.target = (h, int(pt))
                            w.send(payload)
                        except OSError:
                            failed.append(p)
                    n = len(peers) - len(failed)
                    if n == 0:
                        self.status_var.set("群发失败：所有目标均不可达")
                        return False
                    if failed:
                        self._log_event(f"以下目标发送失败: {'、'.join(failed)}")
                else:
                    h, pt = peer.rsplit(":", 1)
                    w.target = (h, int(pt))
                    w.send(payload)
                    n = 1
            elif isinstance(w, TCPServerWorker):
                # 目标 = 当前会话的客户端；选中群发项则广播
                n = w.send(payload, None if peer == "*" else peer)
            else:   # TCPClientWorker：目标 = 当前会话的服务器连接
                w.send(payload, peer)
                n = 1
        except (ValueError, OSError) as e:
            self.status_var.set(f"发送失败: {e}")
            return False
        self.tx_bytes += len(payload) * n
        self.tx_pkts += n
        st = self._cstats.setdefault(ckey, [0, 0, 0, 0])
        st[0] += len(payload) * n
        st[1] += n
        self._ensure_convo(ckey)
        self._store_msg(ckey, "tx", payload)
        if ckey == self.current_peer:       # 定时发送可能锁定在非当前会话
            self._append_msgs([("msg", "tx", ckey, payload, time.time())])
        tag = "随机包" if random_pkt else "数据"
        self.status_var.set(f"已发送{tag} {len(payload)} 字节"
                            + (f" × {n}" if n > 1 else ""))
        return True

    # ---------------- 定时发送 ----------------

    def _toggle_loop(self):
        if self._timer_job:
            self.root.after_cancel(self._timer_job)
            self._timer_job = None
        if self.loop_var.get():
            self._loop_ckey = self.current_peer   # 锁定会话，切换不影响发送目标
            self._loop_tick()
        else:
            self._loop_ckey = None

    def _loop_tick(self):
        if not self.loop_var.get():
            return
        if not self._send(random_pkt=self.loop_rand_var.get(),
                          ckey=self._loop_ckey):
            self.loop_var.set(False)   # 发送失败自动停止
            self._loop_ckey = None
            return
        try:
            interval = max(10, int(self.loop_ms.get()))
        except ValueError:
            interval = 1000
        self._timer_job = self.root.after(interval, self._loop_tick)

    # ---------------- 统计（按会话） ----------------

    def _refresh_convo_stats(self):
        """刷新聊天区顶部的当前会话统计行（速率由 _update_stats 每秒刷）。"""
        tx_b, tx_p, rx_b, rx_p = self._cstats.get(
            self.current_peer, (0, 0, 0, 0))
        self.convo_stats_tx.config(text=f"↑ {pretty_bytes(tx_b)} / {tx_p} 包")
        self.convo_stats_rx.config(text=f"↓ {pretty_bytes(rx_b)} / {rx_p} 包")

    def _reset_stats(self):
        """清零按钮：只清当前会话的统计；内部全局总计一并归零。"""
        self.tx_bytes = self.tx_pkts = self.rx_bytes = self.rx_pkts = 0
        ckey = self.current_peer
        if ckey is not None:
            self._cstats[ckey] = [0, 0, 0, 0]
            self._crate.pop(ckey, None)
        self._refresh_convo_stats()
        self.convo_rate.config(text="↑ 0 B/s ↓ 0 B/s")

    def _update_stats(self):
        now = time.monotonic()
        ckey = self.current_peer
        tx_b, _tx_p, rx_b, _rx_p = self._cstats.get(ckey, (0, 0, 0, 0))
        base = self._crate.setdefault(ckey, [now, tx_b, rx_b])
        dt = now - base[0]
        if dt >= 1.0:
            tx_rate = (tx_b - base[1]) / dt
            rx_rate = (rx_b - base[2]) / dt
            self.convo_rate.config(
                text=f"↑ {pretty_bytes(tx_rate)}/s ↓ {pretty_bytes(rx_rate)}/s")
            base[0], base[1], base[2] = now, tx_b, rx_b
        self._refresh_convo_stats()
        self.root.after(500, self._update_stats)

    # ---------------- 退出 ----------------

    def _on_close(self):
        self.loop_var.set(False)
        self._loop_ckey = None
        if self._timer_job:
            self.root.after_cancel(self._timer_job)
        for w in self.channels.values():
            w.stop()
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

    root = tk.Tk()
    apply_modern_theme(root)
    gui = NetTesterGUI(root)
    # --open 时直接按参数建会话；否则作为「发起新会话」对话框的默认预填
    gui._cli_cfg = {
        "mode": args.mode,
        "lhost": args.local_host,
        "lport": args.local_port,
        "target": f"{args.remote_host}:{args.remote_port}"
                  if args.remote_host and args.remote_port else None,
    }
    if args.open:
        root.after(100, gui._cli_open)
    root.mainloop()


if __name__ == "__main__":
    main()
