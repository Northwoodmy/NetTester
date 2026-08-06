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
import ctypes
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
    from tkinter import ttk, messagebox
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
VERSION = "2.2.8"                # 与 release tag 对应，发版时同步递增
MONO_FONT = "Consolas" if sys.platform == "win32" else "Monospace"
IS_WIN = sys.platform == "win32"


def resource_path(name: str) -> str:
    """打包/源码两用的资源路径：PyInstaller 单文件运行时资源在
    sys._MEIPASS 临时目录，源码运行时在脚本所在目录。"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


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

    def disconnect(self, key: str):
        """断开单个连接；_conn_loop 收尾时从 conns 移除并发断开事件。"""
        with self._lock:
            sock = self.conns.get(key)
        if not sock:
            return
        try:    # 先 shutdown 再 close：对端立刻收到 FIN（recv 阻塞时
                # 单纯 close 因 fd 引用计数不会发 FIN）
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

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

    def disconnect(self, key: str):
        """断开单个客户端连接（继续监听）；_client_loop 负责收尾。"""
        with self._lock:
            conn = self.clients.get(key)
        if not conn:
            return
        try:    # 同 TCPClientWorker.disconnect：先 shutdown 再 close
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            conn.close()
        except OSError:
            pass

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

_THEME_IMAGES = []               # 自绘控件图像（滚动条/复选框），防 GC


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
                troughcolor=p["surface"], focuscolor=p["bg"])
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
    # 输入框：Material 文本框 —— 白底灰描边，聚焦不变色（无焦点蓝框）
    s.configure("TEntry", fieldbackground=p["field"], foreground=p["fg"],
                insertcolor=p["fg"], bordercolor=p["border"],
                lightcolor=p["field"], darkcolor=p["field"], padding=6)
    s.map("TEntry",
          fieldbackground=[("disabled", p["disabled_bg"])],
          foreground=[("disabled", p["disabled_fg"])],
          bordercolor=[("active", p["subtle"])])
    # 下拉框：白底 + 箭头悬停加深，文字与箭头间留白
    s.configure("TCombobox", fieldbackground=p["field"], foreground=p["fg"],
                background=p["field"], arrowcolor=p["subtle"], arrowsize=13,
                bordercolor=p["border"], lightcolor=p["field"],
                darkcolor=p["field"], padding=(6, 6, 20, 6))
    s.map("TCombobox",
          fieldbackground=[("readonly", p["field"]), ("disabled", p["disabled_bg"])],
          foreground=[("readonly", p["fg"]), ("disabled", p["disabled_fg"])],
          bordercolor=[("active", p["subtle"])],
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
    # 复选框：自绘 14px 圆角小方框（与 10pt 字号匹配）——
    # 未选=灰框白底，悬停=蓝框，选中=蓝底白勾，禁用=浅灰
    def _chk_rrect(img, x0, y0, x1, y1, r, color):
        for y in range(y0, y1):
            for x in range(x0, x1):
                dx = max(0, (x0 + r - x) if x < x0 + r else (x - (x1 - 1 - r)))
                dy = max(0, (y0 + r - y) if y < y0 + r else (y - (y1 - 1 - r)))
                if dx * dx + dy * dy <= r * r + 1:
                    img.put(color, to=(x, y))

    def _chk_seg_d2(px, py, ax, ay, bx, by):
        vx, vy, wx, wy = bx - ax, by - ay, px - ax, py - ay
        c1 = vx * wx + vy * vy
        if c1 <= 0:
            return (px - ax) ** 2 + (py - ay) ** 2
        c2 = vx * vx + vy * vy
        if c2 <= c1:
            return (px - bx) ** 2 + (py - by) ** 2
        t = c1 / c2
        return (px - (ax + t * vx)) ** 2 + (py - (ay + t * vy)) ** 2

    _CHK_ARMS = (((3.8, 7.4), (6.0, 9.8)), ((6.0, 9.8), (10.4, 3.8)))

    def _chk_img(selected, outline, interior=None):
        """14x14 复选框图：interior 非空=描边+填充底，否则实心底；selected 加白勾。"""
        img = tk.PhotoImage(width=14, height=14)
        if interior:
            _chk_rrect(img, 0, 0, 14, 14, 3, outline)
            _chk_rrect(img, 2, 2, 12, 12, 2, interior)
        else:
            _chk_rrect(img, 0, 0, 14, 14, 3, outline)
        if selected:
            for y in range(14):
                for x in range(14):
                    d = min(_chk_seg_d2(x + .5, y + .5, *a, *b)
                            for a, b in _CHK_ARMS)
                    if d <= 0.85:
                        img.put("#FFFFFF", to=(x, y))
        _THEME_IMAGES.append(img)
        return img

    # 注意：element_create 的图像状态表是“先匹配优先”，具体状态必须放前面
    s.element_create("Chk.indicator", "image",
                     _chk_img(False, p["disabled_fg"], "#FFFFFF"),
                     ("selected disabled", _chk_img(True, p["border"])),
                     ("disabled", _chk_img(False, p["border"], p["disabled_bg"])),
                     ("selected active", _chk_img(True, p["accent_hi"])),
                     ("selected", _chk_img(True, p["accent"])),
                     ("active", _chk_img(False, p["accent"], "#FFFFFF")))
    s.layout("TCheckbutton", [
        ("Checkbutton.padding", {"sticky": "nswe", "children": [
            ("Chk.indicator", {"side": "left", "sticky": ""}),
            ("Checkbutton.spacing", {"side": "left"}),
            ("Checkbutton.focus", {"side": "left", "sticky": "nswe",
                                   "children": [
                                       ("Checkbutton.label",
                                        {"sticky": "nswe"})]})]})])
    s.configure("TCheckbutton", background=p["bg"], foreground=p["fg"])
    s.map("TCheckbutton", background=[("active", p["bg"])])
    s.configure("TSeparator", background=p["border"])
    s.configure("Vertical.TScrollbar", background=p["border"], troughcolor=p["bg"],
                bordercolor=p["bg"], arrowcolor=p["subtle"], arrowsize=12)
    s.map("Vertical.TScrollbar",
          background=[("active", "#BDC1C6"), ("pressed", p["disabled_fg"])])
    s.configure("Status.TLabel", background=p["surface"], foreground=p["subtle"])

    # —— 细圆角滚动条：图像元素自绘，12px 无箭头，滑块悬停/按下变色 ——
    _sb_trough = tk.PhotoImage(width=12, height=4)          # 全透明滑槽
    _THEME_IMAGES.append(_sb_trough)

    def _sb_thumb(color):
        img = tk.PhotoImage(width=12, height=24)       # 圆角滑块，两侧留 2px 透明
        for y in range(24):
            for x in range(2, 10):
                dx = max(0, (6 - x) if x < 6 else (x - 5))
                dy = max(0, (4 - y) if y < 4 else (y - 19))
                if dx * dx + dy * dy <= 17:            # 半径 4 的圆角
                    img.put(color, to=(x, y))
        _THEME_IMAGES.append(img)
        return img

    s.element_create("Slim.trough", "image", _sb_trough, sticky="nswe")
    s.element_create("Slim.thumb", "image", _sb_thumb("#C4C7CB"),
                     ("pressed", _sb_thumb("#80868B")),
                     ("active", _sb_thumb(p["disabled_fg"])),
                     border=(2, 2, 10, 10), sticky="nswe")
    s.layout("Slim.Vertical.TScrollbar", [
        ("Slim.trough", {"sticky": "nswe", "children": [
            ("Slim.thumb", {"sticky": "nswe"})]})])

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
                  highlightcolor="#DADCE0")   # 焦点不变色：不要蓝色焦点框


# ---------------------------------------------------------------------------
# 无边框窗口：平台去装饰 + 原生拖动/缩放
# ---------------------------------------------------------------------------
# Linux(X11/XWayland)：_MOTIF_WM_HINTS decorations=0 去框，窗口仍归 WM 管理
# （任务栏/Alt-Tab/最小化都正常——不能用 overrideredirect，那是 unmanaged
# 窗口，会丢任务栏和 Alt-Tab）；拖动与八向缩放通过 _NET_WM_MOVERESIZE
# ClientMessage 交给 WM 原生执行（GTK CSD 应用在 X11 上的同款做法），
# 手感与系统窗口一致、无闪烁。
# Windows：SetWindowLongPtr 去掉 WS_CAPTION/WS_SYSMENU、保留
# WS_THICKFRAME —— 无边框但原生可缩放，任务栏/Aero Snap 正常。
# 所有平台调用都 try/except 兜底：失败则保留系统标题栏，仅外观差异。

_X11 = None                            # libX11 ctypes 句柄缓存
_X11_DPY = None                        # 自有 Display 连接缓存


def _x11_lib():
    """加载 libX11 并打开一根自有连接（与 Tk 的连接互不干扰）。"""
    global _X11, _X11_DPY
    if _X11 is None:
        lib = ctypes.CDLL("libX11.so.6")
        lib.XOpenDisplay.restype = ctypes.c_void_p
        lib.XDefaultRootWindow.restype = ctypes.c_ulong
        lib.XDefaultRootWindow.argtypes = [ctypes.c_void_p]
        lib.XInternAtom.restype = ctypes.c_ulong
        lib.XInternAtom.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                                    ctypes.c_int]
        lib.XChangeProperty.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                        ctypes.c_ulong, ctypes.c_ulong,
                                        ctypes.c_int, ctypes.c_int,
                                        ctypes.c_void_p, ctypes.c_int]
        lib.XSendEvent.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                   ctypes.c_int, ctypes.c_long,
                                   ctypes.c_void_p]
        lib.XFlush.argtypes = [ctypes.c_void_p]
        lib.XFree.argtypes = [ctypes.c_void_p]
        lib.XQueryTree.argtypes = [ctypes.c_void_p, ctypes.c_ulong,
                                   ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_void_p, ctypes.c_void_p]
        _X11 = lib
    if _X11_DPY is None:
        _X11_DPY = _X11.XOpenDisplay(None)
        if not _X11_DPY:
            raise OSError("XOpenDisplay 失败")
    return _X11, _X11_DPY


def _x11_frame_id(root) -> int:
    """返回被 WM 管理的那个窗口的 XID。Tk 顶层在 X11 上有一层包装窗口：
    winfo_id() 是内层内容窗口（hints 设这里没用），wm_frame() 又越过了
    包装层、直接指向 WM 的 frame 窗口（mutter 自己的窗口，设了白设）——
    正确目标是 winfo_id 的父窗口（XQueryTree）。无包装层时退回内层。"""
    X, dpy = _x11_lib()
    inner = root.winfo_id()
    rootw = ctypes.c_ulong()
    parent = ctypes.c_ulong()
    children = ctypes.c_void_p()
    n = ctypes.c_uint()
    X.XQueryTree(ctypes.c_void_p(dpy), ctypes.c_ulong(inner),
                 ctypes.byref(rootw), ctypes.byref(parent),
                 ctypes.byref(children), ctypes.byref(n))
    if children.value:
        X.XFree(children)
    if parent.value and parent.value != rootw.value:
        return parent.value
    return inner


def _x11_set_no_decorations(root):
    """_MOTIF_WM_HINTS decorations=0：去掉标题栏/边框，窗口仍被 WM 管理。"""
    X, dpy = _x11_lib()
    atom = X.XInternAtom(dpy, b"_MOTIF_WM_HINTS", 0)
    hints = (ctypes.c_ulong * 5)(2, 0, 0, 0, 0)   # flags=DECORATIONS, decorations=0
    X.XChangeProperty(dpy, _x11_frame_id(root), atom, atom, 32, 0,
                      ctypes.cast(hints, ctypes.c_void_p), 5)
    X.XFlush(dpy)


class _XClientMessageData(ctypes.Union):
    _fields_ = [("b", ctypes.c_char * 20),
                ("s", ctypes.c_short * 10),
                ("l", ctypes.c_long * 5)]


class _XClientMessageEvent(ctypes.Structure):
    _fields_ = [("type", ctypes.c_int),
                ("serial", ctypes.c_ulong),
                ("send_event", ctypes.c_int),
                ("display", ctypes.c_void_p),
                ("window", ctypes.c_ulong),
                ("message_type", ctypes.c_ulong),
                ("format", ctypes.c_int),
                ("data", _XClientMessageData)]


class _XEvent(ctypes.Union):
    _fields_ = [("type", ctypes.c_int),
                ("xclient", _XClientMessageEvent),
                ("pad", ctypes.c_long * 24)]


def _x11_wm_moveresize(root, x_root, y_root, direction):
    """让 WM 原生执行交互式拖动/缩放。direction: 8=移动，0-7=八向缩放
    （0 左上 1 上 2 右上 3 右 4 右下 5 下 6 左下 7 左）。须在按钮按住时调用。"""
    X, dpy = _x11_lib()
    ev = _XEvent()
    c = ev.xclient
    c.type = 33                                          # ClientMessage
    c.display = dpy
    c.window = _x11_frame_id(root)
    c.message_type = X.XInternAtom(dpy, b"_NET_WM_MOVERESIZE", 0)
    c.format = 32
    c.data.l[0] = x_root
    c.data.l[1] = y_root
    c.data.l[2] = direction
    c.data.l[3] = 1                                      # button 1
    c.data.l[4] = 1                                      # source: application
    # SubstructureRedirectMask | SubstructureNotifyMask（EWMH 规定发到根窗口）
    X.XSendEvent(dpy, X.XDefaultRootWindow(dpy), 0,
                 (1 << 20) | (1 << 19), ctypes.byref(ev))
    X.XFlush(dpy)


def _win32_native_borderless(root):
    """去 WS_CAPTION/WS_SYSMENU/WS_BORDER、留 WS_THICKFRAME：无边框 +
    原生缩放进热区 + 任务栏 + Aero Snap。代价：保留 1px 细边框。"""
    u32 = ctypes.windll.user32
    hwnd = int(root.wm_frame(), 16)
    if ctypes.sizeof(ctypes.c_void_p) == 8:
        get_style = u32.GetWindowLongPtrW
        set_style = u32.SetWindowLongPtrW
    else:
        get_style = u32.GetWindowLongW
        set_style = u32.SetWindowLongW
    get_style.restype = ctypes.c_ssize_t
    get_style.argtypes = [ctypes.c_void_p, ctypes.c_int]
    set_style.restype = ctypes.c_ssize_t
    set_style.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_ssize_t]
    GWL_STYLE = -16
    style = get_style(hwnd, GWL_STYLE)
    style &= ~(0x00C00000 | 0x00080000 | 0x00800000)  # CAPTION|SYSMENU|BORDER
    style |= 0x00040000                               # WS_THICKFRAME
    set_style(hwnd, GWL_STYLE, style)
    u32.SetWindowPos(ctypes.c_void_p(hwnd), 0, 0, 0, 0, 0,
                     0x0001 | 0x0002 | 0x0004 | 0x0020)  # NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED
    return hwnd


def _seg_d2(px, py, ax, ay, bx, by):
    """点 (px,py) 到线段 (ax,ay)-(bx,by) 的距离平方（自绘图标用）。"""
    vx, vy, wx, wy = bx - ax, by - ay, px - ax, py - ay
    c1 = vx * wx + vy * wy
    if c1 <= 0:
        return (px - ax) ** 2 + (py - ay) ** 2
    c2 = vx * vx + vy * vy
    if c2 <= c1:
        return (px - bx) ** 2 + (py - by) ** 2
    t = c1 / c2
    return (px - (ax + t * vx)) ** 2 + (py - (ay + t * vy)) ** 2


def _tb_icon(kind: str, color: str) -> "tk.PhotoImage":
    """12x12 标题栏按钮图标：min=横线，max=方框，restore=错位双方框，
    close=叉。线段扫描线光栅化，1.2px 笔宽，跨平台字形一致。"""
    img = tk.PhotoImage(width=12, height=12)
    W2 = 0.36                       # 距离平方阈值 ≈ 1.2px 线宽
    if kind == "restore":
        for y in range(12):
            for x in range(12):
                px, py = x + .5, y + .5
                front = 1.5 <= px <= 8.5 and 4.0 <= py <= 10.5
                front_edge = front and \
                    (px < 2.7 or px > 7.3 or py < 5.2 or py > 9.3)
                back = 3.5 <= px <= 10.5 and 1.5 <= py <= 8.5
                back_edge = back and \
                    (px < 4.7 or px > 9.3 or py < 2.7 or py > 7.3)
                if front_edge or (back_edge and not front):
                    img.put(color, to=(x, y))
    else:
        strokes = {
            "min":   [((2.5, 6.0), (9.5, 6.0))],
            "max":   [((2.5, 2.5), (9.5, 2.5)), ((9.5, 2.5), (9.5, 9.5)),
                      ((9.5, 9.5), (2.5, 9.5)), ((2.5, 9.5), (2.5, 2.5))],
            "close": [((3.0, 3.0), (9.0, 9.0)), ((9.0, 3.0), (3.0, 9.0))],
        }[kind]
        for y in range(12):
            for x in range(12):
                if min(_seg_d2(x + .5, y + .5, *a, *b)
                       for a, b in strokes) <= W2:
                    img.put(color, to=(x, y))
    _THEME_IMAGES.append(img)
    return img


# ---------------------------------------------------------------------------
# GUI 层
# ---------------------------------------------------------------------------

class NetTesterGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title("TCP/UDP 网络测试工具")
        root.withdraw()              # 先藏：无边框改造完成后才出场，避免闪框
        self._borderless = False     # 去装饰是否成功（失败则隐藏自定义标题栏）
        # 窗口图标（任务栏/Alt-Tab/dock；缺文件不影响运行）
        self._app_icons = []
        try:
            self._app_icons = [
                tk.PhotoImage(file=resource_path(f"assets/icon_{s}.png"))
                for s in (16, 32, 48, 256)]
            root.iconphoto(True, *self._app_icons)
        except tk.TclError:
            self._app_icons = []

        self.channels = {}               # 通道 cid -> worker；cid = 协议:地址:端口
        self.msg_queue: queue.Queue = queue.Queue()
        self._local_ips = set()          # 本机 IP 缓存（"忽略本机来源"用）

        # 会话（类微信：每个对端地址 = 一个联系人，各自一份聊天记录）
        # 会话挂在通道上：ckey = f"{cid}|{对端}"，"|*" 为该通道的群发会话。
        # 不同会话可属于不同协议、不同端口的通道。
        self._convos = {}                # ckey -> [(direction, data, time), ...]
        self._convo_keys = []            # 联系人列表行对应的 ckey
        self._cards = {}                 # ckey -> 卡片 Frame（含 _badge 角标）
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
        self._make_borderless()
        root.deiconify()
        if not IS_WIN and self._borderless:
            # 两个坑：1) Tk 在映射前后会重写 _MOTIF_WM_HINTS，pre-map
            # 设置会被覆写/打到未创建的窗口上（BadWindow，Xlib 默认错误
            # 处理器会杀进程）；2) 顶层窗口自身的 <Map> 事件不会触发
            # 绑定（Tk 内部消化了 MapNotify）。所以映射后用几次延时
            # 重断言盖住 Tk 的全部覆写时机；mutter 支持动态去装饰。
            for delay in (150, 500, 1500):
                root.after(delay, self._assert_no_decorations)
        self._poll_queue()
        self._update_stats()
        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------------- UI 搭建 ----------------

    def _build_ui(self):
        self._ui_font = "Segoe UI" if IS_WIN else "Noto Sans CJK SC"

        # Linux 无边框形态需要 4px 边缘热区做八向缩放（Windows 由
        # WS_THICKFRAME 原生提供）：外层套一圈与标题栏同色的 Frame，
        # 指针进入这圈环时换 resize 光标，按下转 _NET_WM_MOVERESIZE。
        container = self.root
        if not IS_WIN:
            self._edge = tk.Frame(self.root, bg=PALETTE["surface"],
                                  bd=4, relief="flat")
            self._edge.pack(fill=tk.BOTH, expand=True)
            self._edge.bind("<Motion>", self._edge_motion)
            self._edge.bind("<Leave>", self._edge_leave)
            self._edge.bind("<Button-1>", self._edge_press)
            container = self._edge
        self._build_titlebar(container)

        # 底部状态栏：仅状态文字（统计已并入各会话）
        status = ttk.Frame(container, padding=(8, 3))
        status.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(status, textvariable=self.status_var, style="Status.TLabel",
                  anchor=tk.W).pack(side=tk.LEFT, fill=tk.X, expand=True)

        main = ttk.Frame(container, padding=6)
        main.pack(fill=tk.BOTH, expand=True)

        # 左栏：会话卡片列表 + 发起新会话按钮（类微信）
        contact_col = ttk.Frame(main)
        contact_col.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 6))
        # 按钮先按底打包，固定在左栏底部；卡片列表填充剩余空间
        ttk.Button(contact_col, text="＋ 发起新会话", style="Accent.TButton",
                   command=self._show_new_session_dialog).pack(
            side=tk.BOTTOM, fill=tk.X, pady=(4, 0))
        # Canvas + 内嵌 Frame 实现可滚动的卡片列
        self.contact_canvas = tk.Canvas(contact_col, width=180,
                                        bg=PALETTE["surface"],
                                        highlightthickness=0)
        self._cards_scroll = ttk.Scrollbar(contact_col, orient=tk.VERTICAL,
                                           style="Slim.Vertical.TScrollbar",
                                           command=self.contact_canvas.yview)
        # 滚动条按需显示：内容不足一屏时隐藏（yscrollcommand 回包可见比例）
        self.contact_canvas.configure(yscrollcommand=self._on_cards_scroll)
        self.contact_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.cards_frame = tk.Frame(self.contact_canvas, bg=PALETTE["surface"])
        self._cards_window = self.contact_canvas.create_window(
            (0, 0), window=self.cards_frame, anchor=tk.NW)
        self.cards_frame.bind("<Configure>", lambda _e: self.contact_canvas.configure(
            scrollregion=self.contact_canvas.bbox("all")))
        self.contact_canvas.bind("<Configure>", lambda e: self.contact_canvas.itemconfigure(
            self._cards_window, width=e.width))
        # 卡片字体（测量与绘制共用，避免反复创建命名字体）
        self._f_card1 = tkfont.Font(family=self._ui_font, size=10, weight="bold")
        self._f_card2 = tkfont.Font(family=self._ui_font, size=8)
        self._f_badge = tkfont.Font(family=self._ui_font, size=8, weight="bold")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            self.contact_canvas.bind(seq, self._on_cards_wheel)
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
        ttk.Button(convo_stats_row, text="清空", width=4,
                   command=self._clear_convo).pack(side=tk.RIGHT)

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

        # —— 中间气泡聊天记录 ——
        rx_wrap = tk.Frame(conv_col, bg="#F5F5F5")
        rx_wrap.pack(fill=tk.BOTH, expand=True)
        self._rx_scroll = ttk.Scrollbar(rx_wrap, orient=tk.VERTICAL,
                                        style="Slim.Vertical.TScrollbar")
        self._rx_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.rx_text = tk.Text(
            rx_wrap, state=tk.DISABLED, font=(MONO_FONT, 10), wrap=tk.CHAR,
            height=12, yscrollcommand=self._rx_scroll.set,
            **{**TEXT_STYLE, "bg": "#F5F5F5"})
        self.rx_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self._rx_scroll.config(command=self.rx_text.yview)
        # —— 拖标题栏导致 Tk 文本自动滚动卡死的防护（详见看门狗注释）——
        # 这里只被动记录文本区内是否发生过真实的 <1> 按下；不加 break，
        # 类绑定（TextButton1/CancelRepeat）照常执行。
        self._rx_b1_held = False
        self._rx_as_streak = 0      # 连续“卡死”判定次数（防误杀合法拖选）
        self._rx_as_prev = None     # 上次采样：(物理指针x,y, Priv.x,Priv.y)
        self.rx_text.bind("<1>", self._rx_b1_down, add="+")
        self.rx_text.bind("<ButtonRelease-1>", self._rx_b1_up, add="+")
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

    # ---------------- 自定义标题栏（无边框形态） ----------------

    def _make_borderless(self):
        """去窗口装饰。任何一步失败都退化为系统标题栏：藏掉自定义栏，
        功能不受影响，只是外观回到原样。
        注意 Linux 下这里只验证 X11 可用——_MOTIF_WM_HINTS 必须等窗口
        映射后才能设（见 __init__ 里的注释）。"""
        try:
            if IS_WIN:
                self._hwnd = _win32_native_borderless(self.root)
            else:
                _x11_lib()
            self._borderless = True
        except Exception:
            self._titlebar.pack_forget()
            self._tb_sep.pack_forget()

    def _assert_no_decorations(self):
        """设置/重申 _MOTIF_WM_HINTS decorations=0（须在窗口映射后调用）。"""
        try:
            _x11_set_no_decorations(self.root)
        except Exception:
            pass

    def _build_titlebar(self, parent):
        """浅灰标题栏：左标题，右 最小化/最大化(还原)/关闭（自绘 12px
        图标，跨平台字形一致）。栏体与标题文字可拖动窗口（Linux 交 WM
        原生拖动，Windows 手动），双击切换最大化。"""
        p = PALETTE
        bar = tk.Frame(parent, bg=p["surface"], height=34)
        bar.pack(side=tk.TOP, fill=tk.X)
        bar.pack_propagate(False)
        self._titlebar = bar
        self._tb_sep = tk.Frame(parent, bg=p["border"], height=1)
        self._tb_sep.pack(side=tk.TOP, fill=tk.X)

        self._tb_icons = {
            "min": _tb_icon("min", p["fg"]),
            "max": _tb_icon("max", p["fg"]),
            "restore": _tb_icon("restore", p["fg"]),
            "close": _tb_icon("close", p["fg"]),
            "close_hi": _tb_icon("close", "#FFFFFF"),
        }
        self._tb_drag_start = None     # Windows 手动拖动起点（兜底路径）
        self._tb_drag_last = None      # 最近一次拖动坐标
        self._tb_drag_job = None       # 16ms 节流定时器

        drag_widgets = [bar]
        if self._app_icons:
            app_ic = tk.Label(bar, image=self._app_icons[0],
                              bg=p["surface"], bd=0)
            app_ic.pack(side=tk.LEFT, padx=(10, 0))
            drag_widgets.append(app_ic)
        title = tk.Label(bar, text="TCP/UDP 网络测试工具",
                         bg=p["surface"], fg=p["fg"],
                         font=(self._ui_font, 9))
        title.pack(side=tk.LEFT, padx=(6, 0))
        drag_widgets.append(title)
        ver = tk.Label(bar, text=f"v{VERSION}", bg=p["surface"],
                       fg=p["subtle"], font=(self._ui_font, 8))
        ver.pack(side=tk.LEFT, padx=(6, 0), pady=(2, 0))
        drag_widgets.append(ver)

        self._tb_close = self._tb_button(bar, "close", self._on_close)
        self._tb_close.pack(side=tk.RIGHT)
        self._tb_max = self._tb_button(bar, "max", self._toggle_maximize)
        self._tb_max.pack(side=tk.RIGHT)
        self._tb_min = self._tb_button(bar, "min", self.root.iconify)
        self._tb_min.pack(side=tk.RIGHT)

        for wgt in drag_widgets:
            wgt.bind("<Button-1>", self._tb_press)
            wgt.bind("<B1-Motion>", self._tb_drag)
            wgt.bind("<Double-1>", lambda _e: self._toggle_maximize())
        # 外部途径改变最大化状态（Super+↑/拖到屏幕顶部平铺等）时同步图标
        self.root.bind("<Configure>", self._on_root_configure, add="+")

    def _tb_button(self, bar, kind, cmd):
        """40x34 扁平按钮：悬停 min/max 变浅灰、close 变红底白叉。"""
        p = PALETTE
        hover = "#E81123" if kind == "close" else "#E0E2E5"
        lbl = tk.Label(bar, width=40, height=34, bd=0, highlightthickness=0,
                       bg=p["surface"], image=self._tb_icons[kind])

        def enter(_e):
            lbl.config(bg=hover)
            if kind == "close":
                lbl.config(image=self._tb_icons["close_hi"])
            elif kind == "max":
                self._sync_max_icon()   # Super+↑/拖到顶部等外部途径也会改状态

        def leave(_e):
            lbl.config(bg=p["surface"])
            if kind == "close":
                lbl.config(image=self._tb_icons["close"])

        lbl.bind("<Enter>", enter)
        lbl.bind("<Leave>", leave)
        lbl.bind("<Button-1>", lambda _e: cmd())
        return lbl

    def _is_zoomed(self) -> bool:
        try:
            if IS_WIN:
                return self.root.state() == "zoomed"
            return bool(int(self.root.wm_attributes("-zoomed")))
        except (tk.TclError, ValueError):
            return False

    def _sync_max_icon(self):
        """按当前最大化状态同步按钮图标。X11 下状态经 WM 异步生效，
        读回有延迟——调用方要么在状态已稳定后调（悬停/<Configure>/
        延时回校），要么用 _toggle_maximize 的目标状态直设。"""
        want = self._tb_icons["restore" if self._is_zoomed() else "max"]
        if str(self._tb_max.cget("image")) != str(want):
            self._tb_max.config(image=want)

    def _toggle_maximize(self):
        target = not self._is_zoomed()
        try:
            if IS_WIN:
                self.root.state("zoomed" if target else "normal")
            else:
                self.root.wm_attributes("-zoomed", 1 if target else 0)
        except tk.TclError:
            return
        # 立即按目标状态换图标（X11 异步读回不可靠），200ms 后再按
        # WM 实际状态回校一次
        self._tb_max.config(
            image=self._tb_icons["restore" if target else "max"])
        self.root.after(200, self._sync_max_icon)

    def _on_root_configure(self, e):
        """窗口尺寸变化（含 Super+↑/拖到顶部平铺等外部最大化途径）
        时同步最大化按钮图标。"""
        if e.widget is self.root:
            self._sync_max_icon()

    def _tb_press(self, e):
        """标题栏按下：拖动交给系统原生移动循环——Linux 发
        _NET_WM_MOVERESIZE（direction 8=移动），Windows 投递
        WM_NCLBUTTONDOWN/HTCAPTION 进入系统移动循环（自带拖到顶部
        最大化/贴边平铺）。必须 PostMessage 异步投递：SendMessage
        会让模态移动循环嵌套在 Tk 事件处理器内部启动，消息泵重入
        即卡死、后续点击直接崩。手动拖动仅作兜底。"""
        if IS_WIN:
            self._tb_drag_start = None
            try:
                hwnd = getattr(self, "_hwnd", None) or \
                    int(self.root.wm_frame(), 16)
                u32 = ctypes.windll.user32
                u32.ReleaseCapture()
                u32.PostMessageW(ctypes.c_void_p(hwnd), 0x00A1, 2, 0)
            except Exception:
                if self.root.state() != "zoomed":       # 失败退回手动拖
                    self._tb_drag_start = (e.x_root, e.y_root,
                                           self.root.winfo_x(),
                                           self.root.winfo_y())
                    self._tb_drag_last = (e.x_root, e.y_root)
        else:
            try:
                _x11_wm_moveresize(self.root, e.x_root, e.y_root, 8)
            except Exception:
                pass

    def _tb_drag(self, e):
        """手动拖动兜底：只记最新坐标，16ms 节流应用——逐事件改
        geometry 在高回报率鼠标下会堆积、刷新跟不上（残影）。"""
        if not (IS_WIN and self._tb_drag_start):
            return
        self._tb_drag_last = (e.x_root, e.y_root)
        if self._tb_drag_job is None:
            self._tb_drag_job = self.root.after(16, self._tb_drag_apply)

    def _tb_drag_apply(self):
        self._tb_drag_job = None
        if not (IS_WIN and self._tb_drag_start and self._tb_drag_last):
            return
        sx, sy, wx, wy = self._tb_drag_start
        lx, ly = self._tb_drag_last
        self.root.geometry(f"+{wx + lx - sx}+{wy + ly - sy}")

    # ---------------- Linux 窗口边缘缩放（4px 热区环） ----------------
    # _edge 外框的 bd=4 形成一圈同色热区：内部被子控件占满，指针只有
    # 进入这圈环时事件才落到外框本身，按方位换光标/发起 WM 原生缩放。

    _RESIZE_CURSOR = {
        (-1, -1): "top_left_corner",   (0, -1): "top_side",
        (1, -1): "top_right_corner",   (1, 0): "right_side",
        (1, 1): "bottom_right_corner", (0, 1): "bottom_side",
        (-1, 1): "bottom_left_corner", (-1, 0): "left_side",
    }
    _RESIZE_DIR = {
        (-1, -1): 0, (0, -1): 1, (1, -1): 2, (1, 0): 3,
        (1, 1): 4, (0, 1): 5, (-1, 1): 6, (-1, 0): 7,
    }

    @staticmethod
    def _edge_dir(x, y, w, h):
        """按坐标判定缩放方位 (hx,hy)；不在任何边上返回 None。
        角区沿边延长 14px，提高角落命中率。"""
        B, C = 4, 14
        on_l, on_r = x < B, x >= w - B
        on_t, on_b = y < B, y >= h - B
        if on_l or on_r:                 # 侧边上靠近角的 14px 也算角
            if y < C:
                on_t = True
            elif y >= h - C:
                on_b = True
        if on_t or on_b:                 # 顶/底边上靠近角的 14px 也算角
            if x < C:
                on_l = True
            elif x >= w - C:
                on_r = True
        hx = -1 if on_l else (1 if on_r else 0)
        hy = -1 if on_t else (1 if on_b else 0)
        return (hx, hy) if (hx or hy) else None

    def _edge_motion(self, e):
        if not self._borderless:
            return
        if self._is_zoomed():            # 最大化不可缩放，恢复默认光标
            self._edge.config(cursor="")
            return
        d = self._edge_dir(e.x, e.y, self._edge.winfo_width(),
                           self._edge.winfo_height())
        self._edge.config(cursor=self._RESIZE_CURSOR.get(d, ""))

    def _edge_leave(self, _e):
        self._edge.config(cursor="")

    def _edge_press(self, e):
        if not self._borderless or self._is_zoomed():
            return
        d = self._edge_dir(e.x, e.y, self._edge.winfo_width(),
                           self._edge.winfo_height())
        if d:
            try:
                _x11_wm_moveresize(self.root, e.x_root, e.y_root,
                                   self._RESIZE_DIR[d])
            except Exception:
                pass

    # ---------------- 通道管理（多通道并存：协议 + 本地端口） ----------------

    @staticmethod
    def _cid(proto: str, host: str, port) -> str:
        return f"{proto}:{host}:{port}"

    @staticmethod
    def _cid_tag(cid: str) -> str:
        proto, _h, p = cid.split(":", 2)
        return {"udp": f"UDP·{p}", "tcps": f"TCP·{p}", "tcpc": "TCP"}[proto]

    @staticmethod
    def _conn_no(cid: str) -> str:
        """tcpc 并行连接的展示序号：cid 端口段带 #n 时返回 ' #n'，否则空串。"""
        if cid.startswith("tcpc:") and "#" in cid:
            return " #" + cid.rsplit("#", 1)[1]
        return ""

    @staticmethod
    def _chan_disp(cid: str) -> str:
        """通道的展示名：UDP·50021 / TCP·9000 / TCP→host:port（并行连接加 #n）。"""
        proto, h, p = cid.split(":", 2)
        if proto == "tcpc":
            return f"TCP→{h}:{p.split('#', 1)[0]}" + NetTesterGUI._conn_no(cid)
        return f"{'UDP' if proto == 'udp' else 'TCP'}·{p}"

    @staticmethod
    def _peer_of(ckey: str) -> str:
        return ckey.rsplit("|", 1)[1]

    @staticmethod
    def _chan_of(ckey: str) -> str:
        return ckey.rsplit("|", 1)[0]

    def _display(self, ckey: str) -> str:
        """联系人显示名：对端 [协议·端口]；并行连接加 #n，通道已关闭则标注。"""
        cid, peer = ckey.rsplit("|", 1)
        tag = self._cid_tag(cid)
        if cid not in self.channels:
            tag += "·已关闭"
        return (f"（群发）[{tag}]" if peer == "*"
                else f"{peer}{self._conn_no(cid)} [{tag}]")

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

    def _on_contact_menu(self, ckey: str, event):
        """右键会话卡片：按卡片类型给出连接级/通道级操作。

        普通会话卡片只动自己这条连接（断开/重连），不再误伤整个通道；
        通道级关闭/重开只出现在（群发）卡片和已关闭的卡片上。"""
        self._select_convo(ckey)
        cid = self._chan_of(ckey)
        peer = self._peer_of(ckey)
        chan_open = cid in self.channels
        menu = tk.Menu(self.root, tearoff=0, bd=0, relief=tk.FLAT,
                       bg="#FFFFFF", fg=PALETTE["fg"],
                       activebackground=PALETTE["select"],
                       activeforeground=PALETTE["accent_press"],
                       disabledforeground=PALETTE["disabled_fg"],
                       activeborderwidth=0,
                       font=(self._ui_font, 10))
        if not chan_open:
            menu.add_command(label=f"重新打开通道 {self._chan_disp(cid)}",
                             command=lambda: self._reopen_channel(cid))
        elif peer == "*":
            menu.add_command(label=f"关闭通道 {self._chan_disp(cid)}",
                             command=lambda: self._close_channel(cid))
        elif cid.startswith(("tcps:", "tcpc:")):
            w = self.channels[cid]
            alive = peer in (w.client_keys() if cid.startswith("tcps:")
                             else w.conn_keys())
            if alive:
                menu.add_command(label="断开此连接",
                                 command=lambda: self._disconnect_peer(ckey))
            elif cid.startswith("tcpc:"):
                menu.add_command(label="重新连接",
                                 command=lambda: self._reconnect_peer(ckey))
            # TCP Server 的已断客户端只能等对方重连，不提供主动项
        # UDP 普通会话无连接概念，只提供下面的删除项
        menu.add_command(label="删除会话记录",
                         command=lambda: self._delete_convo(ckey))
        # 不要在这里 grab_release：tk_popup 的全局抓取会把「点击菜单外部」
        # 路由给菜单从而自动关闭；立即释放抓取会导致菜单点不掉
        menu.tk_popup(event.x_root, event.y_root)

    def _disconnect_peer(self, ckey: str):
        """断开该会话对应的单条 TCP 连接（不影响通道上的其他连接）。"""
        cid, peer = ckey.rsplit("|", 1)
        w = self.channels.get(cid)
        if w is None or peer == "*":
            return
        # tcpc 一条连接一个通道（并行连接各有独立通道）：断它就连通道一起收掉
        last_one = isinstance(w, TCPClientWorker) and w.conn_keys() == [peer]
        w.disconnect(peer)
        if last_one:
            self._close_channel(cid)
        self._refresh_contacts()
        self._log_event(f"--- 连接已断开 {peer} ---")

    def _reconnect_peer(self, ckey: str):
        """TCP Client 会话断线后重新拨号（沿用原通道 id，回到原卡片）。"""
        cid, peer = ckey.rsplit("|", 1)
        host, port = peer.rsplit(":", 1)
        new_key = self._connect_tcp_client(host, int(port), cid=cid)
        if new_key:
            self._select_convo(new_key)

    def _reopen_channel(self, cid: str):
        """重开已关闭的通道：UDP/TCP 监听按原地址绑定，TCP 连接重新拨号。"""
        proto, host, port = cid.split(":", 2)
        if proto == "tcpc":
            # 并行连接的 cid 端口段带 #n 后缀（tcpc:h:5000#2），拨号前要剥掉
            ckey = self._connect_tcp_client(host, int(port.split("#", 1)[0]),
                                            cid=cid)
            if ckey:
                self._select_convo(ckey)
        else:
            self._open_channel(proto, host, port)

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

    def _connect_tcp_client(self, host: str, port: int, cid: str = None):
        """建立到 host:port 的 TCP 客户端连接；每次新拨号都是独立通道。

        cid 为 None（新拨号）时分配唯一通道 id：首个连接用 tcpc:host:port，
        并行第 n 个用 tcpc:host:port#n——同目标多客户端互不干扰。
        传入 cid（断线重连/重开通道）则沿用原 id，会话卡片与聊天记录延续。
        成功返回会话 key。"""
        if cid is None:
            base = self._cid("tcpc", host, port)
            cid, n = base, 2
            while cid in self.channels:
                cid = f"{base}#{n}"
                n += 1
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

    def _on_cards_scroll(self, first: str, last: str):
        """滚动条按需显示：可见比例不足全量（内容超出）时才占位。"""
        if float(last) - float(first) >= 0.999:
            self._cards_scroll.pack_forget()
        elif self._cards_scroll.winfo_manager() != "pack":
            self._cards_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self._cards_scroll.set(first, last)

    def _card_lines(self, ckey: str):
        """卡片两行文本：第一行对端地址，第二行本机通道说明。"""
        cid, peer = ckey.rsplit("|", 1)
        proto, _h, p = cid.split(":", 2)
        # tcpc 并行连接靠 _conn_no 的 #n 序号区分（同目标卡片对端地址相同）
        line1 = "（群发）" if peer == "*" else peer + self._conn_no(cid)
        if proto == "udp":
            line2 = f"本机 UDP·{p}"
        elif proto == "tcps":
            line2 = f"本机 TCP 监听·{p}"
        else:
            line2 = "TCP 连接"           # TCP Client 本地是临时端口，不显示
        if cid not in self.channels:
            line2 += " · 已关闭"
        elif peer != "*" and proto in ("tcps", "tcpc"):
            # 通道还在但该连接已断（对方主动断开/被「断开此连接」踢掉）
            w = self.channels[cid]
            alive = peer in (w.client_keys() if proto == "tcps"
                             else w.conn_keys())
            if not alive:
                line2 += " · 已断开"
        return line1, line2

    def _fit_card_width(self):
        """卡片列宽度按内容自适应：读取卡片框架的实际需求宽度
        （含两行文本、角标、内边距，比字体测量估算可靠），夹在 [180, 340]。"""
        self.cards_frame.update_idletasks()
        req = self.cards_frame.winfo_reqwidth()
        width = max(180, min(340, req + 2))
        if width != int(self.contact_canvas.cget("width")):
            self.contact_canvas.config(width=width)

    def _refresh_contacts(self):
        """刷新会话卡片：只有会话增删/顺序变化才整体重建；
        未读数、选中态、关闭态等变化逐张原地更新，避免整列闪烁。"""
        keys = self._all_convo_keys()
        if keys != self._convo_keys:
            for w in self.cards_frame.winfo_children():
                w.destroy()
            self._cards = {k: self._build_card(k) for k in keys}
            self._convo_keys = keys
        for k in keys:
            self._update_card(k)
        self._fit_card_width()
        if self.current_peer in keys:
            self.convo_title.config(text=self._display(self.current_peer))
        else:
            self.convo_title.config(text="未选择会话（点击 ＋发起新会话 开始）")

    def _update_card(self, ckey: str):
        """原地刷新一张卡片的两行文本、未读角标与配色（不重建控件）。"""
        card = self._cards.get(ckey)
        if card is None:
            return
        line1, line2 = self._card_lines(ckey)
        if card._l1.cget("text") != line1:
            card._l1.config(text=line1)
        if card._l2.cget("text") != line2:
            card._l2.config(text=line2)
        closed = self._chan_of(ckey) not in self.channels
        card._l1.config(fg=PALETTE["subtle"] if closed else PALETTE["fg"])
        card._l2.config(fg=PALETTE["disabled_fg"] if closed
                        else PALETTE["subtle"])
        n = self._unread.get(ckey, 0)
        badge = card._badge
        if n:
            txt = str(n if n <= 9999 else "9999+")
            if badge.cget("text") != txt:
                badge.config(text=txt)
            if badge.winfo_manager() != "pack":
                badge.pack(side=tk.RIGHT)
        elif badge.winfo_manager() == "pack":
            badge.pack_forget()
        selected = ckey == self.current_peer
        if card._selected != selected:
            card._selected = selected
            self._card_paint(card, PALETTE["select"] if selected else "#FFFFFF")

    def _build_card(self, ckey: str) -> tk.Frame:
        """一张会话卡片：第一行对端地址+红色未读角标，第二行本机通道。"""
        line1, line2 = self._card_lines(ckey)
        selected = ckey == self.current_peer
        closed = self._chan_of(ckey) not in self.channels
        bg = PALETTE["select"] if selected else "#FFFFFF"
        fg = PALETTE["subtle"] if closed else PALETTE["fg"]
        sub_fg = PALETTE["disabled_fg"] if closed else PALETTE["subtle"]

        card = tk.Frame(self.cards_frame, bg=bg, cursor="hand2",
                        highlightthickness=1,
                        highlightbackground=PALETTE["border"],
                        highlightcolor=PALETTE["border"])
        card.pack(fill=tk.X, padx=6, pady=3)
        top = tk.Frame(card, bg=bg)
        top.pack(fill=tk.X, padx=8, pady=(6, 0))
        l1 = tk.Label(top, text=line1, bg=bg, fg=fg, anchor=tk.W,
                      font=self._f_card1)
        l1.pack(side=tk.LEFT, fill=tk.X, expand=True)
        n = self._unread.get(ckey, 0)
        badge = tk.Label(top, text=str(n if n <= 9999 else "9999+"),
                         bg="#D93025", fg="#FFFFFF", font=self._f_badge,
                         padx=5, pady=1)
        if n:
            badge.pack(side=tk.RIGHT)       # 未读为 0 时角标隐藏
        l2 = tk.Label(card, text=line2, bg=bg, fg=sub_fg, anchor=tk.W,
                      font=self._f_card2)
        l2.pack(fill=tk.X, padx=8, pady=(0, 6))

        card._selected = selected
        card._badge = badge                 # 测试与原地更新用
        card._l1 = l1
        card._l2 = l2
        card._paintables = (card, top, l1, l2)
        for w in (card, top, l1, l2, badge):
            w.bind("<Button-1>", lambda _e, k=ckey: self._select_convo(k))
            # 松开右键才弹菜单：若在按下时弹，随后的松开事件会被菜单抓取，
            # 落在指针下的第一个菜单项上被当成点击（松手即触发）
            w.bind("<ButtonRelease-3>",
                   lambda e, k=ckey: self._on_contact_menu(k, e))
            w.bind("<Enter>", lambda _e, c=card: self._card_hover(c, True))
            w.bind("<Leave>", lambda _e, c=card: self._card_hover(c, False))
            w.bind("<MouseWheel>", self._on_cards_wheel)     # Win/macOS
            w.bind("<Button-4>", self._on_cards_wheel)       # X11 上滚
            w.bind("<Button-5>", self._on_cards_wheel)       # X11 下滚
        return card

    def _card_paint(self, card, bg: str):
        for w in card._paintables:
            w.config(bg=bg)

    def _card_hover(self, card, on: bool):
        if not card._selected:
            self._card_paint(card, PALETTE["surface"] if on else "#FFFFFF")

    def _on_cards_wheel(self, event):
        """卡片区滚轮：X11 用 Button-4/5，Windows/macOS 用 MouseWheel delta。"""
        up = getattr(event, "num", None) == 4 or getattr(event, "delta", 0) > 0
        self.contact_canvas.yview_scroll(-1 if up else 1, "units")

    def _ensure_convo(self, ckey: str) -> bool:
        is_new = ckey not in self._convos
        self._convos.setdefault(ckey, [])
        return is_new

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
        self._rx_autoscroll_watchdog()   # 先解卡死的自动滚动，再收包钉底
        appends = []                   # 批量渲染，每 50ms 只刷一次，抗高包速
        contacts_dirty = False         # 卡片重建较重，本批结束后只刷一次
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
                        contacts_dirty = True
                    self._store_msg(ckey, "rx", b)
                    if self.current_peer is None:
                        self._select_convo(ckey)   # 第一个会话自动选中
                    if ckey == self.current_peer:
                        if not self.rx_pause_var.get():
                            appends.append(("msg", "rx", ckey, b, time.time()))
                    else:
                        self._unread[ckey] = self._unread.get(ckey, 0) + 1
                        contacts_dirty = True
                else:
                    self.status_var.set(a)
                    appends.append(("sys", f"* [{self._cid_tag(cid)}] {a}"))
                    contacts_dirty = True   # 连接断开/接入等事件影响卡片标注
        except queue.Empty:
            pass
        if contacts_dirty:
            self._refresh_contacts()
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

    def _rx_b1_down(self, _e):
        self._rx_b1_held = True

    def _rx_b1_up(self, _e):
        self._rx_b1_held = False

    def _rx_autoscroll_active(self) -> bool:
        """接收区自己的 TextAutoScan（50ms 自续滚动定时器）是否在跑。
        tk::Priv 是解释器级共享的，发送框的拖选自动滚动也会置位
        afterId——用 after info 取出定时器脚本里的控件路径来区分。"""
        try:
            armed = self.root.tk.eval(
                "expr {[info exists ::tk::Priv(afterId)] "
                "&& $::tk::Priv(afterId) ne {} "
                "? [lindex [lindex [after info $::tk::Priv(afterId)] 0] end]"
                " : {}}")
        except tk.TclError:
            return False
        return armed == str(self.rx_text)

    def _rx_autoscroll_watchdog(self):
        """取消卡死的 TextAutoScan——接收区 IP 行闪动的根因。

        TextAutoScan 是 Tk 文本类绑定的“按住左键拖出窗口边缘就自动滚动”
        机制：<B1-Leave> 武装一个 50ms 自续定时器，每拍按 Priv(y) 滚动
        （指针在窗口上方则上滚 (-1+y) 像素）并用 TextSelectTo 把 insert
        钉到指针处（= 顶行）；正常由 <ButtonRelease-1>/<B1-Enter> 的
        tk::CancelRepeat 解除。

        卡死路径：按住**标题栏**拖窗口时，窗口相对指针移动，指针可能从
        文本区上缘掠过——<B1-Leave> 据此武装 AutoScan；但按钮的
        press/release 都归 WM 所有，文本框永远收不到 release，
        CancelRepeat 不执行 → 定时器永久卡死，每拍上滚约一个窗口高，
        与收包后的钉底互相拉扯 = IP 行在两个位置间交替重绘（闪动）。
        在文本区里点一下（真实 press+release 走一遍 CancelRepeat）或
        再次拖到指针重新进入文本区（B1-Enter）即恢复——与现象吻合。

        判据（满足其一即视为卡死，连续两拍确认后取消）：
        1) 我们没见到文本区内的 <1> 按下——武装来源只可能是标题栏拖动；
        2) 见过按下但物理指针在动而 Tk 记录的 Priv(x/y) 冻结——隐式抓取
           已丢（release 丢失），按住是假象。
        """
        if not self._rx_autoscroll_active():
            self._rx_as_streak = 0
            self._rx_as_prev = None
            return
        w = self.rx_text
        px = self.root.winfo_pointerx() - w.winfo_rootx()
        py = self.root.winfo_pointery() - w.winfo_rooty()
        try:
            privx = int(self.root.tk.eval(
                "expr {[info exists ::tk::Priv(x)] ? $::tk::Priv(x) : -99999}"))
            privy = int(self.root.tk.eval(
                "expr {[info exists ::tk::Priv(y)] ? $::tk::Priv(y) : -99999}"))
        except (tk.TclError, ValueError):
            privx = privy = -99999
        prev = self._rx_as_prev
        self._rx_as_prev = (px, py, privx, privy)
        stale = not self._rx_b1_held
        if not stale and prev is not None:
            stale = (px, py) != (prev[0], prev[1]) and \
                    (privx, privy) == (prev[2], prev[3])
        self._rx_as_streak = self._rx_as_streak + 1 if stale else 0
        if self._rx_as_streak >= 2:
            self._rx_as_streak = 0
            try:
                self.root.tk.eval("tk::CancelRepeat")
            except tk.TclError:
                pass
            self._pin_bottom()      # 把被扯走的视图拉回钉底位置

    def _pin_bottom(self):
        """钉住聊天区底部。不要用 see(END)：它的“接近则锚底、否则居中”
        分支以窗口高度的 1/3 为界——当每条消息的像素高度恰好超过该阈值
        时（与窗口高、内容折行有关，拖动窗口会改变这个关系），see 会把
        末行放到窗口中部，底部留白又触发控件重绘时的上拉校正，两个位置
        交替绘制 = 底部内容（来源 IP 行）与上一条消息重叠闪动。
        moveto(1.0) 无条件定位到内容末尾，重绘的空白填充校正只会把
        视图补齐到底部这一个确定位置，振荡在结构上不存在。
        自动滚动（拖选/卡死的 AutoScan）活动期间不钉底，由看门狗处理。"""
        if self._rx_autoscroll_active():
            return
        self.rx_text.yview_moveto(1.0)

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
        self._pin_bottom()
        w.config(state=tk.DISABLED)

    def _render_chat(self, peer: str):
        w = self.rx_text
        w.config(state=tk.NORMAL)
        w.delete("1.0", tk.END)
        for direction, data, t in self._convos.get(peer, []):
            self._insert_msg(direction, peer, data, t)
        self._pin_bottom()
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
        """清掉当前会话的聊天记录和视图。"""
        if self.current_peer in self._convos:
            self._convos[self.current_peer].clear()
        self._clear_view()

    def _clear_convo(self):
        """「清空」按钮：清掉当前会话的聊天记录 + 统计。"""
        self._clear_rx()
        self._reset_stats()
        if self.current_peer is not None:
            self.status_var.set("已清空当前会话的记录与统计")

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
