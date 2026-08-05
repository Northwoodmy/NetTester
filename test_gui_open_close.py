#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""通道打开/关闭/重开回归测试：端口释放竞态 & 会话创建入口。

历史 bug：关闭通道后立刻重开报 EADDRINUSE（worker 线程尚未释放端口）。
现入口为 _create_session（对话框/CLI 共用），关闭走 _close_channel。
"""

import os
import socket
import tkinter as tk

import net_tester
from net_tester import NetTesterGUI


class FakeMessageBox:
    errors = []

    @staticmethod
    def showerror(title, msg):
        FakeMessageBox.errors.append((title, msg))

    @staticmethod
    def showinfo(title, msg):
        pass


net_tester.messagebox = FakeMessageBox


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def port_is_busy(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError:
        return True
    finally:
        s.close()


PORT = free_port()
CID = f"udp:127.0.0.1:{PORT}"
GROUP = f"{CID}|*"

root = tk.Tk()
gui = NetTesterGUI(root)
steps = []


def step(fn):
    steps.append(fn)


def step_open():
    assert gui._create_session("udp", "127.0.0.1", str(PORT)), "打开失败"
    assert CID in gui.channels, "通道未注册"
    assert gui.current_peer == GROUP, "无目标会话应选中群发项"
    assert port_is_busy(PORT), "打开后端口应被占用"
    step(step_close)


def step_close():
    gui._close_channel(CID)
    assert CID not in gui.channels, "通道未移除"
    assert not port_is_busy(PORT), "关闭后端口应立即释放（竞态回归）"
    step(step_reopen)


def step_reopen():
    # 关闭后立刻重开同一端口：旧 bug 在此报 EADDRINUSE
    assert gui._create_session("udp", "127.0.0.1", str(PORT)), \
        f"重开失败: {FakeMessageBox.errors}"
    assert CID in gui.channels
    gui._close_channel(CID)
    assert CID not in gui.channels
    # TCP Server 通道同样走 _create_session
    assert gui._create_session("tcps", "127.0.0.1", str(PORT)), "TCP 监听失败"
    cid2 = f"tcps:127.0.0.1:{PORT}"
    assert cid2 in gui.channels
    gui._close_channel(cid2)
    assert not FakeMessageBox.errors, f"不应有错误弹窗: {FakeMessageBox.errors}"
    root.destroy()
    print("通道打开/关闭/重开测试通过（UDP + TCP Server）")


def runner():
    if not steps:
        root.after(30, runner)
        return
    fn = steps.pop(0)
    fn()
    root.after(30, runner)


root.after(50, step_open)
root.after(30, runner)
root.after(8000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
