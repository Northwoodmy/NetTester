#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证 UDP 打开/关闭/重开流程：按钮状态、端口立即释放、快速重开。"""

import errno
import os
import socket
import sys
import traceback
import tkinter as tk

import net_tester
from net_tester import NetTesterGUI


class FakeMessageBox:                     # 不弹模态对话框，避免阻塞事件循环
    errors = []

    @staticmethod
    def showerror(title, msg):
        FakeMessageBox.errors.append((title, msg))
        print(f"[对话框] {title}: {msg.splitlines()[0]}")


net_tester.messagebox = FakeMessageBox


def free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


PORT = free_port()
root = tk.Tk()
gui = NetTesterGUI(root)

CID = f"udp:127.0.0.1:{PORT}"
gui.mode_var.set("UDP")
gui._on_mode_change()
for entry, val in ((gui.local_host, "127.0.0.1"), (gui.local_port, str(PORT))):
    entry.delete(0, tk.END)
    entry.insert(0, val)


def port_is_busy(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # 无 SO_REUSEADDR 探针
    try:
        s.bind(("127.0.0.1", port))
        return False
    except OSError as e:
        return e.errno == errno.EADDRINUSE
    finally:
        s.close()


def step(fn):
    """失败立即终止，不让 mainloop 空转。"""
    try:
        fn()
    except Exception:
        traceback.print_exc()
        root.destroy()
        os._exit(1)


def step_open():
    gui._toggle_open()
    assert CID in gui.channels, "打开失败"
    assert gui.open_btn.cget("text") == "关闭", f"按钮文本: {gui.open_btn.cget('text')}"
    assert port_is_busy(PORT), "打开后端口应处于绑定状态"
    print("PASS 打开后按钮变为'关闭'，端口已绑定")
    root.after(50, lambda: step(step_close))


def step_close():
    gui._toggle_open()
    assert CID not in gui.channels, "关闭后通道应移除"
    assert gui.open_btn.cget("text") == "打开", f"按钮文本: {gui.open_btn.cget('text')}"
    assert not port_is_busy(PORT), "关闭后端口应立即释放"   # 竞态回归项
    print("PASS 关闭后按钮恢复'打开'，端口立即释放")
    root.after(50, lambda: step(step_reopen))


def step_reopen():
    gui._toggle_open()                    # 关闭后立刻重开（旧 bug 在此报 EADDRINUSE）
    assert CID in gui.channels, f"重开失败: {FakeMessageBox.errors}"
    assert port_is_busy(PORT)
    gui._toggle_open()
    assert CID not in gui.channels
    print("PASS 关闭后可立刻重新打开")
    root.destroy()
    print("UDP 打开/关闭/重开测试全部通过")


root.after(100, lambda: step(step_open))
root.after(10000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
