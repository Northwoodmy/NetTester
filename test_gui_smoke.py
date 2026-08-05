#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI 冒烟测试：真实打开窗口，模拟切换 UDP 模式并自发自收。"""

import os
import tkinter as tk
from net_tester import NetTesterGUI

root = tk.Tk()
gui = NetTesterGUI(root)

# 切到 UDP，本地与目标都指向 127.0.0.1:19099（自发自收）
gui.mode_var.set("UDP")
gui._on_mode_change()
for entry, val in ((gui.local_host, "127.0.0.1"), (gui.local_port, "19099"),
                   (gui.remote_host, "127.0.0.1"), (gui.remote_port, "19099")):
    entry.delete(0, tk.END)
    entry.insert(0, val)

assert gui._toggle_open.__name__ == "_toggle_open"
gui._toggle_open()                      # 打开 UDP
assert gui.worker is not None, "UDP worker 未打开"

# 发送 256 字节随机包
gui.rand_size.delete(0, tk.END)
gui.rand_size.insert(0, "256")
root.after(300, lambda: gui._send(random_pkt=True))

# 手动文本发送
root.after(400, lambda: (gui.tx_text.insert("1.0", "hello udp"),
                         gui._send(random_pkt=False)))

# HEX 发送
def hex_send():
    gui.tx_hex_var.set(True)
    gui.tx_text.delete("1.0", tk.END)
    gui.tx_text.insert("1.0", "DE AD BE EF")
    gui._send(random_pkt=False)
root.after(500, hex_send)

def finish():
    print(f"tx_pkts={gui.tx_pkts} rx_pkts={gui.rx_pkts} "
          f"tx_bytes={gui.tx_bytes} rx_bytes={gui.rx_bytes}")
    assert gui.tx_pkts == 3, "应发送 3 包"
    assert gui.rx_pkts >= 3, f"应至少收到 3 包，实际 {gui.rx_pkts}"
    # 来源列表应出现自己（自发自收），点选后填入目标地址栏
    vals = str(gui.client_box.cget("values"))
    assert "127.0.0.1:19099" in vals, f"来源列表未更新: {vals}"
    gui.client_var.set("127.0.0.1:19099")
    gui._on_client_pick()
    assert gui.remote_host.get() == "127.0.0.1" and gui.remote_port.get() == "19099", \
        "点选来源未填入目标地址"
    gui._close_worker()
    root.destroy()
    print("GUI 冒烟测试通过（含来源列表联动）")

root.after(1500, finish)
root.after(10000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
