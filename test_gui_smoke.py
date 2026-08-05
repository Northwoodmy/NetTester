#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI 冒烟测试：真实打开窗口，模拟切换 UDP 模式并自发自收。"""

import os
import tkinter as tk
from net_tester import NetTesterGUI, apply_modern_theme

root = tk.Tk()
apply_modern_theme(root)          # 顺带验证主题样式代码不报错
gui = NetTesterGUI(root)

# 切到 UDP，本地绑 127.0.0.1:19099，再主动添加自己为会话目标（自发自收）
gui.mode_var.set("UDP")
gui._on_mode_change()
for entry, val in ((gui.local_host, "127.0.0.1"), (gui.local_port, "19099")):
    entry.delete(0, tk.END)
    entry.insert(0, val)

assert gui._toggle_open.__name__ == "_toggle_open"
gui._toggle_open()                      # 打开 UDP
assert gui.worker is not None, "UDP worker 未打开"
gui.new_peer.insert(0, "127.0.0.1:19099")
gui._add_target()
assert gui.current_peer == "127.0.0.1:19099", "添加目标后应选中该会话"

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

def phase2():
    print(f"tx_pkts={gui.tx_pkts} rx_pkts={gui.rx_pkts} "
          f"tx_bytes={gui.tx_bytes} rx_bytes={gui.rx_bytes}")
    assert gui.tx_pkts == 3, "应发送 3 包"
    assert gui.rx_pkts >= 3, f"应至少收到 3 包，实际 {gui.rx_pkts}"
    # 会话列表应出现自己（自发自收），且已自动选中
    peer = "127.0.0.1:19099"
    assert peer in gui._convo_keys, f"联系人列表未更新: {gui._convo_keys}"
    assert gui.current_peer == peer, f"首个会话应自动选中，实际 {gui.current_peer}"
    # 点选联系人 -> 切换当前会话
    idx = gui._convo_keys.index(peer)
    gui.contact_list.selection_clear(0, tk.END)
    gui.contact_list.selection_set(idx)
    gui._on_contact_pick()
    assert gui.current_peer == peer, "点选联系人未切换会话"
    # 会话里应同时有 rx 和 tx 气泡记录
    dirs = [m[0] for m in gui._convos[peer]]
    assert dirs.count("rx") >= 3 and "tx" in dirs, f"会话消息记录不完整: {dirs}"
    # 主动添加多个目标 -> 进入联系人列表并选中最后一个
    # （用 127.0.0.x：整个 127/8 都走本机回环，发送必然成功但无人应答）
    gui.new_peer.delete(0, tk.END)
    gui.new_peer.insert(0, "127.0.0.2:6000, 127.0.0.3:6000")
    gui._add_target()
    assert "127.0.0.2:6000" in gui._convo_keys and "127.0.0.3:6000" in gui._convo_keys, \
        f"主动添加目标失败: {gui._convo_keys}"
    assert gui.current_peer == "127.0.0.3:6000", "添加后应选中最后添加的目标"
    # 群发：选中"（所有已知来源）"发随机包 -> 向 3 个已知来源各发一份
    gui._select_convo("（所有已知来源）")
    assert gui.current_peer == "（所有已知来源）"
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(700, phase3)

def phase3():
    assert gui.tx_pkts == 3, f"群发应向 3 个目标各发 1 包，实际 {gui.tx_pkts}"
    assert gui.rx_pkts == 1, f"群发只有本机回 1 包，实际 {gui.rx_pkts}"
    # 勾选"忽略本机来源"后，自发自收应被过滤掉
    gui._select_convo("127.0.0.1:19099")
    gui.rx_ignore_local_var.set(True)
    gui._refresh_ignore_cache()
    assert "127.0.0.1" in gui._local_ips, "本机 IP 缓存未包含 127.0.0.1"
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(800, finish)

def finish():
    assert gui.tx_pkts == 1, f"忽略本机阶段应只发 1 包，实际 {gui.tx_pkts}"
    assert gui.rx_pkts == 0, f"勾选忽略本机来源后不应收到自己的包，实际 {gui.rx_pkts}"
    gui._close_worker()
    # 会话跨关闭/重开保留（主动添加的目标不丢）
    assert "127.0.0.2:6000" in gui._convo_keys, "关闭后主动添加的目标应保留"
    gui._toggle_open()
    assert gui.worker is not None, "重新打开失败"
    assert "127.0.0.3:6000" in gui._convo_keys, "重开后主动添加的目标应保留"
    gui._close_worker()
    root.destroy()
    print("GUI 冒烟测试通过（会话/主动添加目标/群发/忽略本机来源）")

root.after(1500, phase2)
root.after(10000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
