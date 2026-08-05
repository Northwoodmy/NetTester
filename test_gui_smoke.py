#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI 冒烟测试：真实打开窗口，覆盖多通道多协议会话。

流程：UDP 自发自收 -> 主动添加目标 -> 通道内群发 -> 忽略本机来源 ->
第二个 UDP 通道（不同端口）-> TCP Client 会话与 UDP 通道并存 -> 关闭保留。
"""

import os
import socket
import threading
import tkinter as tk
from net_tester import NetTesterGUI, apply_modern_theme


def start_echo_server():
    """回环 echo 服务器，端口自动分配。"""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen(2)
    port = s.getsockname()[1]

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            threading.Thread(target=echo, args=(c,), daemon=True).start()

    def echo(c):
        try:
            while (d := c.recv(65536)):
                c.sendall(b"echo:" + d)
        except OSError:
            pass
        c.close()

    threading.Thread(target=loop, daemon=True).start()
    return port


ECHO_PORT = start_echo_server()

root = tk.Tk()
apply_modern_theme(root)          # 顺带验证主题样式代码不报错
gui = NetTesterGUI(root)

CID = "udp:127.0.0.1:19099"
PEER = f"{CID}|127.0.0.1:19099"
GROUP = f"{CID}|*"
TCP_CKEY = f"tcpc:127.0.0.1:{ECHO_PORT}|127.0.0.1:{ECHO_PORT}"

# UDP 模式，本地绑 127.0.0.1:19099，再主动添加自己为会话目标（自发自收）
gui.mode_var.set("UDP")
gui._on_mode_change()
for entry, val in ((gui.local_host, "127.0.0.1"), (gui.local_port, "19099")):
    entry.delete(0, tk.END)
    entry.insert(0, val)

gui._toggle_open()                      # 打开 UDP 通道
assert CID in gui.channels, "UDP 通道未打开"
gui.new_peer.insert(0, "127.0.0.1:19099")
gui._add_target()
assert gui.current_peer == PEER, "添加目标后应选中该会话"

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
    assert PEER in gui._convo_keys, f"联系人列表未更新: {gui._convo_keys}"
    # 点选联系人 -> 切换当前会话
    idx = gui._convo_keys.index(PEER)
    gui.contact_list.selection_clear(0, tk.END)
    gui.contact_list.selection_set(idx)
    gui._on_contact_pick()
    assert gui.current_peer == PEER, "点选联系人未切换会话"
    # 会话里应同时有 rx 和 tx 气泡记录
    dirs = [m[0] for m in gui._convos[PEER]]
    assert dirs.count("rx") >= 3 and "tx" in dirs, f"会话消息记录不完整: {dirs}"
    # 主动添加多个目标（127/8 全回本机，发送必成功但无人应答）
    gui.new_peer.delete(0, tk.END)
    gui.new_peer.insert(0, "127.0.0.2:6000, 127.0.0.3:6000")
    gui._add_target()
    assert f"{CID}|127.0.0.2:6000" in gui._convo_keys, "主动添加目标失败"
    assert gui.current_peer == f"{CID}|127.0.0.3:6000", "添加后应选中最后添加的目标"
    # 通道内群发：向 3 个已知来源各发一份
    gui._select_convo(GROUP)
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(700, phase3)


def phase3():
    assert gui.tx_pkts == 3, f"群发应向 3 个目标各发 1 包，实际 {gui.tx_pkts}"
    assert gui.rx_pkts == 1, f"群发只有本机回 1 包，实际 {gui.rx_pkts}"
    # 勾选"忽略本机来源"后，自发自收应被过滤掉
    gui._select_convo(PEER)
    gui.rx_ignore_local_var.set(True)
    gui._refresh_ignore_cache()
    assert "127.0.0.1" in gui._local_ips, "本机 IP 缓存未包含 127.0.0.1"
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(800, phase4)


def phase4():
    assert gui.tx_pkts == 1, f"忽略本机阶段应只发 1 包，实际 {gui.tx_pkts}"
    assert gui.rx_pkts == 0, f"勾选忽略本机来源后不应收到自己的包，实际 {gui.rx_pkts}"
    gui.rx_ignore_local_var.set(False)
    # 第二个 UDP 通道（不同端口），与第一个并存
    gui.local_port.delete(0, tk.END)
    gui.local_port.insert(0, "19096")
    gui._toggle_open()
    assert "udp:127.0.0.1:19096" in gui.channels and CID in gui.channels, \
        f"两个 UDP 通道应并存: {list(gui.channels)}"
    # 切 TCP Client 加会话（切换模式不应清空已有会话/通道）
    gui.mode_var.set("TCP Client")
    gui._on_mode_change()
    assert PEER in gui._convo_keys, "切换模式后 UDP 会话应保留"
    gui.new_peer.delete(0, tk.END)
    gui.new_peer.insert(0, f"127.0.0.1:{ECHO_PORT}")
    gui._add_target()
    assert gui.current_peer == TCP_CKEY, f"TCP 会话未选中: {gui.current_peer}"
    gui.tx_hex_var.set(False)           # 前面 HEX 发送阶段勾选过，复位
    gui.tx_text.delete("1.0", tk.END)
    gui.tx_text.insert("1.0", "hello tcp")
    root.after(200, lambda: gui._send(random_pkt=False))
    root.after(700, phase5)


def phase5():
    # TCP 会话收到 echo；UDP 通道未受影响
    tcp_rx = b"".join(d for dr, d, _ in gui._convos[TCP_CKEY] if dr == "rx")
    assert b"echo:hello tcp" in tcp_rx, f"TCP 会话应收到 echo: {tcp_rx!r}"
    assert len(gui.channels) == 3, f"应 3 通道并存: {list(gui.channels)}"
    # 切回 UDP 会话，第一个通道仍能自发自收
    gui.mode_var.set("UDP")
    gui._on_mode_change()
    gui._select_convo(PEER)
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(700, phase6)


def phase6():
    assert gui.rx_pkts == 1, f"切回后 UDP 通道应仍能自收，实际 {gui.rx_pkts}"
    # 关闭全部通道：会话保留并标注已关闭
    gui._close_all_channels()
    assert not gui.channels, "通道应全部关闭"
    assert PEER in gui._convo_keys, "关闭通道后会话应保留"
    assert "已关闭" in gui._display(PEER), "已关闭通道的会话应有标注"
    # 重开第一个通道：群发项恢复，历史会话还能继续用
    gui.local_port.delete(0, tk.END)
    gui.local_port.insert(0, "19099")
    gui._toggle_open()
    assert CID in gui.channels, "重新打开通道失败"
    assert GROUP in gui._convo_keys, "重开后群发项应恢复"
    assert "已关闭" not in gui._display(PEER), "重开后不应再标注已关闭"
    gui._close_all_channels()
    root.destroy()
    print("GUI 冒烟测试通过（多通道/多协议会话/群发/忽略本机）")


root.after(1500, phase2)
root.after(15000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
