#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""GUI 冒烟测试：真实打开窗口，覆盖多通道多协议会话。

流程：对话框开合 -> UDP 建会话自发自收 -> 逗号分隔多目标 -> 通道内群发 ->
忽略本机来源 -> 第二个 UDP 通道（不同端口）-> TCP Client 会话并存 ->
关闭全部（已关闭标注 + 删除会话记录）-> 重开恢复。
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

# 发起新会话对话框：能打开、能关闭（交互逻辑人工验证）
gui._show_new_session_dialog()
assert gui._dlg.winfo_exists(), "对话框未打开"
gui._dlg.destroy()

# UDP 通道 127.0.0.1:19099，目标=自己（自发自收）
assert gui._create_session("udp", "127.0.0.1", "19099",
                           "127.0.0.1", "19099"), "UDP 会话创建失败"
assert CID in gui.channels, "UDP 通道未打开"
assert gui.current_peer == PEER, "建会话后应选中目标会话"

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
    assert gui.convo_title.cget("text") == gui._display(PEER), "标题未同步"
    # 点击卡片 -> 切换当前会话；卡片两行文本 = 对端地址 / 本机通道
    gui._cards[PEER].event_generate("<Button-1>")
    assert gui.current_peer == PEER, "点击卡片未切换会话"
    assert gui._card_lines(PEER) == ("127.0.0.1:19099", "本机 UDP·19099"), \
        f"卡片文本不正确: {gui._card_lines(PEER)}"
    # 会话里应同时有 rx 和 tx 气泡记录
    dirs = [m[0] for m in gui._convos[PEER]]
    assert dirs.count("rx") >= 3 and "tx" in dirs, f"会话消息记录不完整: {dirs}"
    # 会话级统计：PEER 已发 3 收 >=3；群发会话没发过
    st = gui._cstats[PEER]
    assert st[1] == 3 and st[3] >= 3, f"PEER 会话统计不正确: {st}"
    assert gui._cstats.get(GROUP, [0, 0, 0, 0])[1] == 0, "群发会话不应有发送统计"
    # 逗号分隔一次添加多个目标（127/8 全回本机，发送必成功但无人应答）
    assert gui._create_session("udp", "127.0.0.1", "19099",
                               "127.0.0.2, 127.0.0.3", "6000")
    assert f"{CID}|127.0.0.2:6000" in gui._convo_keys, "批量目标 1 未添加"
    assert gui.current_peer == f"{CID}|127.0.0.3:6000", "应选中最后添加的目标"
    # 发送草稿按会话隔离（文本 + HEX 勾选）
    k3 = f"{CID}|127.0.0.3:6000"
    # 先把 PEER 的草稿清成已知空白状态（前面 HEX 发送留下过内容）
    gui._select_convo(PEER)
    gui.tx_text.delete("1.0", tk.END)
    gui.tx_hex_var.set(False)
    gui._select_convo(k3)
    gui.tx_text.delete("1.0", tk.END)
    gui.tx_text.insert("1.0", "draft-A")
    gui.tx_hex_var.set(True)
    gui._select_convo(PEER)
    assert gui.tx_text.get("1.0", tk.END).strip() == "" \
        and not gui.tx_hex_var.get(), "切到空白草稿会话应为空白"
    gui.tx_text.insert("1.0", "draft-B")
    gui._select_convo(k3)
    assert gui.tx_text.get("1.0", tk.END).strip() == "draft-A" \
        and gui.tx_hex_var.get(), "切回应恢复 draft-A 与 HEX 勾选"
    gui._select_convo(PEER)
    assert gui.tx_text.get("1.0", tk.END).strip() == "draft-B" \
        and not gui.tx_hex_var.get(), "PEER 的草稿应为 draft-B"
    gui.tx_text.delete("1.0", tk.END)   # 清理，避免影响后续阶段
    # 通道内群发：向 3 个已知来源各发一份
    gui._select_convo(GROUP)
    gui._reset_stats()
    root.after(200, lambda: gui._send(random_pkt=True))
    root.after(700, phase3)


def phase3():
    assert gui.tx_pkts == 3, f"群发应向 3 个目标各发 1 包，实际 {gui.tx_pkts}"
    assert gui.rx_pkts == 1, f"群发只有本机回 1 包，实际 {gui.rx_pkts}"
    # 群发统计记在群发会话上，收包记在对端会话上
    assert gui._cstats[GROUP][1] == 3, f"群发统计应记 3 包: {gui._cstats[GROUP]}"
    assert gui._cstats[PEER][3] >= 1, "自收的包应记在 PEER 会话"
    # 「清空」按钮：同时清聊天记录和统计
    gui._clear_convo()
    assert gui._convos[GROUP] == [] and gui._cstats[GROUP] == [0, 0, 0, 0], \
        "清空应同时清记录与统计"
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
    # 第二个 UDP 通道（不同端口），与第一个并存；无目标 -> 选中其群发项
    assert gui._create_session("udp", "127.0.0.1", "19096")
    assert "udp:127.0.0.1:19096" in gui.channels and CID in gui.channels, \
        f"两个 UDP 通道应并存: {list(gui.channels)}"
    assert gui.current_peer == "udp:127.0.0.1:19096|*", "无目标应选中群发项"
    # TCP Client 会话：与 UDP 通道并存
    assert gui._create_session("tcpc", "", "", "127.0.0.1", str(ECHO_PORT)), \
        "TCP Client 会话创建失败"
    assert gui.current_peer == TCP_CKEY, f"TCP 会话未选中: {gui.current_peer}"
    assert PEER in gui._convo_keys, "UDP 会话应保留"
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
    root.after(200, phase5b)


TCP_TX0 = 0     # 循环测试前 TCP 会话的累计发送包数


def phase5b():
    # 定时发送锁定会话：在 PEER 上启动循环后立刻切到 TCP 会话，
    # 循环包应仍发往 PEER，而不是跟着当前选中会话跑
    global TCP_TX0
    TCP_TX0 = gui._cstats[TCP_CKEY][1]
    gui._select_convo(PEER)
    gui.loop_ms.delete(0, tk.END)
    gui.loop_ms.insert(0, "50")
    gui.loop_var.set(True)
    gui._toggle_loop()
    assert gui._loop_ckey == PEER, "循环应锁定启动时的会话"
    gui._select_convo(TCP_CKEY)
    root.after(350, phase5c)


def phase5c():
    gui.loop_var.set(False)
    gui._toggle_loop()
    assert gui._loop_ckey is None, "停止循环后应解除锁定"
    assert gui._cstats[PEER][1] >= 3, \
        f"循环包应发往锁定的 PEER: {gui._cstats[PEER]}"
    assert gui._cstats[TCP_CKEY][1] == TCP_TX0, "切走后 TCP 会话不应收到循环包"
    # 循环期间当前是 TCP 会话，PEER 的未读应显示在红色角标上
    # （用 winfo_manager 而非 winfo_ismapped：刚重建的卡片要等下一轮事件循环才绘制）
    badge = gui._cards[PEER]._badge
    assert badge.winfo_manager() == "pack" and int(badge.cget("text")) >= 3, \
        "PEER 的未读角标未显示"
    root.after(250, phase5d)        # 等在途 loopback 包落地再清零


def phase5d():
    # 切回 UDP 会话，第一个通道仍能自发自收；选中后未读清零、角标隐藏
    gui._select_convo(PEER)
    assert gui._cards[PEER]._badge.winfo_manager() != "pack", "选中会话后角标应隐藏"
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
    # 右键菜单的删除会话：记录清空、列表移除、选中态复位
    gui._delete_convo(PEER)
    assert PEER not in gui._convos and PEER not in gui._convo_keys, "会话未删除"
    assert gui.current_peer is None, "删除当前会话后应无选中"
    # 重开第一个通道：群发项恢复
    assert gui._create_session("udp", "127.0.0.1", "19099"), "重新打开通道失败"
    assert CID in gui.channels
    assert GROUP in gui._convo_keys, "重开后群发项应恢复"
    assert "已关闭" not in gui._display(GROUP), "重开后不应再标注已关闭"
    gui._close_all_channels()
    root.destroy()
    print("GUI 冒烟测试通过（对话框/多通道/多协议/群发/忽略本机/删除会话）")


root.after(1500, phase2)
root.after(15000, lambda: (print("TIMEOUT"), os._exit(2)))
root.mainloop()
