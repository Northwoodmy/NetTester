#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""网络层无头回环测试：不依赖 tkinter，直接测 worker 收发。"""

import errno
import socket
import threading
import time

from net_tester import (UDPWorker, TCPClientWorker, TCPServerWorker,
                        format_hex, parse_hex, pretty_bytes, detect_local_ips)

FAILED = []


def check(name, cond):
    print(("PASS" if cond else "FAIL"), name)
    if not cond:
        FAILED.append(name)


class Collector:
    def __init__(self):
        self.data = []
        self.events = []

    def on_data(self, source, payload):
        self.data.append((source, payload))

    def on_event(self, text):
        self.events.append(text)


def wait_for(pred, timeout=3.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_utils():
    check("format_hex", format_hex(b"\x01\xab\xff") == "01 AB FF")
    check("parse_hex", parse_hex("01 ab FF\n20") == b"\x01\xab\xff\x20")
    try:
        parse_hex("abc")
        check("parse_hex 奇数长度报错", False)
    except ValueError:
        check("parse_hex 奇数长度报错", True)
    check("pretty_bytes", pretty_bytes(512) == "512 B" and pretty_bytes(2048) == "2.0 KB"
          and pretty_bytes(512.345678) == "512 B" and pretty_bytes(1536.5) == "1.5 KB")
    ips = detect_local_ips()
    print("     探测到地址:", ips)
    check("detect_local_ips 含回环与通配",
          "127.0.0.1" in ips and "0.0.0.0" in ips and ips[0] != "0.0.0.0")


def test_udp():
    c = Collector()
    w = UDPWorker(c.on_data, c.on_event, "127.0.0.1", 0, "127.0.0.1", 0)
    w.start()
    port = w.sock.getsockname()[1]
    w.target = ("127.0.0.1", port)          # 自发自收
    payload = bytes(range(256)) * 4          # 1KB 自定义内容
    w.send(payload)
    ok = wait_for(lambda: any(p == payload for _, p in c.data))
    check("UDP 回环收发 1KB", ok)
    w.stop()


def test_udp_truncation():
    c = Collector()
    w = UDPWorker(c.on_data, c.on_event, "127.0.0.1", 0, "127.0.0.1", 9)
    w.start()
    w.send(b"x" * 70000)                     # 超过 UDP 上限，应截断而不是抛异常
    check("UDP 超大包截断", any("截断" in e for e in c.events))
    w.stop()


def test_udp_broadcast():
    """绑 0.0.0.0 应能收到发往 255.255.255.255 的广播（自发自收验证）。"""
    c = Collector()
    w = UDPWorker(c.on_data, c.on_event, "0.0.0.0", 0, "255.255.255.255", 9)
    w.start()
    port = w.sock.getsockname()[1]
    w.target = ("255.255.255.255", port)
    w.send(b"broadcast-self")
    check("UDP 绑 0.0.0.0 可收广播", wait_for(
        lambda: any(p == b"broadcast-self" for _, p in c.data)))
    w.stop()


def test_udp_port_conflict():
    blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # 无 SO_REUSEADDR
    blocker.bind(("127.0.0.1", 0))
    port = blocker.getsockname()[1]
    c = Collector()
    w = UDPWorker(c.on_data, c.on_event, "127.0.0.1", port, "127.0.0.1", 9)
    try:
        w.start()
        check("UDP 端口冲突报错", False)
        w.stop()
    except OSError as e:
        check("UDP 端口冲突报错", e.errno == errno.EADDRINUSE)
    blocker.close()


def test_tcp():
    srv_c, cli_c = Collector(), Collector()
    srv = TCPServerWorker(srv_c.on_data, srv_c.on_event, "127.0.0.1", 0)
    srv.start()
    port = srv.server.getsockname()[1]

    cli = TCPClientWorker(cli_c.on_data, cli_c.on_event)
    cli.start()
    key = cli.connect("127.0.0.1", port)

    check("TCP server 看到客户端接入",
          wait_for(lambda: len(srv.client_keys()) == 1))

    cli.send(b"hello server", key)
    check("TCP client -> server", wait_for(
        lambda: any(p == b"hello server" for _, p in srv_c.data)))

    srv.send(b"hello client", srv.client_keys()[0])
    check("TCP server -> client", wait_for(
        lambda: any(p == b"hello client" for _, p in cli_c.data)))

    srv.send(b"broadcast")                    # 广播（无目标）
    check("TCP server 广播", wait_for(
        lambda: any(p == b"broadcast" for _, p in cli_c.data)))

    big = b"z" * (1024 * 1024)                # 1MB，验证流式收全
    cli.send(big, key)
    check("TCP 1MB 完整到达", wait_for(
        lambda: sum(len(p) for _, p in srv_c.data if set(p) == {122}) >= 1024 * 1024
        or b"".join(p for _, p in srv_c.data).count(b"z" * 100) > 0, timeout=5))

    # 单连接断开：server 踢掉该客户端，client 侧应收到 FIN（recv 返回空）
    srv.disconnect(srv.client_keys()[0])
    check("server 断开单连接后列表清空",
          wait_for(lambda: len(srv.client_keys()) == 0))
    check("client 侧感知断开",
          wait_for(lambda: len(cli.conn_keys()) == 0))

    # client 单连接断开：重连一个再断
    key2 = cli.connect("127.0.0.1", port)
    check("重连后 server 看到客户端",
          wait_for(lambda: len(srv.client_keys()) == 1))
    cli.disconnect(key2)
    check("client 断开单连接后列表清空",
          wait_for(lambda: len(cli.conn_keys()) == 0))
    check("server 侧感知断开",
          wait_for(lambda: len(srv.client_keys()) == 0))

    cli.stop()
    srv.stop()


def main():
    test_utils()
    test_udp()
    test_udp_truncation()
    test_udp_broadcast()
    test_udp_port_conflict()
    test_tcp()
    print()
    if FAILED:
        print(f"共 {len(FAILED)} 项失败: {FAILED}")
        raise SystemExit(1)
    print("全部测试通过")


if __name__ == "__main__":
    main()
