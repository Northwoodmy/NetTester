# TCP/UDP 网络测试工具

单文件 GUI 网络调试工具（Tkinter），类似"网络调试助手"。支持 Linux / Windows。

## 运行

```bash
sudo apt install python3-tk   # Linux 首次需要；Windows 官方 Python 自带 tkinter
python3 net_tester.py
```

## 打包成独立可执行文件（PyInstaller）

打包不能跨平台：**Windows 的 exe 必须在 Windows 上打包**，Linux 同理。

- **Windows**：装好 Python（勾选 Add to PATH）后双击 `build_windows.bat`，产物在 `dist\NetTester.exe`（约 13MB，无需安装 Python 即可运行）
- **Linux**：`./build_linux.sh`（先 `pip install pyinstaller`，建议 venv），产物在 `dist/NetTester`

打包参数（两个脚本里一致）：`--onefile --windowed`。

## 命令行参数（可选）

```bash
python3 net_tester.py --mode UDP --local-host 0.0.0.0 --local-port 50021 \
    --remote-host 255.255.255.255 --remote-port 50021 --open
```

`--open` 表示启动后立即打开连接；不带参数则全部用界面默认值。

## 功能

- **三种模式**：TCP Server（多客户端，可选目标/广播）、TCP Client、UDP
- **广播支持**：本地地址绑 `0.0.0.0` 可收广播包；目标填 `255.255.255.255` 可发广播
- **随机数据包**：自定义字节数，一键发送（`os.urandom` 生成）
- **手动发送**：文本/HEX 输入，Ctrl+Enter 快捷发送
- **定时循环发送**：毫秒级间隔，可循环发随机包或固定内容（压测/稳定性测试）
- **HEX 显示 / HEX 发送**
- **接收显示**：时间戳、来源地址、包长，可暂停/清空
- **统计**：累计收发字节/包数 + 实时速率

## 自测（无 GUI）

```bash
python3 test_loopback.py
```

对网络层做 UDP 自发自收、广播、TCP Server/Client 互发的回环断言测试。
另有 `test_gui_smoke.py`、`test_gui_open_close.py` 两个 GUI 测试。

