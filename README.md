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

- **多通道并存**：通道 = 协议 + 本地端口（UDP 绑定 / TCP 监听 / TCP 连接），
  可同时打开任意多个——例如一个 UDP 会话走 50021、另一个 UDP 走 50022、
  再来一条 TCP 连接，互不干扰；顶部的「打开」按当前配置开/关对应通道
- **多目标会话（类微信）**：每个对端地址一个会话，左侧联系人列表、右侧气泡
  聊天记录（收到=左白气泡，发出=右绿气泡）；联系人带 `[协议·端口]` 标签区分
  所属通道；点选联系人即切换发送目标，未读消息有计数；每个 UDP/TCP Server
  通道各有「（群发）」会话
- **主动发起会话**：UDP 下添加目标地址（挂在当前本地地址的通道上，通道不存在
  则自动打开）、TCP Client 下连接新服务器，都在联系人列表下方输入 `IP:端口`
  （逗号分隔多个）点「添加」即可，不用等对方先发包；断线/关通道的会话保留
  记录并标注「已关闭」，重开通道即可继续
- **广播支持**：本地地址绑 `0.0.0.0` 可收广播包；目标填 `255.255.255.255` 可发广播
- **随机数据包**：自定义字节数，一键发送（`os.urandom` 生成）
- **手动发送**：文本/HEX 输入，Ctrl+Enter 快捷发送
- **定时循环发送**：毫秒级间隔，可循环发随机包或固定内容（压测/稳定性测试）
- **HEX 显示 / HEX 发送**
- **接收显示**：时间戳、来源地址、包长，可暂停/清空；「忽略本机来源」可过滤掉
  自己发的包（绑 `0.0.0.0` 发广播时系统会把包回投给自己，默认勾选即可只看外部设备）
- **统计**：累计收发字节/包数 + 实时速率

## 自测（无 GUI）

```bash
python3 test_loopback.py
```

对网络层做 UDP 自发自收、广播、TCP Server/Client 互发的回环断言测试。
另有 `test_gui_smoke.py`、`test_gui_open_close.py` 两个 GUI 测试。

