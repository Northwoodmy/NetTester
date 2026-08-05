#!/bin/sh
# Linux 一键打包（建议先在 venv 里装 pyinstaller）
set -e
cd "$(dirname "$0")"
PYI=${PYI:-pyinstaller}
$PYI --onefile --windowed --name NetTester net_tester.py
echo "打包完成：dist/NetTester"
