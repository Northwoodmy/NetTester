@echo off
REM Windows 一键打包 NetTester.exe
REM 前提：已安装 Python 3.10+（安装时勾选 "Add python.exe to PATH"）
cd /d "%~dp0"
python -m pip install --upgrade pyinstaller || goto :err
python -m PyInstaller --onefile --windowed --name NetTester net_tester.py || goto :err
echo.
echo 打包完成：dist\NetTester.exe
pause
exit /b 0
:err
echo 打包失败，请检查 Python 是否已加入 PATH
pause
exit /b 1
