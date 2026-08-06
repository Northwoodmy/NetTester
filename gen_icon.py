#!/usr/bin/env python3
"""生成 NetTester 应用图标：Google 蓝圆角方块 + 白/浅蓝收发双箭头。

4096x4096 超采样绘制后 LANCZOS 缩小，输出：
  assets/icon_16/32/48/256.png   运行时窗口/标题栏图标（Tk iconphoto）
  assets/icon_1024.png           主图
  assets/icon.ico                Windows exe 图标（PyInstaller --icon）
  assets/icon.icns               macOS .app 图标（PyInstaller --icon）
依赖：Pillow。
"""
import os
from PIL import Image, ImageDraw

S = 4096                                # 超采样画布
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def draw_master() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # 圆角方块底（半径≈22.4%，macOS 风 squircle 近似）
    d.rounded_rectangle((0, 0, S - 1, S - 1), radius=int(S * 0.224),
                        fill="#1A73E8")

    def arrow(cy, tip_left, color):
        """横箭头：cy=纵向中心，tip_left=True 头朝左。"""
        t = int(S * 0.055)                # 箭杆半厚
        head_h = int(S * 0.150)           # 箭头半高
        head_w = int(S * 0.230)           # 箭头宽
        x0, x1 = int(S * 0.20), int(S * 0.80)   # 箭杆两端（含头区）
        if tip_left:
            shaft = (x0 + head_w - t, cy - t, x1, cy + t)
            head = [(x0 + head_w, cy - head_h), (x0, cy),
                    (x0 + head_w, cy + head_h)]
        else:
            shaft = (x0, cy - t, x1 - head_w + t, cy + t)
            head = [(x1 - head_w, cy - head_h), (x1, cy),
                    (x1 - head_w, cy + head_h)]
        d.rectangle(shaft, fill=color)
        d.polygon(head, fill=color)

    arrow(int(S * 0.385), tip_left=False, color="#FFFFFF")   # 上：发送 →
    arrow(int(S * 0.615), tip_left=True, color="#A8C7FA")    # 下：接收 ←
    return img


def write_icns(pngs: dict, path: str):
    """最小 icns 写入器：PNG 数据块直接嵌入（icp4..ic10）。"""
    body = b""
    for typ, data in pngs.items():
        body += typ + (8 + len(data)).to_bytes(4, "big") + data
    with open(path, "wb") as f:
        f.write(b"icns" + (8 + len(body)).to_bytes(4, "big") + body)


def main():
    os.makedirs(OUT, exist_ok=True)
    master = draw_master()
    sizes = {16: None, 32: None, 48: None, 128: None, 256: None,
             512: None, 1024: None}
    for sz in sizes:
        sizes[sz] = master.resize((sz, sz), Image.LANCZOS)
    for sz in (16, 32, 48, 256, 1024):
        sizes[sz].save(os.path.join(OUT, f"icon_{sz}.png"))

    # Windows .ico（多尺寸，256 自动走 PNG 压缩条目）
    sizes[256].save(os.path.join(OUT, "icon.ico"), format="ICO",
                    sizes=[(16, 16), (24, 24), (32, 32), (48, 48),
                           (64, 64), (128, 128), (256, 256)])

    # macOS .icns
    import io
    def png_bytes(sz):
        b = io.BytesIO()
        sizes[sz].save(b, format="PNG")
        return b.getvalue()
    write_icns({b"icp4": png_bytes(16), b"icp5": png_bytes(32),
                b"icp6": png_bytes(64) if 64 in sizes else png_bytes(48),
                b"ic07": png_bytes(128), b"ic08": png_bytes(256),
                b"ic09": png_bytes(512), b"ic10": png_bytes(1024)},
               os.path.join(OUT, "icon.icns"))
    print("assets written:", sorted(os.listdir(OUT)))


if __name__ == "__main__":
    main()
