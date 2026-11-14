"""Draws MLWINT's app icon (lime tile, dark shield, lime check) as a multi-size .ico.
Run: experiments/ember2024/.venv/Scripts/python.exe packaging/make_icon.py
Writes packaging/mlwint.ico and copies it to mlwint_app/windows/runner/resources/app_icon.ico."""
import shutil
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
S = 1024                                            # drawn large, scaled down sharply


def tile():
    img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    # lime gradient tile with rounded corners
    grad = Image.new('RGBA', (S, S))
    gd = ImageDraw.Draw(grad)
    for y in range(S):
        t = y / S
        gd.line([(0, y), (S, y)], fill=(int(124 - 40 * t), int(240 - 60 * t), int(90 - 30 * t), 255))
    mask = Image.new('L', (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=230, fill=255)
    img.paste(grad, (0, 0), mask)
    d = ImageDraw.Draw(img)
    # dark shield
    cx, top, w, h = S / 2, 215, 560, 640
    shield = [(cx, top), (cx + w / 2, top + 95), (cx + w / 2, top + 330), (cx + w * 0.30, top + 520),
              (cx, top + h), (cx - w * 0.30, top + 520), (cx - w / 2, top + 330), (cx - w / 2, top + 95)]
    shadow = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).polygon([(x, y + 18) for x, y in shield], fill=(0, 0, 0, 90))
    img = Image.alpha_composite(img, shadow.filter(ImageFilter.GaussianBlur(18)))
    d = ImageDraw.Draw(img)
    d.polygon(shield, fill=(6, 16, 5, 255))
    # lime check mark inside
    d.line([(cx - 135, top + 330), (cx - 35, top + 430), (cx + 150, top + 225)], fill=(124, 240, 90, 255), width=70,
           joint='curve')
    for x, y in [(cx - 135, top + 330), (cx + 150, top + 225)]:
        d.ellipse([x - 35, y - 35, x + 35, y + 35], fill=(124, 240, 90, 255))
    return img


def main():
    big = tile()
    out = ROOT / 'packaging/mlwint.ico'
    big.save(out, sizes=[(16, 16), (24, 24), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    big.resize((256, 256), Image.LANCZOS).save(ROOT / 'packaging/mlwint-256.png')
    shutil.copyfile(out, ROOT / 'mlwint_app/windows/runner/resources/app_icon.ico')
    print('icon written:', out)


if __name__ == '__main__':
    main()
