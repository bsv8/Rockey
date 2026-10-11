"""Compare real C++ text output with independent Pillow/FreeType font pixels.

This checks a software framebuffer, not the physical panel. All coordinates,
glyph shapes, advances, UTF-8 decoding and clipping are verified pixel for pixel.
"""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[3]
manifest = json.loads((ROOT / 'tools/fontsrc/manifest.json').read_text())
profile = manifest['profiles']['fusion-pixel']
role_names = ['title', 'body', 'small', 'mono_small', 'mono_large']
display_source = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / 'src/board/display.cpp'
with tempfile.TemporaryDirectory(prefix='rockey-render-') as directory:
    temporary = Path(directory)
    binary = temporary / 'capture'
    subprocess.run([os.environ.get('CXX', 'c++'), '-std=c++17',
                    '-DROCKEY_FONT_TABLE=1', '-I' + str(ROOT / 'src'),
                    '-I' + str(ROOT / 'tests/host/stubs'),
                    str(Path(__file__).with_name('capture.cpp')), str(display_source),
                    str(ROOT / 'src/ui/font.cpp'), str(ROOT / 'src/ui/text.cpp'),
                    '-o', str(binary)], check=True)
    count = 0
    for role, name in enumerate(role_names):
        spec = profile['roles'][name]
        key = profile['per_lang']['zh-Hans']['replace'].get(spec['font'], spec['font'])
        font = ImageFont.truetype(str(ROOT / manifest['cache'] / manifest['fonts'][key]['file']), spec['size'])
        ascent, _ = font.getmetrics()
        cases = ['设置新密码', '解锁钱包', 'ABC' if role == 0 else 'PIN 123_ABC'] if role < 3 else ['PIN 123_ABC']
        for text in cases:
            for clipped in [False, True]:
                output = temporary / 'render.pgm'
                result = subprocess.run([str(binary), str(role), text, str(output), str(int(clipped))],
                                        check=True, capture_output=True, text=True)
                # Draw one glyph at each integer advance, as the product does;
                # Pillow handles baseline placement directly from the source font.
                reference = Image.new('L', (320, 240))
                draw = ImageDraw.Draw(reference)
                x = 10
                for character in text:
                    draw.text((x, 20 + ascent), character, font=font, fill=255, anchor='ls')
                    x += round(font.getlength(character))
                reference = reference.point(lambda value: 255 if value >= 128 else 0)
                if clipped:
                    masked = Image.new('L', reference.size)
                    masked.paste(reference.crop((15, 23, 57, 38)), (15, 23))
                    reference = masked
                actual = Image.open(output)
                assert int(result.stderr.strip()) == x - 10, (name, text, 'text width mismatch')
                assert actual.tobytes() == reference.tobytes(), (name, text, clipped, 'pixel mismatch')
                count += 1
    print(f'Font render: {count} pixel/width comparisons passed against source fonts.')
    # Check the actual shared PIN row against independently placed source-font
    # pixels: all ten cursor values at every position, including confirmed digits.
    spec = profile['roles']['small']
    key = profile['per_lang']['zh-Hans']['replace'].get(spec['font'], spec['font'])
    font = ImageFont.truetype(str(ROOT / manifest['cache'] / manifest['fonts'][key]['file']), spec['size'])
    ascent, descent = font.getmetrics()
    height = ascent + descent
    for entered in range(6):
        for cursor in range(10):
            output = temporary / 'pin.pgm'
            subprocess.run([str(binary), 'pin', str(cursor), str(output), str(entered)], check=True, capture_output=True)
            reference = Image.new('L', (320, 240))
            draw = ImageDraw.Draw(reference)
            for index in range(6):
                x, w = 16 + index * 46, 42
                character = str(cursor) if index == entered else ('123456'[index] if index < entered else ' ')
                if index == entered:
                    draw.rectangle((x, 50, x + w - 1, 50 + height - 1), outline=255)
                advance = round(font.getlength(character))
                pen = x + (w - advance) // 2
                # Product DrawText clears its advance box, including part of
                # the focus border. Match that behavior before placing the glyph.
                draw.rectangle((pen, 50, pen + advance - 1, 50 + height - 1), fill=0)
                draw.text((pen, 50 + ascent), character, font=font, fill=255, anchor='ls')
            reference = reference.point(lambda value: 255 if value >= 128 else 0)
            assert Image.open(output).tobytes() == reference.tobytes(), (entered, cursor, 'PIN cursor mismatch')
    print('PIN render: 60 cursor/position comparisons passed against source fonts.')
    preview = os.environ.get('ROCKEY_BOOT_PREVIEW')
    if preview:
        output = temporary / 'boot.ppm'
        subprocess.run([str(binary), 'boot', '', str(output), '0'], check=True, capture_output=True)
        Image.open(output).save(preview)
