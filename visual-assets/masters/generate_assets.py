#!/usr/bin/env python3
"""
Asset Generator for SecTrainer (Signal Range Design System).
Generates high-precision brand marks, favicons, app icons, and social sharing cards.
"""

import os
from PIL import Image, ImageDraw, ImageFont

OUTPUT_DIRS = ["public", "visual-assets/improved"]

def ensure_dirs():
    for d in OUTPUT_DIRS:
        os.makedirs(d, exist_ok=True)

def render_rangemark_icon(size, bg_color=(12, 13, 11, 255), fg_color=(236, 235, 228, 255), signal_color=(215, 247, 91, 255), corner_radius_ratio=0.10):
    # Render at 8x supersampling for razor sharp antialiasing
    scale = 8
    w = 32 * scale
    img = Image.new("RGBA", (w, w), bg_color)
    draw = ImageDraw.Draw(img)
    
    stroke = max(2, int(1.2 * scale))
    box_inset = int(1.5 * scale)
    box_r = int(w * corner_radius_ratio)
    
    # Outer rounded rectangle frame
    draw.rounded_rectangle(
        [box_inset, box_inset, w - box_inset, w - box_inset],
        radius=box_r,
        outline=fg_color,
        width=stroke
    )
    
    # Reticle circle: r = 9 on 32 grid
    cx, cy = 16 * scale, 16 * scale
    r = 9 * scale
    
    # Signal quadrant (pie slice top-right: 270 deg to 360 deg)
    draw.pieslice([cx - r, cy - r, cx + r, cy + r], start=270, end=360, fill=signal_color)
    
    # Circle outline
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=fg_color, width=stroke)
    
    # Crosshair struts connecting outer frame to target circle
    draw.line([cx, int(2 * scale), cx, int(7.5 * scale)], fill=fg_color, width=stroke)
    draw.line([cx, int(24.5 * scale), cx, int(30 * scale)], fill=fg_color, width=stroke)
    draw.line([int(2 * scale), cy, int(7.5 * scale), cy], fill=fg_color, width=stroke)
    draw.line([int(24.5 * scale), cy, int(30 * scale), cy], fill=fg_color, width=stroke)
    
    # Center reticle dot
    dot_r = int(1.5 * scale)
    draw.ellipse([cx - dot_r, cy - dot_r, cx + dot_r, cy + dot_r], fill=fg_color)
    
    return img.resize((size, size), Image.Resampling.LANCZOS)

def generate_icons():
    sizes = [
        ("favicon-16x16.png", 16),
        ("favicon-32x32.png", 32),
        ("favicon.png", 64),
        ("apple-touch-icon.png", 180),
        ("icon-192.png", 192),
        ("icon-512.png", 512),
        ("icon.png", 512),
    ]
    
    for filename, sz in sizes:
        img = render_rangemark_icon(sz)
        for out_dir in OUTPUT_DIRS:
            target_path = os.path.join(out_dir, filename)
            img.save(target_path, optimize=True)
            print(f"Generated {target_path} ({sz}x{sz})")

def generate_og_image():
    W, H = 1200, 630
    img = Image.new("RGBA", (W, H), (12, 13, 11, 255))
    draw = ImageDraw.Draw(img)
    
    try:
        font_headline = ImageFont.truetype("/System/Library/Fonts/Avenir Next Condensed.ttc", 68)
        font_sub = ImageFont.truetype("/System/Library/Fonts/Avenir Next.ttc", 22)
        font_mono = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 16)
        font_mono_bold = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 20)
        font_stat_val = ImageFont.truetype("/System/Library/Fonts/Avenir Next Condensed.ttc", 54)
        font_brand = ImageFont.truetype("/System/Library/Fonts/Avenir Next Condensed.ttc", 32)
    except Exception:
        font_headline = ImageFont.load_default()
        font_sub = ImageFont.load_default()
        font_mono = ImageFont.load_default()
        font_mono_bold = ImageFont.load_default()
        font_stat_val = ImageFont.load_default()
        font_brand = ImageFont.load_default()

    # Hairline frame
    draw.rectangle([32, 32, W - 32, H - 32], outline=(44, 47, 39, 255), width=2)
    
    # Corner registration marks (+)
    for x in [32, W - 32]:
        for y in [32, H - 32]:
            draw.line([x - 12, y, x + 12, y], fill=(215, 247, 91, 180), width=2)
            draw.line([x, y - 12, x, y + 12], fill=(215, 247, 91, 180), width=2)

    # Hairline grid dividers
    draw.line([32, 110, W - 32, 110], fill=(35, 38, 30, 255), width=1)
    draw.line([32, 490, W - 32, 490], fill=(35, 38, 30, 255), width=1)
    draw.line([760, 110, 760, 490], fill=(35, 38, 30, 255), width=1)

    # Brand mark at (64, 52)
    bm_size = 40
    bx, by = 64, 52
    draw.rounded_rectangle([bx, by, bx + bm_size, by + bm_size], radius=6, outline=(236, 235, 228, 255), width=2)
    cx, cy = bx + bm_size // 2, by + bm_size // 2
    r = int(bm_size * 0.28)
    draw.pieslice([cx - r, cy - r, cx + r, cy + r], start=270, end=360, fill=(215, 247, 91, 255))
    draw.ellipse([cx - r, cy - r, cx + r, cy + r], outline=(236, 235, 228, 255), width=2)
    draw.line([cx, by + 4, cx, cy - r], fill=(236, 235, 228, 255), width=2)
    draw.line([cx, cy + r, cx, by + bm_size - 4], fill=(236, 235, 228, 255), width=2)
    draw.line([bx + 4, cy, cx - r, cy], fill=(236, 235, 228, 255), width=2)
    draw.line([cx + r, cy, bx + bm_size - 4, cy], fill=(236, 235, 228, 255), width=2)
    draw.ellipse([cx - 2, cy - 2, cx + 2, cy + 2], fill=(236, 235, 228, 255))

    draw.text((120, 50), "SECTRAINER", font=font_brand, fill=(236, 235, 228, 255))
    draw.text((285, 62), "SIGNAL RANGE // OWASP & CTF", font=font_mono, fill=(163, 163, 151, 255))

    # Top right badge
    draw.text((W - 380, 62), "NO SIGNUP · LOCAL PRIVACY", font=font_mono, fill=(215, 247, 91, 255))

    # Main category tag
    draw.text((64, 150), "[ FIELD MANUAL & RANGE ]", font=font_mono_bold, fill=(215, 247, 91, 255))

    # Primary headline
    draw.text((64, 190), "Break it here.", font=font_headline, fill=(236, 235, 228, 255))
    draw.text((64, 265), "Fix it at work.", font=font_headline, fill=(215, 247, 91, 255))

    # Narrative subhead
    draw.text(
        (64, 370),
        "Hands-on application security training. Interactive code labs, OWASP Top 10,\n"
        "CTF challenges, and exploit analysis in your browser.",
        font=font_sub,
        fill=(163, 163, 151, 255),
        spacing=8
    )

    # Right side: Range Instrument diagram
    rcx, rcy = 960, 300
    rr_outer = 140
    rr_mid = 90
    rr_inner = 40
    
    draw.ellipse([rcx - rr_outer, rcy - rr_outer, rcx + rr_outer, rcy + rr_outer], outline=(60, 65, 52, 255), width=2)
    draw.ellipse([rcx - rr_mid, rcy - rr_mid, rcx + rr_mid, rcy + rr_mid], outline=(44, 47, 39, 255), width=1)
    draw.ellipse([rcx - rr_inner, rcy - rr_inner, rcx + rr_inner, rcy + rr_inner], outline=(44, 47, 39, 255), width=1)
    
    # Active calibrated arc
    draw.arc([rcx - rr_outer, rcy - rr_outer, rcx + rr_outer, rcy + rr_outer], start=-90, end=90, fill=(215, 247, 91, 255), width=4)
    # Crosshairs
    draw.line([rcx - rr_outer - 20, rcy, rcx + rr_outer + 20, rcy], fill=(80, 85, 72, 255), width=1)
    draw.line([rcx, rcy - rr_outer - 20, rcx, rcy + rr_outer + 20], fill=(80, 85, 72, 255), width=1)
    # Center calibration target
    draw.ellipse([rcx - 5, rcy - 5, rcx + 5, rcy + 5], fill=(215, 247, 91, 255))
    draw.text((rcx - 28, rcy - 45), "TARGET", font=font_mono, fill=(163, 163, 151, 255))
    draw.text((rcx - 38, rcy + 25), "CALIBRATED", font=font_mono, fill=(215, 247, 91, 255))

    # Bottom telemetry stats
    metrics = [
        ("42", "MODULES"),
        ("255", "LESSONS"),
        ("41", "CODE LABS"),
        ("29", "CTF FLAGS"),
    ]
    col_w = (W - 64) // 4
    for idx, (val, label) in enumerate(metrics):
        col_x = 48 + idx * col_w
        if idx > 0:
            draw.line([col_x - 16, 490, col_x - 16, H - 32], fill=(35, 38, 30, 255), width=1)
        draw.text((col_x, 505), label, font=font_mono, fill=(163, 163, 151, 255))
        draw.text((col_x, 535), val, font=font_stat_val, fill=(236, 235, 228, 255))

    for out_dir in OUTPUT_DIRS:
        target_path = os.path.join(out_dir, "og-image.png")
        img.save(target_path, optimize=True)
        print(f"Generated {target_path} (1200x630)")

if __name__ == "__main__":
    ensure_dirs()
    generate_icons()
    generate_og_image()
    print("All visual assets generated successfully.")
