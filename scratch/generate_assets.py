import os
from PIL import Image, ImageDraw, ImageFont

static_dir = os.path.join(os.path.dirname(__file__), "..", "static")
img_dir = os.path.join(static_dir, "img")
os.makedirs(img_dir, exist_ok=True)

# Helper to draw shield icon
def draw_shield(draw, bbox, fill_color, outline_color):
    x0, y0, x1, y1 = bbox
    w = x1 - x0
    h = y1 - y0
    points = [
        (x0 + w * 0.5, y0),
        (x1, y0 + h * 0.25),
        (x1, y0 + h * 0.65),
        (x0 + w * 0.5, y1),
        (x0, y0 + h * 0.65),
        (x0, y0 + h * 0.25),
    ]
    draw.polygon(points, fill=fill_color, outline=outline_color)

# 1. Generate OG Preview Image (1200 x 630)
og_img = Image.new("RGBA", (1200, 630), (11, 15, 23, 255))
og_draw = ImageDraw.Draw(og_img)

# Draw subtle background gradient rings & grid lines
for i in range(1200):
    # Top banner subtle gradient
    r = int(11 + (i / 1200) * 15)
    g = int(15 + (i / 1200) * 20)
    b = int(23 + (i / 1200) * 40)
    og_draw.line([(i, 0), (i, 630)], fill=(r, g, b, 255))

# Draw decorative grid pattern
for x in range(0, 1200, 40):
    og_draw.line([(x, 0), (x, 630)], fill=(30, 41, 59, 60))
for y in range(0, 630, 40):
    og_draw.line([(0, y), (1200, y)], fill=(30, 41, 59, 60))

# Draw glowing card container in center
card_box = [150, 100, 1050, 530]
og_draw.rounded_rectangle(card_box, radius=24, fill=(15, 23, 42, 230), outline=(99, 102, 241, 100), width=2)

# Draw glowing Shield Icon inside card
draw_shield(og_draw, (230, 190, 350, 330), fill_color=(99, 102, 241, 40), outline_color=(129, 140, 248, 255))
# Inner checkmark
og_draw.line([(270, 260), (285, 275), (310, 240)], fill=(129, 140, 248, 255), width=6)

# Title & Subtitle text using default font with clean layout positioning
try:
    font_large = ImageFont.truetype("DejaVuSans-Bold.ttf", 64)
    font_sub = ImageFont.truetype("DejaVuSans.ttf", 26)
    font_badge = ImageFont.truetype("DejaVuSans-Bold.ttf", 18)
except Exception:
    font_large = font_sub = font_badge = ImageFont.load_default()

# Badge "PASSIVE VAPT & ATTACK SURFACE AUDITOR"
og_draw.rounded_rectangle([390, 190, 890, 230], radius=8, fill=(99, 102, 241, 30), outline=(99, 102, 241, 80))
og_draw.text((410, 200), "PASSIVE VAPT & ATTACK SURFACE AUDITOR", fill=(165, 180, 252, 255), font=font_badge)

# Brand Title
og_draw.text((390, 250), "VulnWatch", fill=(255, 255, 255, 255), font=font_large)

# Subtitle description
og_draw.text((390, 340), "Enterprise Non-Intrusive Security Posture Auditing", fill=(148, 163, 184, 255), font=font_sub)
og_draw.text((390, 380), "TLS, Subdomains, Security Headers & Risk Score Intelligence", fill=(100, 116, 139, 255), font=font_sub)

# Save OG Preview
og_path = os.path.join(img_dir, "og-preview.png")
og_img.save(og_path, "PNG")
print("Saved OG preview to:", og_path)

# 2. Generate Favicon 32x32 PNG
fav_32 = Image.new("RGBA", (32, 32), (11, 15, 23, 255))
fav_draw = ImageDraw.Draw(fav_32)
draw_shield(fav_draw, (4, 4, 28, 28), fill_color=(99, 102, 241, 100), outline_color=(129, 140, 248, 255))
fav_32_path = os.path.join(img_dir, "favicon-32x32.png")
fav_32.save(fav_32_path, "PNG")

# 3. Generate Apple Touch Icon (180x180)
apple_icon = Image.new("RGBA", (180, 180), (11, 15, 23, 255))
apple_draw = ImageDraw.Draw(apple_icon)
apple_draw.rounded_rectangle([0, 0, 180, 180], radius=36, fill=(15, 23, 42, 255))
draw_shield(apple_draw, (40, 30, 140, 150), fill_color=(99, 102, 241, 100), outline_color=(129, 140, 248, 255))
apple_icon_path = os.path.join(img_dir, "apple-touch-icon.png")
apple_icon.save(apple_icon_path, "PNG")

# 4. Generate Favicon ICO in static/
ico_path = os.path.join(static_dir, "favicon.ico")
fav_32.save(ico_path, format="ICO")
print("Saved favicon ICO to:", ico_path)
