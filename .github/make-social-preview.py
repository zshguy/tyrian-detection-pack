"""Generate the GitHub social preview card (1280x640).

This is the image that shows in a link unfurl on X, LinkedIn, Slack and Discord.
Without one, a shared link is a grey box, which is a real click-through cost for
something whose whole distribution plan is people forwarding a link.

Design rules: one number people remember, one sentence saying what it is, high
contrast, and nothing small enough to vanish in a timeline thumbnail.
"""
import pathlib

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
INK = (11, 11, 19)
INK_SOFT = (22, 22, 34)
WHITE = (247, 247, 250)
MUTED = (150, 150, 170)
TYRIAN = (176, 38, 132)
VIOLET = (124, 58, 237)

FONT_DIRS = [
    pathlib.Path(r"C:\Windows\Fonts"),
    pathlib.Path("/usr/share/fonts/truetype/dejavu"),
]


def font(names, size):
    """First font that exists, at the requested size. Falls back to default."""
    for directory in FONT_DIRS:
        for name in names:
            candidate = directory / name
            if candidate.exists():
                try:
                    return ImageFont.truetype(str(candidate), size)
                except OSError:
                    continue
    return ImageFont.load_default()


BOLD = ["segoeuib.ttf", "arialbd.ttf", "DejaVuSans-Bold.ttf"]
SEMI = ["segoeui.ttf", "arial.ttf", "DejaVuSans.ttf"]
MONO = ["consola.ttf", "cour.ttf", "DejaVuSansMono.ttf"]

img = Image.new("RGB", (W, H), INK)
d = ImageDraw.Draw(img)

# A soft diagonal wash so the card is not a flat rectangle. Cheap, and it reads
# as depth at thumbnail size where a gradient mesh would just turn to mud.
for y in range(H):
    t = y / H
    d.line([(0, y), (W, y)],
           fill=(int(11 + 11 * t), int(11 + 9 * t), int(19 + 18 * t)))

# Faint grid, the "technical instrument" cue.
for x in range(60, W, 60):
    d.line([(x, 0), (x, H)], fill=(26, 26, 40))
for y in range(60, H, 60):
    d.line([(0, y), (W, y)], fill=(26, 26, 40))

# Accent bar last, so the grid does not cut through it.
d.rectangle([0, 0, 10, H], fill=TYRIAN)

PAD = 72

# Eyebrow
d.text((PAD, 72), "TYRIAN DETECTION PACK", font=font(MONO, 22), fill=TYRIAN)

# The number is the whole point of the card.
d.text((PAD, 118), "3,633", font=font(BOLD, 150), fill=WHITE)
d.text((PAD + 6, 292), "Wazuh rules, compiled from SigmaHQ",
       font=font(BOLD, 46), fill=WHITE)

d.text((PAD + 6, 356),
       "Wazuh has no Sigma backend. This is the whole corpus,",
       font=font(SEMI, 30), fill=MUTED)
d.text((PAD + 6, 396),
       "already converted, refreshed weekly.",
       font=font(SEMI, 30), fill=MUTED)

# Command block: shows the install is trivial without needing to be read.
box_y = 462
d.rounded_rectangle([PAD, box_y, W - PAD, box_y + 72], radius=10,
                    fill=INK_SOFT, outline=(46, 46, 66))
d.text((PAD + 26, box_y + 24),
       "curl -LO .../sigmahq-wazuh-rules.xml  &&  wazuh-control restart",
       font=font(MONO, 25), fill=(196, 196, 214))

# Footer: proof line on the left, licence on the right.
foot_y = H - 74
claim = "96% of SigmaHQ translates"
claim_font = font(BOLD, 26)
d.text((PAD, foot_y), claim, font=claim_font, fill=VIOLET)
d.text((PAD + d.textlength(claim, font=claim_font) + 28, foot_y),
       "refusals listed, not approximated", font=font(SEMI, 26), fill=MUTED)

right = "MIT  ·  DRL 1.1"
rw = d.textlength(right, font=font(SEMI, 26))
d.text((W - PAD - rw, foot_y), right, font=font(SEMI, 26), fill=MUTED)

out = pathlib.Path(__file__).with_name("social-preview.png")
img.save(out, "PNG", optimize=True)
print(f"wrote {out} ({out.stat().st_size // 1024} KB, {W}x{H})")
