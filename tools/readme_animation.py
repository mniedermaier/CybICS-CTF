"""
Draw docs/pics/cybics-mgmt.gif, the animated diagram at the top of the README.

    python3 tools/readme_animation.py        # needs Pillow, ffmpeg and the Inter font

Every frame is drawn from scratch at twice the size and scaled down, so the
lines are smooth; ffmpeg then builds one palette for the whole loop. The
look follows the CybICS landing page: dark slate, a faint blueprint grid,
CybICS orange as the only accent.
"""
import math
import os
import shutil
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

OUT = os.path.join(os.path.dirname(__file__), "..", "docs", "pics", "cybics-mgmt.gif")
W, H = 960, 540          # output size
S = 2                    # drawn at S times the size, then scaled down
FPS = 12
SECONDS = 11.0

BG = (14, 16, 20)
GRID = (255, 107, 0, 18)
CARD = (27, 30, 37)
CARD_HI = (36, 40, 49)
BORDER = (58, 63, 74)
TEXT = (226, 229, 235)
MUTED = (139, 146, 160)
ORANGE = (255, 107, 0)
ORANGE_SOFT = (255, 160, 90)
GREEN = (61, 220, 113)
RED = (255, 92, 92)

FONT_DIR = "/usr/share/fonts/opentype/inter"


def font(weight, size):
    for name in (f"Inter-{weight}.otf", "Inter-Regular.otf"):
        path = os.path.join(FONT_DIR, name)
        if os.path.exists(path):
            return ImageFont.truetype(path, size * S)
    return ImageFont.load_default()


F_TITLE = font("Bold", 17)
F_LABEL = font("SemiBold", 13)
F_SMALL = font("Regular", 11)
F_TINY = font("Medium", 10)
F_CAPTION = font("SemiBold", 15)
F_STEP = font("Bold", 15)

# Layout, in output pixels.
PI = (395, 205, 565, 335)                       # the CybICS-mgmt Raspberry Pi
PI_C = ((PI[0] + PI[2]) / 2, (PI[1] + PI[3]) / 2)
ORGANISER = (40, 70, 250, 170)
PROJECTOR = (40, 300, 250, 440)
BOARDS = [(705, 40 + i * 92, 925, 112 + i * 92) for i in range(3)]
LAPTOPS = [(705, 330 + i * 76, 925, 392 + i * 76) for i in range(2)]
DEVICES = BOARDS + LAPTOPS
TEAMS = ["Red Team", "Blue Team", "PLC Pwners"]

PHASES = [  # start second, step number, caption
    (0.0, 1, "The Pi hosts CybICS-mgmt and its own Wi-Fi network, cybics-mgmt"),
    (1.6, 2, "CybICS boards see cybics-mgmt and enrol on their own"),
    (4.2, 3, "Virtual CybICS on laptops connect with the event's join code"),
    (5.8, 4, "Solves come in, and the projector scoreboard updates live"),
    (8.0, 5, "The organiser sends signed actions; each device allows them first"),
]
BOARD_JOIN = [1.8, 2.5, 3.2]       # second each board connects
LAPTOP_JOIN = [4.4, 4.9]
SOLVES = [(6.0, 0, 0), (6.35, 3, 1), (6.7, 1, 2), (7.05, 4, 1), (7.4, 2, 0)]   # (second, device, team)
JOB = 8.4                           # organiser presses "restart" for board 2


def s(*values):
    return [v * S for v in values]


def ease(x):
    x = min(1.0, max(0.0, x))
    return x * x * (3 - 2 * x)


def lerp(a, b, t):
    return a + (b - a) * t


def mix(c1, c2, t):
    return tuple(int(lerp(a, b, t)) for a, b in zip(c1, c2))


def card(d, box, fill=CARD, outline=BORDER, width=1, radius=12):
    d.rounded_rectangle(s(*box), radius=radius * S, fill=fill, outline=outline, width=width * S)


def text(d, xy, value, fnt, fill=TEXT, anchor="la"):
    d.text(s(*xy), value, font=fnt, fill=fill, anchor=anchor)


def grid(img):
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    g = ImageDraw.Draw(layer)
    for x in range(0, W, 32):
        g.line(s(x, 0, x, H), fill=GRID, width=S)
    for y in range(0, H, 32):
        g.line(s(0, y, W, y), fill=GRID, width=S)
    img.alpha_composite(layer)


def anchor_of(box, side):
    x0, y0, x1, y1 = box
    return {"left": (x0, (y0 + y1) / 2), "right": (x1, (y0 + y1) / 2),
            "top": ((x0 + x1) / 2, y0), "bottom": ((x0 + x1) / 2, y1)}[side]


def device_anchor(i):
    return anchor_of(DEVICES[i], "left")


def pi_anchor_towards(point):
    x, y = point
    return (PI[2] if x > PI_C[0] else PI[0], lerp(PI[1] + 22, PI[3] - 22, (y - 40) / 440))


def dashed(d, p0, p1, color, width=2, dash=7, gap=6, offset=0.0):
    (x0, y0), (x1, y1) = p0, p1
    length = math.hypot(x1 - x0, y1 - y0)
    pos = -(offset % (dash + gap))
    while pos < length:
        a, b = max(pos, 0), min(pos + dash, length)
        if b > a:
            d.line(s(lerp(x0, x1, a / length), lerp(y0, y1, a / length),
                     lerp(x0, x1, b / length), lerp(y0, y1, b / length)), fill=color, width=width * S)
        pos += dash + gap


def packet(d, p0, p1, t, color, label=None, radius=6):
    if not 0 <= t <= 1:
        return
    t = ease(t)
    x, y = lerp(p0[0], p1[0], t), lerp(p0[1], p1[1], t)
    glow = mix(BG, color, 0.35)
    d.ellipse(s(x - radius * 2, y - radius * 2, x + radius * 2, y + radius * 2), fill=glow)
    d.ellipse(s(x - radius, y - radius, x + radius, y + radius), fill=color)
    if label:
        text(d, (x, y - radius - 6), label, F_TINY, fill=color, anchor="md")


def draw_pi(d, t):
    on = ease(t / 0.8)
    card(d, PI, fill=mix(CARD, CARD_HI, on), outline=mix(BORDER, ORANGE, on), width=2, radius=14)
    # A stylised board: SoC, RAM, GPIO header.
    x0, y0 = PI[0] + 16, PI[1] + 46
    d.rounded_rectangle(s(x0, y0, x0 + 34, y0 + 34), radius=4 * S, fill=(44, 48, 58))
    d.rectangle(s(x0 + 44, y0 + 4, x0 + 64, y0 + 30), fill=(44, 48, 58))
    for k in range(9):
        d.ellipse(s(x0 + 2 + k * 8, y0 - 12, x0 + 6 + k * 8, y0 - 8), fill=mix(MUTED, ORANGE_SOFT, on))
    led = GREEN if on > 0.5 and int(t * 4) % 2 == 0 else (40, 90, 60)
    d.ellipse(s(PI[2] - 22, PI[1] + 12, PI[2] - 14, PI[1] + 20), fill=led)
    text(d, (PI[0] + 92, PI[1] + 50), "CybICS-mgmt", F_LABEL)
    text(d, (PI[0] + 92, PI[1] + 68), "fleet · CTF", F_SMALL, fill=MUTED)
    text(d, (PI[0] + 92, PI[1] + 84), "10.42.0.1", F_SMALL, fill=MUTED)
    text(d, ((PI[0] + PI[2]) / 2, PI[3] + 18), "Raspberry Pi 3 / 4 / 5", F_SMALL, fill=MUTED, anchor="mm")


def draw_wifi(d, t):
    if t < 0.4:
        return
    cx, cy = PI_C[0], PI[1] - 8
    for k in range(3):
        phase = ((t - 0.4) * 0.7 + k / 3) % 1
        r = 18 + phase * 70
        alpha = (1 - phase) * min(1, (t - 0.4) * 2)
        color = mix(BG, ORANGE, alpha * 0.9)
        d.arc(s(cx - r, cy - r, cx + r, cy + r), start=215, end=325, fill=color, width=2 * S)
    text(d, (cx, cy - 92), "Wi-Fi  cybics-mgmt", F_LABEL, fill=mix(BG, ORANGE, min(1, (t - 0.4) * 2)),
         anchor="mm")


def draw_board(d, i, joined, t):
    box = BOARDS[i]
    card(d, box, outline=mix(BORDER, ORANGE_SOFT, joined * 0.6))
    x0, y0 = box[0] + 12, box[1] + 14
    # PCB with the Pi Zero, a display and the USB Wi-Fi dongle.
    d.rounded_rectangle(s(x0, y0, x0 + 54, y0 + 44), radius=4 * S, fill=(22, 70, 52))
    d.rectangle(s(x0 + 6, y0 + 6, x0 + 30, y0 + 18), fill=(16, 32, 26))
    d.rectangle(s(x0 + 6, y0 + 24, x0 + 46, y0 + 38), fill=(40, 46, 56))
    d.rectangle(s(x0 + 54, y0 + 14, x0 + 66, y0 + 24), fill=mix((70, 74, 84), ORANGE, joined))
    text(d, (box[0] + 86, box[1] + 12), f"Board {i + 1}", F_LABEL)
    text(d, (box[0] + 86, box[1] + 31), "Pi Zero 2 W + PCB", F_SMALL, fill=MUTED)
    status = "online" if joined >= 1 else ("enrolling" if joined > 0 else "offline")
    color = GREEN if joined >= 1 else (ORANGE_SOFT if joined > 0 else MUTED)
    d.ellipse(s(box[0] + 86, box[1] + 53, box[0] + 94, box[1] + 61), fill=color)
    text(d, (box[0] + 100, box[1] + 57), status, F_TINY, fill=color, anchor="lm")


def draw_laptop(d, i, joined):
    box = LAPTOPS[i]
    card(d, box, outline=mix(BORDER, ORANGE_SOFT, joined * 0.6))
    x0, y0 = box[0] + 14, box[1] + 12
    d.rounded_rectangle(s(x0, y0, x0 + 46, y0 + 30), radius=3 * S, fill=(40, 46, 56),
                        outline=mix(MUTED, ORANGE_SOFT, joined), width=S)
    d.rectangle(s(x0 - 6, y0 + 32, x0 + 52, y0 + 36), fill=(70, 74, 84))
    text(d, (box[0] + 80, box[1] + 22), f"Laptop {i + 1}", F_LABEL)
    text(d, (box[0] + 80, box[1] + 40), "virtual CybICS (Docker)", F_SMALL, fill=MUTED)


def draw_organiser(d, job_t):
    card(d, ORGANISER)
    x0, y0 = ORGANISER[0] + 14, ORGANISER[1] + 14
    d.rounded_rectangle(s(x0, y0, ORGANISER[2] - 14, y0 + 16), radius=4 * S, fill=(40, 46, 56))
    for k, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse(s(x0 + 6 + k * 10, y0 + 5, x0 + 12 + k * 10, y0 + 11), fill=c)
    text(d, (x0 + 44, y0 + 8), "/admin · Fleet", F_TINY, fill=MUTED, anchor="lm")
    text(d, (x0, y0 + 34), "Organiser", F_LABEL)
    pressed = 0 <= job_t < 0.25
    bx = (x0, y0 + 50, x0 + 120, y0 + 72)
    d.rounded_rectangle(s(*bx), radius=6 * S, fill=ORANGE if pressed else mix(CARD, ORANGE, 0.25),
                        outline=ORANGE, width=S)
    text(d, ((bx[0] + bx[2]) / 2, (bx[1] + bx[3]) / 2), "Restart Board 2", F_TINY,
         fill=(14, 16, 20) if pressed else ORANGE_SOFT, anchor="mm")


def draw_projector(d, scores):
    card(d, PROJECTOR)
    text(d, (PROJECTOR[0] + 14, PROJECTOR[1] + 20), "Scoreboard", F_LABEL)
    text(d, (PROJECTOR[2] - 14, PROJECTOR[1] + 20), "live", F_TINY, fill=GREEN, anchor="ra")
    order = sorted(range(3), key=lambda k: -scores[k])
    top = max(max(scores), 1)
    for rank, k in enumerate(order):
        y = PROJECTOR[1] + 40 + rank * 32
        text(d, (PROJECTOR[0] + 14, y + 4), f"{rank + 1}", F_SMALL, fill=ORANGE if rank == 0 else MUTED)
        text(d, (PROJECTOR[0] + 30, y + 4), TEAMS[k], F_SMALL)
        bar_w = 150 * scores[k] / top if scores[k] else 0
        d.rounded_rectangle(s(PROJECTOR[0] + 30, y + 22, PROJECTOR[0] + 180, y + 26), radius=2 * S,
                            fill=(44, 48, 58))
        if bar_w >= 6:   # narrower than its rounded ends: not drawn yet
            d.rounded_rectangle(s(PROJECTOR[0] + 30, y + 22, PROJECTOR[0] + 30 + bar_w, y + 26),
                                radius=2 * S, fill=ORANGE)
        text(d, (PROJECTOR[2] - 14, y + 4), f"{int(scores[k])}", F_SMALL, fill=TEXT, anchor="ra")


def draw_caption(d, t):
    current = [p for p in PHASES if p[0] <= t][-1]
    fade = ease((t - current[0]) / 0.35)
    y = H - 46
    d.rounded_rectangle(s(40, y, W - 40, y + 32), radius=10 * S, fill=CARD, outline=BORDER, width=S)
    d.ellipse(s(52, y + 6, 72, y + 26), fill=ORANGE)
    text(d, (62, y + 16), str(current[1]), F_STEP, fill=BG, anchor="mm")
    text(d, (84, y + 16), current[2], F_CAPTION, fill=mix(CARD, TEXT, fade), anchor="lm")
    # Progress through the five steps.
    for k in range(5):
        x = W - 140 + k * 18
        d.ellipse(s(x, y + 12, x + 8, y + 20), fill=ORANGE if k < current[1] else BORDER)


def frame(t):
    img = Image.new("RGBA", (W * S, H * S), BG + (255,))
    grid(img)
    d = ImageDraw.Draw(img)
    text(d, (W / 2, 26), "How CybICS-mgmt runs a classroom", F_TITLE, anchor="mm")

    joined_boards = [ease((t - j) / 0.9) if t >= j else 0 for j in BOARD_JOIN]
    joined_laptops = [ease((t - j) / 0.6) if t >= j else 0 for j in LAPTOP_JOIN]
    joined = joined_boards + joined_laptops

    # Links: dashed while enrolling, solid once in; heartbeats ride on them.
    for i, amount in enumerate(joined):
        if amount <= 0:
            continue
        p_dev = device_anchor(i)
        p_pi = pi_anchor_towards(p_dev)
        color = mix(BG, ORANGE_SOFT if i < 3 else MUTED, 0.35 + 0.35 * amount)
        dashed(d, p_dev, p_pi, color, offset=t * 30 * (1 if i < 3 else -1))
        if amount >= 1:   # a heartbeat every few seconds
            hb = ((t - (BOARD_JOIN + LAPTOP_JOIN)[i]) * 0.5) % 1
            packet(d, p_dev, p_pi, hb * 1.4, mix(BG, TEXT, 0.55), radius=3)
    for i, j in enumerate(BOARD_JOIN):
        packet(d, device_anchor(i), pi_anchor_towards(device_anchor(i)), (t - j) / 0.8, ORANGE_SOFT,
               "enrol" if i == 0 else None)
    for i, j in enumerate(LAPTOP_JOIN):
        p = device_anchor(3 + i)
        packet(d, p, pi_anchor_towards(p), (t - j) / 0.7, ORANGE_SOFT, "join code" if i == 0 else None)

    # Organiser and projector hang off the Pi as well.
    org_p, proj_p = anchor_of(ORGANISER, "right"), anchor_of(PROJECTOR, "right")
    dashed(d, org_p, (PI[0], PI[1] + 30), mix(BG, MUTED, 0.6), offset=-t * 20)
    dashed(d, proj_p, (PI[0], PI[3] - 30), mix(BG, MUTED, 0.6), offset=t * 20)

    # Solves: device -> Pi -> scoreboard.
    scores = [0.0, 0.0, 0.0]
    for when, dev, team in SOLVES:
        p = device_anchor(dev)
        packet(d, p, pi_anchor_towards(p), (t - when) / 0.6, ORANGE, "flag")
        packet(d, (PI[0], PI[3] - 30), proj_p, (t - when - 0.6) / 0.5, ORANGE)
        scores[team] += 100 * ease((t - when - 1.1) / 0.5)

    # The signed job and its result.
    packet(d, org_p, (PI[0], PI[1] + 30), (t - JOB) / 0.5, ORANGE, "restart")
    b2 = device_anchor(1)
    packet(d, pi_anchor_towards(b2), b2, (t - JOB - 0.5) / 0.7, ORANGE, "signed job • seq 7")
    packet(d, b2, pi_anchor_towards(b2), (t - JOB - 1.5) / 0.7, GREEN, "done")
    packet(d, (PI[0], PI[1] + 30), org_p, (t - JOB - 2.2) / 0.5, GREEN)

    draw_wifi(d, t)
    draw_pi(d, t)
    for i in range(3):
        draw_board(d, i, joined_boards[i], t)
    for i in range(2):
        draw_laptop(d, i, joined_laptops[i])
    draw_organiser(d, t - JOB)
    draw_projector(d, scores)
    if JOB + 1.2 <= t <= JOB + 1.6:      # board 2 restarts
        box = BOARDS[1]
        text(d, (box[2] - 12, box[1] + 22), "restarting…", F_TINY, fill=ORANGE_SOFT, anchor="ra")
    elif t > JOB + 1.6:
        box = BOARDS[1]
        text(d, (box[2] - 12, box[1] + 22), "✓ restarted", F_TINY, fill=GREEN, anchor="ra")
    draw_caption(d, t)
    return img.resize((W, H), Image.LANCZOS).convert("RGB")


def main():
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        sys.exit("ffmpeg is needed to build the GIF.")
    frames = int(SECONDS * FPS)
    with tempfile.TemporaryDirectory() as tmp:
        for n in range(frames):
            frame(n / FPS).save(os.path.join(tmp, f"f{n:04d}.png"))
        palette = os.path.join(tmp, "palette.png")
        # Fixed arguments and our own temporary files only.
        subprocess.run([ffmpeg, "-loglevel", "error", "-y", "-framerate", str(FPS), "-i",  # noqa: S603
                        os.path.join(tmp, "f%04d.png"), "-vf", "palettegen=max_colors=96:stats_mode=full",
                        palette], check=True)
        subprocess.run([ffmpeg, "-loglevel", "error", "-y", "-framerate", str(FPS), "-i",  # noqa: S603
                        os.path.join(tmp, "f%04d.png"), "-i", palette, "-lavfi",
                        "paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle", "-loop", "0",
                        os.path.abspath(OUT)], check=True)
    print(f"{os.path.abspath(OUT)}: {os.path.getsize(OUT) // 1024} KB, {frames} frames")


if __name__ == "__main__":
    main()
