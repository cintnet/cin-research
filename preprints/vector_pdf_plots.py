#!/usr/bin/env python3
"""
Pure-Python PDF 1.4 Vector Scientific Plotting & Statistical Interval Engine (`vector_pdf_plots.py`).

Generates publication-grade vector PDF figures (`%PDF-1.4`) using native PDF vector
paths and Standard-14 Type1 Helvetica / Helvetica-Bold / Symbol fonts (zero external
dependencies required), and provides exact asymmetric two-sided Wilson score binomial
confidence intervals and continuous run-level standard-error confidence intervals.
"""

from __future__ import annotations

import math
import re
import zlib
from pathlib import Path
from typing import Sequence


def wilson_ci_bounds(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """
    Returns exact two-sided Wilson score confidence interval endpoints (lo_pct, hi_pct)
    in percentage points [0.0, 100.0] for binomial count k out of n trials.
    Follows NIST/Wilson (1927): center = (p + z^2/(2n)) / (1 + z^2/n).
    """
    if n <= 0:
        return (0.0, 0.0)
    k_clamped = max(0, min(n, int(k)))
    p = k_clamped / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))) / denom
    lo = max(0.0, 100.0 * (center - half))
    hi = min(100.0, 100.0 * (center + half))
    return (round(lo, 2), round(hi, 2))


def wilson_ci_halfwidth(k: int, n: int, z: float = 1.96) -> float:
    """Returns the half-width (in percentage points) of the two-sided Wilson interval around the Wilson center."""
    if n <= 0:
        return 0.0
    k_clamped = max(0, min(n, int(k)))
    p = k_clamped / n
    z2 = z * z
    denom = 1.0 + z2 / n
    half = (z * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))) / denom
    return round(100.0 * half, 2)


def wilson_ci_dict(k: int, n: int, z: float = 1.96) -> dict:
    """
    Returns full binomial summary with raw count k, sample size n, observed percentage,
    Wilson center, Wilson half-width, and exact asymmetric [ci_low_pct, ci_high_pct] endpoints.
    """
    if n <= 0:
        return {
            "k": 0,
            "n": 0,
            "pct": 0.0,
            "wilson_center_pct": 0.0,
            "wilson_halfwidth_pct": 0.0,
            "ci_low_pct": 0.0,
            "ci_high_pct": 0.0,
        }
    k_clamped = max(0, min(n, int(k)))
    p = k_clamped / n
    z2 = z * z
    denom = 1.0 + z2 / n
    center = (p + z2 / (2.0 * n)) / denom
    half = (z * math.sqrt((p * (1.0 - p)) / n + z2 / (4.0 * n * n))) / denom
    lo = max(0.0, 100.0 * (center - half))
    hi = min(100.0, 100.0 * (center + half))
    return {
        "k": k_clamped,
        "n": int(n),
        "pct": round(100.0 * p, 2),
        "wilson_center_pct": round(100.0 * center, 2),
        "wilson_halfwidth_pct": round(100.0 * half, 2),
        "ci_low_pct": round(lo, 2),
        "ci_high_pct": round(hi, 2),
    }


def continuous_ci_dict(samples: Sequence[float], z: float = 1.96) -> dict:
    """
    Computes run-level sample mean, sample standard deviation (ddof=1),
    standard error, and normal [ci_low, ci_high] endpoints for continuous observations.
    """
    n = len(samples)
    if n == 0:
        return {"n": 0, "mean": 0.0, "sd": 0.0, "se": 0.0, "ci_halfwidth": 0.0, "ci_low": 0.0, "ci_high": 0.0}
    mean = sum(samples) / n
    if n < 2:
        return {
            "n": n,
            "mean": round(mean, 4),
            "sd": 0.0,
            "se": 0.0,
            "ci_halfwidth": 0.0,
            "ci_low": round(mean, 4),
            "ci_high": round(mean, 4),
        }
    var = sum((x - mean) ** 2 for x in samples) / (n - 1)
    sd = math.sqrt(max(0.0, var))
    se = sd / math.sqrt(n)
    hw = z * se
    return {
        "n": n,
        "mean": round(mean, 4),
        "sd": round(sd, 4),
        "se": round(se, 4),
        "ci_halfwidth": round(hw, 4),
        "ci_low": round(mean - hw, 4),
        "ci_high": round(mean + hw, 4),
    }


# Backward-compatible alias
continuous_se_ci_dict = continuous_ci_dict


# Adobe Standard-14 AFM character widths (in 1/1000 em) for Helvetica & Helvetica-Bold
_HELV_WIDTHS: dict[str, int] = {
    " ": 278, "!": 278, '"': 355, "#": 556, "$": 556, "%": 889, "&": 667, "'": 191,
    "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
    "0": 556, "1": 556, "2": 556, "3": 556, "4": 556, "5": 556, "6": 556, "7": 556,
    "8": 556, "9": 556, ":": 278, ";": 278, "<": 584, "=": 584, ">": 584, "?": 556,
    "@": 1015, "A": 667, "B": 667, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 500, "K": 667, "L": 556, "M": 833, "N": 722, "O": 778,
    "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944,
    "X": 667, "Y": 667, "Z": 611, "[": 278, "\\": 278, "]": 278, "^": 469, "_": 556,
    "`": 333, "a": 556, "b": 556, "c": 500, "d": 556, "e": 556, "f": 278, "g": 556,
    "h": 556, "i": 222, "j": 222, "k": 500, "l": 222, "m": 833, "n": 556, "o": 556,
    "p": 556, "q": 556, "r": 333, "s": 500, "t": 278, "u": 556, "v": 500, "w": 722,
    "x": 500, "y": 500, "z": 500, "{": 334, "|": 260, "}": 334, "~": 584,
    "\u2013": 556, "\u2014": 1000, "\u00b1": 584, "\u00d7": 584, "\u00f7": 584,
    "\u00b5": 556, "\u00b0": 400, "\u00b7": 278, "\u00b2": 333, "\u00b3": 333,
    "\u00b9": 333, "\u2022": 350, "\u2030": 1000,
}

_HELV_BOLD_WIDTHS: dict[str, int] = {
    " ": 278, "!": 333, '"': 474, "#": 556, "$": 556, "%": 889, "&": 722, "'": 238,
    "(": 333, ")": 333, "*": 389, "+": 584, ",": 278, "-": 333, ".": 278, "/": 278,
    "0": 556, "1": 556, "2": 556, "3": 556, "4": 556, "5": 556, "6": 556, "7": 556,
    "8": 556, "9": 556, ":": 333, ";": 333, "<": 584, "=": 584, ">": 584, "?": 611,
    "@": 975, "A": 722, "B": 722, "C": 722, "D": 722, "E": 667, "F": 611, "G": 778,
    "H": 722, "I": 278, "J": 556, "K": 722, "L": 611, "M": 833, "N": 722, "O": 778,
    "P": 667, "Q": 778, "R": 722, "S": 667, "T": 611, "U": 722, "V": 667, "W": 944,
    "X": 667, "Y": 667, "Z": 611, "[": 333, "\\": 278, "]": 333, "^": 584, "_": 556,
    "`": 333, "a": 556, "b": 611, "c": 556, "d": 611, "e": 556, "f": 333, "g": 611,
    "h": 611, "i": 278, "j": 278, "k": 556, "l": 278, "m": 889, "n": 611, "o": 611,
    "p": 611, "q": 611, "r": 389, "s": 556, "t": 333, "u": 611, "v": 556, "w": 778,
    "x": 556, "y": 556, "z": 500, "{": 389, "|": 280, "}": 389, "~": 584,
    "\u2013": 556, "\u2014": 1000, "\u00b1": 584, "\u00d7": 584, "\u00f7": 584,
    "\u00b5": 611, "\u00b0": 400, "\u00b7": 278, "\u00b2": 333, "\u00b3": 333,
    "\u00b9": 333, "\u2022": 350, "\u2030": 1000,
}

# Mapping from Unicode math / Greek characters outside WinAnsi to PDF Standard-14 /Symbol byte codes & widths
_SYMBOL_MAP: dict[str, tuple[int, int]] = {
    "\u0391": (0x41, 722),  # Alpha
    "\u0392": (0x42, 667),  # Beta
    "\u0393": (0x47, 603),  # Gamma
    "\u0394": (0x44, 612),  # Delta
    "\u0395": (0x45, 611),  # Epsilon
    "\u0398": (0x51, 741),  # Theta
    "\u039b": (0x4C, 686),  # Lambda
    "\u039e": (0x58, 645),  # Xi
    "\u03a0": (0x50, 768),  # Pi
    "\u03a3": (0x53, 592),  # Sigma
    "\u03a6": (0x46, 763),  # Phi
    "\u03a8": (0x59, 795),  # Psi
    "\u03a9": (0x57, 768),  # Omega
    "\u03b1": (0x61, 631),  # alpha
    "\u03b2": (0x62, 549),  # beta
    "\u03b3": (0x67, 411),  # gamma
    "\u03b4": (0x64, 494),  # delta
    "\u03b5": (0x65, 439),  # epsilon
    "\u03b6": (0x7A, 494),  # zeta
    "\u03b7": (0x68, 603),  # eta
    "\u03b8": (0x71, 521),  # theta
    "\u03b9": (0x69, 329),  # iota
    "\u03ba": (0x6B, 549),  # kappa
    "\u03bb": (0x6C, 549),  # lambda
    "\u03bc": (0x6D, 576),  # mu
    "\u03bd": (0x6E, 521),  # nu
    "\u03be": (0x78, 493),  # xi
    "\u03c0": (0x70, 549),  # pi
    "\u03c1": (0x72, 549),  # rho
    "\u03c2": (0x56, 439),  # final sigma
    "\u03c3": (0x73, 603),  # sigma
    "\u03c4": (0x74, 439),  # tau
    "\u03c5": (0x75, 576),  # upsilon
    "\u03c6": (0x66, 521),  # phi
    "\u03c7": (0x63, 549),  # chi
    "\u03c8": (0x79, 686),  # psi
    "\u03c9": (0x77, 686),  # omega
    "\u2264": (0xA3, 549),  # <=
    "\u2265": (0xB3, 549),  # >=
    "\u2260": (0xB9, 549),  # !=
    "\u2248": (0xBB, 549),  # approx
    "\u2192": (0xAE, 987),  # ->
    "\u2190": (0xAC, 987),  # <-
    "\u2194": (0xAB, 1042), # <->
    "\u221e": (0xA5, 713),  # infinity
    "\u2208": (0xCE, 713),  # element of
}

_GREEK_ASCII_NAMES: dict[str, str] = {
    "alpha": "\u03b1",
    "beta": "\u03b2",
    "gamma": "\u03b3",
    "delta": "\u03b4",
    "epsilon": "\u03b5",
    "sigma": "\u03c3",
    "rho": "\u03c1",
    "tau": "\u03c4",
    "lambda": "\u03bb",
    "theta": "\u03b8",
    "mu": "\u00b5",
    "eta": "\u03b7",
    "phi": "\u03c6",
    "psi": "\u03c8",
    "omega": "\u03c9",
}


def _normalize_plot_text(raw: str) -> str:
    """
    Normalizes plot titles, axis labels, ticks, and legend strings into clean,
    WinAnsi/Symbol-renderable typographic strings with zero '?' fallback glyphs.
    """
    s = str(raw)
    # Normalize Unicode minus and dashes
    s = s.replace("\u2212", "-").replace("---", "\u2014").replace("--", "\u2013")
    # Convert two-dot numeric/identifier ranges (e.g., 0.10..0.75, 1..S) to en-dash while preserving '...'
    s = re.sub(r"(?<!\.)\.\.(?!\.)", "\u2013", s)
    # Clean unambiguous ASCII math comparison/plus-minus operators
    s = s.replace("+/-", "\u00b1").replace("+-", "\u00b1")
    s = s.replace(">=", "\u2265").replace("<=", "\u2264").replace("!=", "\u2260").replace("->", "\u2192")
    # Map Greek mu directly to WinAnsi micro/mu when lowercase
    s = s.replace("\u03bc", "\u00b5")

    # Safely convert unambiguous lowercase ASCII Greek variable names in math contexts
    # (e.g., "rho = 1.45", "(tau)", "Weight lambda", "alpha=0.05") without touching hyphenated words like "Kendall-Tau"
    def _sub_greek(m: re.Match) -> str:
        word = m.group(1)
        sym = _GREEK_ASCII_NAMES.get(word)
        return sym if sym else word

    # Case 1: lowercase greek name adjacent to =, <, >, <=, >=, ~, or inside (...)
    s = re.sub(
        r"(?<![A-Za-z\-])(alpha|beta|gamma|delta|epsilon|sigma|rho|tau|lambda|theta|mu|eta|phi|psi|omega)(?=\s*(?:[=<>~\u2264\u2265\u2260\u2248\)]|_|\^|$))",
        _sub_greek,
        s,
    )
    s = re.sub(
        r"(?<=[\(\[,])\s*(alpha|beta|gamma|delta|epsilon|sigma|rho|tau|lambda|theta|mu|eta|phi|psi|omega)(?![A-Za-z\-])",
        lambda m: m.group(0).replace(m.group(1), _GREEK_ASCII_NAMES[m.group(1)]),
        s,
    )

    # Ensure any remaining exotic non-WinAnsi / non-Symbol Unicode characters never become '?'
    cleaned: list[str] = []
    for ch in s:
        if ch == "\n" or ch in _SYMBOL_MAP:
            cleaned.append(ch)
            continue
        try:
            ch.encode("cp1252")
            cleaned.append(ch)
        except UnicodeEncodeError:
            # Transliterate rare characters cleanly
            cleaned.append("-")
    return "".join(cleaned)


def measure_text_width(text: str, size: float, bold: bool = False) -> float:
    """Exact visual width in points using Adobe Standard-14 AFM glyph widths."""
    w_table = _HELV_BOLD_WIDTHS if bold else _HELV_WIDTHS
    total_units = 0
    for ch in text:
        if ch in _SYMBOL_MAP:
            total_units += _SYMBOL_MAP[ch][1]
        else:
            total_units += w_table.get(ch, 556)
    return (total_units / 1000.0) * size


def layout_text_width(text: str, size: float, bold: bool = False) -> float:
    """
    Conservative bounding width (max of exact AFM width and uniform char-width audit bound)
    used for wrapping, legend column spacing, and margin clamping so neither visual glyphs
    nor downstream PDF width heuristics ever collide or overflow.
    """
    exact = measure_text_width(text, size, bold)
    audit_bound = len(text) * size * (0.565 if bold else 0.525)
    return max(exact, audit_bound)


def _escape_pdf_bytes(raw_bytes: bytes) -> str:
    """Escapes raw single-byte font codes into a latin-1 string suitable for PDF (...) Tj."""
    out: list[str] = []
    for b in raw_bytes:
        if b == 0x5C:  # \
            out.append("\\\\")
        elif b == 0x28:  # (
            out.append("\\(")
        elif b == 0x29:  # )
            out.append("\\)")
        else:
            out.append(chr(b))
    return "".join(out)


def _pdf_escape(text: str) -> str:
    """Backward-compatible WinAnsi string escaper."""
    raw = str(text).encode("cp1252", errors="replace")
    return _escape_pdf_bytes(raw)


def _wrap_text_lines(
    text: str,
    max_width: float,
    size: float,
    bold: bool = False,
    max_lines: int = 3,
) -> list[str]:
    """
    Splits explicit newlines and word-wraps text so each line fits within `max_width`
    (measured with `layout_text_width`).
    """
    norm = _normalize_plot_text(text)
    paragraphs = [p.strip() for p in norm.split("\n") if p.strip()]
    if not paragraphs:
        return [""]

    lines: list[str] = []
    for para in paragraphs:
        if layout_text_width(para, size, bold) <= max_width:
            lines.append(para)
            continue
        words = para.split(" ")
        cur = ""
        for w in words:
            cand = w if not cur else f"{cur} {w}"
            if layout_text_width(cand, size, bold) <= max_width:
                cur = cand
            else:
                if cur:
                    lines.append(cur)
                # If a single token is wider than max_width, split on '/' or '-' if possible
                if layout_text_width(w, size, bold) > max_width and ("/" in w or "-" in w):
                    parts = re.split(r"(?<=[/\-])", w)
                    sub = ""
                    for pt in parts:
                        scand = pt if not sub else sub + pt
                        if layout_text_width(scand, size, bold) <= max_width:
                            sub = scand
                        else:
                            if sub:
                                lines.append(sub)
                            sub = pt
                    cur = sub
                else:
                    cur = w
        if cur:
            lines.append(cur)

    if len(lines) > max_lines and max_lines >= 1:
        # Merge trailing lines into the last allowed line
        kept = lines[: max_lines - 1]
        tail = " ".join(lines[max_lines - 1 :])
        kept.append(tail)
        return kept
    return lines


class VectorPDFCanvas:
    def __init__(self, width: float = 460.0, height: float = 210.0):
        self.width = float(width)
        self.height = float(height)
        self.ops: list[str] = []

    def set_stroke_rgb(self, r: float, g: float, b: float):
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG")

    def set_fill_rgb(self, r: float, g: float, b: float):
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")

    def set_line_width(self, w: float):
        self.ops.append(f"{w:.2f} w")

    def set_dash(self, pattern: Sequence[float] = (), phase: float = 0.0):
        pat_str = " ".join(f"{x:.1f}" for x in pattern)
        self.ops.append(f"[{pat_str}] {phase:.1f} d")

    def line(self, x1: float, y1: float, x2: float, y2: float):
        self.ops.append(f"{x1:.2f} {y1:.2f} m {x2:.2f} {y2:.2f} l S")

    def rect(self, x: float, y: float, w: float, h: float, fill: bool = True, stroke: bool = False):
        op = "B" if (fill and stroke) else ("f" if fill else "S")
        self.ops.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re {op}")

    def polygon(self, pts: Sequence[tuple[float, float]], fill: bool = True, stroke: bool = True):
        if len(pts) < 3:
            return
        x0, y0 = pts[0]
        segs = [f"{x0:.2f} {y0:.2f} m"]
        for x, y in pts[1:]:
            segs.append(f"{x:.2f} {y:.2f} l")
        op = "b" if (fill and stroke) else ("f" if fill else "s")
        segs.append(op)
        self.ops.append(" ".join(segs))

    def polyline(self, pts: Sequence[tuple[float, float]]):
        if len(pts) < 2:
            return
        x0, y0 = pts[0]
        segs = [f"{x0:.2f} {y0:.2f} m"]
        for x, y in pts[1:]:
            segs.append(f"{x:.2f} {y:.2f} l")
        segs.append("S")
        self.ops.append(" ".join(segs))

    def circle(self, cx: float, cy: float, r: float, fill: bool = True, stroke: bool = True):
        k = 0.5522847498 * r
        op = "B" if (fill and stroke) else ("f" if fill else "S")
        self.ops.append(
            f"{cx + r:.2f} {cy:.2f} m "
            f"{cx + r:.2f} {cy + k:.2f} {cx + k:.2f} {cy + r:.2f} {cx:.2f} {cy + r:.2f} c "
            f"{cx - k:.2f} {cy + r:.2f} {cx - r:.2f} {cy + k:.2f} {cx - r:.2f} {cy:.2f} c "
            f"{cx - r:.2f} {cy - k:.2f} {cx - k:.2f} {cy - r:.2f} {cx:.2f} {cy - r:.2f} c "
            f"{cx + k:.2f} {cy - r:.2f} {cx + r:.2f} {cy - k:.2f} {cx + r:.2f} {cy:.2f} c {op}"
        )

    def marker(
        self,
        cx: float,
        cy: float,
        r: float,
        shape_idx: int,
        color: tuple[float, float, float],
    ):
        """Draws a distinct vector marker shape per series index for colorblind + print clarity."""
        cr, cg, cb = color
        self.set_stroke_rgb(cr * 0.80, cg * 0.80, cb * 0.80)
        self.set_fill_rgb(cr, cg, cb)
        self.set_line_width(1.1)
        kind = shape_idx % 8
        if kind == 0:
            # Filled circle
            self.circle(cx, cy, r, fill=True, stroke=True)
        elif kind == 1:
            # Filled square
            s = r * 0.90
            self.rect(cx - s, cy - s, 2.0 * s, 2.0 * s, fill=True, stroke=True)
        elif kind == 2:
            # Upward triangle
            h = r * 1.18
            self.polygon([(cx, cy + h), (cx - h, cy - h * 0.78), (cx + h, cy - h * 0.78)], fill=True, stroke=True)
        elif kind == 3:
            # Diamond
            d = r * 1.22
            self.polygon([(cx, cy + d), (cx + d, cy), (cx, cy - d), (cx - d, cy)], fill=True, stroke=True)
        elif kind == 4:
            # Downward triangle (distinct shape for 5th series!)
            h = r * 1.18
            self.polygon([(cx, cy - h), (cx - h, cy + h * 0.78), (cx + h, cy + h * 0.78)], fill=True, stroke=True)
        elif kind == 5:
            # Hollow thick-ring circle (white center)
            self.set_fill_rgb(1.0, 1.0, 1.0)
            self.set_stroke_rgb(cr, cg, cb)
            self.set_line_width(1.4)
            self.circle(cx, cy, r, fill=True, stroke=True)
        elif kind == 6:
            # Hollow square (white center)
            s = r * 0.90
            self.set_fill_rgb(1.0, 1.0, 1.0)
            self.set_stroke_rgb(cr, cg, cb)
            self.set_line_width(1.4)
            self.rect(cx - s, cy - s, 2.0 * s, 2.0 * s, fill=True, stroke=True)
        else:
            # Bold cross / star
            d = r * 1.05
            self.set_stroke_rgb(cr, cg, cb)
            self.set_line_width(1.5)
            self.line(cx - d, cy - d, cx + d, cy + d)
            self.line(cx - d, cy + d, cx + d, cy - d)

    def _emit_single_line(
        self,
        x: float,
        y: float,
        line_str: str,
        size: float,
        bold: bool,
        align: str,
        color: tuple[float, float, float],
        clamp_margins: bool = True,
    ):
        base_font = "/F2" if bold else "/F1"
        vis_w = measure_text_width(line_str, size, bold)
        safe_w = layout_text_width(line_str, size, bold)
        tx = x
        if align == "center":
            tx = x - vis_w / 2.0
        elif align == "right":
            tx = x - vis_w

        if clamp_margins:
            if tx + safe_w > self.width - 3.0:
                tx = max(3.0, self.width - 3.0 - safe_w)
            if tx < 3.0:
                tx = 3.0

        r, g, b = color
        has_symbol = any(ch in _SYMBOL_MAP for ch in line_str)
        if not has_symbol:
            esc = _escape_pdf_bytes(line_str.encode("cp1252", errors="replace"))
            self.ops.append(
                f"BT {base_font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg "
                f"{tx:.2f} {y:.2f} Td ({esc}) Tj ET"
            )
            return

        # Split into runs of (is_symbol, text_chunk) within a single BT...ET text object
        runs: list[tuple[bool, str]] = []
        for ch in line_str:
            is_sym = ch in _SYMBOL_MAP
            if runs and runs[-1][0] == is_sym:
                runs[-1] = (is_sym, runs[-1][1] + ch)
            else:
                runs.append((is_sym, ch))

        parts = [f"BT {base_font} {size:.2f} Tf {r:.3f} {g:.3f} {b:.3f} rg {tx:.2f} {y:.2f} Td"]
        cur_font = base_font
        for is_sym, chunk in runs:
            target_font = "/F3" if is_sym else base_font
            if target_font != cur_font:
                parts.append(f"{target_font} {size:.2f} Tf")
                cur_font = target_font
            if is_sym:
                raw_b = bytes(_SYMBOL_MAP[c][0] for c in chunk)
            else:
                raw_b = chunk.encode("cp1252", errors="replace")
            parts.append(f"({_escape_pdf_bytes(raw_b)}) Tj")
        parts.append("ET")
        self.ops.append(" ".join(parts))

    def text(
        self,
        x: float,
        y: float,
        s: str,
        size: float = 8.5,
        bold: bool = False,
        align: str = "left",
        color: tuple[float, float, float] = (0.12, 0.15, 0.20),
    ):
        norm = _normalize_plot_text(s)
        lines = norm.split("\n")
        line_step = size * 1.18
        for idx, ln in enumerate(lines):
            self._emit_single_line(x, y - idx * line_step, ln, size, bold, align, color)

    def save(self, path: str | Path):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        # self.ops contains pure latin-1 byte values mapped 1:1 from WinAnsi / Symbol font codes
        content_bytes = "\n".join(self.ops).encode("latin-1")
        compressed = zlib.compress(content_bytes)

        objects: list[bytes] = []
        objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
        objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
        page_obj = (
            f"3 0 obj\n<< /Type /Page /Parent 2 0 R "
            f"/MediaBox [0 0 {self.width:.2f} {self.height:.2f}] "
            f"/Resources << /Font << /F1 4 0 R /F2 5 0 R /F3 6 0 R >> >> "
            f"/Contents 7 0 R >>\nendobj\n"
        ).encode("ascii")
        objects.append(page_obj)
        objects.append(
            b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>\nendobj\n"
        )
        objects.append(
            b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>\nendobj\n"
        )
        objects.append(
            b"6 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Symbol >>\nendobj\n"
        )
        stream_header = f"7 0 obj\n<< /Length {len(compressed)} /Filter /FlateDecode >>\nstream\n".encode("ascii")
        stream_footer = b"\nendstream\nendobj\n"
        objects.append(stream_header + compressed + stream_footer)

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets: list[int] = []
        for obj in objects:
            offsets.append(len(out))
            out.extend(obj)

        xref_pos = len(out)
        out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
        for off in offsets:
            out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
        out.extend(
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode("ascii")
        )
        payload = bytes(out)
        import time
        for attempt in range(6):
            try:
                p.write_bytes(payload)
                break
            except OSError:
                if attempt == 5:
                    raise
                time.sleep(0.15 * (attempt + 1))


# Backward-compatible class alias
PDFCanvas = VectorPDFCanvas


# 8 distinct, colorblind-safe scientific colors (Okabe-Ito / Tol academic palette)
PALETTE = [
    (0.12, 0.34, 0.60),  # 0: Deep navy blue (#1F5799)
    (0.78, 0.33, 0.11),  # 1: Burnt terracotta (#C7541C)
    (0.11, 0.50, 0.33),  # 2: Forest teal (#1C8054)
    (0.45, 0.25, 0.62),  # 3: Plum purple (#73409E)
    (0.74, 0.53, 0.08),  # 4: Warm ochre gold (#BD8714) — distinct 5th series!
    (0.64, 0.14, 0.23),  # 5: Slate crimson (#A3243B)
    (0.08, 0.52, 0.62),  # 6: Cerulean cyan (#14859E)
    (0.32, 0.37, 0.43),  # 7: Cool slate charcoal (#525E6E)
]


def _extract_point_ci(
    s: dict,
    idx: int,
    val: float,
    y_min: float,
    y_max: float,
) -> tuple[float | None, float | None]:
    """Extracts (lo, hi) confidence interval bounds for point `idx` of series `s`, if present."""
    if "ci_bounds" in s and s["ci_bounds"] and idx < len(s["ci_bounds"]):
        pair = s["ci_bounds"][idx]
        if pair is not None and len(pair) >= 2:
            return (float(pair[0]), float(pair[1]))
    if "ci_low" in s and "ci_high" in s and s["ci_low"] and idx < len(s["ci_low"]):
        return (float(s["ci_low"][idx]), float(s["ci_high"][idx]))
    if "ci" in s and s["ci"] and idx < len(s["ci"]) and float(s["ci"][idx]) > 0:
        hw = float(s["ci"][idx])
        if y_min == 0.0 and 100.0 <= y_max <= 115.0 and 0.0 <= val <= 100.0:
            p_obs = val / 100.0
            h_frac = hw / 100.0
            z2 = 1.96 * 1.96
            disc = p_obs * (1.0 - p_obs)
            if h_frac > 1e-6:
                n_est = max(
                    10.0,
                    z2 * (disc + math.sqrt(disc * disc + h_frac * h_frac)) / (2.0 * h_frac * h_frac),
                )
                denom = 1.0 + z2 / n_est
                center_pct = 100.0 * ((p_obs + z2 / (2.0 * n_est)) / denom)
                return (max(0.0, center_pct - hw), min(100.0, center_pct + hw))
        return (max(y_min, val - hw), val + hw)
    return (None, None)


def _compute_clean_ticks(
    y_min: float,
    y_max: float,
    data_min: float,
    data_max: float,
) -> tuple[float, float, list[float], str]:
    """
    Snaps [y_min, y_max] to human-friendly rounded tick intervals (multiples of 1, 2, 2.5, 5 * 10^k)
    so axis ticks are clean numbers (e.g., 0, 20, 40, 60, 80, 100 instead of 0, 26, 52, 79, 105).
    """
    lo_target = min(float(y_min), data_min)
    # Recognize callers passing y_max in [100, 115] purely as headroom above 0..100% percentage data
    if y_min == 0.0 and 100.0 <= y_max <= 115.0 and data_max <= 100.05:
        return (0.0, 100.0, [0.0, 20.0, 40.0, 60.0, 80.0, 100.0], "{:.0f}")

    hi_target = max(float(y_max), data_max)
    if hi_target <= lo_target + 1e-9:
        hi_target = lo_target + 1.0

    raw_span = hi_target - lo_target
    exp = math.floor(math.log10(raw_span)) - 1
    candidates: list[tuple[float, float, float, int]] = []
    for power in (exp - 1, exp, exp + 1, exp + 2):
        base = 10.0 ** power
        for mult in (1.0, 2.0, 2.5, 5.0):
            step = mult * base
            if step <= 0:
                continue
            t_lo = math.floor((lo_target + 1e-9) / step) * step
            if y_min == 0.0 and lo_target >= 0.0:
                t_lo = 0.0
            t_hi = math.ceil((hi_target - 1e-9) / step) * step
            n_intervals = int(round((t_hi - t_lo) / step))
            if 4 <= n_intervals <= 6:
                overshoot = (t_hi - hi_target) + (lo_target - t_lo)
                # Prefer 4 or 5 intervals and integer/clean steps (mult != 2.5 unless exact)
                penalty = overshoot / raw_span + (0.08 if mult == 2.5 else 0.0) + abs(n_intervals - 5) * 0.03
                candidates.append((penalty, t_lo, t_hi, n_intervals))

    if candidates:
        candidates.sort(key=lambda x: x[0])
        _, t_lo, t_hi, n_int = candidates[0]
        step = (t_hi - t_lo) / n_int
        ticks = [t_lo + i * step for i in range(n_int + 1)]
    else:
        t_lo, t_hi = lo_target, hi_target
        step = (t_hi - t_lo) / 4.0
        ticks = [t_lo + i * step for i in range(5)]

    # Format decimals cleanly
    if all(abs(t - round(t)) < 1e-6 for t in ticks) and (t_hi - t_lo) >= 4.0:
        fmt = "{:.0f}"
    elif all(abs(t * 10 - round(t * 10)) < 1e-5 for t in ticks):
        fmt = "{:.1f}"
    else:
        fmt = "{:.2f}"
    return (t_lo, t_hi, ticks, fmt)


def _plan_legend(
    names: Sequence[str],
    avail_w: float,
    swatch_pad: float,
) -> tuple[int, float, float, int, list[str]]:
    """
    Plans multi-column legend layout so every legend item fits cleanly within `avail_w`
    with zero horizontal overlaps and comfortable bottom margin.
    Returns (n_cols, col_w, font_size, n_rows, normalized_names).
    """
    norm_names = [_normalize_plot_text(nm).replace("\n", " ") for nm in names]
    n_items = max(1, len(norm_names))

    for fsize in (7.2, 6.8, 6.4):
        item_widths = [swatch_pad + layout_text_width(nm, fsize, bold=False) + 10.0 for nm in norm_names]
        max_iw = max(item_widths) if item_widths else 80.0
        if n_items >= 3 and max_iw <= avail_w / 3.0:
            n_cols = 3
            return (n_cols, avail_w / n_cols, fsize, math.ceil(n_items / n_cols), norm_names)
        if n_items >= 2 and max_iw <= avail_w / 2.0:
            n_cols = 2
            return (n_cols, avail_w / n_cols, fsize, math.ceil(n_items / n_cols), norm_names)
        if max_iw <= avail_w:
            return (1, avail_w, fsize, n_items, norm_names)

    return (1, avail_w, 6.2, n_items, norm_names)


def _layout_title_and_ylabel(
    title: str,
    y_label: str,
    canvas_w: float,
    content_top_y: float,
) -> tuple[list[str], float, float, list[str], float, float, float]:
    """
    Plans y_label and title placement above `content_top_y` with zero vertical/horizontal collisions.
    Returns (title_lines, title_size, title_top_y, ylabel_lines, ylabel_size, ylabel_top_y, canvas_h).
    """
    max_text_w = canvas_w - 28.0
    # Plan y_label
    yl_norm = _normalize_plot_text(y_label).replace("\n", " ")
    yl_size = 7.6
    if layout_text_width(yl_norm, yl_size, bold=False) > max_text_w:
        yl_size = 7.0
    yl_lines = _wrap_text_lines(yl_norm, max_text_w, yl_size, bold=False, max_lines=2)
    yl_line_h = yl_size * 1.20
    yl_bottom_y = content_top_y + 8.5
    yl_top_y = yl_bottom_y + (len(yl_lines) - 1) * yl_line_h

    # Plan title (1 line if it fits at 8.4..9.4pt, else balanced 2 lines)
    t_norm = _normalize_plot_text(title).replace("\n", " ")
    t_size = 9.3
    if layout_text_width(t_norm, t_size, bold=True) <= max_text_w:
        t_lines = [t_norm]
    elif layout_text_width(t_norm, 8.5, bold=True) <= max_text_w:
        t_size = 8.5
        t_lines = [t_norm]
    else:
        t_size = 8.8
        t_lines = _wrap_text_lines(t_norm, max_text_w, t_size, bold=True, max_lines=2)
        if any(layout_text_width(ln, t_size, bold=True) > max_text_w for ln in t_lines):
            t_size = 8.1
            t_lines = _wrap_text_lines(t_norm, max_text_w, t_size, bold=True, max_lines=2)

    t_line_h = t_size * 1.22
    t_bottom_y = yl_top_y + 13.5
    t_top_y = t_bottom_y + (len(t_lines) - 1) * t_line_h
    canvas_h = t_top_y + 14.0
    return (t_lines, t_size, t_top_y, yl_lines, yl_size, yl_top_y, canvas_h)


def draw_grouped_bar_pdf(
    path: str | Path,
    title: str,
    y_label: str,
    categories: Sequence[str],
    series: Sequence[dict],
    y_min: float = 0.0,
    y_max: float = 100.0,
):
    """
    Draws a publication-grade grouped bar chart with 95% CI error whiskers.
    Guarantees zero error-bar vs. digit collisions, clean human-rounded y-axis ticks,
    multi-row wrapped categories/legends, and zero MediaBox overflows.
    """
    canvas_w = 488.0
    n_cats = max(1, len(categories))
    n_ser = max(1, len(series))

    # Gather all values and CI endpoints first
    bar_records: list[list[tuple[float, float | None, float | None]]] = []
    data_min = float(y_min)
    data_max = float(y_min)
    for ci_idx in range(n_cats):
        cat_recs: list[tuple[float, float | None, float | None]] = []
        for s in series:
            val = float(s["values"][ci_idx])
            lo_val, hi_val = _extract_point_ci(s, ci_idx, val, y_min, y_max)
            cat_recs.append((val, lo_val, hi_val))
            data_min = min(data_min, val, lo_val if lo_val is not None else val)
            data_max = max(data_max, val, hi_val if hi_val is not None else val)
        bar_records.append(cat_recs)

    t_lo, t_hi, ticks, tick_fmt = _compute_clean_ticks(y_min, y_max, data_min, data_max)
    max_ytick_w = max(layout_text_width(tick_fmt.format(tv), 7.4, bold=False) for tv in ticks)
    left = max(48.0, 14.0 + max_ytick_w + 8.0)
    right = canvas_w - 16.0
    plot_w = right - left
    plot_h = 128.0
    span = max(1e-6, t_hi - t_lo)

    # Plan wrapped category labels
    group_w = plot_w / n_cats
    cat_slot_w = max(36.0, group_w - 7.0)
    cat_size = 7.3 if n_cats <= 5 else 6.8
    wrapped_cats = [_wrap_text_lines(str(cat), cat_slot_w, cat_size, bold=False, max_lines=3) for cat in categories]
    # Shrink slightly if any single word still exceeds slot width
    if any(layout_text_width(ln, cat_size) > cat_slot_w for cl in wrapped_cats for ln in cl):
        cat_size = max(6.2, cat_size - 0.6)
        wrapped_cats = [_wrap_text_lines(str(cat), cat_slot_w, cat_size, bold=False, max_lines=3) for cat in categories]
    max_cat_lines = max((len(cl) for cl in wrapped_cats), default=1)
    cat_line_h = cat_size * 1.18

    # Plan multi-row legend
    leg_cols, leg_col_w, leg_size, leg_rows, leg_names = _plan_legend(
        [str(s["name"]) for s in series],
        avail_w=plot_w,
        swatch_pad=13.0,
    )
    leg_row_h = 11.5
    leg_bottom_y = 12.0
    leg_top_y = leg_bottom_y + (leg_rows - 1) * leg_row_h

    # Bottom of plot frame sits cleanly above wrapped categories + legend block
    bottom = leg_top_y + 14.0 + max_cat_lines * cat_line_h + 7.0
    top = bottom + plot_h

    # Plan bar geometry, whiskers, and non-overlapping bar value labels (size 6.50pt)
    bar_w = min(24.0, (group_w * 0.76) / n_ser)
    bar_gap = 1.6 if bar_w >= 11.0 else 1.0
    val_label_size = 6.5
    placed_labels: list[tuple[float, float, float, str, float]] = []  # (x_left, x_right, y, txt, cx)
    max_visual_top = top

    for ci_idx in range(n_cats):
        gx = left + ci_idx * group_w + (group_w - bar_w * n_ser) / 2.0
        for s_idx in range(n_ser):
            val, lo_val, hi_val = bar_records[ci_idx][s_idx]
            clamped = max(t_lo, min(t_hi, val))
            bh = ((clamped - t_lo) / span) * plot_h
            bx = gx + s_idx * bar_w
            bw_draw = max(2.5, bar_w - bar_gap)
            cx = bx + bw_draw / 2.0

            y_top_elem = bottom + bh
            if lo_val is not None and hi_val is not None and hi_val > lo_val:
                y_hi = bottom + ((max(t_lo, hi_val) - t_lo) / span) * plot_h
                y_top_elem = max(y_top_elem, y_hi)

            lbl_str = f"{val:.1f}" if abs(val) < 1000 else f"{val:.0f}"
            lbl_w = layout_text_width(lbl_str, val_label_size, bold=False)
            lbl_x_left = cx - lbl_w / 2.0
            lbl_x_right = cx + lbl_w / 2.0
            lbl_y = y_top_elem + 5.2

            # Stagger upward if horizontally close to an adjacent bar's value label
            adjusted = True
            while adjusted:
                adjusted = False
                for px_l, px_r, py, _, _ in placed_labels:
                    horiz_close = not (lbl_x_right < px_l - 3.4 or lbl_x_left > px_r + 3.4)
                    if horiz_close and abs(lbl_y - py) < 5.0:
                        lbl_y = py + 6.4
                        adjusted = True

            placed_labels.append((lbl_x_left, lbl_x_right, lbl_y, lbl_str, cx))
            max_visual_top = max(max_visual_top, lbl_y + val_label_size)

    t_lines, t_size, t_top_y, yl_lines, yl_size, yl_top_y, canvas_h = _layout_title_and_ylabel(
        title, y_label, canvas_w, max_visual_top
    )

    # Emit PDF
    c = VectorPDFCanvas(canvas_w, canvas_h)
    c.set_fill_rgb(1.0, 1.0, 1.0)
    c.rect(0, 0, canvas_w, canvas_h, fill=True, stroke=False)

    # Title & Y-label
    for idx, ln in enumerate(t_lines):
        c._emit_single_line(canvas_w / 2.0, t_top_y - idx * (t_size * 1.22), ln, t_size, True, "center", (0.10, 0.13, 0.18))
    for idx, ln in enumerate(yl_lines):
        c._emit_single_line(14.0, yl_top_y - idx * (yl_size * 1.20), ln, yl_size, False, "left", (0.28, 0.32, 0.38))

    # Gridlines & clean human-rounded y-ticks
    c.set_line_width(0.45)
    for i, tv in enumerate(ticks):
        frac = (tv - t_lo) / span
        yy = bottom + frac * plot_h
        c.set_stroke_rgb(0.86, 0.88, 0.91)
        c.set_dash((2.0, 2.0) if i > 0 else ())
        c.line(left, yy, right, yy)
        c.set_dash(())
        c._emit_single_line(left - 6.0, yy - 2.6, tick_fmt.format(tv), 7.4, False, "right", (0.18, 0.21, 0.26))

    # Axes
    c.set_stroke_rgb(0.24, 0.27, 0.32)
    c.set_line_width(0.75)
    c.line(left, bottom, left, max(top, max_visual_top - 4.0))
    c.line(left, bottom, right, bottom)

    # Bars & CI whiskers
    lbl_cursor = 0
    for ci_idx in range(n_cats):
        gx = left + ci_idx * group_w + (group_w - bar_w * n_ser) / 2.0
        for s_idx in range(n_ser):
            val, lo_val, hi_val = bar_records[ci_idx][s_idx]
            clamped = max(t_lo, min(t_hi, val))
            bh = ((clamped - t_lo) / span) * plot_h
            bx = gx + s_idx * bar_w
            bw_draw = max(2.5, bar_w - bar_gap)
            cx = bx + bw_draw / 2.0

            r, g, b = PALETTE[s_idx % len(PALETTE)]
            c.set_fill_rgb(r, g, b)
            c.set_stroke_rgb(r * 0.75, g * 0.75, b * 0.75)
            c.set_line_width(0.5)
            c.rect(bx, bottom, bw_draw, bh, fill=True, stroke=True)

            if lo_val is not None and hi_val is not None and hi_val > lo_val:
                y_lo = bottom + ((max(t_lo, lo_val) - t_lo) / span) * plot_h
                y_hi = bottom + ((max(t_lo, hi_val) - t_lo) / span) * plot_h
                c.set_stroke_rgb(0.10, 0.12, 0.16)
                c.set_line_width(0.70)
                c.line(cx, max(bottom, y_lo), cx, y_hi)
                c.line(cx - 2.5, y_hi, cx + 2.5, y_hi)
                c.line(cx - 2.5, max(bottom, y_lo), cx + 2.5, max(bottom, y_lo))

            _, _, lbl_y, lbl_str, lbl_cx = placed_labels[lbl_cursor]
            lbl_cursor += 1
            c._emit_single_line(lbl_cx, lbl_y, lbl_str, val_label_size, False, "center", (0.18, 0.21, 0.26))

        # Wrapped X category label
        cat_cx = left + (ci_idx + 0.5) * group_w
        for l_idx, cln in enumerate(wrapped_cats[ci_idx]):
            c._emit_single_line(
                cat_cx,
                bottom - 11.5 - l_idx * cat_line_h,
                cln,
                cat_size,
                False,
                "center",
                (0.14, 0.17, 0.22),
            )

    # Multi-row legend
    for s_idx, nm in enumerate(leg_names):
        col = s_idx % leg_cols
        row = s_idx // leg_cols
        lx = left + col * leg_col_w
        ly = leg_top_y - row * leg_row_h
        r, g, b = PALETTE[s_idx % len(PALETTE)]
        c.set_fill_rgb(r, g, b)
        c.set_stroke_rgb(r * 0.75, g * 0.75, b * 0.75)
        c.set_line_width(0.45)
        c.rect(lx, ly - 0.5, 8.5, 6.0, fill=True, stroke=True)
        c._emit_single_line(lx + 12.0, ly, nm, leg_size, False, "left", (0.14, 0.17, 0.22))

    c.save(path)


def draw_line_chart_pdf(
    path: str | Path,
    title: str,
    x_label: str,
    y_label: str,
    x_ticks: Sequence[str],
    series: Sequence[dict],
    y_min: float = 0.0,
    y_max: float = 100.0,
):
    """
    Draws a multi-series vector line chart with distinct colorblind-safe colors,
    distinct marker shapes per series, optional asymmetric CI whiskers, clean rounded
    y-axis ticks, and dynamic multi-row legend inside MediaBox (zero negative y).
    """
    canvas_w = 480.0
    n_pts = max(2, len(x_ticks))

    # Gather data + optional CI bounds
    data_min = float(y_min)
    data_max = float(y_min)
    series_cis: list[list[tuple[float | None, float | None]]] = []
    for s in series:
        s_ci: list[tuple[float | None, float | None]] = []
        for xi, raw_v in enumerate(s["values"]):
            val = float(raw_v)
            lo_val, hi_val = _extract_point_ci(s, xi, val, y_min, y_max)
            s_ci.append((lo_val, hi_val))
            data_min = min(data_min, val, lo_val if lo_val is not None else val)
            data_max = max(data_max, val, hi_val if hi_val is not None else val)
        series_cis.append(s_ci)

    t_lo, t_hi, ticks, tick_fmt = _compute_clean_ticks(y_min, y_max, data_min, data_max)
    max_ytick_w = max(layout_text_width(tick_fmt.format(tv), 7.4, bold=False) for tv in ticks)
    left = max(48.0, 14.0 + max_ytick_w + 8.0)
    right = canvas_w - 22.0
    plot_w = right - left
    plot_h = 124.0
    span = max(1e-6, t_hi - t_lo)

    # Plan wrapped x_ticks so adjacent ticks and canvas edges never collide
    raw_step_w = plot_w / max(1, n_pts - 1)
    # Edge ticks (0 and n_pts-1) are centered near left/right, so constrain slot width or edge alignment
    xt_slot_w = max(34.0, raw_step_w - 8.0)
    xt_size = 7.2 if n_pts <= 6 else 6.6
    wrapped_xticks = [_wrap_text_lines(str(xt), xt_slot_w, xt_size, bold=False, max_lines=2) for xt in x_ticks]
    if any(layout_text_width(ln, xt_size) > xt_slot_w for xl in wrapped_xticks for ln in xl):
        xt_size = max(6.1, xt_size - 0.5)
        wrapped_xticks = [_wrap_text_lines(str(xt), xt_slot_w, xt_size, bold=False, max_lines=3) for xt in x_ticks]
    max_xt_lines = max((len(xl) for xl in wrapped_xticks), default=1)
    xt_line_h = xt_size * 1.18

    # Plan x_label (1 or 2 lines)
    xl_norm = _normalize_plot_text(x_label).replace("\n", " ")
    xl_size = 7.5
    xl_lines = _wrap_text_lines(xl_norm, plot_w, xl_size, bold=False, max_lines=2)
    xl_line_h = xl_size * 1.18

    # Plan multi-row legend (every row strictly >= 12pt inside MediaBox!)
    leg_cols, leg_col_w, leg_size, leg_rows, leg_names = _plan_legend(
        [str(s["name"]) for s in series],
        avail_w=plot_w,
        swatch_pad=18.0,
    )
    leg_row_h = 11.8
    leg_bottom_y = 12.0
    leg_top_y = leg_bottom_y + (leg_rows - 1) * leg_row_h

    xl_bottom_y = leg_top_y + 14.5
    xl_top_y = xl_bottom_y + (len(xl_lines) - 1) * xl_line_h
    bottom = xl_top_y + 13.0 + max_xt_lines * xt_line_h + 6.0
    top = bottom + plot_h

    # Ensure top headroom if any CI upper cap exceeds t_hi slightly
    max_visual_top = top + 4.0
    for s_idx, s in enumerate(series):
        for xi, raw_v in enumerate(s["values"]):
            val = float(raw_v)
            _, hi_val = series_cis[s_idx][xi]
            top_v = max(val, hi_val if hi_val is not None else val)
            yy = bottom + ((top_v - t_lo) / span) * plot_h
            max_visual_top = max(max_visual_top, yy + 4.0)

    t_lines, t_size, t_top_y, yl_lines, yl_size, yl_top_y, canvas_h = _layout_title_and_ylabel(
        title, y_label, canvas_w, max_visual_top
    )

    # Emit PDF
    c = VectorPDFCanvas(canvas_w, canvas_h)
    c.set_fill_rgb(1.0, 1.0, 1.0)
    c.rect(0, 0, canvas_w, canvas_h, fill=True, stroke=False)

    # Title, Y-label, X-label
    for idx, ln in enumerate(t_lines):
        c._emit_single_line(canvas_w / 2.0, t_top_y - idx * (t_size * 1.22), ln, t_size, True, "center", (0.10, 0.13, 0.18))
    for idx, ln in enumerate(yl_lines):
        c._emit_single_line(14.0, yl_top_y - idx * (yl_size * 1.20), ln, yl_size, False, "left", (0.28, 0.32, 0.38))
    for idx, ln in enumerate(xl_lines):
        c._emit_single_line((left + right) / 2.0, xl_top_y - idx * xl_line_h, ln, xl_size, False, "center", (0.28, 0.32, 0.38))

    # Gridlines & clean human-rounded y-ticks
    c.set_line_width(0.45)
    for i, tv in enumerate(ticks):
        frac = (tv - t_lo) / span
        yy = bottom + frac * plot_h
        c.set_stroke_rgb(0.86, 0.88, 0.91)
        c.set_dash((2.0, 2.0) if i > 0 else ())
        c.line(left, yy, right, yy)
        c.set_dash(())
        c._emit_single_line(left - 6.0, yy - 2.6, tick_fmt.format(tv), 7.4, False, "right", (0.18, 0.21, 0.26))

    # Axes
    c.set_stroke_rgb(0.24, 0.27, 0.32)
    c.set_line_width(0.75)
    c.line(left, bottom, left, max(top, max_visual_top - 2.0))
    c.line(left, bottom, right, bottom)

    # X-axis ticks & wrapped labels (with small horizontal inset on plot points so end markers/whiskers breathe)
    x_pad = 8.0
    usable_plot_w = plot_w - 2.0 * x_pad
    for xi in range(len(x_ticks)):
        xx = left + x_pad + (xi / (n_pts - 1)) * usable_plot_w
        c.set_stroke_rgb(0.24, 0.27, 0.32)
        c.set_line_width(0.70)
        c.line(xx, bottom, xx, bottom - 3.0)
        for l_idx, xln in enumerate(wrapped_xticks[xi]):
            c._emit_single_line(
                xx,
                bottom - 11.2 - l_idx * xt_line_h,
                xln,
                xt_size,
                False,
                "center",
                (0.14, 0.17, 0.22),
            )

    # Optional CI whiskers first (behind lines & markers for visual clarity)
    n_ser = max(1, len(series))
    for s_idx, s in enumerate(series):
        r, g, b = PALETTE[s_idx % len(PALETTE)]
        # Slight sub-pixel x-jitter across series when CIs exist so overlapping whiskers remain distinguishable
        jitter = ((s_idx - (n_ser - 1) / 2.0) * 1.1) if n_ser > 1 else 0.0
        for xi in range(len(s["values"])):
            lo_val, hi_val = series_cis[s_idx][xi]
            if lo_val is not None and hi_val is not None and hi_val > lo_val:
                xx = left + x_pad + (xi / (n_pts - 1)) * usable_plot_w + jitter
                y_lo = bottom + ((max(t_lo, lo_val) - t_lo) / span) * plot_h
                y_hi = bottom + ((max(t_lo, hi_val) - t_lo) / span) * plot_h
                c.set_stroke_rgb(r * 0.82, g * 0.82, b * 0.82)
                c.set_line_width(0.65)
                c.line(xx, max(bottom, y_lo), xx, y_hi)
                c.line(xx - 2.0, y_hi, xx + 2.0, y_hi)
                c.line(xx - 2.0, max(bottom, y_lo), xx + 2.0, max(bottom, y_lo))

    # Series lines & distinct markers
    for s_idx, s in enumerate(series):
        col_rgb = PALETTE[s_idx % len(PALETTE)]
        r, g, b = col_rgb
        c.set_stroke_rgb(r, g, b)
        c.set_line_width(1.55)
        pts: list[tuple[float, float]] = []
        for xi, raw_v in enumerate(s["values"]):
            xx = left + x_pad + (xi / (n_pts - 1)) * usable_plot_w
            clamped = max(t_lo, float(raw_v))
            yy = bottom + ((clamped - t_lo) / span) * plot_h
            pts.append((xx, yy))
        c.polyline(pts)
        for xx, yy in pts:
            c.marker(xx, yy, 2.35, s_idx, col_rgb)

    # Multi-row legend with matching line + marker shape
    for s_idx, nm in enumerate(leg_names):
        col = s_idx % leg_cols
        row = s_idx // leg_cols
        lx = left + col * leg_col_w
        ly = leg_top_y - row * leg_row_h
        col_rgb = PALETTE[s_idx % len(PALETTE)]
        r, g, b = col_rgb
        c.set_stroke_rgb(r, g, b)
        c.set_line_width(1.50)
        c.line(lx, ly + 2.2, lx + 13.0, ly + 2.2)
        c.marker(lx + 6.5, ly + 2.2, 2.1, s_idx, col_rgb)
        c._emit_single_line(lx + 17.0, ly, nm, leg_size, False, "left", (0.14, 0.17, 0.22))

    c.save(path)
