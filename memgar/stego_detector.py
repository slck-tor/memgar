"""
Steganography Detector — Layer 5 covert-channel detection.

Detects hidden payloads that bypass pattern matching and ML by hiding
malicious content in characters humans cannot see:

  1. Zero-width characters       (U+200B, U+200C, U+200D, U+FEFF, U+2060)
  2. Unicode tag characters      (U+E0000..U+E007F — invisible "tag" plane)
  3. Bidi override characters    (U+202A..U+202E — RTL/LTR override exploits)
  4. Homoglyph substitution      (Cyrillic 'а' for Latin 'a', etc.)
  5. Embedded base64 payloads    (long base64 runs decoding to suspicious text)
  6. Whitespace steganography    (variable-width spaces encoding bits)
  7. Encoded-text density        (excessive non-printable / control chars)

A single detector returns a StegoReport with risk_boost (0-40) and the
specific findings, suitable for adding as a ThreatMatch in the Analyzer.
"""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Character class definitions
# ---------------------------------------------------------------------------

# Invisible / zero-width — the classic prompt injection covert channel
_ZERO_WIDTH = {
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "⁡",  # FUNCTION APPLICATION
    "⁢",  # INVISIBLE TIMES
    "⁣",  # INVISIBLE SEPARATOR
    "⁤",  # INVISIBLE PLUS
    "﻿",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
}

# Bidi override — used in Trojan Source attacks (CVE-2021-42574 class)
_BIDI_OVERRIDE = {
    "‪",  # LRE — LEFT-TO-RIGHT EMBEDDING
    "‫",  # RLE — RIGHT-TO-LEFT EMBEDDING
    "‬",  # PDF — POP DIRECTIONAL FORMATTING
    "‭",  # LRO — LEFT-TO-RIGHT OVERRIDE
    "‮",  # RLO — RIGHT-TO-LEFT OVERRIDE
    "⁦",  # LRI — LEFT-TO-RIGHT ISOLATE
    "⁧",  # RLI — RIGHT-TO-LEFT ISOLATE
    "⁨",  # FSI — FIRST STRONG ISOLATE
    "⁩",  # PDI — POP DIRECTIONAL ISOLATE
}

# Homoglyph table — visually similar characters from non-Latin scripts.
# Each entry maps a "lookalike" → its Latin counterpart.
# Source: Unicode Confusables (UTS #39, abbreviated for hot-list).
_HOMOGLYPHS: dict = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ι": "i", "ν": "v",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    # Armenian
    "օ": "o", "ա": "a",
    # Mathematical alphanumeric symbols (𝐚𝐛𝐜...) — skip range, regex catches them
}

# Suspicious base64 minimum run length. Below this it's likely a coincidental
# alphanumeric word, not a payload.
_BASE64_MIN_RUN = 24
_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{%d,}={0,2}" % _BASE64_MIN_RUN)

# Suspicious keywords that, if found inside a base64-decoded payload,
# strongly suggest a hidden injection.
_BASE64_TRIGGER_KEYWORDS = (
    "ignore", "previous", "instruction", "system prompt", "jailbreak",
    "reveal", "bypass", "override", "admin", "secret", "exfiltrate",
    "act as", "you are now", "from now on", "disregard", "забудь",
    "новые инструкции", "olvida", "ignora",
)

# Variable-width spaces that aren't normal SP / TAB / NL — used to encode bits.
_EXOTIC_WHITESPACE = {
    " ",  # NO-BREAK SPACE
    " ",  # OGHAM SPACE MARK
    " ", " ", " ", " ", " ", " ",
    " ", " ", " ", " ", " ",  # EN/EM/THIN spaces
    " ",  # NARROW NO-BREAK SPACE
    " ",  # MEDIUM MATHEMATICAL SPACE
    "　",  # IDEOGRAPHIC SPACE
}


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

@dataclass
class StegoFinding:
    """A single steganographic finding within content."""
    technique: str            # e.g. "zero_width", "homoglyph", "base64_payload"
    severity: str             # "low" | "medium" | "high" | "critical"
    description: str
    sample: str = ""          # short evidence excerpt
    position: Optional[Tuple[int, int]] = None


@dataclass
class StegoReport:
    """Aggregate steganography analysis result."""
    detected: bool = False
    risk_boost: int = 0       # 0..40 — how much to bump risk_score
    findings: List[StegoFinding] = field(default_factory=list)
    cleaned_content: str = ""  # content with invisible chars stripped

    def add(self, finding: StegoFinding, boost: int) -> None:
        self.findings.append(finding)
        self.risk_boost = min(40, self.risk_boost + boost)
        self.detected = True

    @property
    def summary(self) -> str:
        if not self.detected:
            return "no steganography detected"
        techniques = ", ".join(sorted({f.technique for f in self.findings}))
        return f"{len(self.findings)} stego finding(s) — techniques: {techniques}"


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class StegoDetector:
    """Detects covert channels in memory entry content.

    Instantiate once and call ``analyze(content)`` per entry.
    Constant-cost (~0.1ms) for typical text.
    """

    def __init__(
        self,
        homoglyph_threshold: float = 0.05,
        bidi_strict: bool = True,
        base64_decode_check: bool = True,
        max_decode_bytes: int = 4096,
    ) -> None:
        self.homoglyph_threshold = homoglyph_threshold
        self.bidi_strict = bidi_strict
        self.base64_decode_check = base64_decode_check
        self.max_decode_bytes = max_decode_bytes

    # -----------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------

    def analyze(self, content: str) -> StegoReport:
        report = StegoReport()
        if not content:
            report.cleaned_content = content or ""
            return report

        cleaned_chars: List[str] = []

        # 1. Zero-width / invisible characters
        zw_count = 0
        zw_positions: List[int] = []
        for i, ch in enumerate(content):
            if ch in _ZERO_WIDTH:
                zw_count += 1
                zw_positions.append(i)
            else:
                cleaned_chars.append(ch)
        if zw_count > 0:
            severity = "critical" if zw_count >= 5 else "high"
            sample_pos = (zw_positions[0], zw_positions[-1] + 1)
            report.add(
                StegoFinding(
                    technique="zero_width",
                    severity=severity,
                    description=(
                        f"{zw_count} zero-width / invisible character(s) detected — "
                        "common prompt-injection covert channel"
                    ),
                    sample=content[max(0, zw_positions[0] - 8):zw_positions[0] + 8],
                    position=sample_pos,
                ),
                boost=25 if severity == "critical" else 18,
            )

        # 2. Bidi override characters
        bidi_count = sum(1 for ch in content if ch in _BIDI_OVERRIDE)
        if bidi_count > 0 and self.bidi_strict:
            report.add(
                StegoFinding(
                    technique="bidi_override",
                    severity="high",
                    description=(
                        f"{bidi_count} bidirectional-override character(s) — "
                        "Trojan Source style display deception"
                    ),
                ),
                boost=20,
            )

        # 3. Homoglyph mixing — Latin script with non-Latin lookalikes
        homo_count = 0
        homo_samples: Set[str] = set()
        latin_letters = 0
        for ch in content:
            if ch.isalpha():
                if ord(ch) < 128:
                    latin_letters += 1
                elif ch in _HOMOGLYPHS:
                    homo_count += 1
                    if len(homo_samples) < 5:
                        homo_samples.add(f"{ch!r}→{_HOMOGLYPHS[ch]!r}")

        # Only flag if there's enough Latin context to suggest mixing rather
        # than a legitimately non-Latin language.
        if homo_count > 0 and latin_letters >= 5:
            ratio = homo_count / max(1, latin_letters + homo_count)
            if ratio >= self.homoglyph_threshold or homo_count >= 3:
                severity = "high" if homo_count >= 5 else "medium"
                report.add(
                    StegoFinding(
                        technique="homoglyph",
                        severity=severity,
                        description=(
                            f"{homo_count} homoglyph(s) mixed with Latin script "
                            f"({ratio:.0%}) — visual deception attack"
                        ),
                        sample=", ".join(sorted(homo_samples)),
                    ),
                    boost=15 if severity == "high" else 8,
                )

        # 4. Embedded base64 payload with suspicious decoded contents
        if self.base64_decode_check:
            for match in _BASE64_RE.finditer(content):
                blob = match.group(0)
                if len(blob) > self.max_decode_bytes:
                    continue
                try:
                    decoded = base64.b64decode(blob, validate=False).decode(
                        "utf-8", errors="ignore"
                    )
                except Exception:
                    continue
                lower = decoded.lower()
                if any(kw in lower for kw in _BASE64_TRIGGER_KEYWORDS):
                    report.add(
                        StegoFinding(
                            technique="base64_payload",
                            severity="critical",
                            description=(
                                "Base64-encoded payload decodes to known "
                                "injection / jailbreak content"
                            ),
                            sample=decoded[:80],
                            position=(match.start(), match.end()),
                        ),
                        boost=30,
                    )
                    break  # one is enough

        # 5. Unicode tag plane (U+E0000..U+E007F) — invisible, machine-readable
        tag_count = sum(1 for ch in content if 0xE0000 <= ord(ch) <= 0xE007F)
        if tag_count > 0:
            report.add(
                StegoFinding(
                    technique="unicode_tag",
                    severity="critical",
                    description=(
                        f"{tag_count} Unicode tag-plane character(s) — "
                        "invisible covert command channel"
                    ),
                ),
                boost=30,
            )

        # 6. Exotic whitespace density
        exotic_ws = sum(1 for ch in content if ch in _EXOTIC_WHITESPACE)
        if exotic_ws >= 3:
            ratio = exotic_ws / max(1, len(content))
            if ratio >= 0.05 or exotic_ws >= 8:
                report.add(
                    StegoFinding(
                        technique="exotic_whitespace",
                        severity="medium",
                        description=(
                            f"{exotic_ws} exotic whitespace character(s) — "
                            "possible whitespace steganography"
                        ),
                    ),
                    boost=10,
                )

        # 7. Control-character density (non-print, non-newline, non-tab)
        ctrl_count = 0
        for ch in content:
            cat = unicodedata.category(ch)
            if cat == "Cc" and ch not in ("\n", "\r", "\t"):
                ctrl_count += 1
        if ctrl_count > 0:
            report.add(
                StegoFinding(
                    technique="control_char",
                    severity="medium",
                    description=f"{ctrl_count} control character(s) outside whitespace",
                ),
                boost=8,
            )

        # Cleaned content: strip invisibles + bidi + tag plane.
        # Useful for downstream pattern matching to re-run on the visible text.
        report.cleaned_content = "".join(
            ch for ch in content
            if ch not in _ZERO_WIDTH
            and ch not in _BIDI_OVERRIDE
            and not (0xE0000 <= ord(ch) <= 0xE007F)
        )
        return report

    # -----------------------------------------------------------------
    # Convenience
    # -----------------------------------------------------------------

    def normalize(self, content: str) -> str:
        """Strip invisibles and apply NFKC + homoglyph fold for re-analysis."""
        cleaned = self.analyze(content).cleaned_content
        nfkc = unicodedata.normalize("NFKC", cleaned)
        return "".join(_HOMOGLYPHS.get(ch, ch) for ch in nfkc)


__all__ = ["StegoDetector", "StegoReport", "StegoFinding"]
