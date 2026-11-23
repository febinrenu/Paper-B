"""RQ1 detectors: content an agent reads but a human reviewer does not see, plus visible injection-style text.

Three detectors, all pure functions over a file's text:

1. scan_unicode(text): invisible / format code points, grouped into runs, each labelled
     benign      legitimate use (BOM at start, emoji ZWJ sequence, emoji variation selector,
                 subdivision-flag tag sequence, ZWNJ/ZWJ/bidi marks inside RTL or Indic text)
     artifact    isolated zero-width space / word joiner / soft hyphen, typical of copy-paste
     suspicious  everything that can carry a hidden payload (tag characters, variation-selector
                 runs, zero-width runs, bidi overrides in non-RTL text, blank-rendering letters)
   Tag-block and variation-selector runs are decoded to the text they smuggle.
2. html_comments(text): <!-- --> blocks outside code fences (invisible once Markdown is rendered),
   flagged when they read like instructions.
3. injection_rules(text): visible instruction patterns (override, exfiltration, remote execution,
   confirmation bypass, concealment). These are candidates for manual / model validation.
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass, field

# ---------------------------------------------------------------- code point classes
ZW = {0x200B: "ZWSP", 0x200C: "ZWNJ", 0x200D: "ZWJ", 0x2060: "WJ", 0xFEFF: "ZWNBSP/BOM", 0x180E: "MVS",
      0x2061: "FUNCTION APPLICATION", 0x2062: "INVISIBLE TIMES", 0x2063: "INVISIBLE SEPARATOR", 0x2064: "INVISIBLE PLUS"}
BIDI_MARKS = {0x200E: "LRM", 0x200F: "RLM", 0x061C: "ALM"}
BIDI_CONTROLS = {0x202A: "LRE", 0x202B: "RLE", 0x202C: "PDF", 0x202D: "LRO", 0x202E: "RLO",
                 0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI"}
BLANK_LETTERS = {0x115F: "HANGUL CHOSEONG FILLER", 0x1160: "HANGUL JUNGSEONG FILLER", 0x3164: "HANGUL FILLER",
                 0xFFA0: "HALFWIDTH HANGUL FILLER", 0x2800: "BRAILLE PATTERN BLANK", 0x00AD: "SOFT HYPHEN",
                 0x034F: "COMBINING GRAPHEME JOINER"}


def cls(cp: int) -> str | None:
    if 0xE0000 <= cp <= 0xE007F:
        return "tag"
    if 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF:
        return "variation_selector"
    if cp in ZW:
        return "zero_width"
    if cp in BIDI_CONTROLS:
        return "bidi_control"
    if cp in BIDI_MARKS:
        return "bidi_mark"
    if cp in BLANK_LETTERS:
        return "blank"
    if 0xE000 <= cp <= 0xF8FF or 0xF0000 <= cp <= 0x10FFFD:
        return "private_use"
    if unicodedata.category(chr(cp)) == "Cf":
        return "other_format"
    return None


def _is_emoji(ch: str) -> bool:
    cp = ord(ch)
    return (0x1F000 <= cp <= 0x1FAFF or 0x2600 <= cp <= 0x27BF or 0x2B00 <= cp <= 0x2BFF or 0x2300 <= cp <= 0x23FF
            or 0x1F3FB <= cp <= 0x1F3FF or cp in (0x00A9, 0x00AE, 0x203C, 0x2049, 0x2122, 0x2139, 0x3030, 0x303D)
            or 0x2190 <= cp <= 0x21FF or 0x25A0 <= cp <= 0x25FF or ch in "#*0123456789")


_RTL = re.compile(r"[֐-ࣿיִ-﷿ﹰ-﻿]")
_INDIC = re.compile(r"[ऀ-෿က-႟ក-៿]")
_CJK = re.compile(r"[㐀-鿿豈-﫿\U00020000-\U0003134F]")


@dataclass
class Finding:
    kind: str                 # code point class
    start: int                # character offset of the run
    line: int
    length: int               # code points in the run
    names: list[str]
    verdict: str              # benign | artifact | suspicious
    reason: str
    decoded: str = ""         # smuggled text, if the run decodes to any

    def to_dict(self) -> dict:
        return asdict(self)


def _decode_tags(run: str) -> str:
    return "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)


def _decode_vs(run: str) -> str:
    """Variation-selector smuggling: each selector encodes one byte (VS1-16 -> 0-15, VS17-256 -> 16-255)."""
    out = bytearray()
    for c in run:
        cp = ord(c)
        if 0xFE00 <= cp <= 0xFE0F:
            out.append(cp - 0xFE00)
        elif 0xE0100 <= cp <= 0xE01EF:
            out.append(cp - 0xE0100 + 16)
    txt = out.decode("utf-8", errors="replace")
    printable = sum(ch.isprintable() for ch in txt)
    return txt if txt and printable / len(txt) >= 0.8 else ""


def _decode_zw_bits(run: str) -> str:
    """Zero-width binary stego (e.g. ZWSP=0 / ZWNJ=1, or ZWNJ=0 / ZWJ=1): try common mappings, keep readable ASCII."""
    best = ""
    for zero, one in ((0x200B, 0x200C), (0x200C, 0x200D), (0x200B, 0x200D)):
        bits = "".join("0" if ord(c) == zero else "1" if ord(c) == one else "" for c in run)
        if len(bits) < 16:
            continue
        chars = [chr(int(bits[i:i + 8], 2)) for i in range(0, len(bits) - 7, 8)]
        txt = "".join(chars)
        if txt and sum(32 <= ord(ch) < 127 for ch in txt) / len(txt) >= 0.9 and len(txt) > len(best):
            best = txt
    return best


def scan_unicode(text: str) -> list[Finding]:
    findings: list[Finding] = []
    i, n = 0, len(text)
    line_starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(pos: int) -> int:
        lo, hi = 0, len(line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if line_starts[mid] <= pos:
                lo = mid
            else:
                hi = mid - 1
        return lo + 1

    while i < n:
        k = cls(ord(text[i]))
        if k is None:
            i += 1
            continue
        j = i
        while j < n and cls(ord(text[j])) is not None:     # a run of invisible code points (mixed classes allowed)
            j += 1
        run = text[i:j]
        kinds = {cls(ord(c)) for c in run}
        prev = text[i - 1] if i > 0 else ""
        nxt = text[j] if j < n else ""
        ls = text.rfind("\n", 0, i) + 1
        le = text.find("\n", j)
        line_text = text[ls: le if le != -1 else n]
        names = [ZW.get(ord(c)) or BIDI_CONTROLS.get(ord(c)) or BIDI_MARKS.get(ord(c)) or BLANK_LETTERS.get(ord(c))
                 or unicodedata.name(c, f"U+{ord(c):04X}") for c in run]
        kind = "tag" if "tag" in kinds else "variation_selector" if "variation_selector" in kinds else \
            "bidi_control" if "bidi_control" in kinds else sorted(kinds)[0] if len(kinds) == 1 else "mixed"
        verdict, reason, decoded = _judge(run, kinds, prev, nxt, line_text, i)
        findings.append(Finding(kind, i, line_of(i), len(run), names[:12], verdict, reason, decoded))
        i = j
    return findings


def _judge(run: str, kinds: set, prev: str, nxt: str, line_text: str, pos: int) -> tuple[str, str, str]:
    cps = [ord(c) for c in run]
    rtl_line = bool(_RTL.search(line_text))
    complex_script = bool(_INDIC.search(prev + nxt) or _RTL.search(prev + nxt))

    if "tag" in kinds:
        decoded = _decode_tags(run)
        # legitimate: subdivision flags, U+1F3F4 + tag letters + CANCEL TAG (<= 7 tags)
        if prev == "\U0001F3F4" and cps[-1] == 0xE007F and len(run) <= 7 and kinds == {"tag"}:
            return "benign", "subdivision flag emoji", ""
        return "suspicious", "Unicode tag characters (ASCII smuggling)", decoded
    if "variation_selector" in kinds:
        vs = [c for c in cps if 0xFE00 <= c <= 0xFE0F or 0xE0100 <= c <= 0xE01EF]
        if len(run) == len(vs) == 1:
            if cps[0] in (0xFE0E, 0xFE0F) and prev and (_is_emoji(prev) or not prev.isascii()):
                return "benign", "emoji/text presentation selector", ""
            if 0xE0100 <= cps[0] <= 0xE01EF and _CJK.match(prev or " "):
                return "benign", "ideographic variation sequence", ""
            if cps[0] in (0xFE0E, 0xFE0F) and prev in "#*0123456789":
                return "benign", "keycap sequence", ""
        if len(vs) >= 2 and not (set(cps) <= {0xFE0F, 0x200D} and _is_emoji(prev or "a") and _is_emoji(nxt or "a")):
            return "suspicious", "variation-selector run (byte smuggling)", _decode_vs(run)
        if len(vs) == 1 and set(cps) <= {0xFE0F, 0x200D} and (_is_emoji(prev or "a") or _is_emoji(nxt or "a")):
            return "benign", "emoji presentation within ZWJ sequence", ""
        return "suspicious", "variation selector after plain text", _decode_vs(run)
    if "bidi_control" in kinds:
        if rtl_line:
            return "benign", "bidi control in RTL text", ""
        return "suspicious", "bidi override/isolate in non-RTL text (Trojan-Source style)", ""
    if kinds == {"bidi_mark"}:
        return ("benign", "bidi mark in RTL text", "") if rtl_line else ("artifact", "stray LRM/RLM", "")
    if kinds == {"zero_width"} or kinds == {"zero_width", "bidi_mark"}:
        if cps == [0xFEFF] and pos == 0:
            return "benign", "byte-order mark", ""
        if set(cps) <= {0x200D} and len(run) <= 2 and (_is_emoji(prev or "a") or _is_emoji(nxt or "a")):
            return "benign", "emoji ZWJ sequence", ""
        if set(cps) <= {0x200C, 0x200D} and complex_script:
            return "benign", "joiner in RTL/Indic script", ""
        decoded = _decode_zw_bits(run)
        if decoded:
            return "suspicious", "zero-width binary encoding", decoded
        if len(run) >= 3:
            return "suspicious", f"run of {len(run)} zero-width characters", ""
        return "artifact", "isolated zero-width character (copy-paste artifact)", ""
    if kinds == {"blank"}:
        if cps == [0x00AD]:
            return "artifact", "soft hyphen", ""
        return "suspicious", "blank-rendering letter", ""
    if kinds == {"private_use"}:
        return "artifact", "private-use code point (icon fonts)", ""
    if kinds == {"other_format"} and len(run) == 1:
        return "artifact", "isolated format character", ""
    return "suspicious", "mixed invisible run", ""


# ---------------------------------------------------------------- HTML comments
_FENCE = re.compile(r"^(```|~~~)", re.M)
_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
_INSTRUCTIONY = re.compile(
    r"\b(you|your|agent|assistant|ai|llm|model|claude|copilot|cursor|always|never|must|do not|don't|ignore|"
    r"instead|run|execute|install|send|upload|delete|remove|add|use|make sure)\b", re.I)


def _outside_fences(text: str) -> list[tuple[int, int]]:
    """Character spans not inside fenced code blocks."""
    spans, pos, inside = [], 0, False
    for m in _FENCE.finditer(text):
        if not inside:
            spans.append((pos, m.start()))
        else:
            pos = m.end()
        inside = not inside
        if not inside:
            pos = text.find("\n", m.end()) + 1 or len(text)
    if not inside:
        spans.append((pos, len(text)))
    return spans


def html_comments(text: str) -> list[dict]:
    out = []
    for a, b in _outside_fences(text):
        for m in _COMMENT.finditer(text, a, b):
            body = m.group(1).strip()
            words = len(re.findall(r"\w+", body))
            hits = len(_INSTRUCTIONY.findall(body))
            out.append({"start": m.start(), "chars": len(body), "words": words,
                        "instruction_like": words >= 5 and hits >= 2,
                        "snippet": body[:300]})
    return out


# ---------------------------------------------------------------- visible injection-style rules
RULES = {
    "override": [r"\bignore (all |any )?(the )?(previous|prior|above|earlier|system) (instructions|rules|prompts?|messages?)",
                 r"\bdisregard (all |any )?(the )?(previous|prior|above|system|safety)",
                 r"\bforget (all |everything )?(you were told|previous instructions)", r"\byou are now (a|an|in) "],
    # uploading local secret FILES (using a token in an auth header is normal API use, not exfiltration)
    "exfiltration": [r"(curl|wget|invoke-webrequest|iwr)\b[^\n]{0,160}(-d\s*@|--data(-binary|-raw)?\s*@|-F\s*\S*=@|-T\s|--upload-file\s|-InFile\s)[^\n]{0,40}(~/\.ssh|\.aws/|\.env\b|id_rsa|/etc/passwd|\.npmrc|\.pypirc|\.netrc|\.git-credentials)",
                     r"\bcat\s+[^\n|]{0,60}(~/\.ssh|\.aws/credentials|\.env\b|id_rsa|\.npmrc|\.netrc)[^\n|]{0,20}\|\s*(curl|nc|wget)\b",
                     r"\b(send|post|upload|exfiltrate|transmit)\b[^\n]{0,60}\b(secrets?|credentials?|api[ _-]?keys?|tokens?|env(ironment)? variables|\.env|ssh keys?)\b[^\n]{0,60}\b(to|at)\b[^\n]{0,40}(https?://|webhook|server)"],
    "remote_exec": [r"(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(sh|bash|zsh|python3?|iex|node)\b",
                    r"\b(iex|invoke-expression)\s*\(\s*(new-object|iwr|invoke-webrequest)"],
    "confirmation_bypass": [r"\b(never|do not|don't|dont)\s+(ask|wait|prompt)\s+(the user\s+)?(for\s+)?(permission|confirmation|approval)",
                            r"\bwithout (asking|requesting|waiting for) (the user'?s? )?(permission|confirmation|approval)",
                            r"--dangerously-skip-permissions", r"\bbypassPermissions\b", r"--yolo\b",
                            r"\bauto[- ]?approve (all|every|any)\b"],
    "concealment": [r"\b(do not|don't|never)\s+(tell|inform|mention (this )?to|reveal (this )?to|show)\s+the user",
                    r"\b(keep|hide) (this|these instructions|it) (secret|hidden) from the user",
                    r"\bwithout (telling|informing|notifying) the user"],
}
_RULES_C = {k: [re.compile(p, re.I) for p in v] for k, v in RULES.items()}


# a match is "negated" when the surrounding text warns against it or treats it as untrusted data
# (e.g. "never `curl | bash`", "treat 'ignore previous instructions' as data"); multilingual cues included
_NEGATION = re.compile(r"(\bnever\b|\bdon'?t\b|\bdo not\b|\bavoid\b|\bwithout\b|\bno\s|\bnot\b|\bforbid|\bprohibit|\bdeny\b|"
                       r"\bunsafe\b|\buntrusted\b|\bmalicious\b|\battack|\binjection\b|\bdirectives? found\b|\bif .{0,30}contains\b|"
                       r"❌|🚫|⛔|\bне\b|\bбез\b|禁止|不得|不要)", re.I)


def injection_rules(text: str) -> list[dict]:
    out = []
    for cat, pats in _RULES_C.items():
        for p in pats:
            for m in p.finditer(text):
                a = max(0, m.start() - 80)
                before = text[max(0, m.start() - 60): m.start()]
                quoted = text[max(0, m.start() - 2): m.start()].strip()[-1:] in ("'", '"', "`", "“", "«")
                negated = bool(_NEGATION.search(before)) or (cat == "override" and quoted)
                if cat == "confirmation_bypass":   # "never ask for X" is itself a negation; look further back only
                    negated = bool(re.search(r"(\bunless\b|\bexcept\b|\bshould not\b|\bmust not\b)", before, re.I))
                out.append({"category": cat, "start": m.start(), "negated": negated,
                            "snippet": text[a: m.end() + 80].replace("\n", " ")[:300]})
    return out


# ---------------------------------------------------------------- per-file summary
@dataclass
class HiddenSummary:
    chars: int
    unicode: list[dict] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    rules: list[dict] = field(default_factory=list)

    def flags(self) -> dict:
        u = self.unicode
        return {
            "n_invisible_runs": len(u),
            "n_suspicious_unicode": sum(f["verdict"] == "suspicious" for f in u),
            "n_artifact_unicode": sum(f["verdict"] == "artifact" for f in u),
            "has_tag_payload": any(f["kind"] == "tag" and f["verdict"] == "suspicious" for f in u),
            "has_decoded_payload": any(f["decoded"] for f in u),
            "has_bidi_override": any(f["kind"] == "bidi_control" and f["verdict"] == "suspicious" for f in u),
            "n_html_comments": len(self.comments),
            "n_instruction_comments": sum(c["instruction_like"] for c in self.comments),
            **{f"rule_{k}": sum(r["category"] == k and not r["negated"] for r in self.rules) for k in RULES},
            **{f"rule_{k}_negated": sum(r["category"] == k and r["negated"] for r in self.rules) for k in RULES},
        }


def analyse(text: str, markdown: bool = True) -> HiddenSummary:
    """Unicode scan for every file; HTML-comment and text rules only for instruction (Markdown-like) files.
    JSON configs are handled by configs.py, which distinguishes allow from deny lists."""
    return HiddenSummary(chars=len(text), unicode=[f.to_dict() for f in scan_unicode(text)],
                         comments=html_comments(text) if markdown else [],
                         rules=injection_rules(text) if markdown else [])
