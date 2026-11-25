"""Manual validation of the RQ1 content detectors (written to local/validation/, never published: links identify repos).

Sample (seed 1122), one row per detector hit, from data/derived/details.jsonl:
  * every suspicious invisible-Unicode run (rare), with the decoded payload where one exists
  * up to 12 non-negated matches per injection-rule category (override, exfiltration, remote_exec,
    confirmation_bypass, concealment)
  * 20 instruction-like HTML comments
The labeller reads the snippet (and the file, through the link, if needed) and assigns one label:
  malicious      written to make an agent act against the user or repository owner (hidden or not)
  risky          legitimate intent, but it tells an agent to do something unsafe (pipe a script from the web to a
                 shell, skip confirmation, auto-approve, keep information from the user)
  benign         legitimate and safe (documentation, an install note for humans, a security rule that forbids the act)
  detector_error the detector misread the text (e.g. negation it missed, quoted example, emoji, RTL text)
Usage: python src/09_validation_sheet.py           (make the sheet; refuses to overwrite a labelled one)
       python src/09_validation_sheet.py --score   (writes tables/b10_validation.csv: label shares per detector)
"""
from __future__ import annotations

import argparse
import json
import random

import pandas as pd

from common import DERIVED, TABLES
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "local" / "validation"
SEED = 1122
PER_RULE = 12
N_COMMENTS = 20
LABELS = {"malicious", "risky", "benign", "detector_error"}
MAX_PER_UNICODE_KIND = 10
RAW = Path(__file__).resolve().parents[1] / "data" / "raw"


def context(sha: str, start: int, length: int, width: int = 120) -> str:
    """Text around an invisible run, with every non-printing or format character shown as <U+XXXX>."""
    try:
        t = (RAW / sha[:2] / sha).read_bytes().decode("utf-8", "replace")
    except OSError:
        return ""
    seg = t[max(0, start - width): start + length + width]
    return "".join(c if c.isprintable() and not hidden(ord(c)) else (" " if c in "\n\t" else f"<U+{ord(c):04X}>")
                   for c in seg)


def hidden(o: int) -> bool:
    return (o == 0x2800 or 0xE0000 <= o <= 0xE007F or 0xFE00 <= o <= 0xFE0F or 0xE0100 <= o <= 0xE01EF
            or 0x200B <= o <= 0x202E or 0x2060 <= o <= 0x2069 or o == 0xFEFF or o == 0xAD)


def make() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    sheet = OUT / "detector_sheet.csv"
    if sheet.exists() and pd.read_csv(sheet).your_label.notna().any():
        raise SystemExit(f"{sheet} already has labels; not overwriting")
    files = pd.read_parquet(DERIVED / "files.parquet", columns=["sha", "repo", "path", "type"]).drop_duplicates("sha")
    where = files.set_index("sha")
    hits = {"unicode": [], "comment": []}
    for line in open(DERIVED / "details.jsonl", encoding="utf-8"):
        d = json.loads(line)
        for u in d["unicode"]:
            if u.get("verdict") == "suspicious":
                hits["unicode"].append((d["sha"], f"unicode:{u['kind']}",
                                        (f"DECODED: {u['decoded']}  | " if u.get("decoded") else "") + f"{u['reason']} | CONTEXT: "
                                        + context(d["sha"], u["start"], u["length"])))
        for c in d["comments"]:
            if c.get("instruction_like"):
                hits["comment"].append((d["sha"], "html_comment", c["snippet"]))
        for r in d["rules"]:
            if not r.get("negated"):
                hits.setdefault(f"rule:{r['category']}", []).append((d["sha"], f"rule:{r['category']}", r["snippet"]))
    rng = random.Random(SEED)
    rows = []
    uni = pd.DataFrame(hits.pop("unicode"), columns=["sha", "det", "snip"])
    for _, g in uni.groupby("det"):           # cap very common kinds (e.g. blank Braille in ASCII art)
        rows += [tuple(x) for x in g.sample(min(MAX_PER_UNICODE_KIND, len(g)), random_state=SEED).itertuples(index=False)]
    rows += rng.sample(hits["comment"], min(N_COMMENTS, len(hits["comment"])))
    hits.pop("comment")
    for k in sorted(hits):
        rows += rng.sample(hits[k], min(PER_RULE, len(hits[k])))
    rng.shuffle(rows)
    out = []
    for i, (sha, det, snip) in enumerate(rows, 1):
        repo, path, typ = (where.loc[sha, ["repo", "path", "type"]] if sha in where.index else ("", "", ""))
        out.append({"id": f"D{i:03d}", "detector": det, "file_type": typ, "snippet": " ".join(str(snip).split())[:600],
                    "link": f"https://github.com/{repo}/blob/HEAD/{path}" if repo else "", "your_label": "", "notes": ""})
    pd.DataFrame(out).to_csv(sheet, index=False, encoding="utf-8-sig")
    print(f"wrote {len(out)} rows to {sheet}")


def score() -> None:
    d = pd.read_csv(OUT / "detector_sheet.csv")
    d = d[d.your_label.notna()].assign(label=lambda x: x.your_label.str.strip().str.lower())
    bad = set(d.label) - LABELS
    if bad:
        raise SystemExit(f"unknown labels {bad}; use one of {sorted(LABELS)}")
    d["group"] = d.detector.str.split(":").str[0].replace({"rule": "rule"})
    rows = []
    for key, g in list(d.groupby("detector")) + list(d.groupby("group")) + [("all", d)]:
        r = {"detector": key, "n": len(g)}
        for lab in sorted(LABELS):
            r[lab] = int((g.label == lab).sum())
        r["precision"] = 1 - r["detector_error"] / len(g)
        r["share_malicious"] = r["malicious"] / len(g)
        r["share_unsafe"] = (r["malicious"] + r["risky"]) / len(g)
        rows.append(r)
    out = pd.DataFrame(rows).drop_duplicates("detector")
    out.to_csv(TABLES / "b10_validation.csv", index=False)
    print(out.to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", action="store_true")
    score() if ap.parse_args().score else make()
