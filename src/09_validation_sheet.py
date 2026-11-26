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


def make(holdout: bool = False) -> None:
    """holdout=True: a fresh sample, drawn after the detectors were corrected on the first sheet, from files (by
    content hash and by repository) not in the first sheet; smaller per stratum, one row per distinct file."""
    OUT.mkdir(parents=True, exist_ok=True)
    sheet = OUT / ("holdout_sheet.csv" if holdout else "detector_sheet.csv")
    if sheet.exists() and pd.read_csv(sheet).your_label.notna().any():
        raise SystemExit(f"{sheet} already has labels; not overwriting")
    files = pd.read_parquet(DERIVED / "files.parquet", columns=["sha", "repo", "path", "type"]).drop_duplicates("sha")
    where = files.set_index("sha")
    seed, per_rule, n_comments, max_uni = (2611, 8, 12, 6) if holdout else (SEED, PER_RULE, N_COMMENTS, MAX_PER_UNICODE_KIND)
    used_sha, used_repo = set(), set()
    if holdout:
        first = pd.read_csv(OUT / "detector_sheet_labeller1.csv")
        rp = first.link.str.extract(r"https://github\.com/([^/]+/[^/]+)/blob/[^/]+/(.+)$")
        used_repo = set(rp[0].str.lower())
        key = {(r.lower(), q): h for h, r, q in zip(files.sha, files.repo, files.path)}
        used_sha = {key.get((a.lower(), b)) for a, b in zip(rp[0], rp[1])} - {None}
    ok = (lambda sha: sha not in used_sha and str(where.loc[sha, "repo"]).lower() not in used_repo
          if sha in where.index else False)
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
    if holdout:                                # one hit per distinct file, none from the first sheet
        for k in hits:
            seen, keep = set(), []
            for h in hits[k]:
                if ok(h[0]) and h[0] not in seen:
                    seen.add(h[0])
                    keep.append(h)
            hits[k] = keep
    rng = random.Random(seed)
    rows = []
    uni = pd.DataFrame(hits.pop("unicode"), columns=["sha", "det", "snip"])
    for _, g in uni.groupby("det"):           # cap very common kinds (e.g. blank Braille in ASCII art)
        rows += [tuple(x) for x in g.sample(min(max_uni, len(g)), random_state=seed).itertuples(index=False)]
    rows += rng.sample(hits["comment"], min(n_comments, len(hits["comment"])))
    hits.pop("comment")
    for k in sorted(hits):
        rows += rng.sample(hits[k], min(per_rule, len(hits[k])))
    rng.shuffle(rows)
    out = []
    for i, (sha, det, snip) in enumerate(rows, 1):
        repo, path, typ = (where.loc[sha, ["repo", "path", "type"]] if sha in where.index else ("", "", ""))
        out.append({"id": f"{'H' if holdout else 'D'}{i:03d}", "detector": det, "file_type": typ, "snippet": " ".join(str(snip).split())[:600],
                    "link": f"https://github.com/{repo}/blob/HEAD/{path}" if repo else "", "your_label": "", "notes": ""})
    pd.DataFrame(out).to_csv(sheet, index=False, encoding="utf-8-sig")
    if holdout:                                # one blank copy per labeller, labelled independently
        for k in (1, 2):
            pd.DataFrame(out).to_csv(OUT / f"holdout_sheet_labeller{k}.csv", index=False, encoding="utf-8-sig")
    print(f"wrote {len(out)} rows to {sheet}")


def kappa(a: pd.Series, b: pd.Series) -> float:
    cats = sorted(set(a) | set(b))
    po = (a == b).mean()
    pe = sum((a == k).mean() * (b == k).mean() for k in cats)
    return (po - pe) / (1 - pe) if pe < 1 else float("nan")


def _still_flagged(rows: pd.DataFrame) -> pd.Series:
    """Re-run the current (corrected) detectors on each labelled file: is the labelled hit still reported?"""
    import re as _re
    from hidden import html_comments, injection_rules, scan_unicode
    files = pd.read_parquet(DERIVED / "files.parquet", columns=["sha", "repo", "path"]).drop_duplicates(["repo", "path"])
    where = {(r.lower(), pth): sha for sha, r, pth in zip(files.sha, files.repo, files.path)}
    out = []
    for _, r in rows.iterrows():
        m = _re.match(r"https://github\.com/([^/]+/[^/]+)/blob/[^/]+/(.+)$", str(r.link))
        sha = where.get((m.group(1).lower(), m.group(2))) if m else None
        if not sha or not (RAW / sha[:2] / sha).exists():
            out.append(None)
            continue
        text = (RAW / sha[:2] / sha).read_bytes().decode("utf-8", "replace")
        det = str(r.detector)
        if det.startswith("unicode"):
            kind = det.split(":", 1)[1]
            out.append(any(f.verdict == "suspicious" and f.kind == kind for f in scan_unicode(text)))
        elif det.startswith("html_comment"):
            snip = str(r.snippet)[:60]
            out.append(any(c["instruction_like"] and (snip[:30] in c["snippet"] or c["snippet"][:30] in snip)
                           for c in html_comments(text)))
        else:
            cat = det.split(":", 1)[1]
            # the detector runs on raw text (sentence and line breaks matter for negation); locate the labelled
            # snippet in the raw text with whitespace-tolerant matching
            words = _re.sub(r"\s+", " ", str(r.snippet))[20:70].strip().split(" ")
            mk = _re.search(r"\s+".join(_re.escape(w) for w in words if w), text)
            hits = [h for h in injection_rules(text) if h["category"] == cat and not h["negated"]]
            out.append(any(abs(h["start"] - mk.start()) < 400 for h in hits) if mk else bool(hits))
    return pd.Series(out, index=rows.index)


def score(holdout: bool = False) -> None:
    """Two independent labellers (labeller1/labeller2 files). holdout=True scores the post-correction hold-out sheet
    (tables/b10_validation_holdout.csv); there every row is a current detection, so n_still_flagged == n."""
    stem = "holdout_sheet" if holdout else "detector_sheet"
    l1, l2 = OUT / f"{stem}_labeller1.csv", OUT / f"{stem}_labeller2.csv"
    a = pd.read_csv(l1)
    b = pd.read_csv(l2) if l2.exists() else None
    d = a[["id", "detector", "file_type", "snippet", "link"]].copy()
    d["l1"] = a.your_label.astype(str).str.strip().str.lower()
    d["l2"] = b.your_label.astype(str).str.strip().str.lower() if b is not None else d.l1
    for c in ("l1", "l2"):
        bad = set(d[c]) - LABELS
        if bad:
            raise SystemExit(f"{c}: unknown labels {bad}; use one of {sorted(LABELS)}")
    d["group"] = d.detector.str.split(":").str[0]
    d["agree"] = d.l1 == d.l2
    d["still"] = _still_flagged(d)
    err1, err2 = d.l1.eq("detector_error"), d.l2.eq("detector_error")
    uns1, uns2 = d.l1.isin(["malicious", "risky"]), d.l2.isin(["malicious", "risky"])
    rows = [{"detector": "agreement", "n": len(d), "agree_share": float(d.agree.mean()), "kappa": kappa(d.l1, d.l2),
             "kappa_error": kappa(err1, err2), "kappa_unsafe": kappa(uns1, uns2)}]
    nc = d.group != "html_comment"      # the two labellers read "detector error" differently for benign comments
    rows.append({"detector": "agreement_excl_comments", "n": int(nc.sum()), "agree_share": float(d.agree[nc].mean()),
                 "kappa": kappa(d.l1[nc], d.l2[nc]), "kappa_error": kappa(err1[nc], err2[nc]),
                 "kappa_unsafe": kappa(uns1[nc], uns2[nc])})
    for key, g in list(d.groupby("detector")) + list(d.groupby("group")) + [("all", d)]:
        e1, e2 = g.l1.eq("detector_error"), g.l2.eq("detector_error")
        u1, u2 = g.l1.isin(["malicious", "risky"]), g.l2.isin(["malicious", "risky"])
        m1, m2 = g.l1.eq("malicious"), g.l2.eq("malicious")
        st = g[g.still.fillna(False).astype(bool)]
        se1, se2 = st.l1.eq("detector_error"), st.l2.eq("detector_error")
        rows.append({"detector": key, "n": len(g),
                     "precision_l1": 1 - e1.mean(), "precision_l2": 1 - e2.mean(),
                     "precision_both": 1 - (e1 & e2).mean(),            # an error only if both labellers say so
                     "precision_either": 1 - (e1 | e2).mean(),          # an error if either labeller says so
                     "malicious_l1": int(m1.sum()), "malicious_l2": int(m2.sum()), "malicious_both": int((m1 & m2).sum()),
                     "unsafe_both_share": float((u1 & u2).mean()), "agree_share": float(g.agree.mean()),
                     "n_still_flagged": len(st),
                     "precision_fixed_both": 1 - (se1 & se2).mean() if len(st) else float("nan"),
                     "precision_fixed_either": 1 - (se1 | se2).mean() if len(st) else float("nan")})
    out = pd.DataFrame(rows).drop_duplicates("detector")
    out.to_csv(TABLES / ("b10_validation_holdout.csv" if holdout else "b10_validation.csv"), index=False)
    print(out.round(3).to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--holdout", action="store_true", help="the post-correction hold-out sample")
    args = ap.parse_args()
    score(args.holdout) if args.score else make(args.holdout)
