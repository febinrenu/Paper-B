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
import re

import numpy as np

import pandas as pd

from statsmodels.stats.proportion import proportion_confint

from common import DERIVED, TABLES
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "local" / "validation"
SEED = 1122
PER_RULE = 12
N_COMMENTS = 20
LABELS = {"malicious", "risky", "benign", "detector_error"}
MAX_PER_UNICODE_KIND = 10
RAW = Path(__file__).resolve().parents[1] / "data" / "raw"
MD = {"agents_md", "claude_md", "gemini_md", "copilot_instr", "cursor_rules_mdc", "cursorrules", "windsurfrules",
      "clinerules"}


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
    if holdout:
        rows += negatives(files, ok, rng)
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


# broad, high-recall cues for the false-negative audit (not a detector: it only selects files for a human to read)
LEXICON = re.compile(r"(ignore|disregard|secret|token|api[_ -]?key|password|credential|curl |wget |exfiltrat|upload|"
                     r"don'?t tell|do not tell|hidden|without asking|auto-?approve|sudo |rm -rf|base64|eval\(|webhook|"
                     r"\.env\b|ssh)", re.I)
N_NEG_LEXICON, N_NEG_RANDOM = 15, 15


def negatives(files_unused, ok, rng) -> list:
    """Detector-negative instruction files for a false-negative audit: half drawn at random, half from negatives that
    contain a broad lexical cue (where a miss is most likely). Labellers mark malicious/risky if the file carries an
    unsafe instruction that the detectors missed, benign otherwise."""
    f = pd.read_parquet(DERIVED / "files.parquet")
    rule_cols = [c for c in f.columns if c.startswith("rule_") and not c.endswith("_negated")]
    md = f[(f.frame == 2) & f.type.isin(MD) & f.fetched.fillna(False)].drop_duplicates("sha")
    neg = md[(md.n_instruction_comments.fillna(0) == 0) & (md.n_suspicious_unicode.fillna(0) == 0)
             & (md[rule_cols].fillna(0).sum(axis=1) == 0)]
    neg = neg[[ok(x) for x in neg.sha]]
    pool = neg.sample(min(4000, len(neg)), random_state=2611)
    rows, lex = [], []
    for sha in pool.sha:
        t = (RAW / sha[:2] / sha).read_bytes().decode("utf-8", "replace")
        ms = list(LEXICON.finditer(t))
        if ms:
            ctx = " ... ".join(t[max(0, m.start() - 150): m.end() + 150] for m in ms[:3])
            lex.append((sha, "negative:lexicon", ctx))
    rows += rng.sample(lex, min(N_NEG_LEXICON, len(lex)))
    for sha in pool.sha[~pool.sha.isin([r[0] for r in rows])].head(N_NEG_RANDOM):
        t = (RAW / sha[:2] / sha).read_bytes().decode("utf-8", "replace")
        rows.append((sha, "negative:random", t[:600]))
    return rows


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


def detector_population() -> dict:
    """Distinct flagged files per detector key in the current scan (details.jsonl)."""
    c: dict = {}
    for line in open(DERIVED / "details.jsonl", encoding="utf-8"):
        d = json.loads(line)
        keys = {f"unicode:{u['kind']}" for u in d["unicode"] if u.get("verdict") == "suspicious"}
        keys |= {"html_comment"} if any(x.get("instruction_like") for x in d["comments"]) else set()
        keys |= {f"rule:{r['category']}" for r in d["rules"] if not r.get("negated")}
        for k in keys:
            c[k] = c.get(k, 0) + 1
    return c


def score(holdout: bool = False) -> None:
    """Two independent labellers (labeller1/labeller2 files). holdout=True scores the post-correction hold-out sheet
    (tables/b10_validation_holdout.csv); there every row is a current detection, so n_still_flagged == n."""
    stem = "holdout_sheet" if holdout else "detector_sheet"
    l1, l2 = OUT / f"{stem}_labeller1.csv", OUT / f"{stem}_labeller2.csv"
    a = pd.read_csv(l1)
    b = pd.read_csv(l2) if l2.exists() else None
    d = a[["id", "detector", "file_type", "snippet", "link"]].copy()
    d["l1"] = a.your_label.fillna("").astype(str).str.strip().str.lower()
    d["l2"] = b.your_label.fillna("").astype(str).str.strip().str.lower() if b is not None else d.l1
    empty = (d.l1 == "") | (d.l2 == "")                 # "leave a row empty if you can't decide": skipped
    if empty.any():
        print(f"skipping {int(empty.sum())} rows without a label from both labellers")
    d = d[~empty].copy()
    for c in ("l1", "l2"):
        bad = set(d[c]) - LABELS
        if bad:
            raise SystemExit(f"{c}: unknown labels {bad}; use one of {sorted(LABELS)}")
    d["group"] = d.detector.str.split(":").str[0]
    d["agree"] = d.l1 == d.l2
    neg, d = d[d.group == "negative"].copy(), d[d.group != "negative"].copy()
    pd.crosstab(d.l1, d.l2, rownames=["labeller1"], colnames=["labeller2"]).to_csv(
        TABLES / ("b10_confusion_holdout.csv" if holdout else "b10_confusion.csv"))
    d["still"] = _still_flagged(d)
    err1, err2 = d.l1.eq("detector_error"), d.l2.eq("detector_error")
    uns1, uns2 = d.l1.isin(["malicious", "risky"]), d.l2.isin(["malicious", "risky"])
    rng = np.random.default_rng(1)

    def kappa_ci(x: pd.Series, y: pd.Series, B: int = 2000) -> tuple[float, float]:
        """Percentile bootstrap over labelled hits."""
        x, y = x.reset_index(drop=True), y.reset_index(drop=True)
        ks = [kappa(x[i], y[i]) for i in (rng.integers(0, len(x), len(x)) for _ in range(B))]
        ks = [k for k in ks if k == k]
        return (float(np.percentile(ks, 2.5)), float(np.percentile(ks, 97.5))) if ks else (np.nan, np.nan)

    def agree_row(name: str, m: pd.Series) -> dict:
        k_lo, k_hi = kappa_ci(d.l1[m], d.l2[m])
        u_lo, u_hi = kappa_ci(uns1[m], uns2[m])
        return {"detector": name, "n": int(m.sum()), "agree_share": float(d.agree[m].mean()),
                "kappa": kappa(d.l1[m], d.l2[m]), "kappa_lo": k_lo, "kappa_hi": k_hi,
                "kappa_error": kappa(err1[m], err2[m]), "kappa_unsafe": kappa(uns1[m], uns2[m]),
                "kappa_unsafe_lo": u_lo, "kappa_unsafe_hi": u_hi}

    rows = [agree_row("agreement", pd.Series(True, index=d.index))]
    # the two labellers read "detector error" differently for benign comments
    rows.append(agree_row("agreement_excl_comments", d.group != "html_comment"))
    for key, g in list(d.groupby("detector")) + list(d.groupby("group")) + [("all", d)]:
        e1, e2 = g.l1.eq("detector_error"), g.l2.eq("detector_error")
        u1, u2 = g.l1.isin(["malicious", "risky"]), g.l2.isin(["malicious", "risky"])
        m1, m2 = g.l1.eq("malicious"), g.l2.eq("malicious")
        st = g[g.still.fillna(False).astype(bool)]
        se1, se2 = st.l1.eq("detector_error"), st.l2.eq("detector_error")
        ok_both = int((~(e1 & e2)).sum())
        pb_lo, pb_hi = proportion_confint(ok_both, len(g), method="wilson")
        rows.append({"detector": key, "n": len(g),
                     "precision_l1": 1 - e1.mean(), "precision_l2": 1 - e2.mean(),
                     "precision_both": 1 - (e1 & e2).mean(),            # an error only if both labellers say so
                     "precision_both_lo": pb_lo, "precision_both_hi": pb_hi,
                     "precision_either": 1 - (e1 | e2).mean(),          # an error if either labeller says so
                     "malicious_l1": int(m1.sum()), "malicious_l2": int(m2.sum()), "malicious_both": int((m1 & m2).sum()),
                     "unsafe_both_share": float((u1 & u2).mean()), "agree_share": float(g.agree.mean()),
                     "n_still_flagged": len(st),
                     "precision_fixed_both": 1 - (se1 & se2).mean() if len(st) else float("nan"),
                     "precision_fixed_either": 1 - (se1 | se2).mean() if len(st) else float("nan")})
    if holdout:
        # the sample is stratified by detector: weight each detector's precision by the number of distinct files it
        # flags in the corpus, so the pooled figure estimates precision over all flagged files
        pop = detector_population()
        # one row per detector key (html_comment is both a detector and its own group: count it once)
        per = pd.DataFrame([r for r in rows if r["detector"] in pop]).drop_duplicates("detector")
        if len(per):
            per["N"] = per.detector.map(pop)
            w = per.N / per.N.sum()
            rows.append({"detector": "all_weighted", "n": int(per.n.sum()),
                         "precision_both": float((w * per.precision_both).sum()),
                         "precision_either": float((w * per.precision_either).sum())})
    for key, g in [("negative:all", neg)] + list(neg.groupby("detector")):
        if not len(g):
            continue
        miss_both = int((g.l1.isin(["malicious", "risky"]) & g.l2.isin(["malicious", "risky"])).sum())
        miss_either = int((g.l1.isin(["malicious", "risky"]) | g.l2.isin(["malicious", "risky"])).sum())
        rows.append({"detector": key, "n": len(g), "missed_both": miss_both, "missed_either": miss_either,
                     "missed_either_hi": proportion_confint(miss_either, len(g), method="wilson")[1],
                     "agree_share": float(g.agree.mean())})
    out = pd.DataFrame(rows).drop_duplicates("detector")
    out.to_csv(TABLES / ("b10_validation_holdout.csv" if holdout else "b10_validation.csv"), index=False)
    print(out.round(3).to_string(index=False))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--score", action="store_true")
    ap.add_argument("--holdout", action="store_true", help="the post-correction hold-out sample")
    args = ap.parse_args()
    score(args.holdout) if args.score else make(args.holdout)
