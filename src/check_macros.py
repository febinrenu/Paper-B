"""List \\R{...} macros used in paper/main.tex that numbers.tex does not define (they render as red ??)."""
import re
from pathlib import Path

P = Path(__file__).resolve().parents[1] / "paper"
BS = chr(92)
used = set(re.findall(re.escape(BS + "R{") + r"([A-Za-z]+)\}", (P / "main.tex").read_text(encoding="utf-8")))
have = set(re.findall(re.escape(BS + "newcommand{" + BS) + r"([A-Za-z]+)\}", (P / "numbers.tex").read_text(encoding="utf-8")))
missing = sorted(used - have)
print(f"{len(used)} used, {len(have)} defined, {len(missing)} missing")
print(" ".join(missing))
