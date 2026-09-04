"""Make Semgrep/OpenGrep rule IDs unique across the flattened crypto rule set.
semgrep-rules reuses ids like `insecure-hash-algorithm-md5` in several files; OpenGrep keeps only one
rule per id, silently dropping the others. Prefix every id with the file stem."""
from __future__ import annotations

import re
import sys
from pathlib import Path

from ecdat import tools


def main(rules_dir: Path = tools.RULES_DIR) -> int:
    changed = 0
    for f in sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml")):
        stem = re.sub(r"[^a-z0-9]+", "-", f.stem.lower()).strip("-")
        text = f.read_text(encoding="utf-8")
        new, n = re.subn(r"^(\s*-\s*id:\s*)([A-Za-z0-9_.\-]+)\s*$",
                         lambda m: m.group(1) + (m.group(2) if m.group(2).startswith(stem) else f"{stem}.{m.group(2)}"),
                         text, flags=re.M)
        if n and new != text:
            f.write_text(new, encoding="utf-8")
            changed += 1
    print(f"rewrote ids in {changed} files under {rules_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1]) if len(sys.argv) > 1 else tools.RULES_DIR))
