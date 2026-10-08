#!/usr/bin/env python3
"""Validate static, accessible SVG documentation assets (stdlib only)."""
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
SVG_DIR = ROOT / "docs" / "assets"
README = (ROOT / "README.md").read_text(encoding="utf-8")
NS = "{http://www.w3.org/2000/svg}"
FILES = (
    "rudevolution-hero.svg",
    "rudevolution-intro.svg",
    "rudevolution-pipeline.svg",
    "rudevolution-learning.svg",
    "rudevolution-trust.svg",
)

def check(name: str) -> None:
    raw = (SVG_DIR / name).read_text(encoding="utf-8")
    size = len(raw.encode("utf-8"))
    assert size <= 48 * 1024, f"{name}: size budget exceeded"
    assert f"docs/assets/{name}" in README, f"{name}: not referenced in README"
    root = ET.fromstring(raw)
    assert root.tag == NS + "svg", f"{name}: unexpected XML root"
    assert root.get("viewBox"), f"{name}: missing responsive viewBox"
    assert root.get("role") == "img", f"{name}: missing role"
    label = root.get("aria-labelledby", "").split()
    assert len(label) == 2, f"{name}: requires title and description label"
    ids = [node.get("id") for node in root.iter() if node.get("id")]
    assert len(ids) == len(set(ids)), f"{name}: duplicate XML IDs"
    assert set(label).issubset(ids), f"{name}: aria labels not defined"
    assert root.find(NS + "title") is not None, f"{name}: missing title"
    assert root.find(NS + "desc") is not None, f"{name}: missing description"
    assert "prefers-reduced-motion" in raw, f"{name}: reduced-motion missing"
    assert "@keyframes" in raw, f"{name}: no animation"
    for node in root.iter():
        tag = node.tag.rsplit("}", 1)[-1].lower()
        assert tag not in {"script", "foreignobject", "image", "iframe", "a"}, f"{name}: unsafe element {tag}"
        for attr, val in node.attrib.items():
            assert not attr.lower().startswith("on"), f"{name}: event handler attribute"
            assert not re.search(r"(?i)(https?:|javascript:|data:)", val), f"{name}: external resource"
    print(f"PASS {name}: {size} bytes")

def main() -> None:
    for name in FILES:
        check(name)
    print(f"PASS: {len(FILES)} visual assets")

if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, ET.ParseError, ValueError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
