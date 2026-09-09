import hashlib
import json
import re
import sys
import zipfile
from collections import Counter
from pathlib import Path

from lxml import etree


NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def accepted(paragraph):
    return "".join(
        node.text or ""
        for node in paragraph.xpath(".//w:t[not(ancestor::w:del)]", namespaces=NS)
    )


source, output = map(Path, sys.argv[1:3])
with zipfile.ZipFile(source) as src, zipfile.ZipFile(output) as dst:
    assert src.testzip() is None and dst.testzip() is None
    assert set(src.namelist()) == set(dst.namelist())
    src_media = {n: digest(src.read(n)) for n in src.namelist() if n.startswith("word/media/")}
    dst_media = {n: digest(dst.read(n)) for n in dst.namelist() if n.startswith("word/media/")}
    assert src_media == dst_media
    root = etree.fromstring(dst.read("word/document.xml"))
    settings = etree.fromstring(dst.read("word/settings.xml"))

texts = [accepted(p).strip() for p in root.xpath(".//w:p", namespaces=NS)]
whole = "\n".join(t for t in texts if t)

assert len(root.xpath(".//w:tbl", namespaces=NS)) == 21
assert len(root.xpath(".//w:ins//w:del|.//w:del//w:ins", namespaces=NS)) == 0
toc_fields = [n.text or "" for n in root.xpath(".//w:instrText[contains(., 'TOC')]", namespaces=NS)]
assert sum('\\o "1-3"' in value for value in toc_fields) == 1
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)

for phrase in [
    "Figure 2–Figure 25 Annotated screenshots",
    "Before the A/B comparison is run",
    "Quantifying this requires the matched-volume A/B experiment",
    "What remains for future work is a matched-volume A/B comparison",
]:
    assert phrase not in whole, phrase

for number in range(2, 26):
    matches = [t for t in texts if re.match(fr"Figure {number}\s{{3}}", t)]
    assert len(matches) == 1, (number, matches)

for required in [
    "Davis, J., & Goadrich, M. (2006).",
    "Saito, T., & Rehmsmeier, M. (2015).",
    "The method and results are reported in Section 5.3.6",
    "The matched static/adaptive experiment was run and is reported in Section 5.3.6 and Appendix C.",
    "Section 7.3.6 defines the remaining test against a re-scanning adversary",
]:
    assert required in whole, required

authors = Counter(
    value
    for value in root.xpath(".//w:ins/@w:author | .//w:del/@w:author", namespaces=NS)
)
assert sum(authors.values()) > 0

report = {
    "zip_ok": True,
    "package_parts_preserved": len(src_media) >= 1,
    "media_files": len(src_media),
    "media_hashes_preserved": True,
    "tables": 21,
    "toc_field_count": 1,
    "toc_depth": "Heading 1–3",
    "update_fields_on_open": True,
    "expanded_figure_entries": 24,
    "nested_revision_errors": 0,
    "revision_authors": dict(authors),
}
Path(sys.argv[3]).write_text(json.dumps(report, indent=2), encoding="utf-8")
print(json.dumps(report, indent=2))
