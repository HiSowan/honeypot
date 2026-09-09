from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from lxml import etree

NS = {
    "w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main",
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def accepted(node):
    return "".join(t.text or "" for t in node.xpath(".//w:t[not(ancestor::w:del)]", namespaces=NS))

source, output, report_path = map(Path, sys.argv[1:4])
with ZipFile(source) as src, ZipFile(output) as dst:
    assert src.testzip() is None and dst.testzip() is None
    src_media = {n: digest(src.read(n)) for n in src.namelist() if n.startswith("word/media/")}
    dst_media = {n: digest(dst.read(n)) for n in dst.namelist() if n.startswith("word/media/")}
    assert set(src_media).issubset(dst_media)
    assert all(dst_media[name] == value for name, value in src_media.items())
    assert "word/media/figure26_iforest_curves.png" in dst_media
    root = etree.fromstring(dst.read("word/document.xml"))
    settings = etree.fromstring(dst.read("word/settings.xml"))

texts = [accepted(p).strip() for p in root.xpath(".//w:p", namespaces=NS)]
whole = "\n".join(t for t in texts if t)
tables = root.xpath(".//w:body/w:tbl", namespaces=NS)
assert len(tables) == 21
assert [len(t.xpath("./w:tr[1]/w:tc", namespaces=NS)) for t in (tables[8], tables[9], tables[13])] == [10, 12, 12]
for table, expected in [(tables[8], "0.611"), (tables[9], "0.610"), (tables[13], "0.148")]:
    assert "ROC-AUC" in accepted(table) and "PR-AUC" in accepted(table) and expected in accepted(table)
assert len(root.xpath(".//w:ins//w:del|.//w:del//w:ins", namespaces=NS)) == 0
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)

for required in [
    "5.2.1.1 Binary Random Forest Detection Baseline",
    "0.963 recall on UNSW-NB15",
    "Threshold-free evaluation changes the interpretation",
    "Figure 26. Isolation Forest ROC and precision–recall curves",
    "Figure 26   Isolation Forest ROC and precision–recall curves",
    "The Table 5.3 counts reproduce model.predict() at the zero decision boundary",
    "Those literal-threshold matrices should not be cited as Table 5.3 results",
    "ROC-AUC 0.611 [0.581, 0.641]",
    "PR-AUC 0.782 [0.766, 0.801]",
    "99.52% of records",
    "contamination selects the predict() offset rather than changing score order",
    "6.4.2 Isolation Forest: Ranking, Operating Points, and the Contamination Constraint",
    "mean paired change of −79.4 percentage points",
]:
    assert required in whole, required

for stale in [
    "cannot be closed by tuning",
    "cannot be bridged by parameter tuning",
    "neither model discriminates attack from benign external traffic",
    "Isolation Forest cannot be calibrated for predominantly-hostile honeypot traffic",
    "the evaluation dataset is too small to produce reliable threshold-performance curves",
    "both models operate at or below chance",
    "fixes the proportion of records scoring below zero by construction",
]:
    assert stale not in whole, stale

abstract_start = texts.index("Abstract")
abstract_end = next(i for i in range(abstract_start + 1, len(texts)) if texts[i].startswith("Keywords:"))
abstract_text = " ".join(texts[abstract_start + 1:abstract_end])
abstract_words = len(re.findall(r"\b[\w%−.–]+\b", abstract_text))
assert 300 <= abstract_words <= 350, abstract_words

authors = Counter(root.xpath(".//w:ins/@w:author | .//w:del/@w:author", namespaces=NS))
assert sum(authors.values()) > 0

report = {
    "zip_ok": True,
    "source_media_files_preserved": len(src_media),
    "output_media_files": len(dst_media),
    "tables": len(tables),
    "phase_b_table_column_counts": [10, 12, 12],
    "abstract_word_count_excluding_keywords": abstract_words,
    "nested_revision_errors": 0,
    "revision_authors": dict(authors),
    "required_claim_checks": 13,
    "stale_claim_checks": 7,
    "update_fields_on_open": True,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
