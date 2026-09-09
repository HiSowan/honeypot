from __future__ import annotations

import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from lxml import etree


W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def accepted(node: etree._Element) -> str:
    return "".join(
        item.text or ""
        for item in node.xpath(".//w:t[not(ancestor::w:del)]", namespaces=NS)
    )


source, output, report_path = map(Path, sys.argv[1:4])
with ZipFile(source) as source_zip, ZipFile(output) as output_zip:
    assert source_zip.testzip() is None and output_zip.testzip() is None
    source_media = {
        name: digest(source_zip.read(name))
        for name in source_zip.namelist() if name.startswith("word/media/")
    }
    output_media = {
        name: digest(output_zip.read(name))
        for name in output_zip.namelist() if name.startswith("word/media/")
    }
    assert source_media == output_media
    document = etree.fromstring(output_zip.read("word/document.xml"))
    settings = etree.fromstring(output_zip.read("word/settings.xml"))

paragraphs = document.xpath(".//w:p", namespaces=NS)
texts = [accepted(paragraph).strip() for paragraph in paragraphs]
whole = "\n".join(text for text in texts if text)

required = [
    "Reversing the live model's score direction gives ROC-AUC 0.813 (95% CI [0.794, 0.830])",
    "the inverted live score is the strongest retrospective ROC ranker on this labelled allowlist-excluded sample",
    "reversing ROC-AUC 0.152 gives 0.848",
    "The reversed score is best understood as attack similarity, not repaired anomaly detection",
    "not its best validated detector",
    "A lower production attack rate would not by itself flip ROC-AUC",
    "prevalence-invariant for fixed class-conditional scores",
    "the unresolved risk is that a different background distribution changes those scores",
    "Reversing the inequality instead produces the separate attack-similarity ranking",
    "does not establish the best deployable detector",
    "Contribution 2: Separation of ranking direction from operating-point failure",
    "exact score reversal gives ROC-AUC 0.813 [0.794, 0.830]",
]
for phrase in required:
    assert phrase in whole, phrase

stale = [
    "cannot rescue the live model beyond an almost-all-positive rule",
    "The live-retrained model remains unusable",
    "direction is fitted to a population that is 68% attack, so it would flip again",
    "ROC-AUC 0.187 is no signal",
]
for phrase in stale:
    assert phrase not in whole, phrase

abstract_start = texts.index("Abstract")
abstract_end = next(
    index for index in range(abstract_start + 1, len(texts))
    if texts[index].startswith("Keywords:")
)
abstract_text = " ".join(texts[abstract_start + 1 : abstract_end])
abstract_words = len(re.findall(r"\b[\w%−.–]+\b", abstract_text))
assert abstract_words == 341

tables = document.xpath(".//w:body/w:tbl", namespaces=NS)
assert len(tables) == 21
assert len(output_media) == 27
assert len(document.xpath(".//w:ins//w:del | .//w:del//w:ins", namespaces=NS)) == 0
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)
authors = Counter(document.xpath(".//w:ins/@w:author | .//w:del/@w:author", namespaces=NS))
assert sum(authors.values()) > 0

report = {
    "zip_ok": True,
    "media_files_preserved": len(output_media),
    "tables": len(tables),
    "abstract_word_count_excluding_keywords": abstract_words,
    "nested_revision_errors": 0,
    "revision_authors": dict(authors),
    "insertions": len(document.xpath(".//w:ins", namespaces=NS)),
    "deletions": len(document.xpath(".//w:del", namespaces=NS)),
    "required_claim_checks": len(required),
    "stale_claim_checks": len(stale),
    "update_fields_on_open": True,
}
report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps(report, indent=2))
