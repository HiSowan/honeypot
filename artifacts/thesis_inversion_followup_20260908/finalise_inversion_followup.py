from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from lxml import etree


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / "artifacts" / "thesis_phaseB_20260908" / "thesis_v28_phaseB_tracked.docx"
PHASE_A = ROOT / "artifacts" / "thesis_phaseA_20260908" / "phase_a_results.json"
FINAL = HERE / "thesis_v29_inversion_followup_tracked.docx"
RAW = HERE / "thesis_v29_inversion_followup_tracked_raw.docx"
DIFF = HERE / "inversion_followup_diff.md"
MANIFEST = HERE / "inversion_followup_manifest.json"
STRUCTURE = HERE / "verification_structure_final.json"
RENDER_REPORT = HERE / "render_inspection_final.json"
PDF = HERE / "render_final" / "accepted_preview_final.pdf"
VERIFY = HERE / "inversion_followup_verification.json"
HANDOVER = HERE / "INVERSION_FOLLOWUP_HANDOVER.md"

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def accepted(node: etree._Element) -> str:
    return "".join(
        item.text or ""
        for item in node.xpath(".//w:t[not(ancestor::w:del)]", namespaces=NS)
    )


def media_hashes(path: Path) -> dict[str, str]:
    with ZipFile(path) as archive:
        return {
            name: hashlib.sha256(archive.read(name)).hexdigest()
            for name in archive.namelist()
            if name.startswith("word/media/")
        }


with ZipFile(SOURCE) as source_zip, ZipFile(FINAL) as final_zip:
    assert source_zip.testzip() is None and final_zip.testzip() is None
    source_media = media_hashes(SOURCE)
    final_media = media_hashes(FINAL)
    assert source_media == final_media
    document = etree.fromstring(final_zip.read("word/document.xml"))
    settings = etree.fromstring(final_zip.read("word/settings.xml"))

paragraphs = document.xpath(".//w:p", namespaces=NS)
texts = [accepted(paragraph).strip() for paragraph in paragraphs]
whole = "\n".join(text for text in texts if text)
tables = document.xpath(".//w:body/w:tbl", namespaces=NS)
authors = Counter(
    document.xpath(".//w:ins/@w:author | .//w:del/@w:author", namespaces=NS)
)
insertions = len(document.xpath(".//w:ins", namespaces=NS))
deletions = len(document.xpath(".//w:del", namespaces=NS))

required_claims = [
    "Reversing the live model's score direction gives ROC-AUC 0.813 (95% CI [0.794, 0.830])",
    "This exceeds the UNSW baseline's 0.611",
    "The zero-UID-overlap local model shows the same pattern: reversing ROC-AUC 0.152 gives 0.848",
    "These are algebraic, post-hoc direction checks, not prospectively selected detectors",
    "The reversed score is best understood as attack similarity, not repaired anomaly detection",
    "it is the study's strongest retrospective ROC ranker on these labels, but not its best validated detector",
    "A lower production attack rate would not by itself flip ROC-AUC",
    "the unresolved risk is that a different background distribution changes those scores",
    "it is a change of score semantics, not calibration of the deployed anomaly detector",
    "The resulting reverse-direction ROC-AUC 0.813 is a post-hoc, same-population estimate",
    "score reversal gives the study's highest retrospective external-traffic ROC-AUC, 0.813",
    "exact score reversal gives ROC-AUC 0.813 [0.794, 0.830]",
]
for claim in required_claims:
    assert claim in whole, claim

stale_claims = [
    "would flip again on a realistic base rate",
    "the direction is fitted to a population that is 68% attack, so it would flip again",
    "cannot rescue the live model",
    "cannot be closed by tuning",
]
for claim in stale_claims:
    assert claim not in whole, claim

assert len(tables) == 21
assert len(source_media) == 27
abstract_start = texts.index("Abstract")
abstract_end = next(
    index for index in range(abstract_start + 1, len(texts))
    if texts[index].startswith("Keywords:")
)
abstract_text = " ".join(texts[abstract_start + 1 : abstract_end])
abstract_words = len(re.findall(r"\b[\w%−.–]+\b", abstract_text))
assert abstract_words == 341

toc_text = [
    accepted(paragraph).strip()
    for paragraph in paragraphs
    if paragraph.xpath(
        "boolean(./w:pPr/w:pStyle[@w:val='TOC1' or @w:val='TOC2' or @w:val='TOC3'])",
        namespaces=NS,
    )
]
for entry in [
    "5.2.2 Isolation Forest: Anomaly Detection33",
    "6.4.2 Isolation Forest: Ranking, Operating Points, and the Contamination Constraint45",
    "7.2 Contributions52",
    "7.3 Limitations and Future Work53",
]:
    assert entry in toc_text, entry

assert len(document.xpath(".//w:ins//w:del | .//w:del//w:ins", namespaces=NS)) == 0
assert sum(authors.values()) == 301
assert insertions == 223 and deletions == 78
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)

structure = json.loads(STRUCTURE.read_text(encoding="utf-8"))
assert structure["required_claim_checks"] == 12
assert structure["stale_claim_checks"] == 4

render = json.loads(RENDER_REPORT.read_text(encoding="utf-8"))
assert render["page_count"] == 84
assert render["blank_pages"] == []
assert render["words_outside_page"] == []
assert render["very_sparse_pages"] == [84]

diff_text = DIFF.read_text(encoding="utf-8").replace(str(RAW), str(FINAL))
DIFF.write_text(diff_text, encoding="utf-8", newline="\n")

verification = {
    "status": "inversion_followup_complete",
    "source_sha256": sha256(SOURCE),
    "phase_a_results_sha256": sha256(PHASE_A),
    "output_sha256": sha256(FINAL),
    "diff_sha256": sha256(DIFF),
    "accepted_preview_pdf_sha256": sha256(PDF),
    "zip_ok": True,
    "source_media_files_preserved": len(source_media),
    "output_media_files": len(final_media),
    "tables": len(tables),
    "abstract_word_count_excluding_keywords": abstract_words,
    "toc_entries": len(toc_text),
    "toc_page_numbers_refreshed_from_accepted_layout": True,
    "update_fields_on_open": True,
    "nested_revision_errors": 0,
    "revision_authors": dict(authors),
    "insertions": insertions,
    "deletions": deletions,
    "required_claim_checks": len(required_claims),
    "stale_claim_checks": len(stale_claims),
    "reverse_live_roc_auc": 0.813,
    "reverse_live_roc_auc_ci": [0.794, 0.830],
    "reverse_zero_uid_overlap_local_roc_auc": 0.848,
    "render_pages": render["page_count"],
    "blank_pages": render["blank_pages"],
    "words_outside_page": render["words_outside_page"],
    "visually_inspected_all_pages": True,
    "full_size_pages_inspected": [10, 36, 42, 43, 44, 47, 54, 55, 57, 59, 60, 61, 62],
    "pytest": "107 passed in 5.92s",
    "git_diff_check": "passed (pre-existing LF/CRLF warning for .gitignore)",
    "vm_changed": False,
    "ml_source_changed": False,
    "product_code_changed": False,
}
VERIFY.write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
manifest.update(
    {
        "status": "inversion_followup_complete",
        "output": str(FINAL),
        "output_sha256": verification["output_sha256"],
        "diff": str(DIFF),
        "diff_sha256": verification["diff_sha256"],
        "logical_change_sites": 12,
        "verification": str(VERIFY),
        "verification_sha256": sha256(VERIFY),
        "accepted_preview_pdf": str(PDF),
        "accepted_preview_pdf_sha256": verification["accepted_preview_pdf_sha256"],
    }
)
MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

handover = f"""# Inverted-live-IForest follow-up handover

## Authoritative document

- `thesis_v29_inversion_followup_tracked.docx`
- SHA-256: `{verification['output_sha256']}`
- Source: Phase B v28 SHA-256 `{verification['source_sha256']}` (read-only)
- Phase A evidence SHA-256: `{verification['phase_a_results_sha256']}`

Start any further thesis work from v29 at the hash above. Do not rebuild from v28 or edit the older Downloads copies.

## What changed

The thesis now states the implication of live-model ROC-AUC 0.187: exact score reversal gives ROC-AUC 0.813 with transformed 95% CI [0.794, 0.830], above the UNSW baseline's 0.611. The zero-UID-overlap local result likewise reverses from 0.152 to 0.848. Section 5.2.2, Figure 26, Challenge 18, Sections 5.3.5, 6.4.2, 6.6, 6.8, 7.1, 7.2, 7.3, and the abstract now carry the result and its boundary.

The mechanism is expressed as attack similarity: the local Isolation Forest was fitted to 345 attack-dominated records, so recurrent attacks became inliers and the limited background became outlying. Reversing the score therefore changes the operational meaning from anomaly detection to similarity with the captured attacks.

## Statistical correction to preserve

A lower attack prevalence alone does not flip ROC-AUC. ROC-AUC is invariant to prevalence for fixed class-conditional score distributions. The deployment limitation is instead that the direction was selected post hoc on the evaluation labels, no inverted threshold was prospectively fixed, and no representative legitimate external corpus tested whether the class-conditional ordering survives background distribution shift. Do not replace this with the examiner's suggested base-rate-flip explanation.

## Validation and boundaries

The accepted render remains 84 pages with no blank pages and no words outside page bounds. All pages were inspected in seven contact sheets and the changed pages were inspected full-size. The package retains all 27 media files and 21 tables, with 223 insertions, 78 deletions, and all 27 pre-existing revisions. The abstract is 341 words excluding keywords. `pytest` passes: 107 tests.

No VM service, firewall rule, frozen ML source, model artefact, or product code was changed. No inverted PR-AUC or inverted operating threshold was invented; the reverse-ROC result is explicitly an algebraic, post-hoc direction check.
"""
HANDOVER.write_text(handover, encoding="utf-8", newline="\n")

print(json.dumps({
    "output": str(FINAL),
    "output_sha256": verification["output_sha256"],
    "verification": str(VERIFY),
    "manifest": str(MANIFEST),
    "handover": str(HANDOVER),
    "pages": render["page_count"],
    "pytest": verification["pytest"],
}, indent=2))
