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
SOURCE = ROOT / "artifacts" / "thesis_phase0_20260907" / "thesis_v27_phase0_tracked.docx"
PHASE_A = ROOT / "artifacts" / "thesis_phaseA_20260908" / "phase_a_results.json"
FINAL = HERE / "thesis_v28_phaseB_tracked.docx"
RAW = HERE / "thesis_v28_phaseB_tracked_raw.docx"
DIFF = HERE / "phaseB_diff.md"
MANIFEST = HERE / "phaseB_manifest.json"
VERIFY = HERE / "phaseB_verification.json"
RENDER_REPORT = HERE / "render_inspection_final.json"
PDF = HERE / "render_accepted_final_v2" / "accepted_phaseB_final.pdf"
FIGURE = HERE / "figure26_iforest_curves.png"
HANDOVER = HERE / "PHASEB_HANDOVER.md"

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
    assert set(source_media).issubset(final_media)
    assert all(final_media[name] == value for name, value in source_media.items())
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
    "5.2.1.1 Binary Random Forest Detection Baseline",
    "accuracy 0.944, precision 0.955, recall 0.963, F1 0.959, and specificity 0.903",
    "Only 4 of 1,544 live attack records were labelled attack",
    "ROC-AUC 0.611 (95% stratified-bootstrap CI [0.581, 0.641])",
    "PR-AUC 0.782 [0.766, 0.801]",
    "post-hoc best F1 of 0.869 at threshold ≤ 0.034956",
    "ROC-AUC 0.187 [0.170, 0.206]",
    "99.52% of records are flagged",
    "The Table 5.3 counts reproduce model.predict() at the zero decision boundary",
    "Those literal-threshold matrices should not be cited as Table 5.3 results",
    "full allowlist-excluded population, 68.0% of records are attack (1,544 of 2,271)",
    "The parameter changes the offset applied to score_samples; it does not change score ordering",
    "no evaluated configuration supports safe live blocking",
    "mean paired change of −79.4 percentage points",
]
for claim in required_claims:
    assert claim in whole, claim

stale_claims = [
    "464 of 683",
    "allowlist-excluded held-out population, 68.0%",
    "cannot be closed by tuning",
    "cannot be bridged by parameter tuning",
    "neither model discriminates attack from benign external traffic",
    "Isolation Forest cannot be calibrated for predominantly-hostile honeypot traffic",
    "the evaluation dataset is too small to produce reliable threshold-performance curves",
    "both models operate at or below chance",
    "fixes the proportion of records scoring below zero by construction",
]
for claim in stale_claims:
    assert claim not in whole, claim

assert len(tables) == 21
assert [len(t.xpath("./w:tr[1]/w:tc", namespaces=NS)) for t in (tables[8], tables[9], tables[13])] == [10, 12, 12]
for table, required in [
    (tables[8], ["0.872", "0.302", "0.611", "0.782", "0.187", "0.628"]),
    (tables[9], ["0.863", "0.299", "0.928", "0.294", "0.610", "0.761", "0.152", "0.553"]),
    (tables[13], ["0.609", "0.784", "0.148", "0.584"]),
]:
    table_text = accepted(table)
    assert "ROC-AUC" in table_text and "PR-AUC" in table_text
    assert all(value in table_text for value in required)

abstract_start = texts.index("Abstract")
abstract_end = next(
    index for index in range(abstract_start + 1, len(texts))
    if texts[index].startswith("Keywords:")
)
abstract_text = " ".join(texts[abstract_start + 1 : abstract_end])
abstract_words = len(re.findall(r"\b[\w%−.–]+\b", abstract_text))
assert abstract_words == 339

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
    "7.2 Contributions51",
    "Appendix C Replicated Phase 1 and Phase 2 Experiment72",
]:
    assert entry in toc_text, entry

assert len(document.xpath(".//w:ins//w:del | .//w:del//w:ins", namespaces=NS)) == 0
assert sum(authors.values()) == 288
assert insertions == 210 and deletions == 78
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)

render = json.loads(RENDER_REPORT.read_text(encoding="utf-8"))
assert render["page_count"] == 84
assert render["blank_pages"] == []
assert render["words_outside_page"] == []
assert render["very_sparse_pages"] == [84]

diff_text = DIFF.read_text(encoding="utf-8").replace(str(RAW), str(FINAL))
DIFF.write_text(diff_text, encoding="utf-8", newline="\n")

verification = {
    "status": "phase_b_complete",
    "source_sha256": sha256(SOURCE),
    "phase_a_results_sha256": sha256(PHASE_A),
    "output_sha256": sha256(FINAL),
    "diff_sha256": sha256(DIFF),
    "figure26_sha256": sha256(FIGURE),
    "accepted_preview_pdf_sha256": sha256(PDF),
    "zip_ok": True,
    "source_media_files_preserved": len(source_media),
    "output_media_files": len(final_media),
    "tables": len(tables),
    "phase_b_table_column_counts": [10, 12, 12],
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
    "render_pages": render["page_count"],
    "blank_pages": render["blank_pages"],
    "words_outside_page": render["words_outside_page"],
    "visually_inspected_all_pages": True,
    "full_size_pages_inspected": [10, 36, 42, 43, 44, 48, 54, 55, 57],
    "pytest": "107 passed in 2.16s",
    "git_diff_check": "passed",
    "vm_changed": False,
    "ml_source_changed": False,
    "product_code_changed": False,
}
VERIFY.write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
manifest.update(
    {
        "status": "phase_b_complete",
        "output": str(FINAL),
        "output_sha256": verification["output_sha256"],
        "diff": str(DIFF),
        "diff_sha256": verification["diff_sha256"],
        "logical_change_sites": 73,
        "verification": str(VERIFY),
        "verification_sha256": sha256(VERIFY),
        "accepted_preview_pdf": str(PDF),
        "accepted_preview_pdf_sha256": verification["accepted_preview_pdf_sha256"],
    }
)
MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

handover = f"""# Phase B handover

## Authoritative document

- `thesis_v28_phaseB_tracked.docx`
- SHA-256: `{verification['output_sha256']}`
- Source: Phase 0 v27 SHA-256 `{verification['source_sha256']}` (read-only)
- Phase A evidence SHA-256: `{verification['phase_a_results_sha256']}`

Start any further thesis work from v28 at the hash above. Do not rebuild from v27 or edit the older Downloads copies.

## What changed

The abstract is 339 words excluding keywords and now leads with the contribution. Tables 5.3, 5.4 and 5.8 include ROC-AUC and PR-AUC. Section 5.2.2 includes the full score-threshold sweep and Figure 26, and it distinguishes modest useful ranking by the UNSW IForest from anti-ranking by the live-retrained model. Table 5.3 is now correctly described as the default zero decision boundary; the literal −0.1 matrices are reported separately. A binary Random Forest baseline is included in Section 5.2.1.1. Challenge 18 and Chapters 6–7 now separate the contamination API offset constraint from score ordering.

## Canonical evidence now stated

- UNSW IForest, allowlist-excluded: ROC-AUC 0.611 [0.581, 0.641], PR-AUC 0.782 [0.766, 0.801] against base rate 0.680; post-hoc best F1 0.869 at threshold ≤0.034956, flagging 82.47%.
- Live-retrained IForest: ROC-AUC 0.187 [0.170, 0.206], PR-AUC 0.628 [0.617, 0.640]; best F1 0.812 only by flagging 99.52%.
- Binary RF: UNSW test accuracy 0.944, precision 0.955, recall 0.963, F1 0.959, specificity 0.903; live sensitivity 4/1,544 = 0.26%.
- Contamination 0.10 understates the full allowlist-excluded attack rate, 1,544/2,271 = 68.0%, by 58.0 percentage points. The API cap affects the standard predict() offset, while arbitrary score thresholds remain possible.

## “And therefore also” reconciliation

- Chapter 4 model description and Challenge 18 were corrected.
- Chapter 5 tables, captions, operating-point note, held-out interpretation, threshold sweep, Figure 26 and key insight were updated.
- Chapter 6 RQ3, prior-work comparison, limitations, Design Science reflection and summary were updated.
- Chapter 7 answer, Contribution 2 and future-work limitation were updated.
- Abstract, List of Figures and ToC were updated. The ToC page results come from the accepted 84-page layout.

## Validation and boundaries

The accepted render is 84 pages with no blank pages and no words outside page bounds; all pages were inspected in contact sheets and changed pages were inspected full-size. The package retains all 26 source media plus Figure 26, 21 tables, 210 insertions, 78 deletions and all 27 pre-existing revisions. `pytest` passes: 107 tests. Full records are `phaseB_diff.md`, `phaseB_verification.json` and `phaseB_manifest.json`.

No VM service, firewall rule, frozen ML source, model artefact or product code was changed in Phase B.
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
