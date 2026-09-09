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
SOURCE = (
    ROOT
    / "artifacts"
    / "thesis_inversion_followup_20260908"
    / "thesis_v29_inversion_followup_tracked.docx"
)
FINAL = HERE / "thesis_v30_rf_consistency_tracked.docx"
RAW = HERE / "thesis_v30_rf_consistency_tracked_raw.docx"
IDENTITY = (
    ROOT
    / "artifacts"
    / "thesis_rf_consistency_audit_20260908"
    / "rf_record_identity.json"
)
DIFF = HERE / "rf_consistency_diff.md"
MANIFEST = HERE / "rf_consistency_manifest.json"
STRUCTURE = HERE / "verification_structure_final.json"
RENDER_REPORT = HERE / "render_inspection_final.json"
RENDER_COMPARISON = HERE / "render_comparison.json"
PDF = HERE / "render_final" / "accepted_preview_final.pdf"
VERIFY = HERE / "rf_consistency_verification.json"
AUDIT = HERE / "RF_CONSISTENCY_AUDIT.md"
HANDOVER = HERE / "RF_CONSISTENCY_HANDOVER.md"

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


expected_source = "3d9e79da3d2cda64a10e55d108d0dfe71fc6246b7ce14629959dae24e4e7e2cf"
assert sha256(SOURCE) == expected_source
identity = json.loads(IDENTITY.read_text(encoding="utf-8"))
assert identity["canonical_archive_content_sha256"] == "b3b27e7fa83c63202406d61cb1460cfdf20f1e9d180cdafb22f2b6e9bf709f7b"
assert identity["unsw_csv_sha256"] == "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa"
assert identity["multiclass_model_sha256"] == "d5d8821cf4e5c6c403cf88a1f7fb8d5ee3e5f16e9c8bb211d05c093cdd7e52f7"
assert identity["binary_detected"] == identity["multiclass_detected"] == 4
assert identity["intersection"] == 0
assert identity["binary_only"] == identity["multiclass_only"] == 4
assert identity["identical_detection_masks"] is False

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

required = [
    "4/1,544 live attacks (0.259%, rounded to 0.3%), matching the multiclass count with no shared detections",
    "the two four-record detection sets were disjoint (intersection 0)",
    "independently reproduces the count and sensitivity—4/1,544 (0.259%, rounded to 0.3%)",
    "The counts match, but the detected records are disjoint",
    "Reversing the live model's score direction gives ROC-AUC 0.813 (95% CI [0.794, 0.830])",
    "The reversed score is best understood as attack similarity, not repaired anomaly detection",
    "A lower production attack rate would not by itself flip ROC-AUC",
]
for phrase in required:
    assert phrase in whole, phrase

stale = [
    "0.26%",
    "0.26 %",
    "the same 4/1,544",
    "detects the same 4/1,544 live attacks",
]
for phrase in stale:
    assert phrase not in whole, phrase
assert whole.count("0.259%") == 4
assert whole.count("rounded to 0.3%") == 4

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
    "6.8 Chapter Summary50",
    "7.1 Conclusions51",
    "7.3 Limitations and Future Work53",
]:
    assert entry in toc_text, entry

assert len(tables) == 21
assert len(final_media) == 27
assert len(document.xpath(".//w:ins//w:del | .//w:del//w:ins", namespaces=NS)) == 0
assert sum(authors.values()) == 301
assert insertions == 223 and deletions == 78
assert settings.xpath("boolean(./w:updateFields[@w:val='true'])", namespaces=NS)

structure = json.loads(STRUCTURE.read_text(encoding="utf-8"))
assert structure["nested_revision_errors"] == 0
render = json.loads(RENDER_REPORT.read_text(encoding="utf-8"))
comparison = json.loads(RENDER_COMPARISON.read_text(encoding="utf-8"))
assert render["page_count"] == 84
assert render["blank_pages"] == []
assert render["words_outside_page"] == []
assert render["very_sparse_pages"] == [84]
assert comparison["changed_pages"] == [10, 42, 59, 60]
assert comparison["unchanged_pages"] == 80

diff_text = DIFF.read_text(encoding="utf-8").replace(str(RAW), str(FINAL))
DIFF.write_text(diff_text, encoding="utf-8", newline="\n")

verification = {
    "status": "rf_consistency_correction_complete",
    "source_sha256": sha256(SOURCE),
    "identity_evidence_sha256": sha256(IDENTITY),
    "output_sha256": sha256(FINAL),
    "diff_sha256": sha256(DIFF),
    "accepted_preview_pdf_sha256": sha256(PDF),
    "zip_ok": True,
    "media_files_preserved": len(final_media),
    "tables": len(tables),
    "abstract_word_count_excluding_keywords": abstract_words,
    "toc_entries": len(toc_text),
    "toc_page_numbers_refreshed_from_accepted_layout": True,
    "update_fields_on_open": True,
    "nested_revision_errors": 0,
    "revision_authors": dict(authors),
    "insertions": insertions,
    "deletions": deletions,
    "identity_result": {
        "binary_detected": 4,
        "multiclass_detected": 4,
        "intersection": 0,
        "binary_only": 4,
        "multiclass_only": 4,
    },
    "reported_rate": "4/1,544 = 0.259%, rounded to 0.3%",
    "render_pages": render["page_count"],
    "blank_pages": render["blank_pages"],
    "words_outside_page": render["words_outside_page"],
    "changed_pages": comparison["changed_pages"],
    "pixel_identical_unchanged_pages": comparison["unchanged_pages"],
    "visually_inspected_changed_pages": True,
    "pytest": "107 passed in 8.62s",
    "git_diff_check": "passed (pre-existing LF/CRLF warning for .gitignore)",
    "vm_state_changed": False,
    "temporary_vm_files_removed": True,
    "ml_source_changed": False,
    "product_code_changed": False,
}
VERIFY.write_text(json.dumps(verification, indent=2) + "\n", encoding="utf-8")

manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
manifest.update(
    {
        "status": "rf_consistency_correction_complete",
        "output": str(FINAL),
        "output_sha256": verification["output_sha256"],
        "diff": str(DIFF),
        "diff_sha256": verification["diff_sha256"],
        "logical_change_sites": 4,
        "verification": str(VERIFY),
        "verification_sha256": sha256(VERIFY),
        "accepted_preview_pdf": str(PDF),
        "accepted_preview_pdf_sha256": verification["accepted_preview_pdf_sha256"],
    }
)
MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

audit = f"""# RF consistency audit

## Findings

1. **The rounding criticism was correct.** The exact sensitivity is 4/1,544 = 0.00259067, or 0.259067%. v29 mixed 0.3% and 0.26% for that fraction. v30 states 0.259%, rounded to 0.3%, at each binary-RF comparison and retains 0.3% in the established 26% → 5.4% → 0.3% evaluation trail.

2. **The original Phase A evidence proved equal counts, not record identity.** A new read-only VM audit used the same canonical archive, UNSW CSV, multiclass model and binary-RF procedure. It found binary detected = 4, multiclass detected = 4, intersection = 0, binary-only = 4 and multiclass-only = 4. The binary detections were TCP/22 records with conn_state SH; the multiclass detections were UDP records with conn_state S0 and label Fuzzers. v30 now says the counts match but the detected records are disjoint.

3. **The protected-section edits were authorized by later user instructions.** The 7 September protection applied to a prior closeout. The later Phase 0 request explicitly required paired reconciliation in §6.8, §7.1 RQ2 and §7.3.6, and the user then approved Phase B to integrate the new measured evidence across Chapters 5–7. Leaving the old “chance” conclusion would have contradicted ROC-AUC 0.611 [0.581, 0.641]. The changes were therefore within the later, narrower authorization and are recorded on both coordination boards.

4. **The sign-flip gap is already closed in v29/v30.** §5.2.2 explicitly reports reversed ROC-AUC 0.813 [0.794, 0.830], and §6.4.2 directly explains why this is post-hoc attack similarity after attack-dominated fitting rather than a validated deployable anomaly detector. v30 preserves that wording.

## Evidence

- Identity audit JSON SHA-256: `{sha256(IDENTITY)}`
- v30 SHA-256: `{verification['output_sha256']}`
- Accepted render: 84 pages; changed pages 10, 42, 59 and 60 inspected; other 80 pages pixel-identical to v29.
"""
AUDIT.write_text(audit, encoding="utf-8", newline="\n")

handover = f"""# RF consistency correction handover

## Authoritative document

- `thesis_v30_rf_consistency_tracked.docx`
- SHA-256: `{verification['output_sha256']}`
- Source: v29 SHA-256 `{verification['source_sha256']}` (read-only)

Start further thesis work from v30 at this hash.

## Correction

All binary-RF comparisons now report 4/1,544 as 0.259%, rounded to 0.3%, consistent with the canonical multiclass reporting. The abstract, §5.2.1.1, §6.8 and §7.1 no longer imply that the two models detected the same records.

The read-only VM audit proved the stronger result: binary detected = 4 and multiclass detected = 4, but intersection = 0. The two detection masks are disjoint. Preserve the wording “the counts match, but the detected records are disjoint.” Exact evidence is `../thesis_rf_consistency_audit_20260908/rf_record_identity.json`.

The sign-reversal explanation from v29 remains correct and direct. §5.2.2 reports reversed ROC-AUC 0.813 [0.794, 0.830], while §6.4.2 explains attack-only centring, post-hoc direction selection and the missing representative background validation.

## Validation

The accepted document remains 84 pages. Only pages 10, 42, 59 and 60 differ from v29; the other 80 rendered pages are pixel-identical. The four changed pages were inspected full-size. All 27 media files, 21 tables, tracked revision counts and contents entries are preserved. `pytest`: 107 passed. No VM state, ML source, model artefact, firewall or product code changed; temporary VM audit files were removed.
"""
HANDOVER.write_text(handover, encoding="utf-8", newline="\n")

print(
    json.dumps(
        {
            "output": str(FINAL),
            "output_sha256": verification["output_sha256"],
            "audit": str(AUDIT),
            "verification": str(VERIFY),
            "manifest": str(MANIFEST),
            "handover": str(HANDOVER),
        },
        indent=2,
    )
)
