"""Build the evidence-led tracked Phase B thesis successor.

The source is never modified. Existing revisions, fields and media are preserved;
all new prose is attributed to the author and every change is located by accepted text.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
from pathlib import Path
from zipfile import ZipFile

from lxml import etree

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ROOT / "artifacts" / "thesis_phase0_20260907" / "thesis_v27_phase0_tracked.docx"
PHASE0_BUILDER = ROOT / "artifacts" / "thesis_phase0_20260907" / "build_phase0.py"
FIGURE = HERE / "figure26_iforest_curves.png"
OUTPUT = HERE / "thesis_v28_phaseB_tracked_raw.docx"
DIFF = HERE / "phaseB_diff.md"
MANIFEST = HERE / "phaseB_manifest.json"

spec = importlib.util.spec_from_file_location("phase0_builder", PHASE0_BUILDER)
phase0 = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(phase0)
phase0.DATE = "2026-09-08T00:00:00Z"

NS = dict(phase0.NS)
NS.update({
    "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
    "wp": "http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing",
    "a": "http://schemas.openxmlformats.org/drawingml/2006/main",
    "pic": "http://schemas.openxmlformats.org/drawingml/2006/picture",
    "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
})
W = phase0.W
R = "{%s}" % NS["r"]
PR = "{%s}" % NS["pr"]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_one_style(root, prefix: str, style: str):
    found = [
        p for p in phase0.paragraphs(root)
        if phase0.accepted_text(p).strip().startswith(prefix)
        and phase0.paragraph_style(p) == style
    ]
    if len(found) != 1:
        raise LookupError((prefix, style, len(found)))
    return found[0]


def rewrite(editor, paragraph, new_text: str, label: str):
    if paragraph.xpath(".//w:ins|.//w:del", namespaces=NS):
        editor.rewrite_inserted(paragraph, new_text, label)
    else:
        editor.rewrite_original(paragraph, new_text, label)


def set_style(paragraph, style: str):
    ppr = paragraph.find(W + "pPr")
    if ppr is None:
        ppr = etree.Element(W + "pPr")
        paragraph.insert(0, ppr)
    pstyle = ppr.find(W + "pStyle")
    if pstyle is None:
        pstyle = etree.Element(W + "pStyle")
        ppr.insert(0, pstyle)
    pstyle.set(W + "val", style)


def set_cell_text(editor, cell, text: str, width: int):
    tcpr = cell.find(W + "tcPr")
    if tcpr is None:
        tcpr = etree.Element(W + "tcPr")
        cell.insert(0, tcpr)
    tcw = tcpr.find(W + "tcW")
    if tcw is None:
        tcw = etree.SubElement(tcpr, W + "tcW")
    tcw.set(W + "w", str(width))
    tcw.set(W + "type", "dxa")
    cell_ins = editor.revision("cellIns")
    tcpr.append(cell_ins)
    paras = cell.xpath("./w:p", namespaces=NS)
    template = copy.deepcopy(paras[0]) if paras else etree.Element(W + "p")
    for child in list(cell):
        if child.tag != W + "tcPr":
            cell.remove(child)
    phase0.clear_paragraph_content(template)
    ins = editor.revision("ins")
    ins.append(phase0.new_run(text, phase0.first_rpr(paras[0]) if paras else None))
    template.append(ins)
    cell.append(template)


def add_metric_columns(editor, table, expected_header, values_by_row, scale: float, label: str):
    rows = table.xpath("./w:tr", namespaces=NS)
    header = [phase0.accepted_text(c) for c in rows[0].xpath("./w:tc", namespaces=NS)]
    if header != expected_header:
        raise AssertionError((label, header))
    grid = table.find(W + "tblGrid")
    old_widths = [int(c.get(W + "w")) for c in grid.findall(W + "gridCol")]
    total = sum(old_widths)
    scaled = [max(300, round(value * scale)) for value in old_widths]
    new_width = (total - sum(scaled)) // 2
    for col, width in zip(grid.findall(W + "gridCol"), scaled):
        col.set(W + "w", str(width))
    for width in (new_width, total - sum(scaled) - new_width):
        col = etree.SubElement(grid, W + "gridCol")
        col.set(W + "w", str(width))

    for row_index, row in enumerate(rows):
        cells = row.xpath("./w:tc", namespaces=NS)
        if len(cells) == 1:
            spans = cells[0].xpath("./w:tcPr/w:gridSpan", namespaces=NS)
            if spans:
                spans[0].set(W + "val", str(int(spans[0].get(W + "val")) + 2))
            continue
        if len(cells) != len(expected_header):
            raise AssertionError((label, row_index, len(cells)))
        for cell, width in zip(cells, scaled):
            tcw = cell.find("./w:tcPr/w:tcW", namespaces=NS)
            if tcw is not None:
                tcw.set(W + "w", str(width))
        values = values_by_row[row_index]
        for text, width in zip(values, (new_width, total - sum(scaled) - new_width)):
            new_cell = copy.deepcopy(cells[-1])
            set_cell_text(editor, new_cell, text, width)
            row.append(new_cell)
    editor.changes.append({
        "label": label,
        "old": " | ".join(expected_header),
        "new": " | ".join(expected_header + ["ROC-AUC", "PR-AUC"]),
    })


def rewrite_cell(editor, table, row_index: int, col_index: int, text: str, label: str):
    cell = table.xpath("./w:tr", namespaces=NS)[row_index].xpath("./w:tc", namespaces=NS)[col_index]
    paras = cell.xpath("./w:p", namespaces=NS)
    if len(paras) != 1:
        raise AssertionError((label, len(paras)))
    rewrite(editor, paras[0], text, label)


def set_table_font(table, half_points: int):
    for run in table.xpath(".//w:r", namespaces=NS):
        rpr = run.find(W + "rPr")
        if rpr is None:
            rpr = etree.Element(W + "rPr")
            run.insert(0, rpr)
        for tag in ("sz", "szCs"):
            node = rpr.find(W + tag)
            if node is None:
                node = etree.SubElement(rpr, W + tag)
            node.set(W + "val", str(half_points))


def set_table_widths(table, widths):
    grid = table.find(W + "tblGrid")
    cols = grid.findall(W + "gridCol")
    if len(cols) != len(widths):
        raise AssertionError((len(cols), len(widths)))
    for col, width in zip(cols, widths):
        col.set(W + "w", str(width))
    for row in table.xpath("./w:tr", namespaces=NS):
        cells = row.xpath("./w:tc", namespaces=NS)
        if len(cells) != len(widths):
            continue
        for cell, width in zip(cells, widths):
            tcw = cell.find("./w:tcPr/w:tcW", namespaces=NS)
            if tcw is not None:
                tcw.set(W + "w", str(width))


def keep_rows_with_next(table, row_indexes):
    rows = table.xpath("./w:tr", namespaces=NS)
    for row_index in row_indexes:
        for paragraph in rows[row_index].xpath(".//w:p", namespaces=NS):
            ppr = paragraph.find(W + "pPr")
            if ppr is None:
                ppr = etree.Element(W + "pPr")
                paragraph.insert(0, ppr)
            if ppr.find(W + "keepNext") is None:
                etree.SubElement(ppr, W + "keepNext")


def add_figure(editor, document, rels, anchor, caption_template):
    captions = [
        p for p in phase0.paragraphs(document)
        if phase0.accepted_text(p).strip().startswith("Figure C.1 ")
        and phase0.paragraph_style(p) == "Caption"
    ]
    if len(captions) != 1:
        raise LookupError("Figure C.1 caption")
    source_image = captions[0].getprevious()
    if not source_image.xpath(".//@r:embed", namespaces=NS):
        raise AssertionError("Figure C.1 image paragraph not found")
    image_para = copy.deepcopy(source_image)
    for attr in list(image_para.attrib):
        if attr.endswith("paraId") or attr.endswith("textId"):
            del image_para.attrib[attr]

    ids = []
    for value in rels.xpath("./pr:Relationship/@Id", namespaces=NS):
        match = re.fullmatch(r"rId(\d+)", value)
        if match:
            ids.append(int(match.group(1)))
    rid = f"rId{max(ids) + 1}"
    relationship = etree.SubElement(rels, PR + "Relationship")
    relationship.set("Id", rid)
    relationship.set("Type", "http://schemas.openxmlformats.org/officeDocument/2006/relationships/image")
    relationship.set("Target", "media/figure26_iforest_curves.png")
    for blip in image_para.xpath(".//@r:embed", namespaces=NS):
        pass
    for blip in image_para.xpath(".//a:blip", namespaces=NS):
        blip.set(R + "embed", rid)

    width, height = 5486400, 2114500
    for extent in image_para.xpath(".//wp:extent | .//a:xfrm/a:ext", namespaces=NS):
        extent.set("cx", str(width))
        extent.set("cy", str(height))
    max_docpr = max([int(v) for v in document.xpath(".//wp:docPr/@id", namespaces=NS)] or [100]) + 1
    for docpr in image_para.xpath(".//wp:docPr", namespaces=NS):
        docpr.set("id", str(max_docpr))
        docpr.set("name", "Figure 26 Isolation Forest curves")
    for nvpr in image_para.xpath(".//pic:cNvPr", namespaces=NS):
        nvpr.set("id", str(max_docpr))
        nvpr.set("name", "figure26_iforest_curves.png")

    insertion = editor.revision("ins")
    for child in list(image_para):
        if child.tag != W + "pPr":
            image_para.remove(child)
            insertion.append(child)
    image_para.append(insertion)
    ppr = image_para.find(W + "pPr")
    if ppr is None:
        ppr = etree.Element(W + "pPr")
        image_para.insert(0, ppr)
    mark = ppr.find(W + "rPr")
    if mark is None:
        mark = etree.SubElement(ppr, W + "rPr")
    mark.append(editor.revision("ins"))
    anchor.addnext(image_para)
    editor.changes.append({"label": "B2 Figure 26 full ROC/PR curves", "old": "", "new": "[Figure 26 inserted]"})

    caption = editor.inserted_clone_after(
        image_para,
        caption_template,
        "Figure 26. Isolation Forest ROC and precision–recall curves on the allowlist-excluded population (n = 2,271). The anomaly direction is −score_samples. The UNSW baseline ranks attacks modestly above background (ROC-AUC 0.611; PR-AUC 0.782 versus 0.680 base rate), whereas the live-retrained model ranks in the wrong direction (ROC-AUC 0.187; PR-AUC 0.628). Full curve coordinates are retained with the Phase A evaluation artefacts.",
        "B2 Figure 26 caption",
    )
    set_style(caption, "Caption")


def main():
    with ZipFile(SOURCE) as package:
        document = etree.fromstring(package.read("word/document.xml"))
        settings = etree.fromstring(package.read("word/settings.xml"))
        rels = etree.fromstring(package.read("word/_rels/document.xml.rels"))
        editor = phase0.Editor(document)

        abstract = [
            "This thesis contributes an empirical diagnosis of public-benchmark ML failure on real Zeek traffic, an adaptive honeypot artefact, and a replicated evaluation of scanner-triggered exposure. It asks whether one low-resource VM can capture attacks, change its exposed surface, and support reliable automated detection.",
            "Using Design Science Research, the artefact combines Cowrie, Zeek, Loki, Grafana, a Python adaptive controller, and Random Forest and Isolation Forest models on Ubuntu Server 24.04. Three runtime phases provide static exposure, scan-triggered port rotation, and ML-augmented shadow-mode blocking.",
            "RQ1 was answered affirmatively within SSH-only coverage. Cowrie captured 56 credential pairs; the pipeline accumulated 36,911 uid-deduplicated Zeek records, including 1,544 labelled attacks; and five services operated concurrently.",
            "For RQ2, eight replicated static/adaptive pairs using real Cowrie-backed services showed that rotation withdrew the original endpoints but reduced authorised-client post-scan success from 99.4% to 20.0%, a mean paired change of −79.4 percentage points. Because the scanner did not re-enumerate, the experiment establishes endpoint withdrawal and continuity cost rather than improved intelligence yield.",
            "For RQ3, the nine-class Random Forest labelled 1,540 of 1,544 live attacks Normal. A binary baseline achieved 0.963 recall on UNSW-NB15 but the same 4/1,544 (0.26%) live sensitivity, confirming that the coverage gap is independent of prediction target. On allowlist-excluded traffic (n = 2,271; base rate 0.680), the UNSW-trained Isolation Forest showed modest ranking (ROC-AUC 0.611; PR-AUC 0.782) and post-hoc best F1 0.869. The live model anti-ranked (ROC-AUC 0.187; PR-AUC 0.628) and reached F1 0.812 only by flagging 99.52%. The contamination parameter cannot represent a 68.0% rate, although arbitrary thresholds remain possible; no evaluated configuration supports safe live blocking.",
            "The transferable rule is to verify every categorical vocabulary before assuming that a shared field name creates a shared feature across sensors. Section 4.10 documents 19 engineering and evaluation defects whose correction changed headline figures, showing that the measurement harness requires the artefact's level of iterative scrutiny.",
        ]
        word_count = len(re.findall(r"\b[\w%−.–]+\b", " ".join(abstract)))
        assert 300 <= word_count <= 350, word_count
        for prefix, new, label in zip(
            [
                "Honeypots are a well-established technique",
                "The system was designed and built using",
                "First, a Random Forest classifier",
                "Second, an Isolation Forest",
                "Third, a controlled nmap experiment",
                "The findings demonstrate that",
            ],
            abstract,
            [f"B3 Abstract paragraph {i}" for i in range(1, 7)],
        ):
            rewrite(editor, phase0.find_one(document, prefix), new, label)

        rewrite(editor, phase0.find_one(document, "The Isolation Forest was trained with n_estimators"),
            "The Isolation Forest was trained with n_estimators=100, contamination=0.1, and random_state=42. Two models exist: iforest_anomaly.joblib (trained on UNSW-NB15) provides the public-dataset baseline, while iforest_live.joblib was retrained on 345 real Zeek records. Section 5.2.2 separates operating-point performance from ranking quality. On allowlist-excluded traffic, the UNSW model has modest useful ranking (ROC-AUC 0.611; PR-AUC 0.782 against a 0.680 base rate), although its default decision boundary has low recall. The live-retrained model anti-ranks attacks (ROC-AUC 0.187; PR-AUC 0.628), so its higher flag rate reflects a boundary fitted to attack-only local data rather than improved detection. predict.py automatically prefers the live model when present; the results therefore support retaining shadow mode until retraining includes representative background traffic and an independently validated operating point.",
            "Final sweep Chapter 4 IForest description")

        rewrite(editor, phase0.find_one(document, "Problem: The Isolation Forest was trained with contamination"),
            "Problem: The Isolation Forest was configured with contamination = 0.10. In the full allowlist-excluded population, 68.0% of records are attack (1,544 of 2,271), so that setting understates the observed rate by 58.0 percentage points. scikit-learn restricts contamination to values below 0.5, which prevents its standard predict() offset from being set to the observed base rate. The parameter changes the offset applied to score_samples; it does not change score ordering, and an analyst can threshold decision_function at any value. The earlier claim that the 18.0-point gap could not be closed by tuning therefore overstated what the API limit proves.",
            "B2 Challenge 18 problem correction")
        rewrite(editor, phase0.find_one(document, "Resolution: None applied. The gap is a library constraint"),
            "Resolution: No model or production-code change was applied. Table 5.8 retains the contamination experiment as evidence about the standard predict() parameterisation, while Section 5.2.2 reports a full score-threshold sweep. On allowlist-excluded traffic, the UNSW baseline reaches a post-hoc best F1 of 0.869, proving that its fixed operating point discarded modest ranking signal. The live-retrained model remains unusable: its best F1 is 0.812 only when 99.52% of records are flagged. The corrected conclusion separates an API operating-point limitation from model ranking quality.",
            "B2 Challenge 18 resolution")

        rf_anchor = phase0.find_one(document, "The training coverage gap is the primary cause")
        rf_heading = editor.inserted_clone_after(rf_anchor, find_one_style(document, "5.2.2 Isolation Forest", "Heading3"),
            "5.2.1.1 Binary Random Forest Detection Baseline", "A3 binary RF heading")
        set_style(rf_heading, "Heading4")
        rf_p1 = editor.inserted_clone_after(rf_heading, rf_anchor,
            "To test whether the nine-class attack-type target caused the transfer failure, a second Random Forest was trained on the same 12 features using UNSW-NB15's uncontaminated binary label (0 = normal, 1 = attack). It used 100 trees, random_state = 42, n_jobs = −1, and an 80/20 split stratified on the binary target (140,272 training and 35,069 test records). On the UNSW-NB15 test set it achieved accuracy 0.944, precision 0.955, recall 0.963, F1 0.959, and specificity 0.903 (TP = 22,994; FP = 1,090; TN = 10,110; FN = 875). The attack_cat canonicalisation defect does not affect this binary target.",
            "A3 binary RF benchmark result")
        editor.inserted_clone_after(rf_p1, rf_anchor,
            "Transfer to the canonical live archive still failed. Only 4 of 1,544 live attack records were labelled attack, giving sensitivity 0.26%, exactly the 4/1,544 result of the multiclass detector. On the full archive, accuracy was 0.926 but precision and F1 were each approximately 0.003 because the background class dominates; on the allowlist-excluded population, accuracy was 0.310 and F1 was 0.005. The binary experiment therefore rules out prediction-target choice as the explanation and strengthens the sensor-vocabulary coverage-gap diagnosis.",
            "A3 binary RF live transfer result")

        rewrite(editor, phase0.find_one(document, "The IForest evaluation on the full Zeek conn.log archive"),
            "The IForest evaluation on the full Zeek conn.log archive (36,911 uid-deduplicated records: 1,544 attack and 35,367 background; base rate 4.18%) is reported in Table 5.3. Its fixed operating-point columns use model.predict() = −1, equivalently decision_function < 0. The full-archive lifts of 4.249 and 4.101 remain an allowlist-separation artefact: 93.85% of the archive is allowlisted hypervisor and loopback traffic, and 89.9% of full-archive false positives fall on allowlisted addresses. The added ROC-AUC and PR-AUC columns evaluate score ordering independently of that operating point; PR-AUC is read against each population's attack base rate as established in Section 2.3.",
            "B1 §5.2.2 AUC introduction")

        tables = document.xpath(".//w:body/w:tbl", namespaces=NS)
        add_metric_columns(editor, tables[8],
            ["Model", "Population", "Flags", "Flag rate", "Precision [95% CI]", "Recall [95% CI]", "F1", "Lift"],
            {
                0: ("ROC-AUC", "PR-AUC"),
                1: ("0.872", "0.302"), 2: ("0.942", "0.315"),
                3: ("0.611", "0.782"), 4: ("0.187", "0.628"),
            }, 0.80, "A1 Table 5.3 AUC columns")
        add_metric_columns(editor, tables[9],
            ["Model", "TP", "FP", "TN", "FN", "Precision [95% CI]", "Recall [95% CI]", "F1", "Flag%", "Lift"],
            {
                0: ("ROC-AUC", "PR-AUC"),
                2: ("0.863", "0.299"), 3: ("0.928", "0.294"),
                5: ("0.610", "0.761"), 6: ("0.152", "0.553"),
            }, 0.82, "A1 Table 5.4 AUC columns")
        add_metric_columns(editor, tables[13],
            ["Model", "TP", "FP", "TN", "FN", "Precision [95\u00a0CI]", "Recall [95\u00a0CI]", "F1", "Flag%", "Lift"],
            {
                0: ("ROC-AUC", "PR-AUC"),
                1: ("0.609", "0.784"), 2: ("0.148", "0.584"), 3: ("0.148", "0.584"),
            }, 0.82, "A1 Table 5.8 AUC columns")

        # Keep the added columns legible on the existing portrait pages. The
        # captions retain all sample-size detail, so repeated labels can be compact.
        for row, model, population, flags in [
            (1, "UNSW", "Full archive", "2031"),
            (2, "Live", "Full archive", "2355"),
            (3, "UNSW", "Allowlist-excl.", "529"),
            (4, "Live", "Allowlist-excl.", "1108"),
        ]:
            rewrite_cell(editor, tables[8], row, 0, model, f"Table 5.3 compact model row {row}")
            rewrite_cell(editor, tables[8], row, 1, population, f"Table 5.3 compact population row {row}")
            rewrite_cell(editor, tables[8], row, 2, flags, f"Table 5.3 compact flags row {row}")
        rewrite_cell(editor, tables[8], 0, 3, "Flag%", "Table 5.3 compact flag header")
        rewrite_cell(editor, tables[8], 0, 4, "P [95% CI]", "Table 5.3 compact precision header")
        rewrite_cell(editor, tables[8], 0, 5, "R [95% CI]", "Table 5.3 compact recall header")
        set_table_font(tables[8], 18)
        set_table_widths(tables[8], [920, 1500, 562, 678, 1050, 1050, 720, 720, 913, 913])

        for row, model in [(2, "UNSW"), (3, "Local split"), (5, "UNSW"), (6, "Local split")]:
            rewrite_cell(editor, tables[9], row, 0, model, f"Table 5.4 compact model row {row}")
        rewrite_cell(editor, tables[9], 2, 3, "10119", "Table 5.4 compact TN row 2")
        rewrite_cell(editor, tables[9], 3, 3, "9667", "Table 5.4 compact TN row 3")
        rewrite_cell(editor, tables[9], 0, 5, "P [95% CI]", "Table 5.4 compact precision header")
        rewrite_cell(editor, tables[9], 0, 6, "R [95% CI]", "Table 5.4 compact recall header")
        set_table_font(tables[9], 17)
        keep_rows_with_next(tables[9], [0, 1])

        for row, model in [(1, "UNSW (0.10)"), (2, "Local (0.10)"), (3, "Local (0.499)")]:
            rewrite_cell(editor, tables[13], row, 0, model, f"Table 5.8 compact model row {row}")
        rewrite_cell(editor, tables[13], 0, 5, "P [95% CI]", "Table 5.8 compact precision header")
        rewrite_cell(editor, tables[13], 0, 6, "R [95% CI]", "Table 5.8 compact recall header")
        set_table_font(tables[13], 17)

        caption53 = phase0.find_one(document, "Table 5.3: IForest ground-truth")
        rewrite(editor, caption53,
            "Table 5.3: IForest ground-truth evaluation (frozen uid-deduplicated archive). Ground-truth label: src_ip 10.10.0.2 = attack, all others = background. Full archive: n = 36,911 (1,544 attack and 35,367 background, base rate 4.18%). Allowlist-excluded: n = 2,271 (1,544 attack and 727 background, base rate 67.99%). Fixed operating point: model.predict() = −1, equivalently decision_function < 0. Wilson 95% confidence intervals are shown for precision and recall. ROC-AUC and PR-AUC (average precision) are threshold-free; PR baselines equal 0.042 and 0.680 respectively.",
            "Table 5.3 operating-point and AUC caption")
        correction = editor.inserted_clone_after(caption53, phase0.find_one(document, "Note: Recall is identical across both populations"),
            "Operating-point correction. The Table 5.3 counts reproduce model.predict() at the zero decision boundary; the earlier caption's −0.1 description was incorrect. Applying decision_function < −0.1 literally gives, for the UNSW baseline, TP = 297, FP = 104, TN = 623, FN = 1,247 and F1 = 0.305; for the live-retrained model, TP = 217, FP = 314, TN = 413, FN = 1,327 and F1 = 0.209. Those literal-threshold matrices should not be cited as Table 5.3 results. The separate 432-record session figures and controller blocking gate continue to use −0.1.",
            "Table 5.3 threshold correction note")

        caption54 = phase0.find_one(document, "Table 5.4: IForest held-out evaluation")
        rewrite(editor, caption54, phase0.accepted_text(caption54) +
            " ROC-AUC and PR-AUC use −score_samples; PR baselines are 0.042 for the full held-out population and 0.648 for its allowlist-excluded subset.",
            "Table 5.4 AUC caption")
        rewrite(editor, phase0.find_one(document, "Note: Recall is identical across both populations"),
            "The held-out AUCs reproduce the ranking contrast without UID overlap. On the allowlist-excluded held-out set, the UNSW baseline reaches ROC-AUC 0.610 and PR-AUC 0.761 against a 0.648 base rate, while the corrected-split local model reaches ROC-AUC 0.152 and PR-AUC 0.553. The fixed-boundary lifts of 1.042 and 0.500 therefore describe operating-point quality, not score ordering: the UNSW model retains modest ranking signal, whereas the local model anti-ranks. The high full-held-out ROC-AUC values, 0.863 and 0.928, remain dominated by separation of allowlisted traffic and are not evidence of attack-versus-legitimate-external discrimination.",
            "A1 Table 5.4 held-out interpretation")
        sweep = phase0.find_one(document, "Removing allowlisted addresses yields the production-representative evaluation")
        rewrite(editor, sweep,
            "Threshold-free evaluation changes the interpretation of the fixed-boundary results. On all 2,271 allowlist-excluded records, the UNSW baseline has ROC-AUC 0.611 (95% stratified-bootstrap CI [0.581, 0.641]) and PR-AUC 0.782 [0.766, 0.801], above the 0.680 PR baseline. A full decision_function sweep gives a post-hoc best F1 of 0.869 at threshold ≤ 0.034956 (precision 0.793, recall 0.962; 82.47% flagged), compared with an all-positive F1 of 0.809. The model therefore contains modest ranking signal that the default boundary discards. The live-retrained model anti-ranks in the intended anomaly direction: ROC-AUC 0.187 [0.170, 0.206] and PR-AUC 0.628 [0.617, 0.640], below baseline. Its best F1 is 0.812 at threshold ≤ 0.092544 only because 99.52% of records are flagged (precision 0.683, recall 1.000), an improvement of 0.002 over predicting every record as attack. These best-F1 values are descriptive post-hoc upper bounds on this population, not validated deployment thresholds.",
            "A2 §5.2.2 threshold sweep")
        caption_template = phase0.find_one(document, "Figure 1. System architecture")
        add_figure(editor, document, rels, sweep, caption_template)
        lof25 = [p for p in phase0.paragraphs(document) if phase0.accepted_text(p).startswith("Figure 25   ")]
        if len(lof25) != 1:
            raise LookupError(("LoF Figure 25", len(lof25)))
        editor.inserted_mixed_clone_after(lof25[0], lof25[0], "Figure 26   ",
            "Isolation Forest ROC and precision–recall curves on allowlist-excluded traffic (Section 5.2.2)",
            "List of Figures entry Figure 26")

        rewrite(editor, phase0.find_one(document, "Table 5.8: IForest contamination-mismatch"),
            "Table 5.8: IForest contamination-mismatch experiment (allowlist-excluded held-out partition, n = 683: 464 attack and 219 background; base rate 67.9%). Same attack partition as Table 5.4, with an independent background draw. Local-ext models were retrained on the corresponding 70% training partition. scikit-learn enforces contamination < 0.5, so its standard predict() offset cannot be set to the observed 68.0% attack rate; arbitrary decision thresholds remain possible. Identical AUCs for the two Local-ext settings show that contamination changes the offset, not score ordering. Zero UID overlap was verified. Wilson 95% confidence intervals are shown for precision and recall; the PR baseline is 0.679.",
            "B2 Table 5.8 corrected caption")
        rewrite(editor, phase0.find_one(document, "Table 5.7: Dataset attribute comparison"),
            "Table 5.7: Dataset attribute comparison, UNSW-NB15 versus live Zeek data. The contamination setting of 0.1 selects the model's training-data offset; it does not fix the score < 0 rate on a different evaluation population or change score ordering. The table's score < 0 counts are measured operating-point outcomes on the 432-record session, while the blocking figures use the stricter −0.1 threshold.",
            "B2 Table 5.7 contamination clarification")

        rewrite(editor, phase0.find_one(document, "Key insight: neither model discriminates"),
            "Key insight: fixed operating-point metrics and ranking metrics answer different questions. The full-archive lift of 4.1–4.2 is an allowlist-separation artefact. On allowlist-excluded traffic, the UNSW baseline's default boundary is weak (lift 1.004; recall 0.234), yet its ROC-AUC 0.611 and PR-AUC 0.782 versus a 0.680 base rate show modest useful ordering; a post-hoc sweep raises F1 from 0.348 to 0.869. The live-retrained model ranks in the wrong direction (ROC-AUC 0.187; PR-AUC 0.628) and reaches best F1 0.812 only by flagging 99.52% of records. Table 5.8 isolates the contamination parameter: changing it from 0.10 to 0.499 changes predict() counts but leaves both local-model AUCs identical (0.148 ROC; 0.584 PR). The API cap prevents the standard contamination setting from matching a 68.0% attack rate, but it does not constrain arbitrary score thresholds. Neither evaluated configuration supports safe live blocking; the causes are a discarded modest signal for the UNSW model and anti-ranking after attack-only local retraining.",
            "B2 §5.3.5 key insight")

        heading642 = find_one_style(document, "6.4.2 Isolation Forest", "Heading3")
        rewrite(editor, heading642, "6.4.2 Isolation Forest: Ranking, Operating Points, and the Contamination Constraint", "B2 §6.4.2 heading")
        toc642 = find_one_style(document, "6.4.2 Isolation Forest", "TOC3")
        toc_old = phase0.accepted_text(toc642)
        page_suffix = re.search(r"(\d+)\s*$", toc_old)
        rewrite(editor, toc642, "6.4.2 Isolation Forest: Ranking, Operating Points, and the Contamination Constraint" + (page_suffix.group(1) if page_suffix else ""), "B2 ToC §6.4.2 heading")

        replacements = [
            ("The IForest comparison (Table 5.3) produces a clean negative result.",
             "Table 5.3 separates ranking from the default operating point. On the allowlist-excluded population (n = 2,271; base rate 67.99%), the UNSW baseline's fixed-boundary lift is 1.004 and recall is 0.234, but ROC-AUC 0.611 [0.581, 0.641] and PR-AUC 0.782 [0.766, 0.801] versus a 0.680 base rate establish modest useful ranking. Its post-hoc best F1 is 0.869 rather than the default-boundary 0.348. The live-retrained model is qualitatively different: ROC-AUC 0.187 and PR-AUC 0.628 show anti-ranking, and its best F1 0.812 requires flagging 99.52% of records. On the full archive both models show high ROC-AUC, 0.872 and 0.942, but those values are dominated by the 93.85% allowlisted hypervisor and loopback traffic; they do not measure attack-versus-legitimate-external separation. The zero-UID-overlap results in Table 5.4 reproduce the same ranking directions on held-out data.", "B2 §6.4.2 ranking interpretation"),
            ("The root cause is a structural parametrisation constraint, not a model quality problem.",
             "The contamination constraint is narrower than the earlier claim. scikit-learn's contamination parameter selects the offset used by predict(); it does not alter score ordering. Because the API restricts contamination to values below 0.5, the standard parameter cannot be set to the observed 68.0% attack rate, but decision_function can be thresholded anywhere. Table 5.8 demonstrates the distinction: Local-ext contamination settings 0.10 and 0.499 produce different confusion matrices yet identical ROC-AUC 0.148 and PR-AUC 0.584. The full threshold sweep then shows that arbitrary thresholding recovers useful F1 from the UNSW ranking but cannot rescue the live model beyond an almost-all-positive rule. The missing realistic background corpus remains the substantive data problem: retraining on 345 attack-dominated local records makes typical attacks central rather than anomalous.", "B2 §6.4.2 contamination correction"),
            ("Neither model is suitable for live blocking on the production-representative population",
             "Neither model is suitable for live blocking on the production-representative population. The UNSW model's modest ranking has not been validated as a prospective threshold and its best-F1 point would flag 82.47% of external records; the live model anti-ranks. Shadow mode identified two background IPs (10.0.2.15 and 127.0.0.1) that were added to the operator allowlist before live blocking was considered. The retraining infrastructure remains useful, but safe deployment requires representative labelled background traffic, independent threshold validation and monitoring for ranking inversion. Earlier contaminated evaluations are superseded by the zero-UID-overlap analyses in Tables 5.4 and 5.8.", "B2 §6.4.2 deployment conclusion"),
            ("The contamination-mismatch result carries a general external-validity implication.",
             "The contamination-mismatch result supports two bounded external-validity lessons. First, scikit-learn's standard contamination parameter cannot directly encode an expected anomaly proportion above 50%, although users remain free to threshold scores outside predict(). Second, contamination changes the operating-point offset rather than the ranking, so evaluations must report threshold-free metrics and compare PR-AUC with the observed positive-class base rate. For honeypots, results should also be reported after applying the production allowlist and on a zero-overlap held-out partition, since the full archive can measure separation from management traffic rather than attacks from legitimate external traffic.", "B2 §6.5 external-validity narrowing"),
            ("Isolation Forest in network security.",
             "Isolation Forest in network security. Liu et al. (2008) demonstrated that Isolation Forest can perform competitively on network intrusion datasets. The present result does not contradict that general finding. The UNSW baseline retains modest ordering on allowlist-excluded live traffic, but its deployed boundary discards much of the signal; the attack-only live retraining reverses the ordering. Training speed remains operationally attractive, yet it does not replace representative background data, threshold-free evaluation, or independent operating-point validation.", "B2 §6.5 prior-work comparison"),
            ("Single-host, single-session evaluation.",
             "Single-host, controlled-environment evaluation. The canonical archive comes from one Kali VM and one Ubuntu honeypot VM on an isolated VirtualBox network, while the paired Phase 1/2 experiment uses a separate scripted workload. Unknown tools, multi-source attacks, evasion and diverse legitimate traffic are not represented. The IForest ranking results therefore describe this captured population: modest for the UNSW baseline and inverted for the live model. The post-hoc best-F1 threshold is an upper bound fitted to these labels, not an expected production result. External deployment requires independently labelled benign traffic and prospective threshold validation.", "Final sweep §6.6 controlled-evaluation limitation"),
            ("Training and evaluation set overlap.",
             "Training and evaluation set overlap. The live IForest was trained on 345 records and its full-archive evaluation is partially in-sample. Table 5.4 resolves this for the corrected-split model through a zero-UID-overlap partition: the allowlist-excluded held-out results reproduce the ranking directions, with ROC-AUC 0.610 for the UNSW baseline and 0.152 for the locally trained model. The 345-record corpus is also small and attack-dominated, so increasing it without adding representative background traffic need not improve ranking; it may make common attacks still less anomalous.", "Final sweep §6.6 overlap limitation"),
            ("Threshold sensitivity.",
             "Threshold sensitivity. The controller's −0.1 blocking threshold was selected from the observed score distribution rather than an independent optimisation set. The completed full sweep shows that threshold choice discarded useful UNSW ranking signal, but its best F1 of 0.869 is post-hoc on the evaluation population. It must not be deployed as a validated threshold. A future calibration phase should select the operating point on separate labelled data, freeze it, and then evaluate it prospectively; the live model's anti-ranking must first be corrected through representative background training.", "A2 §6.6 threshold limitation"),
            ("The design cycle did not proceed in one pass.",
             "The design cycle did not proceed in one pass. Initial RF transfer failed, leading to correction of the Argus-to-Zeek encoding defect and diagnosis of the remaining vocabulary coverage gap. Six evaluation defects were then identified: deduplication key error, capture-interface contamination, allowlist bypass, stratification error, contamination mismatch and silent exception swallowing. A subsequent threshold-free pass found a seventh interpretive defect: fixed-threshold lift had been treated as ranking evidence. ROC/PR analysis showed modest UNSW IForest ordering and live-model anti-ranking, while the binary RF baseline showed that supervised transfer failure persists independently of prediction target. Each correction changed the inference only where the evidence required it.", "Final sweep §6.7 design-cycle update"),
            ("This is the design science cycle operating as intended.",
             "This is the design-science cycle operating as intended. The artefact captures traffic and surfaces decisions, while the evaluation distinguishes implementation function from detector validity. The RF finding is a sensor-vocabulary coverage failure confirmed under both multiclass and binary targets. The IForest finding is two-part: threshold selection discarded modest signal in the UNSW baseline, whereas attack-only local retraining inverted the ranking. The appropriate next iteration is closed-loop retraining with representative labelled Zeek background traffic and a prospectively validated operating point.", "Final sweep §6.7 interpretation update"),
            ("RQ3 is answered negatively for both models on the production-representative population.",
             "RQ3 receives a qualified negative answer for operational detection. The multiclass RF labels 1,540 of 1,544 live attacks Normal, and the binary RF independently reproduces sensitivity of 4/1,544 (0.26%) despite achieving 0.963 recall on the UNSW test set. The coverage gap therefore survives the change of target. The UNSW IForest does rank attacks modestly on allowlist-excluded traffic (ROC-AUC 0.611; PR-AUC 0.782 versus 0.680), and its post-hoc best F1 is 0.869, so it is incorrect to call the model signal-free. However, that operating point is unvalidated and flags 82.47% of records. The live-retrained IForest anti-ranks (ROC-AUC 0.187; PR-AUC 0.628) and cannot be rescued except by an almost-all-positive threshold. The standard contamination parameter also cannot be set to the observed 68.0% rate, but that API restriction does not prevent arbitrary score thresholding. None of these evaluated configurations supports safe automated blocking.", "B2 §6.8 RQ3 summary"),
            ("In the supervised case, no.",
             "In the supervised case, no reliable live transfer was observed. The multiclass Random Forest classifies 1,540 of 1,544 attacks as Normal, and a binary Random Forest trained on the same 12 features achieves 0.963 recall on the UNSW test set yet detects the same 4/1,544 live attacks (0.26%). The confirmed mechanism is the sensor-vocabulary coverage gap: conn_state_REJ appears in 66.4% of live attacks but has no UNSW training example, and 86.8% of live attacks carry an unrepresented state. In the unsupervised case, the answer is more nuanced. The UNSW IForest has modest useful ranking on allowlist-excluded traffic (ROC-AUC 0.611; PR-AUC 0.782 versus a 0.680 base rate), but its default operating point has low recall and its post-hoc best-F1 threshold would flag 82.47% of records. The live-retrained IForest anti-ranks (ROC-AUC 0.187; PR-AUC 0.628) and its best F1 0.812 is essentially the all-positive baseline. The contamination cap limits the standard predict() parameterisation, not the score ranking. These results do not justify live blocking without representative background data and prospective threshold validation.", "B2 §7.1 RQ3 answer"),
            ("Contribution 2: Isolation Forest cannot be calibrated",
             "Contribution 2: Separation of ranking failure from operating-point failure in honeypot anomaly detection. On allowlist-excluded traffic (n = 2,271; base rate 0.680), the UNSW baseline's fixed-boundary lift of 1.004 masks modest useful ordering: ROC-AUC 0.611 [0.581, 0.641], PR-AUC 0.782 [0.766, 0.801], and post-hoc best F1 0.869. The live-retrained model instead anti-ranks attacks (ROC-AUC 0.187; PR-AUC 0.628) and reaches best F1 0.812 only by flagging 99.52% of records. Table 5.8 further shows that contamination settings 0.10 and 0.499 give identical local-model AUCs despite different confusion matrices, empirically demonstrating that contamination selects the predict() offset rather than changing score order. scikit-learn's <0.5 constraint prevents the standard contamination parameter from matching the observed 68.0% attack rate, but arbitrary thresholds remain available. The contribution is therefore a diagnostic method and a bounded negative deployment result: report allowlist-excluded ROC/PR curves, compare PR-AUC with the attack base rate, sweep thresholds, and distinguish an unvalidated operating point from anti-ranking before enabling automated blocking.", "B2 §7.2 Contribution 2"),
            ("No realistic benign external traffic.",
             "No realistic benign external traffic. The archive's background class is loopback and NAT-gateway traffic, most of which is removed by the production allowlist. This limits the meaning of precision and makes attack-only local retraining especially unsuitable: the model learns attacks as its centre and anti-ranks them. The UNSW baseline's modest ranking does not remove this limitation, because its post-hoc best threshold has not been validated against diverse legitimate external activity. A dedicated benign-baseline collection is required before retraining or threshold selection.", "B2 §7.3 limitation update"),
        ]
        for prefix, new, label in replacements:
            rewrite(editor, phase0.find_one(document, prefix), new, label)

        rewrite(editor, phase0.find_one(document, "The 99.7% Normal classification rate on 1,544 live attack records"),
            "The 99.7% Normal classification rate on 1,544 live attack records is a severe instance of the external-validity problem described by Sommer and Paxson (2010) and Ring et al. (2019). The same transfer failure under a binary target, only 4/1,544 attacks detected despite 0.963 UNSW test recall, rules out the multiclass objective as its cause. The dominant mechanism is the sensor-vocabulary coverage gap: conn_state_REJ appears in 66.4% of live attacks and has no UNSW-NB15 training example. The transferable lesson is to verify vocabulary overlap for every categorical feature before assuming a shared field name produces a shared feature representation.",
            "A3 §6.5 binary RF and transferable rule")

        rewrite(editor, phase0.find_one(document, "The Zeek log captured key distinguishing features"),
            "The Zeek log captured the nmap scan's S0/REJ, zero-byte and short-duration signature. Section 5.2.2 shows why this visible pattern did not produce a safe deployed detector: the UNSW IForest ranks attacks only modestly and its default boundary discards much of that signal, while the live-retrained model ranks attacks in the wrong direction. Distinctive traffic is therefore necessary but insufficient without representative training data and validated calibration.",
            "Final sweep §5.1 IForest claim")

        phase0.set_update_fields(settings)
        document_bytes = etree.tostring(document, xml_declaration=True, encoding="UTF-8", standalone=True)
        settings_bytes = etree.tostring(settings, xml_declaration=True, encoding="UTF-8", standalone=True)
        rels_bytes = etree.tostring(rels, xml_declaration=True, encoding="UTF-8", standalone=True)
        with ZipFile(SOURCE) as package, ZipFile(OUTPUT, "w") as out:
            for item in package.infolist():
                if item.filename == "word/media/figure26_iforest_curves.png":
                    continue
                data = package.read(item.filename)
                if item.filename == "word/document.xml":
                    data = document_bytes
                elif item.filename == "word/settings.xml":
                    data = settings_bytes
                elif item.filename == "word/_rels/document.xml.rels":
                    data = rels_bytes
                out.writestr(item, data)
            out.writestr("word/media/figure26_iforest_curves.png", FIGURE.read_bytes())

    diff_lines = [
        "# Phase B tracked-change record",
        "",
        f"Source: `{SOURCE}`",
        f"Output: `{OUTPUT}`",
        "",
        f"Abstract word count (excluding keywords): **{word_count}**",
        "",
    ]
    for index, change in enumerate(editor.changes, 1):
        diff_lines.extend([
            f"## {index}. {change['label']}", "",
            "**Before**", "", change["old"] or "_(new insertion)_", "",
            "**After**", "", change["new"] or "_(deleted)_", "",
        ])
    DIFF.write_text("\n".join(diff_lines), encoding="utf-8", newline="\n")
    manifest = {
        "source": str(SOURCE),
        "source_sha256": sha256(SOURCE),
        "raw_output": str(OUTPUT),
        "raw_output_sha256": sha256(OUTPUT),
        "phase_a_results_sha256": sha256(ROOT / "artifacts" / "thesis_phaseA_20260908" / "phase_a_results.json"),
        "figure26_sha256": sha256(FIGURE),
        "diff": str(DIFF),
        "diff_sha256": sha256(DIFF),
        "abstract_word_count_excluding_keywords": word_count,
        "logical_change_sites": len(editor.changes),
        "status": "raw_tracked_build_complete_pending_render_qa",
    }
    MANIFEST.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()
