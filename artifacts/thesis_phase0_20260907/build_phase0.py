"""Apply the user-requested Phase 0 repairs to thesis_v26_tracked.docx.

The builder edits OOXML directly so existing revisions, fields, images,
bookmarks and package parts survive byte-for-byte except document.xml and
settings.xml. New content changes are attributed to the AI assistant.
"""

from __future__ import annotations

import copy
import difflib
import hashlib
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree


NS = {"w": "http://schemas.openxmlformats.org/wordprocessingml/2006/main"}
W = "{%s}" % NS["w"]
XML_SPACE = "{http://www.w3.org/XML/1998/namespace}space"
AUTHOR = "AI assistant"
DATE = datetime(2026, 9, 7, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def accepted_text(paragraph: etree._Element) -> str:
    return "".join(
        node.text or ""
        for node in paragraph.xpath(".//w:t[not(ancestor::w:del)]", namespaces=NS)
    )


def paragraph_style(paragraph: etree._Element) -> str:
    values = paragraph.xpath("./w:pPr/w:pStyle/@w:val", namespaces=NS)
    return values[0] if values else ""


def paragraphs(root: etree._Element):
    return root.xpath(".//w:p", namespaces=NS)


def find_one(root: etree._Element, prefix: str) -> etree._Element:
    found = [p for p in paragraphs(root) if accepted_text(p).strip().startswith(prefix)]
    if len(found) != 1:
        raise LookupError(f"expected one paragraph starting {prefix!r}, found {len(found)}")
    return found[0]


def first_rpr(paragraph: etree._Element):
    values = paragraph.xpath(".//w:r/w:rPr", namespaces=NS)
    return copy.deepcopy(values[0]) if values else None


def clear_paragraph_content(paragraph: etree._Element):
    for child in list(paragraph):
        if child.tag != W + "pPr":
            paragraph.remove(child)


def new_revision(tag: str, revision_id: int):
    revision = etree.Element(W + tag)
    revision.set(W + "id", str(revision_id))
    revision.set(W + "author", AUTHOR)
    revision.set(W + "date", DATE)
    return revision


def new_run(text: str, rpr=None, deleted=False):
    run = etree.Element(W + "r")
    if rpr is not None:
        run.append(copy.deepcopy(rpr))
    node = etree.SubElement(run, W + ("delText" if deleted else "t"))
    node.set(XML_SPACE, "preserve")
    node.text = text
    return run


def tokenise(text: str):
    return re.findall(r"\s+|[\w]+|[^\w\s]", text, flags=re.UNICODE)


def diff_segments(old: str, new: str):
    left, right = tokenise(old), tokenise(new)
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            yield "keep", "".join(left[i1:i2])
        elif tag == "delete":
            yield "del", "".join(left[i1:i2])
        elif tag == "insert":
            yield "ins", "".join(right[j1:j2])
        elif tag == "replace":
            yield "del", "".join(left[i1:i2])
            yield "ins", "".join(right[j1:j2])


class Editor:
    def __init__(self, root):
        self.root = root
        ids = []
        for value in root.xpath(".//*[@w:id]/@w:id", namespaces=NS):
            if str(value).isdigit():
                ids.append(int(value))
        self.next_id = max(ids, default=10000) + 1
        self.changes = []

    def revision(self, tag):
        result = new_revision(tag, self.next_id)
        self.next_id += 1
        return result

    def append_segment(self, paragraph, kind, text, rpr):
        if not text:
            return
        if kind == "keep":
            paragraph.append(new_run(text, rpr))
        elif kind == "del":
            revision = self.revision("del")
            revision.append(new_run(text, rpr, deleted=True))
            paragraph.append(revision)
        elif kind == "ins":
            revision = self.revision("ins")
            revision.append(new_run(text, rpr))
            paragraph.append(revision)

    def rewrite_original(self, paragraph, new_text, label):
        if paragraph.xpath(".//w:ins|.//w:del", namespaces=NS):
            raise ValueError(f"{label}: expected an unrevised source paragraph")
        old = accepted_text(paragraph)
        rpr = first_rpr(paragraph)
        clear_paragraph_content(paragraph)
        self.append_segment(paragraph, "del", old, rpr)
        self.append_segment(paragraph, "ins", new_text, rpr)
        self.changes.append({"label": label, "old": old, "new": new_text})

    def replace_original_once(self, paragraph, old_fragment, new_fragment, label):
        if paragraph.xpath(".//w:ins|.//w:del", namespaces=NS):
            raise ValueError(f"{label}: expected an unrevised source paragraph")
        old = accepted_text(paragraph)
        if old.count(old_fragment) != 1:
            raise LookupError(f"{label}: expected one old fragment, found {old.count(old_fragment)}")
        before, after = old.split(old_fragment, 1)
        rpr = first_rpr(paragraph)
        clear_paragraph_content(paragraph)
        for kind, text in [
            ("keep", before), ("del", old_fragment), ("ins", new_fragment), ("keep", after)
        ]:
            self.append_segment(paragraph, kind, text, rpr)
        self.changes.append({"label": label, "old": old, "new": before + new_fragment + after})

    def rewrite_inserted(self, paragraph, new_text, label):
        old = accepted_text(paragraph)
        rpr = first_rpr(paragraph)
        clear_paragraph_content(paragraph)
        revision = self.revision("ins")
        revision.append(new_run(new_text, rpr))
        paragraph.append(revision)
        ppr = paragraph.find(W + "pPr")
        if ppr is None:
            ppr = etree.Element(W + "pPr")
            paragraph.insert(0, ppr)
        mark = ppr.find(W + "rPr")
        if mark is None:
            mark = etree.SubElement(ppr, W + "rPr")
        for prior in list(mark):
            if prior.tag in (W + "ins", W + "del"):
                mark.remove(prior)
        mark.append(self.revision("ins"))
        self.changes.append({"label": label, "old": old, "new": new_text})

    def remove_inserted(self, paragraph, label):
        old = accepted_text(paragraph)
        paragraph.getparent().remove(paragraph)
        self.changes.append({"label": label, "old": old, "new": ""})

    def delete_original_paragraph(self, paragraph, label):
        old = accepted_text(paragraph)
        rpr = first_rpr(paragraph)
        clear_paragraph_content(paragraph)
        revision = self.revision("del")
        revision.append(new_run(old, rpr, deleted=True))
        paragraph.append(revision)
        ppr = paragraph.find(W + "pPr")
        if ppr is None:
            ppr = etree.Element(W + "pPr")
            paragraph.insert(0, ppr)
        mark = ppr.find(W + "rPr")
        if mark is None:
            mark = etree.SubElement(ppr, W + "rPr")
        mark.append(self.revision("del"))
        self.changes.append({"label": label, "old": old, "new": ""})

    def inserted_clone_after(self, anchor, template, text, label):
        paragraph = copy.deepcopy(template)
        for attr in list(paragraph.attrib):
            if attr.endswith("paraId") or attr.endswith("textId"):
                del paragraph.attrib[attr]
        clear_paragraph_content(paragraph)
        revision = self.revision("ins")
        revision.append(new_run(text, first_rpr(template)))
        paragraph.append(revision)
        ppr = paragraph.find(W + "pPr")
        if ppr is None:
            ppr = etree.Element(W + "pPr")
            paragraph.insert(0, ppr)
        mark = ppr.find(W + "rPr")
        if mark is None:
            mark = etree.SubElement(ppr, W + "rPr")
        for prior in list(mark):
            if prior.tag in (W + "ins", W + "del"):
                mark.remove(prior)
        mark.append(self.revision("ins"))
        anchor.addnext(paragraph)
        self.changes.append({"label": label, "old": "", "new": text})
        return paragraph

    def inserted_mixed_clone_after(self, anchor, template, label_text, body_text, label):
        paragraph = copy.deepcopy(template)
        for attr in list(paragraph.attrib):
            if attr.endswith("paraId") or attr.endswith("textId"):
                del paragraph.attrib[attr]
        source_runs = template.xpath(".//w:r", namespaces=NS)
        label_rpr = copy.deepcopy(source_runs[0].find(W + "rPr")) if source_runs else None
        body_rpr = None
        if len(source_runs) > 1 and source_runs[1].find(W + "rPr") is not None:
            body_rpr = copy.deepcopy(source_runs[1].find(W + "rPr"))
        clear_paragraph_content(paragraph)
        label_revision = self.revision("ins")
        label_revision.append(new_run(label_text, label_rpr))
        paragraph.append(label_revision)
        body_revision = self.revision("ins")
        body_revision.append(new_run(body_text, body_rpr))
        paragraph.append(body_revision)
        ppr = paragraph.find(W + "pPr")
        if ppr is None:
            ppr = etree.Element(W + "pPr")
            paragraph.insert(0, ppr)
        mark = ppr.find(W + "rPr")
        if mark is None:
            mark = etree.SubElement(ppr, W + "rPr")
        for prior in list(mark):
            if prior.tag in (W + "ins", W + "del"):
                mark.remove(prior)
        mark.append(self.revision("ins"))
        anchor.addnext(paragraph)
        self.changes.append({"label": label, "old": "", "new": label_text + body_text})
        return paragraph


def set_update_fields(settings):
    nodes = settings.xpath("./w:updateFields", namespaces=NS)
    node = nodes[0] if nodes else etree.SubElement(settings, W + "updateFields")
    node.set(W + "val", "true")


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main(source: Path, destination: Path):
    destination.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(source) as package:
        document = etree.fromstring(package.read("word/document.xml"))
        settings = etree.fromstring(package.read("word/settings.xml"))

        editor = Editor(document)

        # 0.1 — add the two cited sources at their alphabetical positions.
        cowrie = find_one(document, "Cowrie Project. (n.d.). Cowrie.")
        davis = (
            "Davis, J., & Goadrich, M. (2006). The relationship between "
            "Precision-Recall and ROC curves. In Proceedings of the 23rd "
            "International Conference on Machine Learning (ICML '06) "
            "(pp. 233–240). ACM. https://doi.org/10.1145/1143844.1143874"
        )
        editor.inserted_clone_after(cowrie, cowrie, davis, "0.1 reference — Davis and Goadrich (2006)")

        ring = find_one(document, "Ring, M., Wunderlich")
        saito = (
            "Saito, T., & Rehmsmeier, M. (2015). The precision-recall plot is "
            "more informative than the ROC plot when evaluating binary "
            "classifiers on imbalanced datasets. PLOS ONE, 10(3), e0118432. "
            "https://doi.org/10.1371/journal.pone.0118432"
        )
        editor.inserted_clone_after(ring, ring, saito, "0.1 reference — Saito and Rehmsmeier (2015)")

        # 0.2 — leave results in 5.3.6 and turn 6.3.2 into interpretation only.
        discussion_start = find_one(document, "The matched comparison called for above")
        new_discussion_1 = (
            "The method and results are reported in Section 5.3.6, with the full "
            "protocol and outcome tables in Appendix C; they are not repeated here. "
            "Read against RQ2, the replication establishes the cost side of adaptive "
            "exposure: withdrawing the advertised endpoints denied access to clients "
            "that continued to address them, substantially reduced authorised-session "
            "continuity, and produced fewer Cowrie interactions under the fixed workload."
        )
        editor.rewrite_inserted(discussion_start, new_discussion_1, "0.2 §6.3.2 results-to-interpretation")
        for prefix in [
            "The result is directional and large.",
            "Read against RQ2, this measures the cost side",
            "Three boundaries prevent this",
            "The defensible position is therefore narrower",
        ]:
            editor.remove_inserted(find_one(document, prefix), f"0.2 §6.3.2 remove duplicated paragraph — {prefix}")
        new_discussion_2 = (
            "It does not establish the proposed intelligence benefit. The scanner "
            "never re-enumerated after rotation, so it could not exhibit the added "
            "probing, delay or evidence generation predicted for an adversary forced "
            "to rediscover the service. Cowrie's direct listeners also remained "
            "reachable inside the laboratory network, and the authorised client was "
            "a controlled workload rather than organic traffic. RQ2 therefore remains "
            "only partly answered: endpoint withdrawal and its continuity cost are "
            "demonstrated, while intelligence yield requires the re-scanning, "
            "bind-restricted experiment specified in Section 7.3.6."
        )
        editor.inserted_clone_after(
            discussion_start, discussion_start, new_discussion_2,
            "0.2 §6.3.2 fixed-adversary limitation",
        )

        # 0.3 — make every forward/back reference describe what was run and what remains.
        key_insight = find_one(document, "What the experiment revealed.")
        old_tail = (
            "What remains for future work is a matched-volume A/B comparison "
            "quantifying the difference in reconnaissance dwell time and log volume "
            "between Phase 1 and Phase 2."
        )
        new_tail = (
            "The paired live-service experiment in Section 5.3.6 subsequently tested "
            "fixed-endpoint withdrawal and continuity under matched static/adaptive "
            "trials. The remaining question is whether a re-scanning adversary "
            "generates additional evidence after forced rediscovery, as specified in "
            "Section 7.3.6."
        )
        editor.replace_original_once(
            key_insight, old_tail, new_tail,
            "0.3 §5.3.5 completed comparison and remaining test",
        )

        earlier_result = find_one(document, "It is important to be precise about what this experiment")
        old_tail = (
            "It does not demonstrate that intelligence collection improves. Ports 22 "
            "and 23, the actual Cowrie-backed services that collect credentials, remain "
            "visible under both phases because their PREROUTING DNAT rules execute "
            "before the INPUT chain and are not modified by the rotation logic. An "
            "attacker targeting the honeypot's real services is therefore not meaningfully "
            "impeded by the Phase 2 rotation in this experimental configuration. "
            "Demonstrating improved intelligence collection would require a matched A/B "
            "experiment measuring credential capture volume, attacker dwell time, and "
            "reconnection frequency under Phase 1 and Phase 2 conditions, which is "
            "identified as the primary future-work direction in Section 7.3."
        )
        new_tail = (
            "On its own, it does not demonstrate that intelligence collection improves. "
            "Ports 22 and 23, the actual Cowrie-backed services that collect credentials, "
            "remain visible under both phases in this earlier configuration because "
            "their PREROUTING redirects are unchanged. The paired experiment in Section "
            "5.3.6 later tested real Cowrie-backed services and showed fewer interactions "
            "under a fixed, non-re-enumerating scanner. Whether forced rediscovery "
            "produces additional evidence remains untested and is specified in Section "
            "7.3.6."
        )
        editor.replace_original_once(
            earlier_result, old_tail, new_tail,
            "0.3 §6.3.1 historical result cross-reference",
        )

        summary = find_one(document, "RQ2 is mechanically confirmed but not fully answered")
        summary_new = (
            "RQ2 is mechanically confirmed but not fully answered. Table 6.1 "
            "established that the controller can hide a probed non-Cowrie port, and "
            "the paired live-service experiment in Section 5.3.6 demonstrated "
            "repeatable withdrawal of the original Cowrie endpoints together with a "
            "substantial continuity cost and fewer interactions under the fixed "
            "workload. That experiment did not test whether forced rediscovery "
            "increases intelligence collection: the scanner did not re-enumerate, and "
            "Cowrie's direct listeners remained reachable inside the laboratory "
            "network. Section 7.3.6 therefore specifies a repeat with a re-scanning "
            "adversary after the Cowrie bind restriction is applied."
        )
        editor.rewrite_original(summary, summary_new, "0.3 §6.8 RQ2 summary")

        rq2_answer = find_one(document, "The adaptive mechanism is mechanically correct and its core")
        rq2_new = (
            "The adaptive mechanism is mechanically correct and its fixed-endpoint "
            "withdrawal effect is empirically confirmed. Table 6.1 demonstrated a "
            "non-Cowrie port changing from closed to filtered, while the paired "
            "experiment in Section 5.3.6 tested real Cowrie SSH and Telnet services "
            "across eight static/adaptive blocks. Adaptive rotation withdrew the "
            "advertised endpoints, imposed a mean 79.4-percentage-point reduction in "
            "authorised-client continuity and reduced subsequent Cowrie interactions "
            "under the fixed workload. This answers the mechanism and cost parts of "
            "RQ2, but it does not establish an intelligence benefit: the scanner did "
            "not re-enumerate after rotation, and Cowrie's direct listeners remained "
            "reachable inside the laboratory network. Section 7.3.6 defines the "
            "remaining test against a re-scanning adversary with the bind restriction "
            "applied."
        )
        editor.rewrite_original(rq2_answer, rq2_new, "0.3 §7.1 RQ2 answer")

        future = find_one(document, "The controlled nmap experiment (Table 6.1, Section 6.3.1)")
        future_new = (
            "The matched static/adaptive experiment was run and is reported in Section "
            "5.3.6 and Appendix C. It demonstrated repeatable withdrawal of the "
            "original endpoints and a substantial continuity cost under a fixed "
            "scanner that continued to probe the same ports. It did not test the "
            "reconnaissance-delay hypothesis because the scanner did not re-enumerate, "
            "and Cowrie remained bound to 0.0.0.0 so its direct listeners were still "
            "reachable inside the laboratory network. The remaining work is to bind "
            "Cowrie to a loopback or internal interface, repeat the paired design with "
            "an adversary that re-scans after each rotation, and measure additional "
            "probe attempts, time to authentication, Zeek and Cowrie evidence volume, "
            "and authorised-client continuity. That experiment would test whether "
            "forced rediscovery improves intelligence collection rather than only "
            "confirming endpoint withdrawal."
        )
        editor.rewrite_original(future, future_new, "0.3 §7.3.6 remaining experiment")

        # 0.4 — preserve the existing real TOC and expand the collapsed LoF entry.
        toc_codes = document.xpath(".//w:instrText[contains(., 'TOC')]", namespaces=NS)
        if not any('\\o "1-3"' in (node.text or "") for node in toc_codes):
            raise AssertionError("Heading 1–3 TOC field not found")
        set_update_fields(settings)

        collapsed = find_one(document, "Figure 2–Figure 25 Annotated screenshots")
        figure_one = find_one(document, "Figure 1   System architecture")
        caption_paragraphs = []
        for paragraph in paragraphs(document):
            text = accepted_text(paragraph).strip()
            match = re.match(r"Figure (\d+)\.\s+(.*)", text)
            if paragraph_style(paragraph) == "Caption" and match and 2 <= int(match.group(1)) <= 25:
                caption_paragraphs.append((int(match.group(1)), match.group(2).rstrip(".")))
        caption_paragraphs.sort()
        if [number for number, _ in caption_paragraphs] != list(range(2, 26)):
            raise AssertionError("Figure 2–25 captions are incomplete")
        editor.delete_original_paragraph(collapsed, "0.4 remove collapsed Figure 2–25 LoF entry")
        anchor = collapsed
        for number, caption in caption_paragraphs:
            label_text = f"Figure {number}   "
            body_text = f"{caption} (Appendix A)"
            anchor = editor.inserted_mixed_clone_after(
                anchor, figure_one, label_text, body_text,
                f"0.4 List of Figures — Figure {number}"
            )

        document_bytes = etree.tostring(
            document, xml_declaration=True, encoding="UTF-8", standalone=True
        )
        settings_bytes = etree.tostring(
            settings, xml_declaration=True, encoding="UTF-8", standalone=True
        )
        with zipfile.ZipFile(destination, "w") as output:
            for item in package.infolist():
                data = package.read(item.filename)
                if item.filename == "word/document.xml":
                    data = document_bytes
                elif item.filename == "word/settings.xml":
                    data = settings_bytes
                output.writestr(item, data)

    manifest = {
        "status": "phase0_complete_pending_user_review",
        "source": str(source),
        "source_sha256": sha256(source),
        "output": str(destination),
        "output_sha256": sha256(destination),
        "author": AUTHOR,
        "changes": editor.changes,
        "toc": {
            "existing_field_preserved": True,
            "depth": "Heading 1–3",
            "update_fields_on_open": True,
            "duplicate_inserted": False,
        },
        "phase_a_started": False,
    }
    manifest_path = destination.with_name("phase0_manifest.json")
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")

    diff_path = destination.with_name("phase0_diff.md")
    lines = [
        "# Phase 0 tracked diff",
        "",
        f"Source: `{source}`",
        "",
        f"Output: `{destination}`",
        "",
    ]
    for change in editor.changes:
        lines.extend([
            f"## {change['label']}",
            "",
            "```diff",
        ])
        if change["old"]:
            lines.append("- " + change["old"])
        if change["new"]:
            lines.append("+ " + change["new"])
        lines.extend(["```", ""])
    diff_path.write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({
        "output": str(destination),
        "sha256": manifest["output_sha256"],
        "changes": len(editor.changes),
        "manifest": str(manifest_path),
        "diff": str(diff_path),
    }, indent=2))


if __name__ == "__main__":
    main(Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve())
