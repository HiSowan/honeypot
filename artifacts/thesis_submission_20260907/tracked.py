"""Minimal tracked-changes helpers for python-docx.

Produces real w:ins / w:del revisions so every edit is reviewable and
individually acceptable or rejectable in Word.
"""
import copy
from datetime import datetime, timezone

from docx.oxml.ns import qn
from docx.oxml import OxmlElement
from docx.text.paragraph import Paragraph

AUTHOR = "AI assistant"
DATE = datetime(2026, 9, 7, tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

_counter = [9000]


def _rid():
    _counter[0] += 1
    return str(_counter[0])


def _revision(tag):
    el = OxmlElement(tag)
    el.set(qn("w:id"), _rid())
    el.set(qn("w:author"), AUTHOR)
    el.set(qn("w:date"), DATE)
    return el


def _run(text, rpr_template, deleted=False):
    r = OxmlElement("w:r")
    if rpr_template is not None:
        r.append(copy.deepcopy(rpr_template))
    t = OxmlElement("w:delText" if deleted else "w:t")
    t.set(qn("xml:space"), "preserve")
    t.text = text
    r.append(t)
    return r


def _rpr_of(p):
    for r in p.runs:
        if r._r.find(qn("w:rPr")) is not None:
            return r._r.find(qn("w:rPr"))
    return None


def rewrite_paragraph(p, segments):
    """Rebuild a paragraph from (kind, text) segments.

    kind is 'keep', 'del' or 'ins'. Only safe on paragraphs whose runs share
    one formatting; callers check that first.
    """
    rpr = _rpr_of(p)
    for r in list(p._p.findall(qn("w:r"))):
        p._p.remove(r)
    for el in list(p._p):
        if el.tag in (qn("w:ins"), qn("w:del")):
            p._p.remove(el)
    for kind, text in segments:
        if not text:
            continue
        if kind == "keep":
            p._p.append(_run(text, rpr))
        elif kind == "del":
            d = _revision("w:del")
            d.append(_run(text, rpr, deleted=True))
            p._p.append(d)
        elif kind == "ins":
            i = _revision("w:ins")
            i.append(_run(text, rpr))
            p._p.append(i)
    return p


def segment(full, ops):
    """Turn (old, new) ops into keep/del/ins segments over `full`.

    new=None deletes outright. Ops are applied left to right; each `old` must
    occur exactly once.
    """
    segs = []
    pos = 0
    for old, new in ops:
        k = full.find(old, pos)
        if k < 0:
            raise LookupError(f"not found: {old[:60]!r}")
        segs.append(("keep", full[pos:k]))
        segs.append(("del", old))
        if new:
            segs.append(("ins", new))
        pos = k + len(old)
    segs.append(("keep", full[pos:]))
    return segs


def tracked_edit(p, ops):
    if len(p.runs) == 0:
        raise ValueError("paragraph has no runs")
    return rewrite_paragraph(p, segment(p.text, ops))


def tracked_replace_all(p, new_text):
    return rewrite_paragraph(p, [("del", p.text), ("ins", new_text)])


def tracked_delete_paragraph(p):
    """Mark every run deleted and mark the paragraph mark itself deleted."""
    rewrite_paragraph(p, [("del", p.text)])
    pPr = p._p.get_or_add_pPr()
    rPr = pPr.find(qn("w:rPr"))
    if rPr is None:
        rPr = OxmlElement("w:rPr")
        pPr.append(rPr)
    rPr.append(_revision("w:del"))
    return p


def insert_paragraph_after(anchor, text, template):
    """Insert a new paragraph after `anchor`, fully marked as an insertion."""
    el = copy.deepcopy(template._p)
    anchor._p.addnext(el)
    np = Paragraph(el, anchor._parent)
    rewrite_paragraph(np, [("ins", text)])
    pPr = np._p.get_or_add_pPr()
    rPr = pPr.find(qn("w:rPr"))
    if rPr is None:
        rPr = OxmlElement("w:rPr")
        pPr.append(rPr)
    rPr.append(_revision("w:ins"))
    return np
