"""Build the submission copy from the revised draft in one pass.

All edits are located by matching text, never by fixed paragraph index, so the
script is order-independent and re-runnable. Nothing in a protected section
(6.8, 7.1 RQ2, 7.3.6) is touched, and no canonical figure is altered.
"""
import copy
import sys

from docx import Document
from docx.text.paragraph import Paragraph

SRC, DST = sys.argv[1], sys.argv[2]
doc = Document(SRC)


def find(prefix, contains=None):
    for p in doc.paragraphs:
        t = p.text.strip()
        if t.startswith(prefix) and (contains is None or contains in t):
            return p
    raise LookupError(f"not found: {prefix!r}")


def set_text(p, new):
    p.runs[0].text = new
    for r in p.runs[1:]:
        r.text = ""


def add_after(anchor, text, template):
    el = copy.deepcopy(template._p)
    anchor._p.addnext(el)
    np = Paragraph(el, anchor._parent)
    for r in np.runs[1:]:
        r.text = ""
    np.runs[0].text = text
    return np


changes = []

# ---------------------------------------------------------------- dates ----
p = find("August 2026")
set_text(p, "September 2026")
changes.append("title page date")

p = find("Date: August 2026")
set_text(p, "Date: September 2026")
changes.append("declaration date")

p = find("Date:  August 2026")
p.runs[0].text = "Date:  "
p.runs[1].text = "September 2026"
changes.append("abstract-page date")

# ------------------------------------------------------------------ F-1 ----
p = find("Initial model training used the UNSW-NB15")
anchor = "The UNSW-NB15 dataset also contains a separate binary label column"
set_text(p, p.text.replace(anchor,
    "Those nine classes are eight attack types plus Normal, not the dataset's full "
    "nine attack types: Backdoor is absent because a label-canonicalisation defect "
    "relabelled its records as Normal before encoding (Section 6.6; Appendix B.1). "
    + anchor))
changes.append("4.7 class-count clarification")

p = find("The absent Backdoors class is a related finding")
set_text(p,
    "The absent Backdoors class is a related finding, and the mechanism is label "
    "canonicalisation rather than absent data. The category list used during "
    "preprocessing spelled the class “Backdoors” while the UNSW-NB15 training CSV "
    "spells it “Backdoor”, and the filter assigned any value outside that list to "
    "“Normal”. The 1,746 Backdoor records were therefore relabelled as benign traffic "
    "in both the training and test partitions rather than dropped, so the trained RF "
    "never learns a Backdoors decision boundary and the Normal class carries backdoor "
    "traffic labelled benign. Appendix B.1 quantifies the effect and shows that it is "
    "bounded at one percentage point of weighted accuracy. Like the connection-state "
    "encoding defect, this failure produced a plausible result rather than an error: "
    "an unrecognised label was silently coerced to a default instead of raising.")
changes.append("5.2.1 absent-class mechanism")

p = find("Note: Backdoors absent from trained model")
set_text(p,
    "Note: the Backdoors class is absent from the trained model. The cause is a "
    "label-canonicalisation defect: the category list spelled the class “Backdoors” "
    "while UNSW_NB15_training-set.csv spells it “Backdoor”, and the preprocessing "
    "filter assigned any unmatched value to “Normal”. The 1,746 Backdoor records were "
    "therefore relabelled as benign in both partitions rather than excluded. This is "
    "visible in the supports above: every class support is exactly 20% of its dataset "
    "count except Normal, which exceeds 20% of 56,000 by 349 — precisely the Backdoor "
    "share of the stratified split, and the nine supports still sum to the full 35,069. "
    "The reported Normal metrics are therefore computed on a class containing 3.0% "
    "backdoor traffic, and the macro average is over nine classes rather than ten. "
    "Because Backdoor is 1.00% of the test set, restoring it as a separate class could "
    "reduce weighted accuracy by at most 1.0 percentage point (0.813 to no less than "
    "0.803) and macro F1 to no less than 0.53. Macro F1 0.59 remains the honest "
    "headline: DoS recall 0.08 and Analysis recall 0.14 expose severe weakness on "
    "minority classes, and weighted accuracy of 0.81 is inflated by the large Generic "
    "and Normal classes.")
changes.append("Table B.1 note")

# ------------------------------------------------------------------ F-2 ----
p = find("The Random Forest trained on UNSW-NB15 achieved 81.3%")
set_text(p,
    "The Random Forest trained on UNSW-NB15 achieved 81.3% weighted accuracy and "
    "0.7948 weighted F1 on the held-out test set (35,069 records). Five-fold stratified "
    "cross-validation gives mean accuracy 81.25% ± 0.18% across five folds (individual "
    "fold accuracies: 81.09%, 81.13%, 81.26%, 81.34%, 81.41%), confirming that the "
    "single-split figure is not an artefact of one partition. One qualification is "
    "required: the cross-validation script encodes connection state without the "
    "Argus→Zeek mapping, so it evaluates the eight-effective-feature configuration "
    "rather than the corrected production model, and it should not be described as "
    "validating the latter. The two results agree to within 0.05 percentage points, "
    "which is consistent with the 2.155% combined importance of the conn_state features "
    "reported below.")
changes.append("5.2.1 cross-validation qualification")

p = find("ML-based IDS benchmark comparisons")
frag = ("The stronger evidence here is the low cross-validation variance and the "
        "explicit live-transfer test, not a claim of state-of-the-art benchmark performance.")
set_text(p, p.text.replace(frag,
    "The stronger evidence here is the explicit live-transfer test, not a claim of "
    "state-of-the-art benchmark performance. The low cross-validation variance supports "
    "only the stability of the split, and was measured on the earlier feature mapping "
    "(Section 5.2.1)."))
changes.append("6.5 benchmark-comparison qualification")

# ------------------------------------------------- Appendix C adversary ----
p = find("The replication confirms a narrow causal mechanism")
set_text(p, p.text +
    " Two features of the design bound the inference further. The scanner was scripted "
    "to continue probing the original ports after its initial sweep rather than "
    "re-enumerating, so the reachability collapse reported above is in part a property "
    "of that fixed adversary model; a re-scanning attacker would locate the rotated "
    "endpoints, which is the behaviour the moving-target argument depends on. The "
    "authorised client was likewise a controlled labelled workload, so the continuity "
    "cost is measured against a cooperative baseline rather than organic users.")
changes.append("Appendix C adversary-model caveat")

# ------------------------------------------------------- new §6.3.2 -------
head_tpl = find("6.3.1 Empirical")
body_tpl = find("It is important to be precise about what this experiment")
anchor = body_tpl
for kind, text in [
 ("H", "6.3.2 Replicated Paired Experiment with Live Services"),
 ("B", "The matched comparison called for above was subsequently run and is reported in "
       "full in Appendix C. Eight paired blocks, each one static and one adaptive "
       "180-second trial with phase order randomised in advance, were executed on 7 "
       "September 2026 against real Cowrie SSH and Telnet services in isolated network "
       "namespaces. It postdates the frozen evaluation of Chapter 5 and does not revise "
       "any figure in it."),
 ("B", "The result is directional and large. Post-scan benign application success fell "
       "from 159 of 160 attempts (99.4 per cent) under static exposure to 32 of 160 "
       "(20.0 per cent) under adaptive exposure, a mean paired difference of -79.4 "
       "percentage points. Scanner TCP reachability fell from 87.0 to 17.4 per cent. "
       "Cowrie independently corroborated 191 authorised sessions in the static trials "
       "against 64 in the adaptive trials, and 80 scanner authentication outcomes "
       "against 16. Rotation fired in all eight adaptive trials at a mean of 60.2 seconds."),
 ("B", "Read against RQ2, this measures the cost side of the trade-off and leaves the "
       "benefit side open. What it establishes is that endpoint withdrawal is real, "
       "repeatable and consequential: once the controller moves the PREROUTING "
       "redirects, any client still addressing the original ports loses access, and the "
       "honeypot consequently observes fewer interactions rather than more. Under this "
       "workload adaptive exposure reduced collected interaction volume; it did not "
       "increase it."),
 ("B", "Three boundaries prevent this from being read as a full answer. First, the "
       "precondition set out in Section 7.3.6 was not met: Cowrie's direct listeners on "
       "2222 and 2223 remained reachable within the laboratory network, so the mechanism "
       "demonstrated is endpoint withdrawal rather than concealment. Second, and most "
       "importantly, the scripted scanner did not re-enumerate after its initial sweep; "
       "it continued to probe the original ports. The reconnaissance-delay benefit "
       "predicted by the moving-target literature (Lei et al., 2018; Luo et al., 2017) "
       "depends precisely on an attacker who re-scans, and an adversary scripted not to "
       "re-scan cannot exhibit it. The question posed in Section 7.1, whether an attacker "
       "forced to re-enumerate generates measurably more log activity, therefore remains "
       "open. Third, the authorised client was a controlled, independently labelled "
       "workload rather than organic traffic, so the continuity cost is characterised "
       "against a cooperative baseline and not against real users."),
 ("B", "The defensible position is therefore narrower than the research question as "
       "originally posed, and better supported than it was before the replication. "
       "Adaptive port exposure demonstrably withdraws the advertised attack surface, and "
       "that withdrawal carries a measurable and substantial continuity cost. Whether it "
       "improves intelligence collection depends on adversary behaviour that this design "
       "deliberately held fixed, and answering it requires the same experiment run "
       "against a re-scanning adversary with the Cowrie bind restriction in place."),
]:
    anchor = add_after(anchor, text, head_tpl if kind == "H" else body_tpl)
changes.append("new 6.3.2 (6 paragraphs)")

# ------------------------------------------------------- front lists ------
add_after(find("Figure 2–Figure 25"),
          "Figure C.1   Paired fixed-endpoint outcomes in the main replication (Appendix C)",
          find("Figure 1   System architecture"))
changes.append("List of Figures: Figure C.1")

lot_anchor = find("Table B.3")
for text in reversed([
    "Table C.1   Aggregate scheduled outcomes (Appendix C replication)",
    "Table C.2   Post-scan outcomes by paired block (Appendix C replication)",
    "Table C.3   Evidence controls (Appendix C replication)",
]):
    add_after(lot_anchor, text, lot_anchor)
changes.append("List of Tables: Tables C.1-C.3")

doc.save(DST)
print(f"{len(changes)} edit groups applied:")
for c in changes:
    print("  -", c)
