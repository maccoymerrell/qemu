"""Sphinx extension: auto-index well-known champsim_tracer symbol names.

Hand-maintaining ``.. index::`` directives for every GEN_OP_*, REG_*,
BRANCH_*, CST_FID_*, SYNC_*, BODY_TAG_*, … occurrence is unsustainable.
This extension walks each parsed doctree and, for every inline
``literal`` node whose text matches a known symbol pattern, injects
an ``index`` node + ``target`` node *immediately next to that
literal*.  Sphinx's index machinery then anchors the genindex
back-link at that exact spot in the rendered page — every individual
mention of every symbol gets its own anchor.

Critical placement detail: we register a ``SphinxTransform`` with
``default_priority = 700`` so the pass runs before the
``SphinxDomains`` transform (priority 850) that collects index
entries.  Hooking ``doctree-read`` (priority 880) is too late —
``_process_doc`` has already run and the index domain has cached its
state before our nodes appear.

Entries strip the common prefix and add it parenthetically as a
qualifier so the genindex disperses them across the alphabet by
their meaningful suffix:

  GEN_OP_INT_ADD   →  INT_ADD (GEN_OP_*)        indexed under "I"
  REG_GPR0         →  GPR0 (REG_*)              indexed under "G"
  CST_FID_LOAD_ADDR_BASE → LOAD_ADDR_BASE (CST_FID_*)  under "L"
"""

from __future__ import annotations

import re

from docutils import nodes
from sphinx.addnodes import index
from sphinx.transforms import SphinxTransform


# (pattern, prefix-to-strip, family qualifier shown parenthetically).
_PATTERNS: list[tuple[re.Pattern, str, str]] = [
    (re.compile(r"^GEN_OP_([A-Z0-9_]+)$"),          "GEN_OP_",          "GEN_OP_*"),
    (re.compile(r"^BRANCH_([A-Z0-9_]+)$"),          "BRANCH_",          "BRANCH_*"),
    (re.compile(r"^REG_([A-Z0-9_]+)$"),             "REG_",             "REG_*"),
    (re.compile(r"^CST_FID_([A-Z0-9_]+)$"),         "CST_FID_",         "CST_FID_*"),
    (re.compile(r"^CST_METAFLAGS_([A-Z])$"),        "CST_METAFLAGS_",   "CST_METAFLAGS_*"),
    (re.compile(r"^CST_WP_EVENT_([A-Z0-9_]+)$"),    "CST_WP_EVENT_",    "CST_WP_EVENT_*"),
    (re.compile(r"^CST_INSN_FLAG_([A-Z0-9_]+)$"),   "CST_INSN_FLAG_",   "CST_INSN_FLAG_*"),
    (re.compile(r"^CST_FLAG_([A-Z0-9_]+)$"),        "CST_FLAG_",        "CST_FLAG_*"),
    (re.compile(r"^SYNC_([A-Z0-9_]+)$"),            "SYNC_",            "SYNC_*"),
    (re.compile(r"^BODY_TAG_([A-Z0-9_]+)$"),        "BODY_TAG_",        "BODY_TAG_*"),
    (re.compile(r"^(CST_MAGIC|CST_TRAILER_MAGIC)$"), "", "CST trace magic"),
    (re.compile(r"^(simpoint_test|thread_test|"
                r"encoding_map_completeness|iframe_cadence|"
                r"regfile_records|thread_switch|thread_distribution|"
                r"wp_events|sync_hints|metaflags|"
                r"regdata_reconstruction|header_window|"
                r"validate_structural)$"), "", "validator term"),
    (re.compile(r"^(cpu_compute_eflags|gen_update_cc_op|"
                r"qemu_plugin_insn_detail|qemu_plugin_get_registers|"
                r"qemu_plugin_insn_symbol|qemu_plugin_read_register)$"),
     "", "qemu function"),
]


# Symbols already covered by hand-curated `.. index::` directives.
_HANDWRITTEN = frozenset({
    "BODY_TAG_END", "BODY_TAG_ENTRY", "BODY_TAG_IFRAME",
    "BODY_TAG_REGFILE", "BODY_TAG_THREAD_SWITCH",
})


# Pages where auto-indexing would compete with the prose-anchor entry
# from reference.rst.  The encoding-tables appendix already IS a
# lookup-by-name listing; deferring it to a secondary genindex link
# keeps reference.rst as the primary destination for each symbol.
_DEFER_DOCS = frozenset({
    "_generated/encoding_tables",
})


def _classify(text: str) -> str | None:
    if text in _HANDWRITTEN:
        return None
    for rx, prefix, qualifier in _PATTERNS:
        m = rx.fullmatch(text)
        if not m:
            continue
        stem = text[len(prefix):] if prefix and text.startswith(prefix) else text
        return f"{stem} ({qualifier})" if qualifier else stem
    return None


class AutoIndexTransform(SphinxTransform):
    """Inject index + target nodes next to every matching ``literal``.

    Runs before ``SphinxDomains`` (priority 850) so the index domain
    sees our entries during its ``process_doc`` pass.
    """

    # Must be < 850 so we run before SphinxDomains in sphinx.transforms
    # .references which calls env.domains._process_doc on the doctree.
    default_priority = 700

    def apply(self, **kwargs):
        seen: set[str] = set()
        docname = self.env.docname
        is_appendix = docname in _DEFER_DOCS

        for literal in list(self.document.findall(nodes.literal)):
            text = literal.astext()
            entry = _classify(text)
            if entry is None:
                continue
            # Dedup per-page: one anchor per unique entry per page.
            # (A symbol mentioned five times in one page still gets
            # one back-link from the genindex per page, not five.)
            if entry in seen:
                continue
            seen.add(entry)

            # Use a stable, page-scoped target id.
            target_id = f"auto-index-{self.env.new_serialno('auto-index')}"

            target = nodes.target("", "", ids=[target_id])
            # Prose pages (everything except the encoding-tables
            # appendix) get main='main' so their link is the primary
            # entry in the genindex: sphinx.environment.adapters.
            # indexentries._key_func_0 sorts targets by ``(not main,
            # uri)``, so main='main' targets land before main=''
            # targets for the same word.  The appendix's exhaustive-
            # listing entries stay as secondary links — clicking
            # "GPR0 (REG_*)" in the genindex takes the reader to the
            # description in reference.rst, with the appendix
            # available as the bracketed secondary link [1].
            main = "" if is_appendix else "main"
            idx = index("",
                        entries=[("single", entry, target_id, main, None)])

            parent = literal.parent
            try:
                pos = parent.index(literal)
            except ValueError:
                continue
            # Order: target, index, literal.  Sphinx walks the doctree
            # in document order to assign anchors, so the target
            # immediately precedes the visible content.
            parent.insert(pos, target)
            parent.insert(pos + 1, idx)

        # NOTE: we deliberately also index the encoding-tables
        # appendix.  Many symbols (REG_GPR8..GPR31, REG_FPR1..FPR62,
        # REG_VEC1..VEC62, etc.) appear ONLY in the appendix's
        # exhaustive tables — they're not mentioned by name in the
        # prose pages.  Stripping the appendix would orphan those
        # symbols from the genindex entirely.  Sphinx's genindex
        # presents each entry's link list in document-discovery order,
        # so as long as reference.rst is read before the appendix,
        # the reference link is the natural primary destination for
        # symbols that appear in both — and for appendix-only symbols
        # the appendix link is the only (and correct) destination.


def setup(app):
    app.add_transform(AutoIndexTransform)
    return {"version": "0.6",
            "parallel_read_safe": True,
            "parallel_write_safe": True}
