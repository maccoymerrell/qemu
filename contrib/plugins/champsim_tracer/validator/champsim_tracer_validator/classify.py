"""Mnemonic classifier — the validator's ground truth for what the wire
should say an instruction IS.

WHERE THE ANSWER COMES FROM
===========================

The plugin no longer classifies from a decoder's instruction id.  QEMU's
own decode rule states a generic WORD, and
``champsim_tracer_vocabulary.cc`` — one sorted table, one bisection — says
what each word means on the wire: a ``GenericOpcode`` and a ``BranchType``.
That file is the plugin's whole word-to-generic mapping, and it is the
population this module classifies against.

The validator's side of the comparison is offline and reaches Capstone the
way the retired mnemonic-table generator always did, through the Python
bindings: it disassembles the guest ELF and asks
``champsim_tracer_mnemonic_audit.classify()`` — the very rules that
generated the per-ISA C tables this module used to parse — what the
mnemonic means.  ``tools/cst_referee.py`` already reaches those rules that
way for the register-set comparison, and this module follows it, sharing
the referee's per-ISA constant maps so the two cannot disagree about which
instruction id is which.

So nothing was invented to replace the retired tables.  The same
classification rules answer, over the same instruction-id space; what
changed is that the answer is now checked against the vocabulary the
plugin ships, rather than read out of a generated C array that no longer
exists.

AN ABSENT VOCABULARY IS A REFUSAL, AND A REFUSAL IS ONE NAMED CHECK
==================================================================

If the vocabulary cannot be read, this module raises
:class:`ClassifierUnavailable` — an ordinary exception a caller can catch,
report as one named per-ISA check failure, and carry on from.  It is
deliberately NOT ``SystemExit``: a constructor that exits the process
converts one missing subject into total blindness across every other
check, which is the opposite of what refusing was for.  What it must never
do is return an empty classification set; comparing answers against
nothing reads exactly like agreement.

Author: Maccoy Merrell
SPDX-License-Identifier: GPL-2.0-or-later
"""

from __future__ import annotations

import importlib.util
import re
from pathlib import Path


class ClassifierUnavailable(RuntimeError):
    """The classification vocabulary could not be read.

    Raised instead of returning an empty table, and raised as an ordinary
    exception so one missing subject costs one named check, not the suite.
    """


# ---------------------------------------------------------------------------
# Layout.  Post-migration:
#   contrib/plugins/champsim_tracer/                       (plugin source root)
#       champsim_tracer_vocabulary.cc
#       champsim_tracer_mnemonic_survey.py
#       tools/cst_referee.py
#       validator/champsim_tracer_validator/<this>.py
# Walk two levels up to reach the plugin source root.
# ---------------------------------------------------------------------------

_PLUGIN_SOURCE_DIR = Path(__file__).resolve().parent.parent.parent
_SURVEY_PATH = _PLUGIN_SOURCE_DIR / "champsim_tracer_mnemonic_survey.py"
_VOCABULARY_PATH = _PLUGIN_SOURCE_DIR / "champsim_tracer_vocabulary.cc"
_REFEREE_PATH = _PLUGIN_SOURCE_DIR / "tools" / "cst_referee.py"


def _load_module(path: Path, name: str):
    if not path.is_file():
        raise ClassifierUnavailable(f"could not locate {name} at {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ClassifierUnavailable(f"could not load {name} from {path}")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:                        # pragma: no cover
        raise ClassifierUnavailable(
            f"{name} at {path} did not import: {exc!r}") from exc
    return mod


# ``{ INSN_DF_WORD_INT_ADD,  GEN_OP_INT_ADD,  BRANCH_NONE },``
_VOCAB_ROW_RE = re.compile(
    r"\{\s*(INSN_DF_WORD_\w+)\s*,\s*(GEN_OP_\w+)\s*,\s*(BRANCH_\w+)\s*\}")


def parse_vocabulary(path: Path = _VOCABULARY_PATH) -> dict[str, tuple[str, str]]:
    """``{ word: (GenericOpcode, BranchType) }`` from the shipped table.

    Refuses an absent file, an absent table and a table that parses to zero
    rows.  Each of those is "I could not read the vocabulary", and none of
    them is "the vocabulary is empty".
    """
    if not path.is_file():
        raise ClassifierUnavailable(
            f"{path} does not exist: the plugin's word-to-generic table is "
            f"the classification population, and there is nothing to "
            f"classify against without it")
    text = path.read_text(errors="replace")
    body = re.search(r"const VocabularyRow rows\[\]\s*=\s*\{(.*?)\n\};",
                     text, re.DOTALL)
    if body is None:
        raise ClassifierUnavailable(
            f"{path}: no `const VocabularyRow rows[]` table found")
    rows = {m.group(1): (m.group(2), m.group(3))
            for m in _VOCAB_ROW_RE.finditer(body.group(1))}
    if not rows:
        raise ClassifierUnavailable(
            f"{path}: the vocabulary table parsed to 0 rows")
    return rows


# ISA name used externally (and by the plugin format) ↔ survey/audit key
_ISA_TO_SURVEY = {
    "x86_64":  "x86",
    "aarch64": "aarch64",
    "riscv64": "riscv",
    "mipsel":  "mips",
}


class Classifier:
    """Maps a disassembled instruction to the wire's GenericOpcode.

    The population is the shipped vocabulary; the per-instruction rules are
    the offline referee's, so this and the referee cannot drift apart.
    """

    def __init__(self) -> None:
        # The shipped word-to-generic table: the set of answers the plugin
        # is able to publish at all.
        self.vocabulary = parse_vocabulary()
        self.vocabulary_opcodes = {op for op, _ in self.vocabulary.values()}
        self.vocabulary_branches = {br for _, br in self.vocabulary.values()}
        # The survey is still the ELF→Capstone configuration (endianness,
        # ELF class, per-ISA extension set); it holds no classification.
        self._survey = _load_module(_SURVEY_PATH,
                                    "champsim_tracer_mnemonic_survey")
        self._referee = _load_module(_REFEREE_PATH, "cst_referee")
        self._tables: dict[str, tuple] = {}
        #: {isa: sorted list of (gen_op, n_encodings)} the rules produce but
        #: the shipped vocabulary has no word for.  Counted, never silent.
        self.unpublishable: dict[str, list[str]] = {}

    # -- population -------------------------------------------------------

    def _build(self, isa: str) -> tuple:
        key = _ISA_TO_SURVEY.get(isa)
        if key is None:
            raise ValueError(f"unsupported isa {isa!r}")
        try:
            ref_isa = self._referee.Isa(isa)
        except Exception as exc:
            raise ClassifierUnavailable(
                f"the offline referee could not configure {isa}: {exc!r}"
            ) from exc
        vocab = self._referee.vocab
        info = vocab.ISAS[key]

        known_ids: set[int] = set()
        id_to_class: dict[int, tuple[str, str, str]] = {}
        id_to_name: dict[int, str] = {}
        outside: set[str] = set()
        for insn_id, suffix in ref_isa.ins.items():
            const_name = info.prefix + suffix
            entry = vocab.classify(info, const_name)
            if entry is None:
                continue
            id_to_name[insn_id] = const_name
            known_ids.add(insn_id)
            id_to_class[insn_id] = (entry.op, entry.branch, entry.flags)
            if entry.op not in self.vocabulary_opcodes:
                outside.add(entry.op)
        if not id_to_class:
            raise ClassifierUnavailable(
                f"{isa}: the classification rules produced 0 rows over "
                f"{len(ref_isa.ins)} instruction ids — a zero over an empty "
                f"population is a gap, not an answer")
        # A GenericOpcode the rules produce that the shipped vocabulary
        # cannot publish means the two vocabularies have drifted; it is
        # recorded per ISA so a caller can quote it.  BranchType is NOT
        # constrained this way on purpose: BRANCH_REP is applied
        # structurally by the self-loop fan-out (champsim_tracer.cc,
        # champsim_tracer_qdep.cc), not by any word, so it is correctly
        # absent from the word table.
        self.unpublishable[isa] = sorted(outside)
        return known_ids, id_to_class, id_to_name

    def _table_for(self, isa: str) -> tuple:
        if isa not in self._tables:
            self._tables[isa] = self._build(isa)
        return self._tables[isa]

    def population(self, isa: str) -> int:
        """How many instruction encodings this ISA classifies — the subject
        count a caller must quote beside any zero it reports."""
        known_ids, _, _ = self._table_for(isa)
        return len(known_ids)

    def reachable_opcodes(self, isa: str) -> set[str]:
        """GenericOpcode names (no ``GEN_OP_`` prefix) reachable on @isa."""
        _, id_to_class, _ = self._table_for(isa)
        return {op[len("GEN_OP_"):] for op, _, _ in id_to_class.values()
                if isinstance(op, str) and op.startswith("GEN_OP_")}

    def reachable_branches(self, isa: str) -> set[str]:
        """BranchType names (no ``BRANCH_`` prefix) reachable on @isa."""
        _, id_to_class, _ = self._table_for(isa)
        return {br[len("BRANCH_"):] for _, br, _ in id_to_class.values()
                if isinstance(br, str) and br.startswith("BRANCH_")}

    # -- per-instruction --------------------------------------------------

    def classify(self, isa: str, insn_id: int
                 ) -> tuple[str, str, str] | None:
        """Return (gen_op, branch_type, flags) or None if unknown."""
        _, id_to_class, _ = self._table_for(isa)
        return id_to_class.get(insn_id)

    def make_capstone(self, elf_path: Path):
        """Open an ELF with LIEF, build a Capstone disassembler, return
        (lief_binary, capstone_md, isa_survey_key).
        """
        import lief  # noqa: local import (optional dep)
        binary = lief.parse(str(elf_path))
        md, isa_key = self._survey.make_disassembler(binary)
        if md is None:
            raise RuntimeError(f"no disassembler for {elf_path}")
        md.detail = True  # so we get operands/registers in analyzer
        return binary, md, isa_key


# Convenience singleton; constructed lazily.
_classifier: Classifier | None = None


def get_classifier() -> Classifier:
    global _classifier
    if _classifier is None:
        _classifier = Classifier()
    return _classifier
