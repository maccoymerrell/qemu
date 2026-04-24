"""Mnemonic classifier.

Thin wrapper around `champsim_tracer_mnemonic_survey.parse_header`.  We reuse
its canonical "mnemonic → (GenericOpcode, BranchType, flags)" tables so
the validator's ground-truth classification matches exactly what the
plugin does in C.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Lazy import of the sibling survey script (hyphen-free module name).
# ---------------------------------------------------------------------------

_PLUGIN_DIR = Path(__file__).resolve().parent.parent.parent
_SURVEY_PATH = _PLUGIN_DIR / "champsim_tracer_mnemonic_survey.py"


def _load_survey():
    if not _SURVEY_PATH.is_file():
        raise RuntimeError(
            f"Could not locate champsim_tracer_mnemonic_survey.py at {_SURVEY_PATH}"
        )
    spec = importlib.util.spec_from_file_location(
        "champsim_tracer_mnemonic_survey", _SURVEY_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


# ISA name used externally (and by the plugin format) ↔ survey key
_ISA_TO_SURVEY = {
    "x86_64":  "x86",
    "aarch64": "aarch64",
    "riscv64": "riscv",
    "mipsel":  "mips",
}


class Classifier:
    """Maps Capstone instruction IDs to champsim_tracer GenericOpcode names."""

    def __init__(self) -> None:
        self._survey = _load_survey()
        # { isa_key: (known_ids_set, id_to_class_dict, id_to_name_dict) }
        self._tables = self._survey.parse_header(
            str(self._survey.HEADER_REL)
        )

    def _table_for(self, isa: str):
        key = _ISA_TO_SURVEY.get(isa)
        if key is None:
            raise ValueError(f"unsupported isa {isa!r}")
        t = self._tables.get(key)
        if t is None:
            raise RuntimeError(f"survey table missing for isa {isa!r}")
        return t

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
