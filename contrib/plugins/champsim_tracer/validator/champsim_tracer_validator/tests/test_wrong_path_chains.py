"""Verdict-level tests for _check_wrong_path_chains.

Exercises the fault-poison acceptance (a chain that diverges at/after
the first FAULT-marked wrong-path entry is squash-shadow output per the
plugin's wrong-path fault semantics, accepted as a notable INFO) against
the verdicts that must stay strict: divergence with no fault entry,
divergence before the fault, and truncation without budget exhaustion.

Run standalone:
  python tests/test_wrong_path_chains.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from champsim_tracer_validator.validator import _check_wrong_path_chains


def _blocks(n_insns_by_bid):
    return {bid: {"block_id": bid, "class": "asm_load_burst",
                  "ground_truth": {"n_insns": n}}
            for bid, n in n_insns_by_bid.items()}


def _wp(template_id, fault=False, fault_idx=None, unavail=False, n_insns=13):
    return {"index": 0, "template_id": template_id, "n_insns": n_insns,
            "fault": fault, "fault_insn_index": fault_idx,
            "translation_unavailable": unavail}


def run_case(wp_entries, exp_chain, budget=64, n_insns_by_bid=None,
             chain_event=False):
    """One CP fork at cp_pos 0 (blk_0) with the given wrong path."""
    # template ids: 100 -> CP block 0; 200+bid -> WP block bid
    template_runs = {100: [(0, 1)]}
    blocks = dict(n_insns_by_bid or {})
    blocks.setdefault(0, 10)
    for wp in wp_entries:
        bid = wp["template_id"] - 200
        template_runs.setdefault(wp["template_id"], [(bid, 1)])
        blocks.setdefault(bid, 13)
    for bid in exp_chain:
        template_runs.setdefault(200 + bid, [(bid, 1)])
        blocks.setdefault(bid, 13)
    entries = [{
        "template_id": 100,
        "wp_entries": wp_entries,
        "wp_first_fetch_unavailable": chain_event,
    }]
    return _check_wrong_path_chains(
        entries, template_runs,
        cp_block_seq=[0], correct_path=[0, 1],
        wrong_paths={"0": {"wp_chain": exp_chain}},
        blocks_by_id=_blocks(blocks),
        wp_insn_budget=budget,
        templates_by_id={},
    )


def test_fault_poisoned_divergence_accepted_as_info():
    # pf77/pg40/w6_m_24 shape: every load-bearing entry faults at insn 2
    # (guest-TLB-cold excursion), first cond branch resolves on stale
    # registers, chain diverges at depth 5.
    wps = [_wp(200 + b, fault=True, fault_idx=2) for b in
           (13, 14, 15, 16, 17, 18)]
    issues = run_case(wps, [13, 14, 15, 16, 17, 22, 23],
                      n_insns_by_bid={13: 14, 14: 11, 15: 11, 16: 15,
                                      17: 11, 18: 14, 22: 13, 23: 13})
    errs = [i for i in issues if i.severity == "error"]
    infos = [i for i in issues if i.severity == "info"
             and (i.detail or {}).get("notable")]
    assert not errs, f"expected no errors, got {[i.message for i in errs]}"
    assert len(infos) == 1, f"expected 1 notable info, got {infos}"
    assert "suppressed speculative fault" in infos[0].message


def test_divergence_without_fault_still_errors():
    wps = [_wp(200 + b) for b in (13, 14, 15, 16, 17, 18)]
    issues = run_case(wps, [13, 14, 15, 16, 17, 22, 23],
                      n_insns_by_bid={13: 14, 14: 11, 15: 11, 16: 15,
                                      17: 11, 18: 14, 22: 13, 23: 13})
    errs = [i for i in issues if i.severity == "error"]
    assert len(errs) == 1 and "depth 5" in errs[0].message, \
        f"expected depth-5 error, got {[i.message for i in issues]}"


def test_divergence_before_fault_still_errors():
    # divergence at depth 1, fault only at depth 3: mismatch precedes
    # the poison boundary and must stay an error.
    wps = [_wp(213), _wp(299), _wp(215),
           _wp(216, fault=True, fault_idx=2), _wp(217)]
    issues = run_case(wps, [13, 14, 15, 16, 17],
                      n_insns_by_bid={99: 13})
    errs = [i for i in issues if i.severity == "error"]
    assert len(errs) == 1 and "depth 1" in errs[0].message, \
        f"expected depth-1 error, got {[i.message for i in issues]}"


def test_truncation_without_budget_still_errors():
    # storm shape: matching prefix, chain ends early, unavail marker,
    # sim_insns below budget -> still a truncation error.
    wps = [_wp(213, n_insns=14), _wp(214, unavail=True, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17])
    errs = [i for i in issues if i.severity == "error"]
    assert len(errs) == 1 and "truncated" in errs[0].message, \
        f"expected truncation error, got {[i.message for i in issues]}"


def test_exact_match_clean():
    wps = [_wp(200 + b) for b in (13, 14, 15, 16, 17)]
    issues = run_case(wps, [13, 14, 15, 16, 17])
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"OK ({len(fns)} tests)")
