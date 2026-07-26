"""Verdict-level tests for the LIVE wrong-path chain policy.

This suite REPLACES the retired poison + dep-branch-kill replay tests (removed
from the plugin on 2026-07-12; commits 18bbec8956, 914d452978, 7b69c88aa4).
It exercises ``validator._check_wrong_path_chains`` directly against the
continue-to-budget policy the plugin now implements:

  * On a mispredicted path nothing retires, so a back-end synchronous fault is
    served deterministic placeholder data, MARKED ``CST_WP_EVENT_FAULT`` at
    ``fault_insn_index``, and the excursion CONTINUES to the wpdepth budget.
  * SEQUENCE: up to the first marked fault the emitted block chain must be an
    exact-or-longer prefix of the synthetic prediction (an UNMARKED divergence
    is a bug).  Past a marked fault the tail is synthetic placeholder, so a
    divergence at a position strictly after the first fault is EXPECTED.
  * TERMINATION: a short chain is only legitimate at a real terminator —
    depth budget, privilege-domain crossing, translation-unavailable, or
    wpprune.  Every one is a FETCH condition.  A syscall is NOT a terminator:
    the wrong path continues past it at its architectural fall-through, the
    not-taken side it takes for any other branch.  A fault must CONTINUE to a
    real terminator; a fault that truncates the excursion short is itself an
    error.
  * The kill policy is RETIRED: a fault-carrying chain that resolves a
    fault-dependent branch and CONTINUES is now correct output, never an
    error — the exact inversion of the old policy's canonical negative test.

The end-to-end plugin-behaviour guard is ``tests/test_wp_synthetic_fault.py``
(full's ``features.wp_fault``); this file is the fast, plugin-free verdict
oracle for the same policy.

Run standalone:
  python tests/test_wrong_path_chains.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from champsim_tracer_validator.validator import _check_wrong_path_chains

REG_ZERO = 241
REG_FLAGS = 251
REG_T0 = 8
REG_T8 = 24
REG_T1 = 9
REG_NAME_TO_ID = {"REG_ZERO": REG_ZERO, "REG_FLAGS": REG_FLAGS}

BR_JUMP = 3        # a plain (non-syscall) branch id
BR_SYSCALL = 7     # the syscall-class branch id
SYSCALL_IDS = {BR_SYSCALL}


def _blocks(n_insns_by_bid):
    return {bid: {"block_id": bid, "class": "asm_load_burst",
                  "ground_truth": {"n_insns": n}}
            for bid, n in n_insns_by_bid.items()}


def _burst_insns(n, terminator=BR_JUMP):
    """Load-burst block: sets t8, loads t0/t1, ends in @terminator."""
    insns = [
        {"src_regs": [], "dst_regs": [REG_T8], "branch_type": 0,
         "branch_conditional": False},
        {"src_regs": [REG_T8], "dst_regs": [REG_T8], "branch_type": 0,
         "branch_conditional": False},
        {"src_regs": [REG_T8], "dst_regs": [REG_T0], "branch_type": 0,
         "branch_conditional": False},          # lw t0 (fault site)
        {"src_regs": [REG_T8], "dst_regs": [REG_T1], "branch_type": 0,
         "branch_conditional": False},          # lw t1
    ]
    while len(insns) < n - 1:
        insns.append({"src_regs": [REG_T0, REG_T1], "dst_regs": [REG_T0],
                      "branch_type": 0, "branch_conditional": False})
    insns.append({"src_regs": [], "dst_regs": [], "branch_type": terminator,
                  "branch_conditional": False})
    return insns


def _wp(bid, fault=False, fault_idx=None, unavail=False, n_insns=13):
    return {"index": 0, "template_id": 200 + bid, "n_insns": n_insns,
            "fault": fault, "fault_insn_index": fault_idx,
            "translation_unavailable": unavail}


N_BY_BID = {13: 14, 14: 11, 15: 11, 16: 15, 17: 11, 18: 14,
            22: 13, 23: 13}


def run_case(wp_entries, exp_chain, budget=64, n_insns_by_bid=None,
             chain_event=False, syscall_bids=(), templates_by_id_extra=None):
    """One CP fork at cp_pos 0 (blk_0) with the given wrong path.
    Template ids: 100 -> CP block 0; 200+bid -> WP block bid.  Blocks in
    @syscall_bids terminate in a BR_SYSCALL branch; others in a bare jump."""
    template_runs = {100: [(0, 1)]}
    blocks = dict(n_insns_by_bid or {})
    blocks.setdefault(0, 10)
    templates_by_id = dict(templates_by_id_extra or {})
    bids = {wp["template_id"] - 200 for wp in wp_entries} | set(exp_chain)
    for bid in bids:
        template_runs.setdefault(200 + bid, [(bid, 1)])
        blocks.setdefault(bid, 13)
        term = BR_SYSCALL if bid in syscall_bids else BR_JUMP
        templates_by_id[200 + bid] = {"template_id": 200 + bid,
                                      "insns": _burst_insns(blocks[bid], term)}
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
        templates_by_id=templates_by_id,
        reg_name_to_id=REG_NAME_TO_ID,
    )


def _errs(issues):
    return [i for i in issues if i.severity == "error"]


# --------------------------------------------------------------------------
# Exact-match / clean
# --------------------------------------------------------------------------
def test_exact_match_clean():
    wps = [_wp(b, n_insns=N_BY_BID[b]) for b in (13, 14, 15, 16, 17)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


def test_fault_full_match_clean():
    # A fault mid-chain whose garbage happens to steer the SAME predicted
    # way: full-length match, marked FAULT, no divergence -> clean.
    wps = [_wp(13, n_insns=14), _wp(14, fault=True, fault_idx=2, n_insns=11),
           _wp(15, n_insns=11), _wp(16, n_insns=15), _wp(17, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


# --------------------------------------------------------------------------
# Sequence verdicts
# --------------------------------------------------------------------------
def test_unmarked_divergence_errors():
    # No fault anywhere; chain diverges at depth 3 -> real bug.
    wps = [_wp(b, n_insns=N_BY_BID[b]) for b in (13, 14, 15, 18, 17)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    errs = _errs(issues)
    assert len(errs) == 1 and "depth 3" in errs[0].message, \
        f"expected depth-3 divergence error, got {[i.message for i in issues]}"


def test_post_fault_divergence_accepted():
    # Block 15 faults at insn 2, then the chain diverges at depth 3
    # (blk_16 instead of predicted blk_22).  The divergence is strictly
    # AFTER the fault's collapsed position (2 < 3) -> synthetic, accepted.
    wps = [_wp(13, n_insns=14), _wp(14, n_insns=11),
           _wp(15, fault=True, fault_idx=2, n_insns=11),
           _wp(16, n_insns=15), _wp(17, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 22, 23], n_insns_by_bid=N_BY_BID)
    assert not issues, \
        f"post-fault divergence must be accepted, got {[i.message for i in issues]}"


def test_late_fault_does_not_excuse_early_divergence():
    # Divergence at depth 0 (blk_14 instead of predicted blk_13); a fault
    # marked on a LATER block (position 2) must NOT license it.
    wps = [_wp(14, n_insns=11), _wp(13, n_insns=14),
           _wp(15, fault=True, fault_idx=0, n_insns=11),
           _wp(16, n_insns=15)]
    issues = run_case(wps, [13, 14, 15, 16], n_insns_by_bid=N_BY_BID)
    errs = _errs(issues)
    assert any("depth 0" in i.message for i in errs), \
        f"expected depth-0 divergence error, got {[i.message for i in issues]}"


def test_continue_past_fault_dependent_branch_clean():
    # The retired kill policy's canonical NEGATIVE test, INVERTED: a chain
    # that faults at insn 2 in every block and resolves the fault-dependent
    # branch, CONTINUING to a full-length match, is now correct output —
    # no verdict keys off any kill flag any more.
    wps = [_wp(b, fault=True, fault_idx=2, n_insns=N_BY_BID[b])
           for b in (13, 14, 15, 16, 17)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    assert not issues, \
        f"continue-past-fault must be clean now, got {[i.message for i in issues]}"


# --------------------------------------------------------------------------
# Termination verdicts
# --------------------------------------------------------------------------
def test_truncation_without_terminator_errors():
    # Fault-free short chain, below budget, no crossing/syscall -> truncation.
    wps = [_wp(13, n_insns=14), _wp(14, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    errs = _errs(issues)
    assert len(errs) == 1 and "truncated" in errs[0].message, \
        f"expected truncation error, got {[i.message for i in issues]}"


def test_fault_chain_truncated_without_terminator_errors():
    # A fault chain that STOPS short of budget with no terminator is a
    # regression of the continue-to-budget guarantee -> truncation error.
    wps = [_wp(13, n_insns=14), _wp(14, fault=True, fault_idx=2, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    errs = _errs(issues)
    assert len(errs) == 1 and "truncated" in errs[0].message \
        and "carries a FAULT" in errs[0].message, \
        f"expected fault-truncation error, got {[i.message for i in issues]}"


def test_budget_exhaustion_accepted():
    # Short in block count but sim_insns >= budget -> legitimate budget end.
    wps = [_wp(13, n_insns=40), _wp(14, n_insns=40)]
    issues = run_case(wps, [13, 14, 15, 16, 17], budget=64,
                      n_insns_by_bid=N_BY_BID)
    assert not issues, \
        f"budget exhaustion must be accepted, got {[i.message for i in issues]}"


def test_syscall_does_not_terminate_a_chain():
    # Short chain whose LAST block ends in a syscall-class branch.  The wrong
    # path continues past a syscall at its architectural fall-through, so
    # stopping there is a truncation like any other -- the exact inversion of
    # the terminate-at-syscall policy this suite used to assert.
    wps = [_wp(13, n_insns=14), _wp(14, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID,
                      syscall_bids=(14,))
    errs = _errs(issues)
    assert len(errs) == 1 and "truncated" in errs[0].message, \
        f"a syscall must not terminate a chain, got {[i.message for i in issues]}"


def test_syscall_mid_chain_does_not_terminate():
    # Same verdict from the other side: a syscall on a MIDDLE block never
    # licensed a short chain even under the old policy, and still does not.
    wps = [_wp(13, n_insns=14), _wp(14, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID,
                      syscall_bids=(13,))
    errs = _errs(issues)
    assert len(errs) == 1 and "truncated" in errs[0].message, \
        f"a mid-chain syscall must not terminate, got {[i.message for i in issues]}"


def test_syscall_chain_continuing_to_budget_is_clean():
    # And the positive: a chain that walks THROUGH a syscall block and on to
    # the budget is correct output, no issue at all.
    wps = [_wp(13, n_insns=14), _wp(14, n_insns=11), _wp(15, n_insns=11),
           _wp(16, n_insns=15), _wp(17, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID,
                      syscall_bids=(14,))
    assert not issues, \
        f"walking past a syscall must be clean, got {[i.message for i in issues]}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items())
           if k.startswith("test_") and callable(v)]
    n_pass = n_fail = 0
    for fn in fns:
        try:
            fn()
        except AssertionError as e:
            print(f"FAIL {fn.__name__}: {e}")
            n_fail += 1
        else:
            print(f"PASS {fn.__name__}")
            n_pass += 1
    print(f"{'OK' if n_fail == 0 else 'FAILED'} "
          f"({n_pass} passed, {n_fail} failed)")
    sys.exit(1 if n_fail else 0)
