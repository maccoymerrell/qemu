"""Verdict-level tests for _check_wrong_path_chains.

Exercises the wrong-path fault policy: the plugin proceeds around a
suppressed speculative fault with the accumulated wrong-path state
(independent instructions run exactly as they normally would), poisons
the faulted instruction's destinations, propagates poison through
register dataflow, and MUST kill the excursion at the first branch
whose sources are poisoned (CST_WP_EVENT_DEP_BRANCH_KILL on the
chain's last entry).  Post-fault divergence is an error; a chain that
continues past a provably fault-dependent branch is an error; the old
(pre-policy) trace shape — fault-carrying chains resolving the
dependent branch and continuing — is the canonical NEGATIVE test.

Run standalone:
  python tests/test_wrong_path_chains.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from champsim_tracer_validator.validator import _check_wrong_path_chains

REG_ZERO = 241
REG_FLAGS = 251
REG_T0 = 8        # branch-condition register
REG_T8 = 24       # arena base
REG_T1 = 9
REG_NAME_TO_ID = {"REG_ZERO": REG_ZERO, "REG_FLAGS": REG_FLAGS}

BR_COND = 3       # any nonzero branch_type id


def _blocks(n_insns_by_bid):
    return {bid: {"block_id": bid, "class": "asm_load_burst",
                  "ground_truth": {"n_insns": n}}
            for bid, n in n_insns_by_bid.items()}


def _load_burst_insns(n):
    """Burst-block template: lui/addiu set t8, loads into t0/t1, ends
    in an unconditional direct jump (no sources)."""
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
    insns.append({"src_regs": [], "dst_regs": [], "branch_type": BR_COND,
                  "branch_conditional": False})  # j (no sources)
    return insns


def _cond_branch_insns(n):
    """Cond-branch block: reloads t0 from its slot (insn 2), ends in
    beqz t0 (src = t0)."""
    insns = _load_burst_insns(n)
    insns[-1] = {"src_regs": [REG_T0], "dst_regs": [], "branch_type": BR_COND,
                 "branch_conditional": True}     # beqz t0
    return insns


def _wp(template_id, fault=False, fault_idx=None, unavail=False,
        kill=False, n_insns=13):
    return {"index": 0, "template_id": template_id, "n_insns": n_insns,
            "fault": fault, "fault_insn_index": fault_idx,
            "translation_unavailable": unavail,
            "dep_branch_kill": kill}


def run_case(wp_entries, exp_chain, budget=64, n_insns_by_bid=None,
             chain_event=False, cond_bids=(17, 42)):
    """One CP fork at cp_pos 0 (blk_0) with the given wrong path.
    Template ids: 100 -> CP block 0; 200+bid -> WP block bid.  Blocks
    in @cond_bids get a beqz-t0 terminator; others end in a bare j."""
    template_runs = {100: [(0, 1)]}
    blocks = dict(n_insns_by_bid or {})
    blocks.setdefault(0, 10)
    templates_by_id = {}
    bids = {wp["template_id"] - 200 for wp in wp_entries} | set(exp_chain)
    for bid in bids:
        template_runs.setdefault(200 + bid, [(bid, 1)])
        blocks.setdefault(bid, 13)
        mk = _cond_branch_insns if bid in cond_bids else _load_burst_insns
        templates_by_id[200 + bid] = {"template_id": 200 + bid,
                                      "insns": mk(blocks[bid])}
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


N_BY_BID = {13: 14, 14: 11, 15: 11, 16: 15, 17: 11, 18: 14,
            22: 13, 23: 13}


def test_old_policy_shape_is_flagged():
    # pf77/pg40/w6_m_24 (negative test): guest-TLB-cold excursion,
    # every block faults at insn 2, the dependent branch at blk_17
    # is RESOLVED with stale state and the chain continues to blk_18.
    # Under the corrected policy this must be flagged: continuation
    # past a fault-dependent branch AND post-fault divergence.
    wps = [_wp(200 + b, fault=True, fault_idx=2, n_insns=N_BY_BID[b])
           for b in (13, 14, 15, 16, 17, 18)]
    issues = run_case(wps, [13, 14, 15, 16, 17, 22, 23],
                      n_insns_by_bid=N_BY_BID)
    errs = [i for i in issues if i.severity == "error"]
    assert any("must die on that branch" in i.message for i in errs), \
        f"expected required-kill error, got {[i.message for i in issues]}"
    assert any("depth 5" in i.message for i in errs), \
        f"expected depth-5 divergence error, got {[i.message for i in issues]}"


def test_kill_terminated_chain_accepted():
    # Corrected-policy shape: same TLB-cold scenario, but the chain
    # dies at blk_17 (its beqz reads the faulted t0) with the kill
    # marker on the last entry.  Prefix matches; accepted.
    wps = [_wp(200 + b, fault=True, fault_idx=2, n_insns=N_BY_BID[b])
           for b in (13, 14, 15, 16)]
    wps.append(_wp(217, fault=True, fault_idx=2, kill=True,
                   n_insns=N_BY_BID[17]))
    issues = run_case(wps, [13, 14, 15, 16, 17, 22, 23],
                      n_insns_by_bid=N_BY_BID)
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


def test_kill_not_last_is_error():
    wps = [_wp(213, fault=True, fault_idx=2, kill=True, n_insns=14),
           _wp(214, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17], n_insns_by_bid=N_BY_BID)
    errs = [i for i in issues if i.severity == "error"]
    assert any("must be the last entry" in i.message for i in errs), \
        f"expected kill-placement error, got {[i.message for i in issues]}"


def test_kill_without_fault_is_error():
    wps = [_wp(213, n_insns=14), _wp(217, kill=True, n_insns=11)]
    issues = run_case(wps, [13, 17, 22, 23, 24], n_insns_by_bid=N_BY_BID)
    errs = [i for i in issues if i.severity == "error"]
    assert any("without a FAULT" in i.message for i in errs), \
        f"expected kill-sanity error, got {[i.message for i in issues]}"


def test_independent_branches_proceed():
    # Fault in a burst block whose terminator is an unconditional j
    # (no sources): the chain continues normally, no kill required,
    # and a full-length matching chain is clean.
    wps = [_wp(213, fault=True, fault_idx=3, n_insns=14),
           _wp(214, n_insns=11), _wp(215, n_insns=11),
           _wp(216, n_insns=15), _wp(218, n_insns=14)]
    issues = run_case(wps, [13, 14, 15, 16, 18],
                      n_insns_by_bid=N_BY_BID, cond_bids=())
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


def test_divergence_without_fault_still_errors():
    wps = [_wp(200 + b, n_insns=N_BY_BID[b]) for b in
           (13, 14, 15, 16, 17, 18)]
    issues = run_case(wps, [13, 14, 15, 16, 17, 22, 23],
                      n_insns_by_bid=N_BY_BID, cond_bids=())
    errs = [i for i in issues if i.severity == "error"]
    assert len(errs) == 1 and "depth 5" in errs[0].message, \
        f"expected depth-5 error, got {[i.message for i in issues]}"


def test_truncation_without_budget_still_errors():
    # storm shape: matching prefix, chain ends early, unavail marker,
    # sim_insns below budget -> still a truncation error.
    wps = [_wp(213, n_insns=14), _wp(214, unavail=True, n_insns=11)]
    issues = run_case(wps, [13, 14, 15, 16, 17],
                      n_insns_by_bid=N_BY_BID, cond_bids=())
    errs = [i for i in issues if i.severity == "error"]
    assert len(errs) == 1 and "truncated" in errs[0].message, \
        f"expected truncation error, got {[i.message for i in issues]}"


def test_exact_match_clean():
    wps = [_wp(200 + b, n_insns=N_BY_BID[b]) for b in (13, 14, 15, 16, 17)]
    issues = run_case(wps, [13, 14, 15, 16, 17],
                      n_insns_by_bid=N_BY_BID, cond_bids=())
    assert not issues, f"expected clean, got {[i.message for i in issues]}"


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print(f"PASS {fn.__name__}")
    print(f"OK ({len(fns)} tests)")
