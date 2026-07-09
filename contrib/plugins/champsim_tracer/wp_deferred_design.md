# Task #92 — 0-block wrong paths: corrected problem statement (design TBD pending diagnosis)

## Status: the original "deferred retry for un-resident text" design is RETRACTED.

The maintainer challenged its premise and the evidence killed it. Empirical findings from the
archived failing run (/mnt/md0/QEMU/cst_runs/f1_m22, mipsel system, seed 4242):

- The failing instance: validator "WP at CP pos 32 (blk_50) truncated: 0 blocks (sim_insns=0);
  predicted 5". In the trace, blk_50 (template BB1909 @ 0x400ba4) executes exactly once, branch
  NOT taken on the CP (`taken_cp=0 nottaken_cp=1`, consistent with its `beqz` reading t0=1), so
  the wrong path is the TAKEN target 0x400c40 (blk_53).
- **Every relevant page was resident**: blk_50, the fall-through blk_51 (0x400bd0), and the wrong
  target blk_53 (0x400c40) all sit on the SAME 4 KB text page the CP was executing at that
  moment; blk_53's arena data page (0x411xxx) had been written by the immediately preceding CP
  entry. Translation cannot have failed for residency.
- Run stats show two suspect classes: `WP simulations skipped: 32` (skips upstream of any
  translation attempt) and `WP early exits (fault): 40` (excursions bailed by the spec-fault
  suppression).

## Correct framing (maintainer)

- **User mode**: a WP target outside the binary means the fetch would fault; a real frontend
  fetches nothing; a 0-block chain is CORRECT output there, not a defect.
- **System mode**: wrong-path blocks outside the current ASID's mapped segments must not be
  encoded (same argument). A properly simulated wrong path does not "stumble into" unmapped
  code — targets come from real static branch targets / observed indirect history inside the
  workload's text.
- Therefore an empty chain where the target is demonstrably resident (this case) is a PLUGIN
  BUG in the kick/skip/bail path, not an architectural condition to excuse or retry around.

## Open hypotheses for the diagnosis (in likelihood order)

1. **Kick skipped at this seal** — the "WP simulations skipped" counter's conditions (whatever
   they are: merge-path seals, fault-adjacent seals, dedup/wpprune interactions) swallowing a
   normal branch's excursion.
2. **Stale poison** — an earlier excursion faulted at/near 0x400c40 (e.g., before its arena page
   first-touch) and the target stayed poisoned after the condition healed.
3. **First-insn spec-fault bail** — the excursion ran and faulted at wrong-path insn 0 for a
   non-residency reason, sealing nothing. (Also raises the fidelity question: real hardware
   continues fetching past a squashed faulting load; our sandbox bails the excursion. Worth a
   separate decision once the primary bug is fixed.)

## Next step

Read-only diagnosis to classify which mechanism produced THIS 0-block (enumerate every increment
site of "WP simulations skipped" and every 0-block-producing bail; map entry 1069's seal path).
Then a targeted fix + a validator case reproducing the exact class. No wire change anticipated.
