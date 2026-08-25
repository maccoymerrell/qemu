"""
ARC 3 -- the gem5 START PROOF.  Run BY gem5, as its config script.

``gem5.opt --help`` proves nothing about whether gem5 can run: with an
ABI-mismatched ``libstdc++`` ahead of the one it was compiled against, gem5
parses its options, imports ``m5``, builds SimObjects, and then dies at the
FIRST ``cprintf`` to ``std::cout``:

    src/base/cprintf.cc:55   savedFlags = stream.flags();
    src/sim/core.cc:108      fixClockFrequency()

observed under gdb on this host.  ``m5.instantiate()`` is what calls
``fixClockFrequency``, so this script is the shallowest thing that reaches the
frame the failure actually occupies.  It is the difference between a
prerequisite check that fires and one that is inert.

Prints ``ARC3-GEM5-START-OK`` on success; the harness requires that token and
refuses to score without it.

Author: Maccoy Merrell.
"""
import m5
from m5.objects import Root, SrcClockDomain, VoltageDomain

root = Root(full_system=False)
root.clk_domain = SrcClockDomain(clock='1GHz', voltage_domain=VoltageDomain())
m5.instantiate()
print('ARC3-GEM5-START-OK')
