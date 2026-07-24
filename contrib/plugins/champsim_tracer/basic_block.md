# What is a basic block?

A basic block is a segment of instructions, beginning with a branch target and ending with a branch instruction.
Branch targets are of either two types, actual jump targets or fall-through addresses.
This means every instruction falls within at least one basic block, and basic blocks branch to two other possible basic blocks (fall through or jump target) for standard conditional branches.
Indirect branches act as dynamic-links between basic blocks, which may change over time.
Basic blocks ALWAYS end with a branch. If the basic block does not end with a branch, it is not the end of the basic block.
Basic blocks are keyed by start PC (paired with the code's address-space id): for a given program text at a given address, one block. They may share the same end PC, as branch targets may fall within the bounds of other basic blocks.
The one deliberate exception is self-modifying code: when correct-path code at a start PC is patched in place and re-executes with different bytes, the tracer mints a new template *revision* — a distinct `template_id` at the same start PC. On the wire, blocks are therefore unique by `template_id`, not by start PC; a start PC carrying more than one template is a self-modified block's revision history, and body entries always name the `template_id` that was live when they executed.