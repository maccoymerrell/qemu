# What is a basic block?

A basic block is a segment of instructions, beginning with a branch target and ending with a branch instruction.
Branch targets are of either two types, actual jump targets or fall-through addresses.
This means every instruction falls within at least one basic block, and basic blocks branch to two other possible basic blocks (fall through or jump target) for standard conditional branches.
Indirect branches act as dynamic-links between basic blocks, which may change over time.
Basic blocks ALWAYS end with a branch. If the basic block does not end with a branch, it is not the end of the basic block.
Basic blocks are unique by start PC, no two basic blocks share the same start PC. They may share the same end PC, as branch targets may fall within the bounds of other basic blocks.
To track true basic blocks, only the start PC is required.