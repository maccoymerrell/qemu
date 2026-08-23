# ARC 3 coverage denominator — aarch64

These scripts enumerate the A64 **opcode space** that the ARC 3 coverage
claim is measured against.  They read the Arm Machine Readable
Architecture XML (rank-1 reference for this ISA) and never consult
Capstone, which is the subject under test (ruling R7).

```sh
# rank-1 reference, once:
#   archive.org/download/arm-xml-a-profile-2022-12/ISA_A64_xml_A_profile-2022-12.tar.gz
#   archive.org/download/arm-xml-a-profile-2022-12/SysReg_xml_A_profile-2022-12.tar.gz
python build_opcodes.py <ISA_A64_xml_A_profile-2022-12/> <outdir>   # opcodes.tsv
python build_sysreg.py  <SysReg_xml_A_profile-2022-12/>  <out.tsv>  # selectors

# release-gap measurement: exhaustive top-22-bit LLVM mnemonic census,
# then one rank-2 row per operand shape for anything the MRA release
# predates.
python census.py | isaxcheck --isa=aarch64 --batch \
      | awk -F'\t' 'NR>1 && $17=="1"{n=split($19,a," "); print tolower(a[1])}' \
      | sort | uniq -c | sort -rn > llvm_census.txt
python census.py | isaxcheck --isa=aarch64 --batch | python harvest_gap.py
python append_gap.py
```

One row per Arm-named encoding — that naming is already the operand-shape
split ARC 3 wants — with encodings occupying the identical bit range and
an `Unconditionally` alias condition merged as pure re-spellings.  Every
representative encoding is verified by decoding it with `isaxcheck`.

The produced denominator, its README and its evidence live outside the
tree, under `/mnt/md0/QEMU/cst_runs/_arc3_cov/aarch64/`.
