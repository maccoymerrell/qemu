/*
 * Wrong-Path Tracing Plugin for QEMU
 *
 * Extended trace format implementing the ChampSim wrong-path specification:
 *
 *   HEADER: A map of BB templates encoding all unique basic blocks within
 *           the traced window, with static instruction context (PCs, sizes,
 *           raw instruction bytes, and decoded x86 fields when applicable).
 *
 *   BODY:   The execution trace of BBs as they executed on the correct-path,
 *           with dynamic context (branch targets, memory addresses) and
 *           wrong-path BB sequences per correct-path BB.
 *
 * Two output modes:
 *   - Packed binary (.bin): Compact ULEB128-based encoding of header + body
 *   - Debug text (.txt): Human-readable representation (toggleable)
 *
 * Features:
 *   - BB template deduplication (unique BBs stored once in header)
 *   - Wrong-path execution with real IF and DF addresses
 *   - Start/stop tracing by instruction number
 *   - x86 instruction field extraction (prefixes, opcode, ModRM, SIB, disp, imm)
 *   - Compact LEB128 variable-length integer encoding
 *   - ISA-agnostic core (x86 decode is optional enrichment)
 *
 * Usage:
 *   -plugin wptrace[,depth=N][,outfile=PATH][,debug=1]
 *                  [,wp=0|1][,start=N][,stop=N]
 *                  [,program=NAME]
 *
 * Copyright (c) 2025
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <qemu-plugin.h>

QEMU_PLUGIN_EXPORT int qemu_plugin_version = QEMU_PLUGIN_VERSION;

/* ========================= Configuration ========================= */

static int max_wrong_path_depth = 64;
static bool enable_wrong_path = true;
static bool enable_debug_text = false;
static char *output_base_path = NULL;
static char *program_name = NULL;
static uint64_t trace_start_insn = 0;
static uint64_t trace_stop_insn = UINT64_MAX;
static const char *target_name;
static bool is_x86 = false;

#define MAX_INSN_BYTES 16

/* Magic for binary format */
#define WPT_MAGIC  0x54505702  /* "WPT\x02" - version 2 */

/* ========================= Data Structures ========================= */

/* Decoded x86 instruction fields for trace enrichment */
typedef struct {
    uint8_t n_prefixes;         /* Number of prefix bytes */
    uint8_t opcode_len;         /* Opcode length (1-3 bytes) */
    uint8_t opcode[3];          /* Opcode bytes */
    bool has_modrm;             /* Has ModRM byte */
    uint8_t modrm;              /* ModRM byte */
    bool has_sib;               /* Has SIB byte */
    uint8_t sib;                /* SIB byte */
    uint8_t disp_size;          /* Displacement size (0/1/2/4) */
    int32_t disp;               /* Displacement value */
    uint8_t imm_size;           /* Immediate size (0/1/2/4/8) */
    int64_t imm;                /* Immediate value */
} X86InsnFields;

/*
 * Lightweight x86 instruction field extraction.
 * Best-effort decoder for trace enrichment, not a full disassembler.
 */
static void decode_x86_insn(const uint8_t *bytes, uint32_t len,
                             X86InsnFields *out)
{
    memset(out, 0, sizeof(*out));
    uint32_t pos = 0;

    if (len == 0) {
        return;
    }

    /* Scan prefix bytes */
    while (pos < len) {
        uint8_t b = bytes[pos];
        if (b == 0x66 || b == 0x67 || b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || (b >= 0x40 && b <= 0x4F)) {
            out->n_prefixes++;
            pos++;
        } else {
            break;
        }
    }

    if (pos >= len) {
        return;
    }

    /* Read opcode */
    out->opcode[0] = bytes[pos++];
    out->opcode_len = 1;

    if (out->opcode[0] == 0x0F && pos < len) {
        out->opcode[1] = bytes[pos++];
        out->opcode_len = 2;

        if ((out->opcode[1] == 0x38 || out->opcode[1] == 0x3A) &&
            pos < len) {
            out->opcode[2] = bytes[pos++];
            out->opcode_len = 3;
        }
    }

    /*
     * Determine if opcode requires ModRM.
     * For 2/3-byte opcodes, most require ModRM.
     * For 1-byte opcodes, use a simplified check.
     */
    bool needs_modrm = false;
    uint8_t imm_bytes = 0;

    if (out->opcode_len >= 2) {
        /* Most 2/3-byte opcodes have ModRM */
        needs_modrm = true;

        /* 2-byte conditional jumps (0F 80-8F) do not have ModRM */
        if (out->opcode_len == 2 &&
            out->opcode[1] >= 0x80 && out->opcode[1] <= 0x8F) {
            needs_modrm = false;
            imm_bytes = 4; /* rel32 */
        }
    } else {
        uint8_t op = out->opcode[0];

        /* Opcodes that generally have ModRM byte */
        if ((op <= 0x03) ||                /* ADD r/m, r / ADD r, r/m */
            (op >= 0x08 && op <= 0x0B) || /* OR */
            (op >= 0x10 && op <= 0x13) || /* ADC */
            (op >= 0x18 && op <= 0x1B) || /* SBB */
            (op >= 0x20 && op <= 0x23) || /* AND */
            (op >= 0x28 && op <= 0x2B) || /* SUB */
            (op >= 0x30 && op <= 0x33) || /* XOR */
            (op >= 0x38 && op <= 0x3B) || /* CMP */
            (op >= 0x80 && op <= 0x83) || /* Grp1 imm */
            op == 0x84 || op == 0x85 ||   /* TEST */
            (op >= 0x86 && op <= 0x8F) || /* XCHG, LEA, MOV, POP */
            op == 0xC0 || op == 0xC1 ||   /* Shift Grp2 imm8 */
            op == 0xC6 || op == 0xC7 ||   /* MOV imm */
            op == 0xD0 || op == 0xD1 ||   /* Shift Grp2 1 */
            op == 0xD2 || op == 0xD3 ||   /* Shift Grp2 CL */
            op == 0xF6 || op == 0xF7 ||   /* Grp3 */
            op == 0xFE || op == 0xFF ||   /* Grp4/5 */
            op == 0x63 || op == 0x69 || op == 0x6B) { /* MOVSXD, IMUL */
            needs_modrm = true;
        }

        /* Determine immediate size for 1-byte opcodes */
        if (op >= 0x04 && op <= 0x05) {
            /* ADD AL/eAX, imm */
            imm_bytes = (op & 1) ? 4 : 1;
        } else if (op >= 0x0C && op <= 0x0D) {
            imm_bytes = (op & 1) ? 4 : 1; /* OR AL/eAX */
        } else if (op >= 0x14 && op <= 0x15) {
            imm_bytes = (op & 1) ? 4 : 1; /* ADC AL/eAX */
        } else if (op >= 0x1C && op <= 0x1D) {
            imm_bytes = (op & 1) ? 4 : 1; /* SBB AL/eAX */
        } else if (op >= 0x24 && op <= 0x25) {
            imm_bytes = (op & 1) ? 4 : 1; /* AND AL/eAX */
        } else if (op >= 0x2C && op <= 0x2D) {
            imm_bytes = (op & 1) ? 4 : 1; /* SUB AL/eAX */
        } else if (op >= 0x34 && op <= 0x35) {
            imm_bytes = (op & 1) ? 4 : 1; /* XOR AL/eAX */
        } else if (op >= 0x3C && op <= 0x3D) {
            imm_bytes = (op & 1) ? 4 : 1; /* CMP AL/eAX */
        } else if (op == 0x68) {
            imm_bytes = 4; /* PUSH imm32 */
        } else if (op == 0x6A) {
            imm_bytes = 1; /* PUSH imm8 */
        } else if (op == 0x69) {
            imm_bytes = 4; /* IMUL r, r/m, imm32 */
        } else if (op == 0x6B) {
            imm_bytes = 1; /* IMUL r, r/m, imm8 */
        } else if (op >= 0x70 && op <= 0x7F) {
            imm_bytes = 1; /* Jcc rel8 */
        } else if (op == 0x80 || op == 0x82) {
            imm_bytes = 1; /* Grp1 r/m8, imm8 */
        } else if (op == 0x81) {
            imm_bytes = 4; /* Grp1 r/m, imm32 */
        } else if (op == 0x83) {
            imm_bytes = 1; /* Grp1 r/m, imm8 */
        } else if (op == 0xA8) {
            imm_bytes = 1; /* TEST AL, imm8 */
        } else if (op == 0xA9) {
            imm_bytes = 4; /* TEST eAX, imm32 */
        } else if (op >= 0xB0 && op <= 0xB7) {
            imm_bytes = 1; /* MOV r8, imm8 */
        } else if (op >= 0xB8 && op <= 0xBF) {
            imm_bytes = 4; /* MOV r, imm32 (or imm64 with REX.W) */
        } else if (op == 0xC0 || op == 0xC1) {
            imm_bytes = 1; /* Shift Grp2 imm8 */
        } else if (op == 0xC2) {
            imm_bytes = 2; /* RET imm16 */
        } else if (op == 0xC6) {
            imm_bytes = 1; /* MOV r/m8, imm8 */
        } else if (op == 0xC7) {
            imm_bytes = 4; /* MOV r/m, imm32 */
        } else if (op == 0xCD) {
            imm_bytes = 1; /* INT imm8 */
        } else if (op == 0xE8 || op == 0xE9) {
            imm_bytes = 4; /* CALL/JMP rel32 */
        } else if (op == 0xEB) {
            imm_bytes = 1; /* JMP rel8 */
        } else if (op == 0xE4 || op == 0xE5 || op == 0xE6 || op == 0xE7) {
            imm_bytes = 1; /* IN/OUT imm8 */
        }
    }

    /* Read ModRM if needed */
    if (needs_modrm && pos < len) {
        out->has_modrm = true;
        out->modrm = bytes[pos++];

        uint8_t mod = (out->modrm >> 6) & 3;
        uint8_t rm = out->modrm & 7;

        /* SIB byte: present when mod != 11 and rm == 4 */
        if (mod != 3 && rm == 4 && pos < len) {
            out->has_sib = true;
            out->sib = bytes[pos++];
        }

        /* Displacement */
        if (mod == 1) {
            out->disp_size = 1;
        } else if (mod == 2) {
            out->disp_size = 4;
        } else if (mod == 0 && rm == 5) {
            out->disp_size = 4; /* RIP-relative or disp32 */
        }

        /* Read displacement bytes */
        if (out->disp_size > 0 && pos + out->disp_size <= len) {
            uint32_t d = 0;
            for (uint8_t i = 0; i < out->disp_size; i++) {
                d |= (uint32_t)bytes[pos++] << (i * 8);
            }
            /* Sign-extend 1-byte displacement */
            if (out->disp_size == 1 && (d & 0x80)) {
                d |= 0xFFFFFF00;
            }
            out->disp = (int32_t)d;
        }

        /* Determine immediate for ModRM opcodes that also have immediates */
        if (out->opcode_len == 1) {
            uint8_t op = out->opcode[0];
            if (op == 0xF6) {
                /* Grp3: TEST r/m8, imm8 when reg==0 */
                uint8_t reg = (out->modrm >> 3) & 7;
                if (reg == 0) {
                    imm_bytes = 1;
                }
            } else if (op == 0xF7) {
                /* Grp3: TEST r/m, imm32 when reg==0 */
                uint8_t reg = (out->modrm >> 3) & 7;
                if (reg == 0) {
                    imm_bytes = 4;
                }
            }
        }
    }

    /* Read immediate bytes */
    if (imm_bytes > 0 && pos + imm_bytes <= len) {
        out->imm_size = imm_bytes;
        uint64_t imm = 0;
        for (uint8_t i = 0; i < imm_bytes; i++) {
            imm |= (uint64_t)bytes[pos++] << (i * 8);
        }
        /* Sign-extend */
        if (imm_bytes == 1 && (imm & 0x80)) {
            imm |= ~(uint64_t)0xFF;
        } else if (imm_bytes == 2 && (imm & 0x8000)) {
            imm |= ~(uint64_t)0xFFFF;
        } else if (imm_bytes == 4 && (imm & 0x80000000ULL)) {
            imm |= ~(uint64_t)0xFFFFFFFF;
        }
        out->imm = (int64_t)imm;
    }
}

/*
 * BB Template - static instruction context for a unique basic block.
 * Populated during translation and referenced by ID in the trace body.
 */
typedef struct {
    uint32_t template_id;       /* Unique ID for this template */
    uint64_t start_pc;          /* Block start address */
    uint32_t n_insns;           /* Number of instructions */
    uint64_t *insn_pcs;         /* Array of instruction PCs */
    uint32_t *insn_sizes;       /* Array of instruction sizes in bytes */
    uint8_t **insn_bytes;       /* Array of raw instruction byte arrays */
    uint64_t fall_through_pc;   /* PC after last instruction (sequential) */
    X86InsnFields *insn_fields; /* Decoded fields per insn (x86 only, else NULL) */
} BBTemplate;

/*
 * Dynamic parameter types for body entries.
 */
enum DynParamType {
    DYN_BRANCH_TARGET = 0,     /* Branch target address */
    DYN_LOAD_ADDR = 1,         /* Load memory address */
    DYN_STORE_ADDR = 2,        /* Store memory address */
};

typedef struct {
    uint8_t type;               /* DynParamType */
    uint64_t value;             /* Address value */
} DynParam;

/*
 * Wrong-path BB entry within a body entry.
 * Represents one BB executed on the wrong path.
 */
typedef struct {
    uint32_t template_id;       /* BB template ID (or UINT32_MAX if new) */
    uint64_t start_pc;          /* Start PC (for identification) */
    GArray *dyn_params;         /* GArray of DynParam */
    uint32_t n_insns_executed;  /* Number of insns executed in this WP BB */
    bool exception;             /* True if WP BB ended due to exception */
} WPBBEntry;

/*
 * Body entry - one correct-path BB execution.
 */
typedef struct {
    uint32_t seq_num;           /* Sequence number in trace */
    uint32_t template_id;       /* BB template ID */
    GArray *dyn_params;         /* GArray of DynParam (correct-path) */
    GArray *wp_entries;         /* GArray of WPBBEntry (wrong-path chain) */
} BodyEntry;

/*
 * Per-vCPU scoreboard for tracking execution state between blocks.
 */
typedef struct {
    uint64_t current_pc;        /* Current block's start PC */
    uint64_t prev_last_pc;      /* Last insn PC of previous block */
    uint64_t prev_fall_through; /* Expected sequential next from prev block */
    uint64_t insn_count;        /* Total instructions executed */
} VCPUScoreBoard;

/*
 * Branch record for Smith predictor.
 */
typedef struct {
    uint64_t pc;                /* Branch instruction PC */
    uint64_t fall_through;      /* Sequential next PC */
    uint64_t taken_target;      /* Observed taken target */
    bool has_taken_target;      /* Whether taken target has been seen */
    uint8_t smith_counter;      /* 2-bit saturating counter (0-3) */
} BranchRecord;

/*
 * Memory access during wrong-path execution.
 */
typedef struct {
    uint64_t insn_pc;           /* PC of the instruction making the access */
    uint64_t mem_vaddr;         /* Virtual address of the memory access */
    bool is_store;              /* Whether this was a store operation */
} WPMemAccess;

/*
 * Trace state - collects body entries for a single trace segment.
 */
typedef struct {
    GArray *body_entries;       /* GArray of BodyEntry */
    uint64_t start_insn;        /* Instruction number at trace start */
    uint64_t stop_insn;         /* Instruction number at trace end */
    char *label;                /* Label for output file naming */
    FILE *text_file;            /* Debug text output (NULL if disabled) */
    FILE *bin_file;             /* Binary output */
} TraceSegment;

/* ========================= Global State ========================= */

static GMutex data_lock;
static GHashTable *template_map;    /* start_pc (uint64*) → BBTemplate* */
static GHashTable *branch_map;      /* branch_pc (uint64*) → BranchRecord* */
static uint32_t next_template_id = 1;

/* Per-vCPU scoreboard */
static struct qemu_plugin_scoreboard *vcpu_sb;
static qemu_plugin_u64 sb_current_pc;
static qemu_plugin_u64 sb_prev_last_pc;
static qemu_plugin_u64 sb_prev_fall_through;
static qemu_plugin_u64 sb_insn_count;

/* Tracing state */
static bool trace_active = false;
static TraceSegment *current_segment = NULL;
static uint32_t body_seq_num = 0;

/* Wrong-path execution state */
static bool wp_in_progress = false;
static GArray *wp_mem_accesses = NULL;
static uint64_t wp_current_insn_pc = 0;

/* Correct-path memory accesses for current BB */
static GArray *cp_mem_accesses = NULL;

/* Statistics */
static uint64_t stat_blocks_translated;
static uint64_t stat_branches_observed;
static uint64_t stat_branches_taken;
static uint64_t stat_branches_not_taken;
static uint64_t stat_wp_simulations;
static uint64_t stat_wp_skipped;
static uint64_t stat_wp_total_insns;
static uint64_t stat_wp_early_exits;
static uint64_t stat_wp_total_mem_accesses;

/* ========================= Smith Predictor ========================= */

static inline uint8_t smith_update(uint8_t counter, bool taken)
{
    if (taken && counter < 3) {
        return counter + 1;
    } else if (!taken && counter > 0) {
        return counter - 1;
    }
    return counter;
}

/* ========================= Memory Management ========================= */

static void dyn_param_array_free(GArray *arr)
{
    if (arr) {
        g_array_unref(arr);
    }
}

static void wp_bb_entry_clear(WPBBEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
}

static void body_entry_clear(BodyEntry *entry)
{
    dyn_param_array_free(entry->dyn_params);
    if (entry->wp_entries) {
        for (guint i = 0; i < entry->wp_entries->len; i++) {
            wp_bb_entry_clear(&g_array_index(entry->wp_entries, WPBBEntry, i));
        }
        g_array_unref(entry->wp_entries);
    }
}

static void bb_template_free(gpointer data)
{
    BBTemplate *tmpl = data;
    if (tmpl->insn_bytes) {
        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            g_free(tmpl->insn_bytes[i]);
        }
        g_free(tmpl->insn_bytes);
    }
    g_free(tmpl->insn_fields);
    g_free(tmpl->insn_pcs);
    g_free(tmpl->insn_sizes);
    g_free(tmpl);
}

static TraceSegment *trace_segment_new(const char *label,
                                       uint64_t start, uint64_t stop)
{
    TraceSegment *seg = g_new0(TraceSegment, 1);
    seg->body_entries = g_array_new(false, false, sizeof(BodyEntry));
    seg->start_insn = start;
    seg->stop_insn = stop;
    seg->label = g_strdup(label);
    return seg;
}

static void trace_segment_free(TraceSegment *seg)
{
    if (!seg) {
        return;
    }
    for (guint i = 0; i < seg->body_entries->len; i++) {
        body_entry_clear(&g_array_index(seg->body_entries, BodyEntry, i));
    }
    g_array_unref(seg->body_entries);
    if (seg->text_file) {
        fclose(seg->text_file);
    }
    if (seg->bin_file) {
        fclose(seg->bin_file);
    }
    g_free(seg->label);
    g_free(seg);
}

/* ========================= BB Template Management ========================= */

/*
 * Find or create a BB template for the given start PC.
 * If a template already exists for this PC, returns it.
 * Otherwise creates a new one with the given instruction data.
 *
 * Must be called with data_lock held.
 */
static BBTemplate *get_or_create_template(uint64_t start_pc,
                                          uint32_t n_insns,
                                          uint64_t *insn_pcs,
                                          uint32_t *insn_sizes,
                                          uint8_t **insn_bytes,
                                          uint64_t fall_through_pc)
{
    BBTemplate *tmpl = g_hash_table_lookup(template_map, &start_pc);
    if (tmpl) {
        return tmpl;
    }

    tmpl = g_new0(BBTemplate, 1);
    tmpl->template_id = next_template_id++;
    tmpl->start_pc = start_pc;
    tmpl->n_insns = n_insns;
    tmpl->fall_through_pc = fall_through_pc;

    tmpl->insn_pcs = g_new0(uint64_t, n_insns);
    tmpl->insn_sizes = g_new0(uint32_t, n_insns);
    tmpl->insn_bytes = g_new0(uint8_t *, n_insns);

    for (uint32_t i = 0; i < n_insns; i++) {
        tmpl->insn_pcs[i] = insn_pcs[i];
        tmpl->insn_sizes[i] = insn_sizes[i];
        if (insn_bytes && insn_bytes[i]) {
            tmpl->insn_bytes[i] = g_memdup2(insn_bytes[i], insn_sizes[i]);
        }
    }

    if (is_x86) {
        tmpl->insn_fields = g_new0(X86InsnFields, n_insns);
        for (uint32_t i = 0; i < n_insns; i++) {
            if (insn_bytes && insn_bytes[i]) {
                decode_x86_insn(insn_bytes[i], insn_sizes[i],
                                &tmpl->insn_fields[i]);
            }
        }
    }

    g_hash_table_replace(template_map, &tmpl->start_pc, tmpl);
    stat_blocks_translated++;
    return tmpl;
}

/*
 * Look up a template by start PC.
 * Must be called with data_lock held.
 */
static BBTemplate *find_template(uint64_t start_pc)
{
    return g_hash_table_lookup(template_map, &start_pc);
}

/* ========================= Memory Access Tracking ========================= */

/*
 * Per-instruction memory access callback.
 * During wrong-path execution (wp_in_progress), records data addresses.
 * During correct-path execution with tracing active, records data addresses.
 */
static void vcpu_mem_cb(unsigned int cpu_index,
                        qemu_plugin_meminfo_t info,
                        uint64_t vaddr,
                        void *udata)
{
    uint64_t insn_pc = (uint64_t)(uintptr_t)udata;

    if (wp_in_progress && wp_mem_accesses) {
        WPMemAccess acc = {
            .insn_pc = wp_current_insn_pc ? wp_current_insn_pc : insn_pc,
            .mem_vaddr = vaddr,
            .is_store = qemu_plugin_mem_is_store(info),
        };
        g_array_append_val(wp_mem_accesses, acc);
        return;
    }

    if (trace_active && cp_mem_accesses) {
        WPMemAccess acc = {
            .insn_pc = insn_pc,
            .mem_vaddr = vaddr,
            .is_store = qemu_plugin_mem_is_store(info),
        };
        g_array_append_val(cp_mem_accesses, acc);
    }
}

/* ========================= Wrong-Path Simulation ========================= */

/*
 * Create a WPBBEntry from a sequence of wrong-path instructions.
 * Groups consecutive instructions into a BB and matches to a template.
 */
static WPBBEntry create_wp_bb_entry(uint64_t bb_start_pc,
                                    GArray *insn_pcs_arr,
                                    GArray *insn_sizes_arr,
                                    GArray *insn_bytes_arr,
                                    GArray *mem_accesses,
                                    guint mem_start_idx)
{
    WPBBEntry entry;
    uint32_t n_insns = insn_pcs_arr->len;

    entry.start_pc = bb_start_pc;
    entry.dyn_params = g_array_new(false, false, sizeof(DynParam));
    entry.n_insns_executed = n_insns;
    entry.exception = false;

    /* Try to find existing template */
    g_mutex_lock(&data_lock);
    BBTemplate *tmpl = find_template(bb_start_pc);

    if (!tmpl && n_insns > 0) {
        /* Create template from wrong-path data */
        uint64_t *pcs = g_new0(uint64_t, n_insns);
        uint32_t *sizes = g_new0(uint32_t, n_insns);
        uint8_t **bytes = g_new0(uint8_t *, n_insns);
        uint64_t ft_pc = 0;

        for (uint32_t i = 0; i < n_insns; i++) {
            pcs[i] = g_array_index(insn_pcs_arr, uint64_t, i);
            sizes[i] = g_array_index(insn_sizes_arr, uint32_t, i);
            if (insn_bytes_arr) {
                uint8_t *src = g_array_index(insn_bytes_arr, uint8_t *, i);
                bytes[i] = g_memdup2(src, sizes[i]);
            }
        }
        ft_pc = pcs[n_insns - 1] + sizes[n_insns - 1];

        tmpl = get_or_create_template(bb_start_pc, n_insns, pcs, sizes,
                                      bytes, ft_pc);

        /* get_or_create_template makes its own copies */
        for (uint32_t i = 0; i < n_insns; i++) {
            g_free(bytes[i]);
        }
        g_free(pcs);
        g_free(sizes);
        g_free(bytes);
    }

    entry.template_id = tmpl ? tmpl->template_id : UINT32_MAX;
    g_mutex_unlock(&data_lock);

    /* Collect memory access dynamic params for this WP BB */
    if (mem_accesses) {
        for (guint m = mem_start_idx; m < mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(mem_accesses, WPMemAccess, m);
            /* Check if this access belongs to an instruction in this BB */
            bool in_bb = false;
            for (uint32_t i = 0; i < n_insns; i++) {
                if (acc->insn_pc == g_array_index(insn_pcs_arr, uint64_t, i)) {
                    in_bb = true;
                    break;
                }
            }
            if (in_bb) {
                DynParam dp = {
                    .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                    .value = acc->mem_vaddr,
                };
                g_array_append_val(entry.dyn_params, dp);
            }
        }
    }

    return entry;
}

/*
 * Execute wrong-path instructions starting from @wrong_target.
 * Returns a GArray of WPBBEntry representing the wrong-path BB chain.
 */
static GArray *simulate_wrong_path_ext(uint64_t branch_pc,
                                       uint64_t correct_target,
                                       uint64_t wrong_target,
                                       unsigned int cpu_index)
{
    GArray *wp_chain = g_array_new(false, false, sizeof(WPBBEntry));
    uint64_t sim_insns = 0;
    bool early_exit = false;
    GByteArray *insn_buf = g_byte_array_new();

    /* State for grouping instructions into BBs */
    GArray *bb_insn_pcs = g_array_new(false, false, sizeof(uint64_t));
    GArray *bb_insn_sizes = g_array_new(false, false, sizeof(uint32_t));
    GArray *bb_insn_bytes = g_array_new(false, false, sizeof(uint8_t *));
    uint64_t bb_start_pc = wrong_target;
    guint bb_mem_start_idx = 0;

    /* Save complete CPU state for rollback */
    struct qemu_plugin_cpu_state *saved_state = qemu_plugin_cpu_state_save();
    if (!saved_state) {
        stat_wp_early_exits++;
        stat_wp_simulations++;
        g_byte_array_unref(insn_buf);
        g_array_unref(bb_insn_pcs);
        g_array_unref(bb_insn_sizes);
        g_array_unref(bb_insn_bytes);
        return wp_chain;
    }

    /* Initialize wrong-path memory access collection */
    wp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));
    wp_in_progress = true;

    /* Enter speculative mode, providing saved state for exception recovery */
    qemu_plugin_spec_mode_begin(saved_state);

    /* Set PC to wrong-path target */
    qemu_plugin_set_pc(wrong_target);

    for (int depth = 0; depth < max_wrong_path_depth; depth++) {
        uint64_t pre_pc = qemu_plugin_get_pc();

        /* Read instruction bytes at current PC */
        g_byte_array_set_size(insn_buf, 0);
        qemu_plugin_read_memory_vaddr(pre_pc, insn_buf, MAX_INSN_BYTES);

        wp_current_insn_pc = pre_pc;

        /* Execute exactly one instruction */
        if (!qemu_plugin_exec_inline_insn()) {
            early_exit = true;
            break;
        }

        sim_insns++;
        uint64_t post_pc = qemu_plugin_get_pc();

        /* Determine instruction size */
        uint32_t insn_size;
        bool is_sequential;
        if (post_pc > pre_pc && (post_pc - pre_pc) <= MAX_INSN_BYTES) {
            insn_size = (uint32_t)(post_pc - pre_pc);
            is_sequential = true;
        } else {
            /* Branch or backwards jump - use template_map if available */
            g_mutex_lock(&data_lock);
            BBTemplate *known = find_template(bb_start_pc);
            g_mutex_unlock(&data_lock);

            insn_size = 0;
            if (known) {
                uint32_t idx_in_bb = bb_insn_pcs->len;
                if (idx_in_bb < known->n_insns) {
                    insn_size = known->insn_sizes[idx_in_bb];
                }
            }
            if (insn_size == 0) {
                insn_size = insn_buf->len < MAX_INSN_BYTES ?
                            insn_buf->len : MAX_INSN_BYTES;
            }
            is_sequential = false;
        }

        /* Record instruction in current BB */
        g_array_append_val(bb_insn_pcs, pre_pc);
        g_array_append_val(bb_insn_sizes, insn_size);
        uint8_t *bytes_copy = g_memdup2(insn_buf->data,
                                         insn_size < insn_buf->len ?
                                         insn_size : insn_buf->len);
        g_array_append_val(bb_insn_bytes, bytes_copy);

        /* Track memory accesses */
        for (guint m = bb_mem_start_idx; m < wp_mem_accesses->len; m++) {
            WPMemAccess *acc = &g_array_index(wp_mem_accesses, WPMemAccess, m);
            if (acc->insn_pc == pre_pc) {
                stat_wp_total_mem_accesses++;
            }
        }

        /* Check for BB boundary (non-sequential PC) */
        if (!is_sequential) {
            /* Finalize current WP BB */
            WPBBEntry wp_bb = create_wp_bb_entry(
                bb_start_pc, bb_insn_pcs, bb_insn_sizes,
                bb_insn_bytes, wp_mem_accesses, bb_mem_start_idx);

            /* Add branch target as dynamic param */
            DynParam target_dp = {
                .type = DYN_BRANCH_TARGET,
                .value = post_pc,
            };
            g_array_append_val(wp_bb.dyn_params, target_dp);
            g_array_append_val(wp_chain, wp_bb);

            /* Start new BB */
            bb_mem_start_idx = wp_mem_accesses->len;
            g_array_set_size(bb_insn_pcs, 0);
            g_array_set_size(bb_insn_sizes, 0);
            /* Free old byte pointers before clearing */
            for (guint j = 0; j < bb_insn_bytes->len; j++) {
                g_free(g_array_index(bb_insn_bytes, uint8_t *, j));
            }
            g_array_set_size(bb_insn_bytes, 0);
            bb_start_pc = post_pc;
        }
    }

    /* Finalize any remaining instructions as a WP BB */
    if (bb_insn_pcs->len > 0) {
        WPBBEntry wp_bb = create_wp_bb_entry(
            bb_start_pc, bb_insn_pcs, bb_insn_sizes,
            bb_insn_bytes, wp_mem_accesses, bb_mem_start_idx);
        if (early_exit) {
            wp_bb.exception = true;
        }
        g_array_append_val(wp_chain, wp_bb);
    } else if (early_exit && wp_chain->len > 0) {
        /* Exception on first insn of new BB - mark previous BB */
        WPBBEntry *last = &g_array_index(wp_chain, WPBBEntry,
                                          wp_chain->len - 1);
        last->exception = true;
    }

    /* Stop wrong-path collection */
    wp_in_progress = false;

    /* Exit speculative mode */
    qemu_plugin_spec_mode_end();

    /* Restore CPU state */
    qemu_plugin_cpu_state_restore(saved_state);
    qemu_plugin_cpu_state_free(saved_state);

    /* Clean up */
    g_array_unref(wp_mem_accesses);
    wp_mem_accesses = NULL;
    g_byte_array_unref(insn_buf);

    /* Free remaining byte arrays */
    for (guint j = 0; j < bb_insn_bytes->len; j++) {
        g_free(g_array_index(bb_insn_bytes, uint8_t *, j));
    }
    g_array_unref(bb_insn_pcs);
    g_array_unref(bb_insn_sizes);
    g_array_unref(bb_insn_bytes);

    /* Update statistics */
    stat_wp_simulations++;
    stat_wp_total_insns += sim_insns;
    if (early_exit) {
        stat_wp_early_exits++;
    }

    return wp_chain;
}

/* ========================= Output: Text Format ========================= */

/*
 * Write the header section (BB templates) in human-readable text format.
 */
static void write_text_header(FILE *f)
{
    if (!f) {
        return;
    }
    GHashTableIter iter;
    gpointer value;

    fprintf(f, "HEADER\n------\n");

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        fprintf(f, "BB%" PRIu32 " [pc=0x%" PRIx64 ", insns=%" PRIu32
                ", fall_through=0x%" PRIx64 "]\n",
                tmpl->template_id, tmpl->start_pc,
                tmpl->n_insns, tmpl->fall_through_pc);

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            fprintf(f, "  [%u] 0x%" PRIx64 ": ", i, tmpl->insn_pcs[i]);
            if (tmpl->insn_bytes && tmpl->insn_bytes[i]) {
                for (uint32_t b = 0; b < tmpl->insn_sizes[i]; b++) {
                    fprintf(f, "%02x", tmpl->insn_bytes[i][b]);
                }
            }
            fprintf(f, " (%u bytes)", tmpl->insn_sizes[i]);
            if (tmpl->insn_fields) {
                X86InsnFields *fld = &tmpl->insn_fields[i];
                if (fld->opcode_len > 0) {
                    fprintf(f, " [");
                    if (fld->n_prefixes > 0) {
                        fprintf(f, "%u pfx ", fld->n_prefixes);
                    }
                    fprintf(f, "op=");
                    for (uint8_t o = 0; o < fld->opcode_len; o++) {
                        fprintf(f, "%02X", fld->opcode[o]);
                    }
                    if (fld->has_modrm) {
                        fprintf(f, " modrm=0x%02x", fld->modrm);
                    }
                    if (fld->has_sib) {
                        fprintf(f, " sib=0x%02x", fld->sib);
                    }
                    if (fld->disp_size > 0) {
                        fprintf(f, " disp=%d", fld->disp);
                    }
                    if (fld->imm_size > 0) {
                        fprintf(f, " imm=%" PRId64, fld->imm);
                    }
                    fprintf(f, "]");
                }
            }
            fprintf(f, "\n");
        }
        fprintf(f, "\n");
    }
}

/*
 * Write the body section (execution trace) in human-readable text format.
 */
static void write_text_body(FILE *f, GArray *body_entries)
{
    if (!f) {
        return;
    }
    fprintf(f, "BODY\n----\n");

    for (guint i = 0; i < body_entries->len; i++) {
        BodyEntry *entry = &g_array_index(body_entries, BodyEntry, i);

        fprintf(f, "%04u BB%" PRIu32 " [",
                entry->seq_num, entry->template_id);

        /* Write dynamic parameters */
        for (guint d = 0; d < entry->dyn_params->len; d++) {
            DynParam *dp = &g_array_index(entry->dyn_params, DynParam, d);
            if (d > 0) {
                fprintf(f, " ");
            }
            switch (dp->type) {
            case DYN_BRANCH_TARGET:
                fprintf(f, "target=0x%" PRIx64, dp->value);
                break;
            case DYN_LOAD_ADDR:
                fprintf(f, "load=0x%" PRIx64, dp->value);
                break;
            case DYN_STORE_ADDR:
                fprintf(f, "store=0x%" PRIx64, dp->value);
                break;
            }
        }
        fprintf(f, "]");

        /* Write wrong-path BB chain */
        if (entry->wp_entries) {
            for (guint w = 0; w < entry->wp_entries->len; w++) {
                WPBBEntry *wp = &g_array_index(entry->wp_entries,
                                               WPBBEntry, w);
                if (wp->template_id != UINT32_MAX) {
                    fprintf(f, " [wp%u=BB%" PRIu32, w, wp->template_id);
                } else {
                    fprintf(f, " [wp%u=0x%" PRIx64, w, wp->start_pc);
                }

                /* WP dynamic params */
                for (guint d = 0; d < wp->dyn_params->len; d++) {
                    DynParam *dp = &g_array_index(wp->dyn_params,
                                                  DynParam, d);
                    switch (dp->type) {
                    case DYN_BRANCH_TARGET:
                        fprintf(f, " target=0x%" PRIx64, dp->value);
                        break;
                    case DYN_LOAD_ADDR:
                        fprintf(f, " load=0x%" PRIx64, dp->value);
                        break;
                    case DYN_STORE_ADDR:
                        fprintf(f, " store=0x%" PRIx64, dp->value);
                        break;
                    }
                }
                if (wp->exception) {
                    fprintf(f, " EXCEPTION");
                }
                fprintf(f, " n_insns=%" PRIu32, wp->n_insns_executed);
                fprintf(f, "]");
            }
        }
        fprintf(f, "\n");
    }
}

/*
 * Write a complete trace in text format (header + body).
 */
static void write_text_trace(FILE *f, GArray *body_entries)
{
    g_mutex_lock(&data_lock);
    write_text_header(f);
    g_mutex_unlock(&data_lock);
    write_text_body(f, body_entries);
}

/* ========================= Output: Binary Format ========================= */

/*
 * Helper to write packed little-endian values.
 */
static void write_uleb128(FILE *f, uint64_t v)
{
    if (!f) {
        return;
    }
    do {
        uint8_t byte = v & 0x7F;
        v >>= 7;
        if (v != 0) {
            byte |= 0x80;
        }
        fwrite(&byte, 1, 1, f);
    } while (v != 0);
}

static inline void write_u8(FILE *f, uint8_t v)
{
    if (!f) {
        return;
    }
    fwrite(&v, 1, 1, f);
}

static inline void write_u16(FILE *f, uint16_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[2] = { v & 0xFF, (v >> 8) & 0xFF };
    fwrite(buf, 1, 2, f);
}

static inline void write_u32(FILE *f, uint32_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[4] = {
        v & 0xFF, (v >> 8) & 0xFF,
        (v >> 16) & 0xFF, (v >> 24) & 0xFF
    };
    fwrite(buf, 1, 4, f);
}

static inline void write_u64(FILE *f, uint64_t v)
{
    if (!f) {
        return;
    }
    uint8_t buf[8] = {
        v & 0xFF, (v >> 8) & 0xFF,
        (v >> 16) & 0xFF, (v >> 24) & 0xFF,
        (v >> 32) & 0xFF, (v >> 40) & 0xFF,
        (v >> 48) & 0xFF, (v >> 56) & 0xFF,
    };
    fwrite(buf, 1, 8, f);
}

/*
 * Write the header section in packed binary format (v2 ULEB128).
 *
 * Binary header layout:
 *   magic:            uint32 (WPT_MAGIC v2)
 *   num_templates:    ULEB128
 *   For each template:
 *     template_id:      ULEB128
 *     start_pc:         uint64
 *     num_insns:        ULEB128
 *     fall_through_pc:  uint64
 *     For each instruction:
 *       pc:             uint64
 *       size:           ULEB128
 *       bytes:          [size bytes]
 *       has_fields:     uint8 (1 if decoded fields, 0 otherwise)
 *       If has_fields:
 *         n_prefixes:   uint8
 *         opcode_len:   uint8
 *         opcode:       [opcode_len bytes]
 *         modrm:        uint8 (0xFF if no modrm)
 *         sib:          uint8 (0xFF if no sib)
 *         disp_size:    uint8
 *         disp:         [disp_size bytes, little-endian]
 *         imm_size:     uint8
 *         imm:          [imm_size bytes, little-endian]
 */
static void write_bin_header(FILE *f)
{
    if (!f) {
        return;
    }
    GHashTableIter iter;
    gpointer value;

    write_u32(f, WPT_MAGIC);
    write_uleb128(f, g_hash_table_size(template_map));

    g_hash_table_iter_init(&iter, template_map);
    while (g_hash_table_iter_next(&iter, NULL, &value)) {
        BBTemplate *tmpl = value;
        write_uleb128(f, tmpl->template_id);
        write_u64(f, tmpl->start_pc);
        write_uleb128(f, tmpl->n_insns);
        write_u64(f, tmpl->fall_through_pc);

        for (uint32_t i = 0; i < tmpl->n_insns; i++) {
            write_u64(f, tmpl->insn_pcs[i]);
            uint32_t sz = tmpl->insn_sizes[i];
            write_uleb128(f, sz);
            if (tmpl->insn_bytes && tmpl->insn_bytes[i]) {
                fwrite(tmpl->insn_bytes[i], 1, sz, f);
            }

            /* Write decoded instruction fields */
            if (tmpl->insn_fields && tmpl->insn_fields[i].opcode_len > 0) {
                X86InsnFields *fld = &tmpl->insn_fields[i];
                write_u8(f, 1); /* has_fields */
                write_u8(f, fld->n_prefixes);
                write_u8(f, fld->opcode_len);
                fwrite(fld->opcode, 1, fld->opcode_len, f);
                write_u8(f, fld->has_modrm ? fld->modrm : 0xFF);
                write_u8(f, fld->has_sib ? fld->sib : 0xFF);
                write_u8(f, fld->disp_size);
                if (fld->disp_size > 0) {
                    /* Write displacement as little-endian */
                    int32_t d = fld->disp;
                    for (uint8_t b = 0; b < fld->disp_size; b++) {
                        uint8_t byte = (d >> (b * 8)) & 0xFF;
                        fwrite(&byte, 1, 1, f);
                    }
                }
                write_u8(f, fld->imm_size);
                if (fld->imm_size > 0) {
                    /* Write immediate as little-endian */
                    int64_t imm = fld->imm;
                    for (uint8_t b = 0; b < fld->imm_size; b++) {
                        uint8_t byte = (imm >> (b * 8)) & 0xFF;
                        fwrite(&byte, 1, 1, f);
                    }
                }
            } else {
                write_u8(f, 0); /* no fields */
            }
        }
    }
}

/*
 * Write the body section in packed binary format (v2 ULEB128).
 *
 * Binary body layout:
 *   num_entries:      ULEB128
 *   For each entry:
 *     template_id:      ULEB128  (seq_num implicit from position)
 *     num_dyn:          ULEB128
 *     For each dyn_param:
 *       type:           uint8
 *       value:          uint64
 *     num_wp:           ULEB128
 *     For each wp_bb:
 *       template_id:    ULEB128
 *       start_pc:       uint64
 *       num_dyn:        ULEB128
 *       n_insns_executed: ULEB128
 *       exception:      uint8
 *       For each dyn_param:
 *         type:         uint8
 *         value:        uint64
 */
static void write_bin_body(FILE *f, GArray *body_entries)
{
    if (!f) {
        return;
    }
    write_uleb128(f, body_entries->len);

    for (guint i = 0; i < body_entries->len; i++) {
        BodyEntry *entry = &g_array_index(body_entries, BodyEntry, i);

        write_uleb128(f, entry->template_id);
        write_uleb128(f, entry->dyn_params->len);

        for (guint d = 0; d < entry->dyn_params->len; d++) {
            DynParam *dp = &g_array_index(entry->dyn_params, DynParam, d);
            write_u8(f, dp->type);
            write_u64(f, dp->value);
        }

        uint32_t num_wp = entry->wp_entries ? entry->wp_entries->len : 0;
        write_uleb128(f, num_wp);

        for (uint32_t w = 0; w < num_wp; w++) {
            WPBBEntry *wp = &g_array_index(entry->wp_entries, WPBBEntry, w);
            write_uleb128(f, wp->template_id);
            write_u64(f, wp->start_pc);
            write_uleb128(f, wp->dyn_params->len);
            write_uleb128(f, wp->n_insns_executed);
            write_u8(f, wp->exception ? 1 : 0);

            for (guint d = 0; d < wp->dyn_params->len; d++) {
                DynParam *dp = &g_array_index(wp->dyn_params, DynParam, d);
                write_u8(f, dp->type);
                write_u64(f, dp->value);
            }
        }
    }
}

/*
 * Write a complete trace in binary format (header + body).
 */
static void write_bin_trace(FILE *f, GArray *body_entries)
{
    g_mutex_lock(&data_lock);
    write_bin_header(f);
    g_mutex_unlock(&data_lock);
    write_bin_body(f, body_entries);
}

/* ========================= Trace State Management ========================= */

/*
 * Start a new trace segment with the given label and instruction range.
 */
static void start_trace_segment(const char *label,
                                uint64_t start, uint64_t stop)
{
    if (current_segment) {
        trace_segment_free(current_segment);
    }

    current_segment = trace_segment_new(label, start, stop);
    body_seq_num = 0;

    /* Determine output file paths based on mode */
    g_autofree char *bin_path = NULL;
    g_autofree char *txt_path = NULL;

    if (output_base_path) {
        bin_path = g_strdup_printf("%s.bin", output_base_path);
        if (enable_debug_text) {
            txt_path = g_strdup_printf("%s.txt", output_base_path);
        }
    }

    if (bin_path) {
        current_segment->bin_file = fopen(bin_path, "wb");
        if (!current_segment->bin_file) {
            fprintf(stderr, "wptrace: cannot open binary output: %s\n",
                    bin_path);
        }
    }

    if (txt_path) {
        current_segment->text_file = fopen(txt_path, "w");
        if (!current_segment->text_file) {
            fprintf(stderr, "wptrace: cannot open text output: %s\n",
                    txt_path);
        }
    }

    trace_active = true;
}

/*
 * Finalize and write the current trace segment.
 */
static void finish_trace_segment(void)
{
    if (!current_segment) {
        return;
    }

    trace_active = false;

    /* Write outputs */
    if (current_segment->bin_file) {
        write_bin_trace(current_segment->bin_file,
                        current_segment->body_entries);
    }
    if (current_segment->text_file) {
        write_text_trace(current_segment->text_file,
                         current_segment->body_entries);
    }

    trace_segment_free(current_segment);
    current_segment = NULL;
}

/* ========================= Execution Callback ========================= */

/*
 * Called at the start of each basic block on the correct path.
 */
static void vcpu_tb_exec(unsigned int cpu_index, void *udata)
{
    uint64_t current_pc = qemu_plugin_u64_get(sb_current_pc, cpu_index);
    uint64_t prev_last = qemu_plugin_u64_get(sb_prev_last_pc, cpu_index);
    uint64_t prev_ft = qemu_plugin_u64_get(sb_prev_fall_through, cpu_index);
    uint64_t icount = qemu_plugin_u64_get(sb_insn_count, cpu_index);

    /* Don't trigger inside wrong-path execution */
    if (wp_in_progress) {
        return;
    }

    /* --- Tracing window management --- */
    if (!trace_active && icount >= trace_start_insn &&
        icount < trace_stop_insn) {
        start_trace_segment("trace", trace_start_insn, trace_stop_insn);
    }
    if (trace_active && icount >= trace_stop_insn) {
        finish_trace_segment();
        exit(0);
    }

    /* Skip initial block (no previous context) */
    if (prev_ft == 0) {
        return;
    }

    bool branch_taken = (current_pc != prev_ft);

    g_mutex_lock(&data_lock);

    stat_branches_observed++;
    if (branch_taken) {
        stat_branches_taken++;
    } else {
        stat_branches_not_taken++;
    }

    /* Find or create branch record */
    BranchRecord *br = g_hash_table_lookup(branch_map, &prev_last);
    if (!br) {
        br = g_new0(BranchRecord, 1);
        br->pc = prev_last;
        br->fall_through = prev_ft;
        br->smith_counter = 1;
        g_hash_table_replace(branch_map, &br->pc, br);
    }

    if (branch_taken) {
        br->taken_target = current_pc;
        br->has_taken_target = true;
    }

    br->smith_counter = smith_update(br->smith_counter, branch_taken);

    /* Determine wrong-path target */
    uint64_t wrong_target = 0;
    if (branch_taken) {
        wrong_target = prev_ft;
    } else if (br->has_taken_target) {
        wrong_target = br->taken_target;
    }

    /* Find template for correct-path BB */
    BBTemplate *cp_tmpl = find_template(current_pc);

    g_mutex_unlock(&data_lock);

    /* --- Collect body entry if tracing is active --- */
    if (trace_active && current_segment) {
        BodyEntry entry;
        entry.seq_num = ++body_seq_num;
        entry.template_id = cp_tmpl ? cp_tmpl->template_id : 0;
        entry.dyn_params = g_array_new(false, false, sizeof(DynParam));
        entry.wp_entries = NULL;

        /* Add branch target dynamic param if branch was taken */
        if (branch_taken) {
            DynParam dp = {
                .type = DYN_BRANCH_TARGET,
                .value = current_pc,
            };
            g_array_append_val(entry.dyn_params, dp);
        }

        /* Collect correct-path memory accesses */
        if (cp_mem_accesses) {
            for (guint m = 0; m < cp_mem_accesses->len; m++) {
                WPMemAccess *acc = &g_array_index(cp_mem_accesses,
                                                  WPMemAccess, m);
                DynParam dp = {
                    .type = acc->is_store ? DYN_STORE_ADDR : DYN_LOAD_ADDR,
                    .value = acc->mem_vaddr,
                };
                g_array_append_val(entry.dyn_params, dp);
            }
            g_array_set_size(cp_mem_accesses, 0);
        }

        /* Run wrong-path execution if enabled and target is known */
        if (enable_wrong_path && wrong_target != 0) {
            entry.wp_entries = simulate_wrong_path_ext(
                prev_last, current_pc, wrong_target, cpu_index);
        } else if (wrong_target == 0) {
            stat_wp_skipped++;
        }

        g_array_append_val(current_segment->body_entries, entry);
    } else {
        /* Clear any accumulated memory accesses when not tracing */
        if (cp_mem_accesses) {
            g_array_set_size(cp_mem_accesses, 0);
        }
    }
}

/* ========================= Translation Callback ========================= */

/*
 * Called when a basic block is translated.
 * Creates BB templates with instruction bytes and instruments the block.
 */
static void vcpu_tb_trans(qemu_plugin_id_t id, struct qemu_plugin_tb *tb)
{
    uint64_t pc = qemu_plugin_tb_vaddr(tb);
    size_t n_insns = qemu_plugin_tb_n_insns(tb);
    struct qemu_plugin_insn *first_insn = qemu_plugin_tb_get_insn(tb, 0);
    struct qemu_plugin_insn *last_insn = qemu_plugin_tb_get_insn(tb,
                                                                  n_insns - 1);
    uint64_t last_insn_pc = qemu_plugin_insn_vaddr(last_insn);
    size_t last_insn_size = qemu_plugin_insn_size(last_insn);
    uint64_t fall_through = last_insn_pc + last_insn_size;

    /* Collect instruction data for BB template */
    uint64_t *insn_pcs = g_new0(uint64_t, n_insns);
    uint32_t *insn_sizes = g_new0(uint32_t, n_insns);
    uint8_t **insn_bytes_arr = g_new0(uint8_t *, n_insns);

    for (size_t i = 0; i < n_insns; i++) {
        struct qemu_plugin_insn *insn = qemu_plugin_tb_get_insn(tb, i);
        insn_pcs[i] = qemu_plugin_insn_vaddr(insn);
        insn_sizes[i] = (uint32_t)qemu_plugin_insn_size(insn);

        /* Capture instruction bytes */
        insn_bytes_arr[i] = g_new0(uint8_t, insn_sizes[i]);
        qemu_plugin_insn_data(insn, insn_bytes_arr[i], insn_sizes[i]);

        /* Register per-instruction memory callback with PC as udata */
        qemu_plugin_register_vcpu_mem_cb(
            insn, vcpu_mem_cb, QEMU_PLUGIN_CB_NO_REGS,
            QEMU_PLUGIN_MEM_RW, (void *)(uintptr_t)insn_pcs[i]);
    }

    /* Create or update BB template */
    g_mutex_lock(&data_lock);
    get_or_create_template(pc, (uint32_t)n_insns, insn_pcs, insn_sizes,
                           insn_bytes_arr, fall_through);
    g_mutex_unlock(&data_lock);

    /* Free temporary arrays (template made copies) */
    for (size_t i = 0; i < n_insns; i++) {
        g_free(insn_bytes_arr[i]);
    }
    g_free(insn_pcs);
    g_free(insn_sizes);
    g_free(insn_bytes_arr);

    /*
     * Instrument the block for execution tracking.
     * Step 1: Store current block's start PC into scoreboard.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_STORE_U64, sb_current_pc, pc);

    /*
     * Step 2: Add instruction count for this block.
     */
    qemu_plugin_register_vcpu_tb_exec_inline_per_vcpu(
        tb, QEMU_PLUGIN_INLINE_ADD_U64, sb_insn_count, n_insns);

    /*
     * Step 3: Register execution callback.
     */
    qemu_plugin_register_vcpu_tb_exec_cb(
        tb, vcpu_tb_exec, QEMU_PLUGIN_CB_RW_REGS, NULL);

    /*
     * Step 4: Update prev_* values for the NEXT block's callback.
     */
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_last_pc, last_insn_pc);
    qemu_plugin_register_vcpu_insn_exec_inline_per_vcpu(
        first_insn, QEMU_PLUGIN_INLINE_STORE_U64,
        sb_prev_fall_through, fall_through);
}

/* ========================= Flush Callback ========================= */

/*
 * Called when the TB cache is flushed.
 *
 * During wrong-path execution, tb_gen_code() may trigger tb_flush() when
 * the code buffer is full. This causes cpu_loop_exit() → longjmp back to
 * the outer cpu_exec_setjmp() handler, bypassing simulate_wrong_path_ext()'s
 * cleanup code. The QEMU core recovers spec_mode via cpu_exec_longjmp_cleanup(),
 * but the plugin's wp_in_progress flag and wp_mem_accesses array are left
 * in a stale state. Reset them here so subsequent vcpu_tb_exec() callbacks
 * are not permanently suppressed.
 */
static void vcpu_tb_flush(qemu_plugin_id_t id)
{
    if (wp_in_progress) {
        wp_in_progress = false;
        if (wp_mem_accesses) {
            g_array_unref(wp_mem_accesses);
            wp_mem_accesses = NULL;
        }
    }
}

/* ========================= Exit / Statistics ========================= */

static void plugin_exit(qemu_plugin_id_t id, void *p)
{
    /* Finish any active trace segment */
    if (trace_active) {
        finish_trace_segment();
    }

    /* Print statistics */
    g_autoptr(GString) report = g_string_new("");

    g_mutex_lock(&data_lock);

    g_string_append_printf(report,
        "\n=== Wrong-Path Trace Plugin Statistics ===\n");
    g_string_append_printf(report,
        "Target architecture: %s\n", target_name ? target_name : "unknown");
    g_string_append_printf(report,
        "Max wrong-path depth: %d instructions\n", max_wrong_path_depth);
    g_string_append_printf(report,
        "BB templates created: %u\n", g_hash_table_size(template_map));

    g_string_append_printf(report,
        "\nCorrect-path:\n");
    g_string_append_printf(report,
        "  Basic blocks translated: %" PRIu64 "\n", stat_blocks_translated);
    g_string_append_printf(report,
        "  Branch transitions observed: %" PRIu64 "\n",
        stat_branches_observed);
    g_string_append_printf(report,
        "    Taken: %" PRIu64 "\n", stat_branches_taken);
    g_string_append_printf(report,
        "    Not-taken: %" PRIu64 "\n", stat_branches_not_taken);
    g_string_append_printf(report,
        "  Unique branch PCs (Smith predictor entries): %u\n",
        g_hash_table_size(branch_map));

    g_string_append_printf(report,
        "\nWrong-path execution:\n");
    g_string_append_printf(report,
        "  Simulations performed: %" PRIu64 "\n", stat_wp_simulations);
    g_string_append_printf(report,
        "  Simulations skipped (unknown target): %" PRIu64 "\n",
        stat_wp_skipped);
    g_string_append_printf(report,
        "  Total wrong-path instructions executed: %" PRIu64 "\n",
        stat_wp_total_insns);
    g_string_append_printf(report,
        "  Total wrong-path data accesses: %" PRIu64 "\n",
        stat_wp_total_mem_accesses);
    g_string_append_printf(report,
        "  Early exits (execution fault): %" PRIu64 "\n",
        stat_wp_early_exits);

    if (stat_wp_simulations > 0) {
        g_string_append_printf(report,
            "  Average wrong-path length: %.1f instructions\n",
            (double)stat_wp_total_insns / stat_wp_simulations);
    }

    g_string_append_printf(report,
        "==========================================\n");

    g_mutex_unlock(&data_lock);

    qemu_plugin_outs(report->str);

    /* Cleanup */
    if (cp_mem_accesses) {
        g_array_unref(cp_mem_accesses);
    }
    g_hash_table_unref(template_map);
    g_hash_table_unref(branch_map);
    qemu_plugin_scoreboard_free(vcpu_sb);
    g_free(output_base_path);
    g_free(program_name);
}

/* ========================= Plugin Installation ========================= */

QEMU_PLUGIN_EXPORT
int qemu_plugin_install(qemu_plugin_id_t id, const qemu_info_t *info,
                        int argc, char **argv)
{
    target_name = info->target_name;
    is_x86 = (g_str_has_prefix(target_name, "x86_64") ||
              g_str_has_prefix(target_name, "i386"));

    /* Parse arguments */
    for (int i = 0; i < argc; i++) {
        char *opt = argv[i];
        g_auto(GStrv) tokens = g_strsplit(opt, "=", 2);

        if (g_strcmp0(tokens[0], "depth") == 0) {
            max_wrong_path_depth = atoi(tokens[1]);
            if (max_wrong_path_depth <= 0) {
                fprintf(stderr, "wptrace: invalid depth: %s\n", tokens[1]);
                return -1;
            }
        } else if (g_strcmp0(tokens[0], "outfile") == 0) {
            output_base_path = g_strdup(tokens[1]);
        } else if (g_strcmp0(tokens[0], "debug") == 0) {
            enable_debug_text = (atoi(tokens[1]) != 0);
        } else if (g_strcmp0(tokens[0], "wp") == 0) {
            enable_wrong_path = (atoi(tokens[1]) != 0);
        } else if (g_strcmp0(tokens[0], "start") == 0) {
            trace_start_insn = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "stop") == 0) {
            trace_stop_insn = g_ascii_strtoull(tokens[1], NULL, 10);
        } else if (g_strcmp0(tokens[0], "program") == 0) {
            program_name = g_strdup(tokens[1]);
        } else {
            fprintf(stderr, "wptrace: unknown option: %s\n", opt);
            return -1;
        }
    }

    /* Validate configuration */
    if (!output_base_path) {
        /* Default output base path */
        output_base_path = g_strdup("wptrace_out");
    }

    /* Initialize data structures */
    g_mutex_init(&data_lock);
    template_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                         NULL, bb_template_free);
    branch_map = g_hash_table_new_full(g_int64_hash, g_int64_equal,
                                       NULL, g_free);

    /* Initialize per-vCPU scoreboard */
    vcpu_sb = qemu_plugin_scoreboard_new(sizeof(VCPUScoreBoard));
    sb_current_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, current_pc);
    sb_prev_last_pc = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_last_pc);
    sb_prev_fall_through = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, prev_fall_through);
    sb_insn_count = qemu_plugin_scoreboard_u64_in_struct(
        vcpu_sb, VCPUScoreBoard, insn_count);

    /* Initialize correct-path memory access collection */
    cp_mem_accesses = g_array_new(false, false, sizeof(WPMemAccess));

    /* For simple start/stop, auto-start if start is 0 */
    if (trace_start_insn == 0) {
        start_trace_segment("trace", 0, trace_stop_insn);
    }

    /* Register callbacks */
    qemu_plugin_register_vcpu_tb_trans_cb(id, vcpu_tb_trans);
    qemu_plugin_register_flush_cb(id, vcpu_tb_flush);
    qemu_plugin_register_atexit_cb(id, plugin_exit, NULL);

    return 0;
}
