#ifndef CHAMPSIM_TRACER_ELF_ATTRS_H
#define CHAMPSIM_TRACER_ELF_ATTRS_H

/*
 * Generic ELF inspection helpers for the per-ISA cap_mode_*()
 * resolvers.  Surfaces:
 *
 *   1. ELF header summary (e_machine, e_flags, EI_CLASS) — for ISAs
 *      whose decoder mode is determined by ELF flags (MIPS).
 *
 *   2. A build-attributes section walker (SHT_RISCV_ATTRIBUTES /
 *      SHT_ARM_ATTRIBUTES, both = SHT_LOPROC + 3) — for ISAs decided
 *      by Tag_<vendor>_<name> strings (RISC-V).
 *
 * All constants come from <elf.h>; nothing is hard-coded here.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "elf.h"
#include <fcntl.h>
#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/* ELF header summary populated by cs_elf_load(). */
typedef struct {
    bool        valid;       /* true iff the file was a usable ELF */
    bool        is64;        /* EI_CLASS == ELFCLASS64 */
    uint16_t    e_machine;   /* EM_*                                  */
    uint32_t    e_flags;     /* arch-specific e_flags (MIPS / RISC-V) */
    /* Mapping kept open for the lifetime of the parse so the caller may
     * also walk an attributes section in-place.  Released by
     * cs_elf_unload(). */
    void       *_map;
    size_t      _size;
} CsElfInfo;

static inline void cs_elf_unload(CsElfInfo *info)
{
    if (info && info->_map) {
        munmap(info->_map, info->_size);
        info->_map = NULL;
        info->_size = 0;
        info->valid = false;
    }
}

static inline bool cs_elf_load(const char *path, CsElfInfo *out)
{
    memset(out, 0, sizeof(*out));
    if (!path) {
        return false;
    }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < (off_t)sizeof(Elf64_Ehdr)) {
        close(fd);
        return false;
    }
    size_t fsize = (size_t)st.st_size;

    void *map = mmap(NULL, fsize, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map == MAP_FAILED) {
        return false;
    }

    const uint8_t *base = (const uint8_t *)map;
    if (fsize < EI_NIDENT
            || base[EI_MAG0] != ELFMAG0
            || base[EI_MAG1] != ELFMAG1
            || base[EI_MAG2] != ELFMAG2
            || base[EI_MAG3] != ELFMAG3) {
        munmap(map, fsize);
        return false;
    }

    out->_map = map;
    out->_size = fsize;
    out->is64 = (base[EI_CLASS] == ELFCLASS64);

    if (out->is64) {
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
        out->e_machine = eh->e_machine;
        out->e_flags = eh->e_flags;
    } else {
        const Elf32_Ehdr *eh = (const Elf32_Ehdr *)base;
        out->e_machine = eh->e_machine;
        out->e_flags = eh->e_flags;
    }
    out->valid = true;
    return true;
}

/*
 * Locate a section by sh_type (e.g. SHT_RISCV_ATTRIBUTES).  Returns
 * true and fills *body / *body_size on success.
 */
static inline bool cs_elf_find_section(const CsElfInfo *info, uint32_t sh_type,
                                       const uint8_t **body, size_t *body_size)
{
    if (!info || !info->valid) {
        return false;
    }
    const uint8_t *base = (const uint8_t *)info->_map;
    uint64_t shoff;
    uint16_t shentsize, shnum;
    if (info->is64) {
        const Elf64_Ehdr *eh = (const Elf64_Ehdr *)base;
        shoff = eh->e_shoff;
        shentsize = eh->e_shentsize;
        shnum = eh->e_shnum;
    } else {
        const Elf32_Ehdr *eh = (const Elf32_Ehdr *)base;
        shoff = eh->e_shoff;
        shentsize = eh->e_shentsize;
        shnum = eh->e_shnum;
    }
    if (!shoff || !shnum) {
        return false;
    }

    for (uint16_t i = 0; i < shnum; i++) {
        uint64_t entry = shoff + (uint64_t)i * shentsize;
        if (entry + shentsize > info->_size) {
            break;
        }
        uint32_t st;
        uint64_t off, size;
        if (info->is64) {
            const Elf64_Shdr *sh = (const Elf64_Shdr *)(base + entry);
            st = sh->sh_type;
            off = sh->sh_offset;
            size = sh->sh_size;
        } else {
            const Elf32_Shdr *sh = (const Elf32_Shdr *)(base + entry);
            st = sh->sh_type;
            off = sh->sh_offset;
            size = sh->sh_size;
        }
        if (st == sh_type && off + size <= info->_size) {
            *body = base + off;
            *body_size = (size_t)size;
            return true;
        }
    }
    return false;
}

/* Decode one ULEB128 value from *p, advancing *p.  Returns false at EOF. */
static inline bool cs_uleb128(const uint8_t **p, const uint8_t *end,
                              uint64_t *out)
{
    uint64_t val = 0;
    unsigned int shift = 0;
    while (*p < end) {
        uint8_t b = *(*p)++;
        val |= ((uint64_t)(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) {
            *out = val;
            return true;
        }
        shift += 7;
        if (shift >= 64) {
            return false;
        }
    }
    return false;
}

/*
 * Walk a build-attribute section (RISC-V psABI / ARM EABI format).
 * For each Tag_File-scope tag/value pair in a subsection whose vendor
 * matches `want_vendor`, call cb(tag, value_ptr, is_string, user):
 * is_string -> value_ptr is a NUL-terminated string, else a uint64_t*.
 *
 * Convention (both psABI and EABI): even tags carry ULEB128 values,
 * odd tags carry strings.  Tag 32 (Tag_compatibility) is a documented
 * exception treated as a string.
 */
typedef void (*CsAttrTagCb)(uint64_t tag, const void *value, bool is_string,
                            void *user);

static inline void cs_elf_walk_attributes(const uint8_t *body, size_t size,
                                          const char *want_vendor,
                                          CsAttrTagCb cb, void *user)
{
    if (!body || size < 1 || *body != ELF_BUILD_ATTRIBUTES_VERSION_A) {
        return;
    }

    const uint8_t *p = body + 1;
    const uint8_t *end = body + size;

    while (p + 4 <= end) {
        uint32_t sub_len;
        memcpy(&sub_len, p, 4);
        if (sub_len < 4 || (size_t)(end - p) < sub_len) {
            break;
        }
        const uint8_t *sub_end = p + sub_len;
        const uint8_t *q = p + 4;

        const uint8_t *vendor = q;
        while (q < sub_end && *q) {
            q++;
        }
        if (q >= sub_end) {
            p = sub_end;
            continue;
        }
        bool match = (strcmp((const char *)vendor, want_vendor) == 0);
        q++;  /* skip vendor NUL */

        while (q < sub_end) {
            if (q + 5 > sub_end) {
                break;
            }
            uint8_t scope = *q++;
            uint32_t section_len;
            memcpy(&section_len, q, 4);
            q += 4;
            const uint8_t *scope_start = q - 5;
            if (section_len < 5
                    || (size_t)(sub_end - scope_start) < section_len) {
                break;
            }
            const uint8_t *sec_end = scope_start + section_len;

            if (scope == Tag_File && match) {
                while (q < sec_end) {
                    uint64_t tag;
                    if (!cs_uleb128(&q, sec_end, &tag)) {
                        break;
                    }
                    bool is_string = (tag == 32) || ((tag & 1) != 0);
                    if (is_string) {
                        const char *s = (const char *)q;
                        const uint8_t *e = q;
                        while (e < sec_end && *e) {
                            e++;
                        }
                        if (e >= sec_end) {
                            break;
                        }
                        cb(tag, s, true, user);
                        q = e + 1;
                    } else {
                        uint64_t v;
                        if (!cs_uleb128(&q, sec_end, &v)) {
                            break;
                        }
                        cb(tag, &v, false, user);
                    }
                }
            }
            q = sec_end;
        }
        p = sub_end;
    }
}

#endif /* CHAMPSIM_TRACER_ELF_ATTRS_H */
