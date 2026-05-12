/*
 * Minimal POSIX-ustar archive writer (impl).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "champsim_tracer_tar.h"

#include <errno.h>
#include <string.h>
#include <sys/stat.h>

/* The 512-byte ustar header (POSIX.1-1988 / IEEE 1003.1-1988).
 * Field offsets are fixed; widths cover the historical ustar
 * conventions.  We only use the regular-file subset. */
struct UstarHeader {
    char name[100];
    char mode[8];
    char uid[8];
    char gid[8];
    char size[12];
    char mtime[12];
    char checksum[8];   /* initialised to spaces, set after layout */
    char typeflag;      /* '0' = regular file */
    char linkname[100];
    char magic[6];      /* "ustar\0" */
    char version[2];    /* "00" (POSIX), not "\0\0" (pre-POSIX) */
    char uname[32];
    char gname[32];
    char devmajor[8];
    char devminor[8];
    char prefix[155];
    char padding[12];
};
static_assert(sizeof(UstarHeader) == 512,
              "ustar header must be exactly 512 bytes");

/* Right-justified zero-padded octal into a fixed-width field, with a
 * trailing NUL.  ustar canonical formatting; @field_len includes
 * room for the NUL. */
static void write_octal(char *field, size_t field_len, uint64_t value)
{
    size_t digits = field_len - 1;
    for (size_t i = digits; i-- > 0; ) {
        field[i] = '0' + (char)(value & 7);
        value >>= 3;
    }
    field[field_len - 1] = '\0';
}

static void write_string(char *field, size_t field_len, const char *s)
{
    size_t n = strlen(s);
    if (n > field_len) {
        n = field_len;
    }
    memcpy(field, s, n);
    if (n < field_len) {
        field[n] = '\0';
    }
}

static void compute_checksum(UstarHeader *h)
{
    /* ustar checksum is the simple sum of all header bytes, with the
     * checksum field itself treated as eight spaces during the sum.
     * The 6-octal-digits + space + NUL formatting matches the
     * reference implementations. */
    memset(h->checksum, ' ', sizeof(h->checksum));
    uint32_t sum = 0;
    const unsigned char *p = (const unsigned char *)h;
    for (size_t i = 0; i < sizeof(*h); i++) {
        sum += p[i];
    }
    for (int i = 5; i >= 0; i--) {
        h->checksum[i] = '0' + (char)(sum & 7);
        sum >>= 3;
    }
    h->checksum[6] = '\0';
    h->checksum[7] = ' ';
}

static bool append_member(FILE *out, const char *src_path, const char *member_name)
{
    struct stat st;
    if (stat(src_path, &st) != 0) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: stat(%s): %s\n",
                src_path, strerror(errno));
        return false;
    }
    UstarHeader h;
    memset(&h, 0, sizeof(h));
    write_string(h.name, sizeof(h.name), member_name);
    write_octal(h.mode,  sizeof(h.mode),  0644);
    write_octal(h.uid,   sizeof(h.uid),   0);
    write_octal(h.gid,   sizeof(h.gid),   0);
    write_octal(h.size,  sizeof(h.size),  (uint64_t)st.st_size);
    write_octal(h.mtime, sizeof(h.mtime), (uint64_t)st.st_mtime);
    h.typeflag = '0';  /* regular file */
    memcpy(h.magic,   "ustar", 5);  /* trailing NUL already zeroed */
    memcpy(h.version, "00", 2);
    compute_checksum(&h);

    if (fwrite(&h, sizeof(h), 1, out) != 1) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: header write failed: %s\n",
                strerror(errno));
        return false;
    }

    FILE *in = fopen(src_path, "rb");
    if (!in) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: open(%s): %s\n",
                src_path, strerror(errno));
        return false;
    }
    uint8_t buf[16 * 1024];
    uint64_t bytes_left = (uint64_t)st.st_size;
    while (bytes_left > 0) {
        size_t want = bytes_left > sizeof(buf) ? sizeof(buf) : (size_t)bytes_left;
        size_t got = fread(buf, 1, want, in);
        if (got == 0) {
            fprintf(stderr,
                    "champsim_tracer: cst_tar: short read on %s: %s\n",
                    src_path, ferror(in) ? strerror(errno) : "(eof)");
            fclose(in);
            return false;
        }
        if (fwrite(buf, 1, got, out) != got) {
            fprintf(stderr,
                    "champsim_tracer: cst_tar: write failed: %s\n",
                    strerror(errno));
            fclose(in);
            return false;
        }
        bytes_left -= got;
    }
    fclose(in);

    /* Pad the member's data to a 512-byte boundary. */
    size_t tail = (size_t)((uint64_t)st.st_size % 512);
    if (tail) {
        uint8_t pad[512] = {0};
        size_t pad_n = 512 - tail;
        if (fwrite(pad, 1, pad_n, out) != pad_n) {
            fprintf(stderr,
                    "champsim_tracer: cst_tar: pad write failed: %s\n",
                    strerror(errno));
            return false;
        }
    }
    return true;
}

bool cst_tar_pack(const char *out_path,
                  const char *body_src_path,   const char *body_member_name,
                  const char *header_src_path, const char *header_member_name)
{
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: open(%s): %s\n",
                out_path, strerror(errno));
        return false;
    }
    /* Members in writer-natural order: body first (it's what streams
     * during execution; its size determines the tar's bulk), header
     * second (small, written after the segment finishes).  Readers
     * walk both regardless of order, but matching the writer keeps
     * any future streaming-tar work simpler. */
    if (!append_member(out, body_src_path, body_member_name)) {
        fclose(out);
        return false;
    }
    if (!append_member(out, header_src_path, header_member_name)) {
        fclose(out);
        return false;
    }
    /* End-of-archive: two consecutive 512-byte zero blocks. */
    uint8_t zero_block[512] = {0};
    if (fwrite(zero_block, 1, sizeof(zero_block), out) != sizeof(zero_block) ||
        fwrite(zero_block, 1, sizeof(zero_block), out) != sizeof(zero_block)) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: trailer write failed: %s\n",
                strerror(errno));
        fclose(out);
        return false;
    }
    if (fclose(out) != 0) {
        fprintf(stderr,
                "champsim_tracer: cst_tar: close(%s): %s\n",
                out_path, strerror(errno));
        return false;
    }
    return true;
}
