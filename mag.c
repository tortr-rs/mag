/* mag: the package manager, one C file on c.h. it installs prebuilt packages from apk repos, and builds
 * CRUX ports: the repos are listed in /etc/mag/repos, their keys are in /etc/mag/keys. it does its own gzip,
 * tar, rsa and ed25519, so all it needs from the system is a download command, and bash for ports */
#if defined(__x86_64__) && !defined(LIBC)
#include "c.h"
#else
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#endif

#define VERSION "0.3"

static const char *prog = "mag";
static const char *root = "";                   /* MAG_ROOT without the trailing slash, "" is / */
static const char *arch;
static int dry, force;

static void say(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    fprintf(stderr, "%s: ", prog);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
}
static __attribute__((noreturn)) void die(const char *fmt, ...)
{
    va_list ap;
    fflush(stdout);
    fprintf(stderr, "%s: ", prog);
    va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

static void *xmalloc(size_t n) { void *p = malloc(n ? n : 1); if (!p) die("out of memory"); return p; }
static void *xrealloc(void *p, size_t n) { p = realloc(p, n ? n : 1); if (!p) die("out of memory"); return p; }
static char *xstrdup(const char *s) { return strcpy(xmalloc(strlen(s) + 1), s); }
static char *xstrndup(const char *s, size_t n) { char *d = strndup(s, n); if (!d) die("out of memory"); return d; }

static char *fmt(const char *f, ...)
{
    char buf[8192];
    va_list ap;
    va_start(ap, f); vsnprintf(buf, sizeof buf, f, ap); va_end(ap);
    return xstrdup(buf);
}

struct list { char **v; int n, cap; };

static void push(struct list *l, char *s)
{
    if (l->n == l->cap) { l->cap = l->cap ? l->cap * 2 : 16; l->v = xrealloc(l->v, l->cap * sizeof *l->v); }
    l->v[l->n++] = s;
}
static int has(const struct list *l, const char *s)
{
    int i;
    for (i = 0; i < l->n; i++) if (!strcmp(l->v[i], s)) return 1;
    return 0;
}
static void list_free(struct list *l)
{
    int i;
    for (i = 0; i < l->n; i++) free(l->v[i]);
    free(l->v);
    memset(l, 0, sizeof *l);
}
static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* the words of s, split on spaces */
static struct list words(const char *s)
{
    struct list l = { 0 };
    while (s && *s) {
        size_t n;
        while (*s == ' ' || *s == '\t' || *s == '\n') s++;
        n = strcspn(s, " \t\n");
        if (n) push(&l, xstrndup(s, n));
        s += n;
    }
    return l;
}

static char *slurp(const char *path, size_t *len)
{
    int fd = open(path, O_RDONLY);
    size_t n = 0, cap = 4096;
    char *b;
    ssize_t r;
    if (fd < 0) return NULL;
    b = xmalloc(cap);
    while ((r = read(fd, b + n, cap - n - 1)) > 0) {
        n += r;
        if (n + 1 >= cap) { cap *= 2; b = xrealloc(b, cap); }
    }
    close(fd);
    b[n] = 0;
    if (len) *len = n;
    return b;
}

static int mkpath(const char *path, mode_t mode)
{
    char *p = xstrdup(path), *s;
    for (s = p + 1; *s; s++) {
        if (*s != '/') continue;
        *s = 0;
        mkdir(p, mode);
        *s = '/';
    }
    if (mkdir(p, mode) < 0 && errno != EEXIST) { free(p); return -1; }
    free(p);
    return 0;
}

static void mkparent(const char *path)
{
    char *d = xstrdup(path), *s = strrchr(d, '/');
    if (s && s != d) { *s = 0; mkpath(d, 0755); }
    free(d);
}

static int exists(const char *p) { struct stat st; return lstat(p, &st) == 0; }

static int wait_for(pid_t pid)
{
    int st;
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return (st & 0x7f) ? 128 + (st & 0x7f) : (st >> 8) & 255;
}

static int run(char *const argv[])
{
    pid_t pid;
    fflush(stdout);
    pid = fork();
    if (pid < 0) die("cannot fork");
    if (!pid) {
        execvp(argv[0], argv);
        fprintf(stderr, "%s: %s: %s\n", prog, argv[0], strerror(errno));
        _exit(127);
    }
    return wait_for(pid);
}

static void rmtree(const char *path)
{
    char *av[] = { "rm", "-rf", (char *)path, NULL };
    run(av);
}

/* ---- sha1 and sha256 ---- */

static const unsigned k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(unsigned *h, const unsigned char *p)
{
    unsigned w[64], v[8];
    int i;
    for (i = 0; i < 16; i++) w[i] = (unsigned)p[i * 4] << 24 | p[i * 4 + 1] << 16 | p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (i = 16; i < 64; i++) {
        unsigned s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3), s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, h, sizeof v);
    for (i = 0; i < 64; i++) {
        unsigned t1 = v[7] + (ROR(v[4], 6) ^ ROR(v[4], 11) ^ ROR(v[4], 25)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k256[i] + w[i];
        unsigned t2 = (ROR(v[0], 2) ^ ROR(v[0], 13) ^ ROR(v[0], 22)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1; v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++) h[i] += v[i];
}

static void sha1_block(unsigned *h, const unsigned char *p)
{
    unsigned w[80], a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], t;
    int i;
    for (i = 0; i < 16; i++) w[i] = (unsigned)p[i * 4] << 24 | p[i * 4 + 1] << 16 | p[i * 4 + 2] << 8 | p[i * 4 + 3];
    for (; i < 80; i++) { t = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]; w[i] = t << 1 | t >> 31; }
    for (i = 0; i < 80; i++) {
        unsigned f, k;
        if (i < 20) f = (b & c) | (~b & d), k = 0x5a827999;
        else if (i < 40) f = b ^ c ^ d, k = 0x6ed9eba1;
        else if (i < 60) f = (b & c) | (b & d) | (c & d), k = 0x8f1bbcdc;
        else f = b ^ c ^ d, k = 0xca62c1d6;
        t = (a << 5 | a >> 27) + f + e + k + w[i];
        e = d; d = c; c = b << 30 | b >> 2; b = a; a = t;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
}

struct hash { unsigned h[8]; unsigned char b[64]; uint64_t len; int sha1; };

static void hash_init(struct hash *s, int sha1)
{
    static const unsigned i1[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    static const unsigned i2[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    memset(s, 0, sizeof *s);
    s->sha1 = sha1;
    memcpy(s->h, sha1 ? i1 : i2, sha1 ? sizeof i1 : sizeof i2);
}

static void hash_add(struct hash *s, const void *data, size_t n)
{
    const unsigned char *p = data;
    size_t used = s->len % 64;
    s->len += n;
    if (used) {
        size_t k = 64 - used < n ? 64 - used : n;
        memcpy(s->b + used, p, k);
        p += k; n -= k;
        if (used + k < 64) return;
        if (s->sha1) sha1_block(s->h, s->b); else sha256_block(s->h, s->b);
    }
    for (; n >= 64; p += 64, n -= 64) if (s->sha1) sha1_block(s->h, p); else sha256_block(s->h, p);
    memcpy(s->b, p, n);
}

/* the digest into out, returns its length */
static int hash_end(struct hash *s, unsigned char *out)
{
    uint64_t bits = s->len * 8;
    unsigned char c = 0x80;
    int i, w = s->sha1 ? 5 : 8;
    hash_add(s, &c, 1);
    c = 0;
    while (s->len % 64 != 56) hash_add(s, &c, 1);
    for (i = 7; i >= 0; i--) { c = bits >> (i * 8); hash_add(s, &c, 1); }
    for (i = 0; i < w * 4; i++) out[i] = s->h[i / 4] >> (24 - 8 * (i % 4));
    return w * 4;
}

static char *hex(const unsigned char *d, int n)
{
    char *s = xmalloc(n * 2 + 1);
    int i;
    for (i = 0; i < n; i++) sprintf(s + i * 2, "%02x", d[i]);
    return s;
}

/* bytes from..to of a file through a hash, to = -1 for the end */
static int hash_range(int fd, off_t from, off_t to, int sha1, unsigned char *out)
{
    struct hash h;
    unsigned char buf[65536];
    ssize_t n;
    hash_init(&h, sha1);
    lseek(fd, from, SEEK_SET);
    while (to < 0 || from < to) {
        size_t want = sizeof buf;
        if (to >= 0 && (off_t)want > to - from) want = to - from;
        if ((n = read(fd, buf, want)) <= 0) break;
        hash_add(&h, buf, n);
        from += n;
    }
    return hash_end(&h, out);
}

static char *sha256_file(const char *path)
{
    unsigned char d[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    hash_range(fd, 0, -1, 0, d);
    close(fd);
    return hex(d, 32);
}

static size_t unbase64(const char *s, unsigned char *out)
{
    static const char a[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t n = 0;
    unsigned v = 0;
    int bits = 0;
    for (; *s && *s != '='; s++) {
        const char *p = strchr(a, *s);
        if (!p) continue;
        v = v << 6 | (p - a);
        bits += 6;
        if (bits >= 8) { bits -= 8; out[n++] = v >> bits; }
    }
    return n;
}

/* ---- gzip ---- */

struct in { int fd; unsigned char buf[65536]; size_t pos, len; off_t off; };

static void in_open(struct in *r, int fd, off_t at) { r->fd = fd; r->pos = r->len = 0; r->off = at; lseek(fd, at, SEEK_SET); }
static off_t in_tell(const struct in *r) { return r->off + r->pos; }
static int in_byte(struct in *r)
{
    if (r->pos == r->len) {
        ssize_t n;
        r->off += r->len;
        r->pos = 0;
        n = read(r->fd, r->buf, sizeof r->buf);
        r->len = n > 0 ? n : 0;
        if (!r->len) return -1;
    }
    return r->buf[r->pos++];
}
static int in_eof(struct in *r) { if (in_byte(r) < 0) return 1; r->pos--; return 0; }

typedef void outfn(void *, const unsigned char *, size_t);

struct huff { unsigned short count[16], sym[320]; };

struct inf {
    struct in *in;
    unsigned bitbuf;
    int bitcnt, bad;
    unsigned char win[32768];
    unsigned wpos;
    outfn *out;
    void *ctx;
};

static unsigned getbits(struct inf *s, int n)
{
    unsigned v;
    while (s->bitcnt < n) {
        int c = in_byte(s->in);
        if (c < 0) { s->bad = 1; c = 0; }
        s->bitbuf |= (unsigned)c << s->bitcnt;
        s->bitcnt += 8;
    }
    v = s->bitbuf & ((1u << n) - 1);
    s->bitbuf >>= n;
    s->bitcnt -= n;
    return v;
}

static void put(struct inf *s, unsigned char c)
{
    s->win[s->wpos++] = c;
    if (s->wpos == sizeof s->win) { s->out(s->ctx, s->win, s->wpos); s->wpos = 0; }
}

static void huff_build(struct huff *h, const unsigned char *len, int n)
{
    unsigned short offs[16];
    int i, sum = 0;
    memset(h->count, 0, sizeof h->count);
    for (i = 0; i < n; i++) h->count[len[i]]++;
    h->count[0] = 0;
    for (i = 0; i < 16; i++) { offs[i] = sum; sum += h->count[i]; }
    for (i = 0; i < n; i++) if (len[i]) h->sym[offs[len[i]]++] = i;
}

static int huff_dec(struct inf *s, const struct huff *h)
{
    int code = 0, first = 0, index = 0, l;
    for (l = 1; l < 16; l++) {
        int c = h->count[l];
        code |= getbits(s, 1);
        if (code - c < first) return h->sym[index + code - first];
        index += c;
        first = (first + c) << 1;
        code <<= 1;
    }
    s->bad = 1;
    return 256;
}

static const unsigned short lbase[29] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258 };
static const unsigned char lext[29] = { 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0 };
static const unsigned short dbase[30] = { 1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073,
    4097, 6145, 8193, 12289, 16385, 24577 };
static const unsigned char dext[30] = { 0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13 };

static void codes(struct inf *s, const struct huff *lh, const struct huff *dh)
{
    while (!s->bad) {
        int sym = huff_dec(s, lh), d;
        unsigned len, dist;
        if (sym < 256) { put(s, sym); continue; }
        if (sym == 256) return;
        sym -= 257;
        if (sym >= 29) { s->bad = 1; return; }
        len = lbase[sym] + getbits(s, lext[sym]);
        d = huff_dec(s, dh);
        if (d >= 30) { s->bad = 1; return; }
        dist = dbase[d] + getbits(s, dext[d]);
        while (len--) put(s, s->win[(s->wpos - dist) & 32767]);
    }
}

static void dynamic(struct inf *s)
{
    static const unsigned char ord[19] = { 16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15 };
    unsigned char len[320];
    struct huff lh, dh;
    int nl = getbits(s, 5) + 257, nd = getbits(s, 5) + 1, nc = getbits(s, 4) + 4, i;
    memset(len, 0, sizeof len);
    for (i = 0; i < nc; i++) len[ord[i]] = getbits(s, 3);
    huff_build(&lh, len, 19);
    for (i = 0; i < nl + nd && !s->bad; ) {
        int sym = huff_dec(s, &lh), rep, v = 0;
        if (sym < 16) { len[i++] = sym; continue; }
        if (sym == 16) { if (!i) { s->bad = 1; return; } v = len[i - 1]; rep = 3 + getbits(s, 2); }
        else if (sym == 17) rep = 3 + getbits(s, 3);
        else rep = 11 + getbits(s, 7);
        if (i + rep > nl + nd) { s->bad = 1; return; }
        while (rep--) len[i++] = v;
    }
    huff_build(&lh, len, nl);
    huff_build(&dh, len + nl, nd);
    codes(s, &lh, &dh);
}

/* one gzip member from r, its bytes go to out. the crc is not checked: what gets unpacked was hashed first */
static int gunzip(struct in *r, outfn *out, void *ctx)
{
    static struct huff fixl, fixd;
    static int ready;
    struct inf *s;
    int fl, last, i, bad;
    if (!ready) {
        unsigned char l[288];
        for (i = 0; i < 288; i++) l[i] = i < 144 ? 8 : i < 256 ? 9 : i < 280 ? 7 : 8;
        huff_build(&fixl, l, 288);
        for (i = 0; i < 30; i++) l[i] = 5;
        huff_build(&fixd, l, 30);
        ready = 1;
    }
    if (in_byte(r) != 0x1f || in_byte(r) != 0x8b || in_byte(r) != 8) return -1;
    fl = in_byte(r);
    for (i = 0; i < 6; i++) in_byte(r);
    if (fl & 4) { int n = in_byte(r); n |= in_byte(r) << 8; while (n-- > 0) in_byte(r); }
    if (fl & 8) while (in_byte(r) > 0) {}
    if (fl & 16) while (in_byte(r) > 0) {}
    if (fl & 2) { in_byte(r); in_byte(r); }
    s = xmalloc(sizeof *s);
    s->in = r; s->bitbuf = 0; s->bitcnt = 0; s->bad = 0; s->wpos = 0; s->out = out; s->ctx = ctx;
    do {
        int type;
        last = getbits(s, 1);
        type = getbits(s, 2);
        if (type == 0) {
            unsigned n;
            s->bitbuf = 0; s->bitcnt = 0;
            n = in_byte(r); n |= in_byte(r) << 8;
            in_byte(r); in_byte(r);
            while (n--) { int c = in_byte(r); if (c < 0) { s->bad = 1; break; } put(s, c); }
        } else if (type == 1) codes(s, &fixl, &fixd);
        else if (type == 2) dynamic(s);
        else s->bad = 1;
    } while (!last && !s->bad);
    if (s->wpos) out(ctx, s->win, s->wpos);
    for (i = 0; i < 8; i++) in_byte(r);
    bad = s->bad;
    free(s);
    return bad ? -1 : 0;
}

struct buf { unsigned char *p; size_t n, cap; };

static void buf_add(struct buf *b, const void *d, size_t n)
{
    if (b->n + n + 1 > b->cap) { b->cap = (b->n + n + 1) * 2; b->p = xrealloc(b->p, b->cap); }
    memcpy(b->p + b->n, d, n);
    b->n += n;
    b->p[b->n] = 0;
}

/* ---- tar, fed a piece at a time ---- */

struct ent { char *name; struct buf data; };

struct tar {
    unsigned char hdr[512];
    size_t hn;
    uint64_t left, pad;
    int what;                   /* where the bytes of this entry go: 0 nowhere, 1 a file, 2 meta, 3 an ent */
    int type, fd, bad;
    struct buf meta;
    char *path, *link;
    unsigned mode, uid, gid;
    const char *dir;            /* unpack here; NULL keeps the files in ents instead */
    struct ent *ents;
    int nents;
};

static uint64_t octal(const unsigned char *p, int n)
{
    uint64_t v = 0;
    if (*p & 0x80) { v = *p++ & 0x7f; while (--n) v = v << 8 | *p++; return v; }
    while (n && *p == ' ') p++, n--;
    for (; n && *p >= '0' && *p <= '7'; p++, n--) v = v * 8 + (*p - '0');
    return v;
}

/* a path from an archive that stays inside the directory: no .. and no leading / */
static char *clean(const char *name)
{
    struct list parts = { 0 };
    char *out;
    size_t len = 0;
    int i;
    while (*name) {
        size_t n = strcspn(name, "/");
        if (n && !(n == 1 && *name == '.')) {
            if (n == 2 && name[0] == '.' && name[1] == '.') { list_free(&parts); return NULL; }
            push(&parts, xstrndup(name, n));
            len += n + 1;
        }
        name += n;
        if (*name) name++;
    }
    if (!parts.n) return NULL;
    out = xmalloc(len + 1);
    *out = 0;
    for (i = 0; i < parts.n; i++) { if (i) strcat(out, "/"); strcat(out, parts.v[i]); }
    list_free(&parts);
    return out;
}

static void tar_done(struct tar *t)
{
    if (t->what == 2) {
        char *p = (char *)t->meta.p, *end = p + t->meta.n;
        if (t->type == 'L') { free(t->path); t->path = xstrdup(p); }
        else if (t->type == 'K') { free(t->link); t->link = xstrdup(p); }
        else while (p < end) {
            char *sp = strchr(p, ' '), *eq, *rec = p;
            long n = strtol(p, NULL, 10);
            if (!sp || n <= 0 || rec + n > end) break;
            eq = strchr(sp, '=');
            if (eq && eq < rec + n) {
                char *val = xstrndup(eq + 1, rec + n - eq - 2);
                if (eq - sp - 1 == 4 && !strncmp(sp + 1, "path", 4)) { free(t->path); t->path = val; }
                else if (eq - sp - 1 == 8 && !strncmp(sp + 1, "linkpath", 8)) { free(t->link); t->link = val; }
                else free(val);
            }
            p = rec + n;
        }
        t->meta.n = 0;
        t->what = 0;
        return;
    }
    if (t->what == 1) {
        if (!geteuid()) fchown(t->fd, t->uid, t->gid);
        fchmod(t->fd, t->mode & 07777);
        if (close(t->fd) < 0) t->bad = 1;
    }
    t->what = 0;
    free(t->path); t->path = NULL;
    free(t->link); t->link = NULL;
}

static void tar_entry(struct tar *t, const char *name, const char *ln)
{
    char *rel = clean(name), *full;
    int type = t->type, file = type == '0' || type == 0 || type == '7';
    t->what = 0;
    if (!rel) return;
    if (!t->dir) {
        if (file) {
            t->ents = xrealloc(t->ents, (t->nents + 1) * sizeof *t->ents);
            t->ents[t->nents].name = rel;
            memset(&t->ents[t->nents].data, 0, sizeof t->ents[t->nents].data);
            buf_add(&t->ents[t->nents].data, "", 0);
            t->nents++;
            t->what = 3;
        } else free(rel);
        return;
    }
    full = fmt("%s/%s", t->dir, rel);
    mkparent(full);
    if (type == '5') {
        mkpath(full, 0755);
        chmod(full, t->mode & 07777);
        if (!geteuid()) lchown(full, t->uid, t->gid);
    } else if (type == '2') {
        unlink(full);
        if (symlink(ln, full) < 0) t->bad = 1;
        else if (!geteuid()) lchown(full, t->uid, t->gid);
    } else if (type == '1') {
        char *l = clean(ln), *from = l ? fmt("%s/%s", t->dir, l) : NULL;
        unlink(full);
        if (!from || link(from, full) < 0) t->bad = 1;
        free(l); free(from);
    } else if (file) {
        unlink(full);
        t->fd = open(full, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (t->fd < 0) t->bad = 1; else t->what = 1;
    }
    free(full);
    free(rel);
}

static void tar_header(struct tar *t)
{
    unsigned char *h = t->hdr;
    char name[300], ln[101];
    uint64_t size;
    if (!h[0]) return;
    size = octal(h + 124, 12);
    t->type = h[156];
    t->mode = octal(h + 100, 8);
    t->uid = octal(h + 108, 8);
    t->gid = octal(h + 116, 8);
    name[0] = 0;
    if (!memcmp(h + 257, "ustar", 5) && h[345]) { memcpy(name, h + 345, 155); name[155] = 0; strcat(name, "/"); }
    { size_t l = strlen(name), k = 0; while (k < 100 && h[k]) { name[l + k] = h[k]; k++; } name[l + k] = 0; }
    memcpy(ln, h + 157, 100); ln[100] = 0;
    t->left = size;
    t->pad = (512 - size % 512) % 512;
    if (t->type == 'x' || t->type == 'L' || t->type == 'K') { t->what = 2; t->meta.n = 0; buf_add(&t->meta, "", 0); }
    else if (t->type == 'g') t->what = 0;
    else tar_entry(t, t->path ? t->path : name, t->link ? t->link : ln);
    if (!size) tar_done(t);
}

static void tar_out(void *ctx, const unsigned char *d, size_t n)
{
    struct tar *t = ctx;
    while (n) {
        size_t k;
        if (t->left) {
            k = t->left < n ? t->left : n;
            if (t->what == 1 && write(t->fd, d, k) != (ssize_t)k) t->bad = 1;
            else if (t->what == 2) buf_add(&t->meta, d, k);
            else if (t->what == 3) buf_add(&t->ents[t->nents - 1].data, d, k);
            t->left -= k; d += k; n -= k;
            if (!t->left) tar_done(t);
        } else if (t->pad) {
            k = t->pad < n ? t->pad : n;
            t->pad -= k; d += k; n -= k;
        } else {
            k = 512 - t->hn < n ? 512 - t->hn : n;
            memcpy(t->hdr + t->hn, d, k);
            t->hn += k; d += k; n -= k;
            if (t->hn == 512) { t->hn = 0; tar_header(t); }
        }
    }
}

static struct ent *tar_find(struct tar *t, const char *name)
{
    int i;
    for (i = 0; i < t->nents; i++) if (!strcmp(t->ents[i].name, name)) return &t->ents[i];
    return NULL;
}

static struct ent *tar_prefix(struct tar *t, const char *prefix)
{
    int i;
    for (i = 0; i < t->nents; i++) if (!strncmp(t->ents[i].name, prefix, strlen(prefix))) return &t->ents[i];
    return NULL;
}

static void tar_free(struct tar *t)
{
    int i;
    for (i = 0; i < t->nents; i++) { free(t->ents[i].name); free(t->ents[i].data.p); }
    free(t->ents); free(t->meta.p); free(t->path); free(t->link);
    memset(t, 0, sizeof *t);
}

/* ---- rsa, for the signatures ---- */

#define LIMBS 130               /* 4160 bits, room for a 4096 bit key */

static int big_less(const unsigned *a, const unsigned *b)
{
    int i;
    for (i = LIMBS; i >= 0; i--) if (a[i] != b[i]) return a[i] < b[i];
    return 0;
}

static void big_sub(unsigned *a, const unsigned *b)
{
    uint64_t borrow = 0;
    int i;
    for (i = 0; i <= LIMBS; i++) {
        uint64_t d = (uint64_t)a[i] - b[i] - borrow;
        a[i] = d;
        borrow = d >> 63;
    }
}

/* r = a * b mod n, all LIMBS + 1 long */
static void big_mulmod(unsigned *r, const unsigned *a, const unsigned *b, const unsigned *n)
{
    unsigned p[2 * LIMBS], m[LIMBS + 1];
    int i, j, top;
    memset(p, 0, sizeof p);
    for (i = 0; i < LIMBS; i++) {
        uint64_t c = 0;
        for (j = 0; j < LIMBS; j++) { c += (uint64_t)a[i] * b[j] + p[i + j]; p[i + j] = c; c >>= 32; }
        p[i + LIMBS] = c;
    }
    memset(m, 0, sizeof m);
    for (top = 2 * LIMBS * 32 - 1; top >= 0 && !(p[top / 32] >> (top % 32) & 1); top--) {}
    for (i = top; i >= 0; i--) {
        for (j = LIMBS; j > 0; j--) m[j] = m[j] << 1 | m[j - 1] >> 31;
        m[0] = m[0] << 1 | (p[i / 32] >> (i % 32) & 1);
        if (!big_less(m, n)) big_sub(m, n);
    }
    memcpy(r, m, sizeof m);
}

static int big_from(unsigned *v, const unsigned char *p, size_t n)
{
    size_t i;
    memset(v, 0, (LIMBS + 1) * 4);
    while (n && !*p) p++, n--;
    if (n > LIMBS * 4) return -1;
    for (i = 0; i < n; i++) v[i / 4] |= (unsigned)p[n - 1 - i] << (8 * (i % 4));
    return 0;
}

static int der(const unsigned char **p, const unsigned char *end, int tag, size_t *len)
{
    const unsigned char *q = *p;
    size_t n;
    if (q + 2 > end || *q++ != tag) return -1;
    n = *q++;
    if (n & 0x80) {
        int k = n & 0x7f;
        if (k > 4 || q + k > end) return -1;
        for (n = 0; k--; ) n = n << 8 | *q++;
    }
    if (q + n > end) return -1;
    *p = q;
    *len = n;
    return 0;
}

/* a pkcs#1 v1.5 signature over digest, checked with the public key in keyfile (pem) */
static int rsa_verify(const char *keyfile, const unsigned char *sig, size_t siglen, const unsigned char *digest, int sha1)
{
    static const unsigned char info1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    static const unsigned char info256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    const unsigned char *info = sha1 ? info1 : info256;
    size_t ilen = sha1 ? sizeof info1 : sizeof info256, dlen = sha1 ? 20 : 32, len, nlen, elen, k, i;
    unsigned n[LIMBS + 1], s[LIMBS + 1], r[LIMBS + 1], ev = 0;
    unsigned char derbuf[4096], em[LIMBS * 4];
    const unsigned char *p = derbuf, *end, *nb, *eb;
    char *pem = slurp(keyfile, NULL), *b, *e;
    int top, bit;
    if (!pem || !(b = strstr(pem, "KEY-----")) || !(e = strstr(b, "-----END")) || (size_t)(e - b) * 3 / 4 > sizeof derbuf) { free(pem); return -1; }
    *e = 0;
    end = derbuf + unbase64(b + 8, derbuf);
    free(pem);
    if (der(&p, end, 0x30, &len) || der(&p, end, 0x30, &len)) return -1;
    p += len;
    if (der(&p, end, 0x03, &len) || ++p > end || der(&p, end, 0x30, &len)) return -1;
    if (der(&p, end, 0x02, &nlen)) return -1;
    nb = p; p += nlen;
    if (der(&p, end, 0x02, &elen) || elen > 4) return -1;
    eb = p;
    while (nlen && !*nb) nb++, nlen--;
    k = nlen;
    if (siglen != k || big_from(n, nb, nlen) || big_from(s, sig, siglen) || !big_less(s, n)) return -1;
    for (i = 0; i < elen; i++) ev = ev << 8 | eb[i];
    for (top = 31; top > 0 && !(ev >> top & 1); top--) {}
    memcpy(r, s, sizeof r);
    for (bit = top - 1; bit >= 0; bit--) {
        big_mulmod(r, r, r, n);
        if (ev >> bit & 1) big_mulmod(r, r, s, n);
    }
    for (i = 0; i < k; i++) em[k - 1 - i] = r[i / 4] >> (8 * (i % 4));
    if (k < ilen + dlen + 11 || em[0] != 0 || em[1] != 1) return -1;
    for (i = 2; i < k - ilen - dlen - 1; i++) if (em[i] != 0xff) return -1;
    if (em[i++] != 0 || memcmp(em + i, info, ilen) || memcmp(em + i + ilen, digest, dlen)) return -1;
    return 0;
}

/* ---- sha512 and ed25519, for the signify signatures of port trees ---- */

static const uint64_t k512[80] = {
    0x428a2f98d728ae22ull, 0x7137449123ef65cdull, 0xb5c0fbcfec4d3b2full, 0xe9b5dba58189dbbcull, 0x3956c25bf348b538ull, 0x59f111f1b605d019ull,
    0x923f82a4af194f9bull, 0xab1c5ed5da6d8118ull, 0xd807aa98a3030242ull, 0x12835b0145706fbeull, 0x243185be4ee4b28cull, 0x550c7dc3d5ffb4e2ull,
    0x72be5d74f27b896full, 0x80deb1fe3b1696b1ull, 0x9bdc06a725c71235ull, 0xc19bf174cf692694ull, 0xe49b69c19ef14ad2ull, 0xefbe4786384f25e3ull,
    0x0fc19dc68b8cd5b5ull, 0x240ca1cc77ac9c65ull, 0x2de92c6f592b0275ull, 0x4a7484aa6ea6e483ull, 0x5cb0a9dcbd41fbd4ull, 0x76f988da831153b5ull,
    0x983e5152ee66dfabull, 0xa831c66d2db43210ull, 0xb00327c898fb213full, 0xbf597fc7beef0ee4ull, 0xc6e00bf33da88fc2ull, 0xd5a79147930aa725ull,
    0x06ca6351e003826full, 0x142929670a0e6e70ull, 0x27b70a8546d22ffcull, 0x2e1b21385c26c926ull, 0x4d2c6dfc5ac42aedull, 0x53380d139d95b3dfull,
    0x650a73548baf63deull, 0x766a0abb3c77b2a8ull, 0x81c2c92e47edaee6ull, 0x92722c851482353bull, 0xa2bfe8a14cf10364ull, 0xa81a664bbc423001ull,
    0xc24b8b70d0f89791ull, 0xc76c51a30654be30ull, 0xd192e819d6ef5218ull, 0xd69906245565a910ull, 0xf40e35855771202aull, 0x106aa07032bbd1b8ull,
    0x19a4c116b8d2d0c8ull, 0x1e376c085141ab53ull, 0x2748774cdf8eeb99ull, 0x34b0bcb5e19b48a8ull, 0x391c0cb3c5c95a63ull, 0x4ed8aa4ae3418acbull,
    0x5b9cca4f7763e373ull, 0x682e6ff3d6b2b8a3ull, 0x748f82ee5defb2fcull, 0x78a5636f43172f60ull, 0x84c87814a1f0ab72ull, 0x8cc702081a6439ecull,
    0x90befffa23631e28ull, 0xa4506cebde82bde9ull, 0xbef9a3f7b2c67915ull, 0xc67178f2e372532bull, 0xca273eceea26619cull, 0xd186b8c721c0c207ull,
    0xeada7dd6cde0eb1eull, 0xf57d4f7fee6ed178ull, 0x06f067aa72176fbaull, 0x0a637dc5a2c898a6ull, 0x113f9804bef90daeull, 0x1b710b35131c471bull,
    0x28db77f523047d84ull, 0x32caab7b40c72493ull, 0x3c9ebe0a15c9bebcull, 0x431d67c49c100d4cull, 0x4cc5d4becb3e42b6ull, 0x597f299cfc657e2aull,
    0x5fcb6fab3ad6faecull, 0x6c44198c4a475817ull };

#define ROR64(x, n) ((x) >> (n) | (x) << (64 - (n)))

static void sha512(const unsigned char *m, size_t n, unsigned char *out)
{
    static const uint64_t iv[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    size_t len = (n + 17 + 127) / 128 * 128, b;
    unsigned char *p = xmalloc(len);
    uint64_t h[8], w[80], v[8];
    int i, j;
    memset(p, 0, len);
    memcpy(p, m, n);
    p[n] = 0x80;
    for (j = 0; j < 8; j++) p[len - 1 - j] = (uint64_t)n * 8 >> (8 * j);
    memcpy(h, iv, sizeof h);
    for (b = 0; b < len; b += 128) {
        for (j = 0; j < 16; j++) for (w[j] = 0, i = 0; i < 8; i++) w[j] = w[j] << 8 | p[b + j * 8 + i];
        for (j = 16; j < 80; j++)
            w[j] = w[j - 16] + (ROR64(w[j - 15], 1) ^ ROR64(w[j - 15], 8) ^ w[j - 15] >> 7) + w[j - 7] + (ROR64(w[j - 2], 19) ^ ROR64(w[j - 2], 61) ^ w[j - 2] >> 6);
        memcpy(v, h, sizeof v);
        for (j = 0; j < 80; j++) {
            uint64_t t1 = v[7] + (ROR64(v[4], 14) ^ ROR64(v[4], 18) ^ ROR64(v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k512[j] + w[j];
            uint64_t t2 = (ROR64(v[0], 28) ^ ROR64(v[0], 34) ^ ROR64(v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
            memmove(v + 1, v, 7 * sizeof *v);
            v[4] += t1;
            v[0] = t1 + t2;
        }
        for (j = 0; j < 8; j++) h[j] += v[j];
    }
    for (j = 0; j < 64; j++) out[j] = h[j / 8] >> (56 - 8 * (j % 8));
    free(p);
}

/* the field and curve of ed25519 the way tweetnacl does them: 16 limbs of 16 bits */
typedef int64_t gf[16];

static const gf gf0, gf1 = { 1 },
    ed_d = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 },
    ed_d2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 },
    ed_x = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 },
    ed_y = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 },
    ed_i = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };

static void fe_copy(gf o, const gf a) { memcpy(o, a, sizeof(gf)); }

static void fe_carry(gf o)
{
    int i;
    for (i = 0; i < 16; i++) {
        int64_t c;
        o[i] += 1LL << 16;
        c = o[i] >> 16;
        o[(i + 1) * (i < 15)] += c - 1 + 37 * (c - 1) * (i == 15);
        o[i] -= c << 16;
    }
}

static void fe_sel(gf p, gf q, int b)
{
    int64_t t, c = ~(b - 1);
    int i;
    for (i = 0; i < 16; i++) { t = c & (p[i] ^ q[i]); p[i] ^= t; q[i] ^= t; }
}

static void fe_pack(unsigned char *o, const gf n)
{
    gf m, t;
    int i, j, b;
    fe_copy(t, n);
    fe_carry(t); fe_carry(t); fe_carry(t);
    for (j = 0; j < 2; j++) {
        m[0] = t[0] - 0xffed;
        for (i = 1; i < 15; i++) { m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1); m[i - 1] &= 0xffff; }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_sel(t, m, 1 - b);
    }
    for (i = 0; i < 16; i++) { o[2 * i] = t[i] & 0xff; o[2 * i + 1] = t[i] >> 8; }
}

static int fe_neq(const gf a, const gf b)
{
    unsigned char c[32], d[32];
    fe_pack(c, a); fe_pack(d, b);
    return memcmp(c, d, 32) != 0;
}

static int fe_par(const gf a) { unsigned char d[32]; fe_pack(d, a); return d[0] & 1; }

static void fe_unpack(gf o, const unsigned char *n)
{
    int i;
    for (i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
    o[15] &= 0x7fff;
}

static void fe_add(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void fe_sub(gf o, const gf a, const gf b) { int i; for (i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

static void fe_mul(gf o, const gf a, const gf b)
{
    int64_t t[31];
    int i, j;
    memset(t, 0, sizeof t);
    for (i = 0; i < 16; i++) for (j = 0; j < 16; j++) t[i + j] += a[i] * b[j];
    for (i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
    for (i = 0; i < 16; i++) o[i] = t[i];
    fe_carry(o); fe_carry(o);
}

static void fe_inv(gf o, const gf in)
{
    gf c;
    int a;
    fe_copy(c, in);
    for (a = 253; a >= 0; a--) { fe_mul(c, c, c); if (a != 2 && a != 4) fe_mul(c, c, in); }
    fe_copy(o, c);
}

static void fe_pow2523(gf o, const gf in)
{
    gf c;
    int a;
    fe_copy(c, in);
    for (a = 250; a >= 0; a--) { fe_mul(c, c, c); if (a != 1) fe_mul(c, c, in); }
    fe_copy(o, c);
}

static void pt_add(gf p[4], gf q[4])
{
    gf a, b, c, d, t, e, f, g, h;
    fe_sub(a, p[1], p[0]); fe_sub(t, q[1], q[0]); fe_mul(a, a, t);
    fe_add(b, p[0], p[1]); fe_add(t, q[0], q[1]); fe_mul(b, b, t);
    fe_mul(c, p[3], q[3]); fe_mul(c, c, ed_d2);
    fe_mul(d, p[2], q[2]); fe_add(d, d, d);
    fe_sub(e, b, a); fe_sub(f, d, c); fe_add(g, d, c); fe_add(h, b, a);
    fe_mul(p[0], e, f); fe_mul(p[1], h, g); fe_mul(p[2], g, f); fe_mul(p[3], e, h);
}

static void pt_mul(gf p[4], gf q[4], const unsigned char *s)
{
    int i, j;
    fe_copy(p[0], gf0); fe_copy(p[1], gf1); fe_copy(p[2], gf1); fe_copy(p[3], gf0);
    for (i = 255; i >= 0; i--) {
        int b = (s[i / 8] >> (i & 7)) & 1;
        for (j = 0; j < 4; j++) fe_sel(p[j], q[j], b);
        pt_add(q, p);
        pt_add(p, p);
        for (j = 0; j < 4; j++) fe_sel(p[j], q[j], b);
    }
}

static void pt_pack(unsigned char *r, gf p[4])
{
    gf tx, ty, zi;
    fe_inv(zi, p[2]);
    fe_mul(tx, p[0], zi);
    fe_mul(ty, p[1], zi);
    fe_pack(r, ty);
    r[31] ^= fe_par(tx) << 7;
}

static int pt_unpackneg(gf r[4], const unsigned char *p)
{
    gf t, chk, num, den, den2, den4, den6;
    fe_copy(r[2], gf1);
    fe_unpack(r[1], p);
    fe_mul(num, r[1], r[1]);
    fe_mul(den, num, ed_d);
    fe_sub(num, num, r[2]);
    fe_add(den, r[2], den);
    fe_mul(den2, den, den); fe_mul(den4, den2, den2); fe_mul(den6, den4, den2);
    fe_mul(t, den6, num); fe_mul(t, t, den);
    fe_pow2523(t, t);
    fe_mul(t, t, num); fe_mul(t, t, den); fe_mul(t, t, den); fe_mul(r[0], t, den);
    fe_mul(chk, r[0], r[0]); fe_mul(chk, chk, den);
    if (fe_neq(chk, num)) fe_mul(r[0], r[0], ed_i);
    fe_mul(chk, r[0], r[0]); fe_mul(chk, chk, den);
    if (fe_neq(chk, num)) return -1;
    if (fe_par(r[0]) == (p[31] >> 7)) fe_sub(r[0], gf0, r[0]);
    fe_mul(r[3], r[0], r[1]);
    return 0;
}

/* a 64 byte number mod the order of the curve */
static void mod_l(unsigned char *r)
{
    static const int64_t l[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };
    int64_t x[64], carry;
    int i, j;
    for (i = 0; i < 64; i++) x[i] = r[i];
    for (i = 63; i >= 32; i--) {
        carry = 0;
        for (j = i - 32; j < i - 12; j++) { x[j] += carry - 16 * x[i] * l[j - (i - 32)]; carry = (x[j] + 128) >> 8; x[j] -= carry * 256; }
        x[j] += carry;
        x[i] = 0;
    }
    carry = 0;
    for (j = 0; j < 32; j++) { x[j] += carry - (x[31] >> 4) * l[j]; carry = x[j] >> 8; x[j] &= 255; }
    for (j = 0; j < 32; j++) x[j] -= carry * l[j];
    for (i = 0; i < 32; i++) { x[i + 1] += x[i] >> 8; r[i] = x[i] & 255; }
}

static int ed25519_ok(const unsigned char *sig, const unsigned char *pk, const char *m, size_t n)
{
    gf p[4], q[4];
    unsigned char t[32], h[64], *b;
    if (pt_unpackneg(q, pk)) return 0;
    b = xmalloc(n + 64);
    memcpy(b, sig, 32);
    memcpy(b + 32, pk, 32);
    memcpy(b + 64, m, n);
    sha512(b, n + 64, h);
    free(b);
    mod_l(h);
    pt_mul(p, q, h);
    fe_copy(q[0], ed_x); fe_copy(q[1], ed_y); fe_copy(q[2], gf1); fe_mul(q[3], ed_x, ed_y);
    {
        gf r[4];
        pt_mul(r, q, sig + 32);
        pt_add(p, r);
    }
    pt_pack(t, p);
    return !memcmp(t, sig, 32);
}

/* ---- the repos ---- */

struct pkg { char *name, *ver, *desc, *csum, *deps, *prov, *size; int prio, repo; };
struct prov { char *key, *ver; struct pkg *p; };

static struct pkg *pkgs;
static int npkgs;
static struct prov *provs;
static int nprovs;
static struct list repo_urls;
static int *kinds;
enum { APK, CRUX };

static char *confdir(void)
{
    char *d = fmt("%s/etc/mag", root);
    if (*root && !exists(d)) { free(d); d = xstrdup("/etc/mag"); }
    return d;
}

static const char *machine(void)
{
    static const char *map[][2] = { { "i386", "x86" }, { "i486", "x86" }, { "i586", "x86" }, { "i686", "x86" }, { "armv7l", "armv7" },
        { "armv6l", "armhf" }, { NULL, NULL } };
    static struct utsname u;
    const char *e = getenv("MAG_ARCH");
    int i;
    char *d, *f, *t;
    if (e && *e) return e;
    d = confdir(); f = fmt("%s/arch", d); t = slurp(f, NULL);
    free(d); free(f);
    if (t && *t) { t[strcspn(t, " \n")] = 0; return t; }
    free(t);
    if (uname(&u) < 0) die("uname: %s", strerror(errno));
    for (i = 0; map[i][0]; i++) if (!strcmp(u.machine, map[i][0])) return map[i][1];
    return u.machine;
}

static void load_repos(void)
{
    char *d = confdir(), *f = fmt("%s/repos", d), *t = slurp(f, NULL), *line, *next;
    if (!t) die("%s is missing: it lists the repos, one url a line", f);
    for (line = t; line && *line; line = next) {
        char *s;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        while (*line == ' ' || *line == '\t') line++;
        for (s = line + strlen(line); s > line && (s[-1] == ' ' || s[-1] == '\t' || s[-1] == '\r' || s[-1] == '/'); ) *--s = 0;
        if (!*line || *line == '#') continue;
        kinds = xrealloc(kinds, (repo_urls.n + 1) * sizeof *kinds);
        kinds[repo_urls.n] = APK;
        if (!strncmp(line, "crux", 4) && (line[4] == ' ' || line[4] == '\t')) for (kinds[repo_urls.n] = CRUX, line += 4; *line == ' ' || *line == '\t'; line++) {}
        push(&repo_urls, xstrdup(line));
    }
    free(t); free(f); free(d);
}

static char *repo_base(int i) { return fmt("%s/%s", repo_urls.v[i], arch); }

static char *flat(int i)
{
    char *u = xstrdup(repo_urls.v[i]), *s;
    for (s = u; *s; s++) if (*s == '/' || *s == ':' || *s == '\'') *s = '_';
    return u;
}

static char *index_file(int i)
{
    char *u = flat(i), *f = fmt("%s/var/cache/mag/index/%s_%s.tar.gz", root, u, arch);
    free(u);
    return f;
}

static char *tree_dir(int i)
{
    char *u = flat(i), *f = fmt("%s/var/cache/mag/ports/%s", root, u);
    free(u);
    return f;
}

static const char *downloader(void)
{
    static const char *cmds[][2] = { { "curl", "curl -fsSL --retry 3 --retry-all-errors -o" }, { "wget", "wget -q -O" }, { "ftp", "ftp -o" } };
    const char *env = getenv("MAG_FETCH"), *pa = getenv("PATH");
    int i;
    if (env) return env;
    if (!access("/etc/ssl/cert.pem", R_OK)) cmds[0][1] = "curl -fsSL --retry 3 --retry-all-errors --cacert /etc/ssl/cert.pem --capath /etc/ssl -o";
    for (i = 0; i < 3; i++) {
        char *p = xstrdup(pa ? pa : "/usr/bin:/bin"), *d = p, *e;
        for (; d; d = e) {
            char *f;
            int ok;
            e = strchr(d, ':');
            if (e) *e++ = 0;
            f = fmt("%s/%s", d, cmds[i][0]);
            ok = !access(f, X_OK);
            free(f);
            if (ok) { free(p); return cmds[i][1]; }
        }
        free(p);
    }
    return "curl -fsSL --retry 3 --retry-all-errors -o";
}

static int download(const char *url, const char *file)
{
    char *part = fmt("%s.part", file);
    char *av[] = { "/bin/sh", "-c", "set -f; $0 \"$1\" \"$2\"", (char *)downloader(), part, (char *)url, NULL };
    int rc;
    mkparent(file);
    rc = run(av);
    if (!rc && rename(part, file) < 0) rc = 1;
    if (rc) unlink(part);
    free(part);
    return rc;
}

/* a signed file starts with a gzip member holding .SIGN.RSA.key or .SIGN.RSA256.key, over the rest of the file */
static int check_signed(const char *file)
{
    struct in *r = xmalloc(sizeof *r);
    struct tar t;
    struct ent *e;
    char *d, *key;
    unsigned char dig[32];
    int sha1, bad = -1, fd = open(file, O_RDONLY);
    off_t at;
    memset(&t, 0, sizeof t);
    if (fd < 0) goto out;
    in_open(r, fd, 0);
    if (gunzip(r, tar_out, &t)) goto out;
    at = in_tell(r);
    if ((e = tar_prefix(&t, ".SIGN.RSA256."))) { sha1 = 0; key = e->name + 13; }
    else if ((e = tar_prefix(&t, ".SIGN.RSA."))) { sha1 = 1; key = e->name + 10; }
    else { say("%s has no signature", file); goto out; }
    d = confdir();
    key = fmt("%s/keys/%s", d, key);
    free(d);
    if (!exists(key)) say("it is signed with %s, which is not there", key);
    else {
        hash_range(fd, at, -1, sha1, dig);
        if (!(bad = rsa_verify(key, e->data.p, e->data.n, dig, sha1) ? -1 : 0)) {}
        else say("the signature does not match %s", key);
    }
    free(key);
out:
    tar_free(&t);
    free(r);
    if (fd >= 0) close(fd);
    return bad;
}

static void add_prov(const char *tok, struct pkg *p)
{
    const char *eq = strchr(tok, '=');
    if (nprovs % 1024 == 0) provs = xrealloc(provs, (nprovs + 1024) * sizeof *provs);
    provs[nprovs].key = eq ? xstrndup(tok, eq - tok) : xstrdup(tok);
    provs[nprovs].ver = eq ? xstrdup(eq + 1) : NULL;
    provs[nprovs].p = p;
    nprovs++;
}

static int cmp_prov(const void *a, const void *b) { return strcmp(((const struct prov *)a)->key, ((const struct prov *)b)->key); }

static void parse_index(char *t, int repo)
{
    struct pkg p;
    char *line, *next;
    memset(&p, 0, sizeof p);
    for (line = t; line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!*line || !next) {
            if (p.name && p.ver) {
                if (npkgs % 1024 == 0) pkgs = xrealloc(pkgs, (npkgs + 1024) * sizeof *pkgs);
                p.repo = repo;
                pkgs[npkgs++] = p;
            }
            memset(&p, 0, sizeof p);
            continue;
        }
        if (line[1] != ':') continue;
        switch (line[0]) {
        case 'P': p.name = line + 2; break;
        case 'V': p.ver = line + 2; break;
        case 'T': p.desc = line + 2; break;
        case 'C': p.csum = line + 2; break;
        case 'D': p.deps = line + 2; break;
        case 'p': p.prov = line + 2; break;
        case 'S': p.size = line + 2; break;
        case 'k': p.prio = atoi(line + 2); break;
        }
    }
}

static void load_index(void)
{
    static int loaded;
    int i, j;
    if (loaded++) return;
    for (i = 0; i < repo_urls.n; i++) {
        char *f = index_file(i);
        int fd;
        if (kinds[i] != APK) {
            char *d = tree_dir(i), *x = fmt("%s/INDEX", d), *t = slurp(x, NULL);
            if (t) parse_index(t, i); else say("%s has no index yet, mag update gets it", repo_urls.v[i]);
            free(d); free(x); free(f);
            continue;
        }
        fd = open(f, O_RDONLY);
        struct in *r;
        struct tar t;
        struct ent *e;
        if (fd < 0) { say("%s has no index yet, mag update gets it", repo_urls.v[i]); free(f); continue; }
        r = xmalloc(sizeof *r);
        memset(&t, 0, sizeof t);
        in_open(r, fd, 0);
        if (gunzip(r, tar_out, &t)) die("%s is broken, mag update gets it again", f);
        tar_free(&t);
        if (gunzip(r, tar_out, &t) || !(e = tar_find(&t, "APKINDEX"))) die("%s is broken, mag update gets it again", f);
        parse_index((char *)e->data.p, i);
        e->data.p = NULL;
        tar_free(&t);
        free(r);
        close(fd);
        free(f);
    }
    for (i = 0; i < npkgs; i++) {
        struct list w = words(pkgs[i].prov);
        add_prov(pkgs[i].name, &pkgs[i]);
        provs[nprovs - 1].ver = pkgs[i].ver;
        for (j = 0; j < w.n; j++) add_prov(w.v[j], &pkgs[i]);
        list_free(&w);
    }
    if (nprovs) qsort(provs, nprovs, sizeof *provs, cmp_prov);
}

/* ---- versions and dependencies ---- */

static int sufrank(const char *s)
{
    static const char *w[] = { "alpha", "beta", "pre", "rc", "", "cvs", "svn", "git", "hg", "p" };
    int i;
    for (i = 0; i < 10; i++) {
        size_t n = strlen(w[i]);
        if (n && !strncmp(s, w[i], n) && !isalpha(s[n])) return i - 4;
    }
    return 0;
}

static int vclass(const char *s)
{
    if (!*s) return 0;
    if (*s == '_') return sufrank(s + 1) < 0 ? -1 : 2;
    if (*s == '-') return 1;
    if (*s == '.') return 4;
    if (isdigit(*s)) return 5;
    return 3;
}

/* apk's order: 1.2_rc1 < 1.2 < 1.2-r1 < 1.2_p1 < 1.2a < 1.2.1 */
static int vercmp(const char *a, const char *b)
{
    for (;;) {
        if (isdigit(*a) && isdigit(*b)) {
            const char *x, *y;
            int c;
            while (*a == '0' && isdigit(a[1])) a++;
            while (*b == '0' && isdigit(b[1])) b++;
            for (x = a; isdigit(*a); a++) {}
            for (y = b; isdigit(*b); b++) {}
            if (a - x != b - y) return a - x < b - y ? -1 : 1;
            c = strncmp(x, y, a - x);
            if (c) return c < 0 ? -1 : 1;
            continue;
        }
        if (*a == '_' && *b == '_') {
            int ra = sufrank(a + 1), rb = sufrank(b + 1);
            if (ra != rb) return ra < rb ? -1 : 1;
            for (a++; isalpha(*a); a++) {}
            for (b++; isalpha(*b); b++) {}
            continue;
        }
        if (*a == *b) { if (!*a) return 0; a++; b++; continue; }
        {
            int ca = vclass(a), cb = vclass(b);
            if (ca != cb) return ca < cb ? -1 : 1;
            return *a < *b ? -1 : 1;
        }
    }
}

struct dep { char key[256], ver[128]; int op, neg; };

enum { LESS = 1, EQUAL = 2, MORE = 4, FUZZY = 8 };

static void dep_parse(const char *tok, struct dep *d)
{
    size_t n;
    memset(d, 0, sizeof *d);
    if (*tok == '!') { d->neg = 1; tok++; }
    n = strcspn(tok, "<>=~");
    if (n >= sizeof d->key) n = sizeof d->key - 1;
    memcpy(d->key, tok, n);
    for (tok += n; *tok && strchr("<>=~", *tok); tok++)
        d->op |= *tok == '<' ? LESS : *tok == '>' ? MORE : *tok == '=' ? EQUAL : FUZZY;
    snprintf(d->ver, sizeof d->ver, "%s", tok);
}

static int dep_ok(const struct dep *d, const char *ver)
{
    int c;
    if (!d->op) return 1;
    if (!ver) return 0;
    if (d->op & FUZZY) return !strncmp(ver, d->ver, strlen(d->ver));
    c = vercmp(ver, d->ver);
    return (c < 0 && d->op & LESS) || (!c && d->op & EQUAL) || (c > 0 && d->op & MORE);
}

/* does name-ver, which also provides prov, meet d */
static int meets(const struct dep *d, const char *name, const char *ver, const char *prov)
{
    struct list w;
    int i, ok = 0;
    if (!strcmp(name, d->key)) return dep_ok(d, ver);
    w = words(prov);
    for (i = 0; i < w.n && !ok; i++) {
        char *eq = strchr(w.v[i], '=');
        if (eq) *eq++ = 0;
        ok = !strcmp(w.v[i], d->key) && dep_ok(d, eq);
    }
    list_free(&w);
    return ok;
}

static struct pkg *pick(const struct dep *d)
{
    struct pkg *best = NULL;
    int lo = 0, hi = nprovs, i;
    while (lo < hi) { int mid = (lo + hi) / 2; if (strcmp(provs[mid].key, d->key) < 0) lo = mid + 1; else hi = mid; }
    for (hi = lo; hi < nprovs && !strcmp(provs[hi].key, d->key); hi++) {}
    for (i = lo; i < hi; i++) {
        struct pkg *p = provs[i].p;
        int named, bnamed;
        if (!dep_ok(d, provs[i].ver)) continue;
        if (!best) { best = p; continue; }
        named = !strcmp(p->name, d->key); bnamed = !strcmp(best->name, d->key);
        if (named != bnamed) { if (named) best = p; continue; }
        if (p->prio != best->prio) { if (p->prio > best->prio) best = p; continue; }
        if (!strcmp(p->name, best->name) ? vercmp(p->ver, best->ver) > 0 : p->repo < best->repo) best = p;
    }
    return best;
}

/* packages to build from a port tree even when a repo has them built */
static struct list from_ports;

static struct pkg *port_of(const char *name)
{
    struct pkg *best = NULL;
    int i;
    for (i = 0; i < npkgs; i++)
        if (kinds[pkgs[i].repo] != APK && !strcmp(pkgs[i].name, name) && (!best || vercmp(pkgs[i].ver, best->ver) > 0)) best = &pkgs[i];
    return best;
}

static struct pkg *newest(const char *name)
{
    struct dep d;
    struct pkg *p;
    dep_parse(name, &d);
    if (has(&from_ports, d.key) && (p = port_of(d.key))) return p;
    p = pick(&d);
    return p && !strcmp(p->name, d.key) ? p : NULL;
}

/* ---- what is installed ---- */

static char *dbdir(const char *name) { return fmt("%s/var/lib/mag/%s", root, name); }

static char *db_get(const char *name, const char *what)
{
    char *d = dbdir(name), *f = fmt("%s/%s", d, what), *v = slurp(f, NULL), *s;
    free(d); free(f);
    if (v) for (s = v + strlen(v); s > v && (s[-1] == '\n' || s[-1] == ' '); ) *--s = 0;
    return v;
}

static int installed(const char *name) { char *v = db_get(name, "version"); free(v); return v != NULL; }

static struct list db_read(const char *name, const char *what)
{
    struct list l = { 0 };
    char *t = db_get(name, what), *line, *next;
    if (!t) return l;
    for (line = t; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (*line) push(&l, xstrdup(line));
    }
    free(t);
    return l;
}

static void db_put(const char *name, const char *what, const char *data, size_t n, mode_t mode)
{
    char *d = dbdir(name), *f = fmt("%s/%s", d, what);
    int fd;
    mkpath(d, 0755);
    unlink(f);
    fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0 || write(fd, data, n) != (ssize_t)n || close(fd) < 0) die("cannot write %s: %s", f, strerror(errno));
    free(d); free(f);
}

static void db_put_file(const char *f, const char *text)
{
    int fd = open(f, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    size_t n = strlen(text);
    if (fd < 0 || write(fd, text, n) != (ssize_t)n || write(fd, "\n", 1) != 1 || close(fd) < 0) die("cannot write %s: %s", f, strerror(errno));
}

static void db_write(const char *name, const char *what, const struct list *l)
{
    struct buf b = { 0 };
    int i;
    buf_add(&b, "", 0);
    for (i = 0; i < l->n; i++) { buf_add(&b, l->v[i], strlen(l->v[i])); buf_add(&b, "\n", 1); }
    db_put(name, what, (char *)b.p, b.n, 0644);
    free(b.p);
}

static struct list db_all(void)
{
    struct list l = { 0 };
    char *base = fmt("%s/var/lib/mag", root);
    DIR *d = opendir(base);
    struct dirent *e;
    if (d) {
        while ((e = readdir(d))) if (e->d_name[0] != '.') push(&l, xstrdup(e->d_name));
        closedir(d);
    }
    free(base);
    if (l.n) qsort(l.v, l.n, sizeof *l.v, cmp_str);
    return l;
}

struct inst { char *name, *ver, *prov; };
static struct inst *insts;
static int ninsts;

static void load_insts(void)
{
    static int done;
    struct list all;
    int i;
    if (done++) return;
    all = db_all();
    insts = xmalloc((all.n + 1) * sizeof *insts);
    for (i = 0; i < all.n; i++) {
        insts[i].name = all.v[i];
        insts[i].ver = db_get(all.v[i], "version");
        insts[i].prov = db_get(all.v[i], "provides");
    }
    ninsts = all.n;
}

/* the installed package that meets d, NULL if none */
static const char *installed_for(const struct dep *d)
{
    int i;
    load_insts();
    for (i = 0; i < ninsts; i++) if (insts[i].ver && meets(d, insts[i].name, insts[i].ver, insts[i].prov)) return insts[i].name;
    return NULL;
}

static struct list rdeps(const char *name)
{
    struct list all = db_all(), out = { 0 };
    int i;
    for (i = 0; i < all.n; i++) {
        struct list d = db_read(all.v[i], "deps");
        if (strcmp(all.v[i], name) && has(&d, name)) push(&out, all.v[i]);
        list_free(&d);
    }
    return out;
}

/* ---- putting files in place ---- */

static void walk(const char *base, const char *rel, struct list *files, struct list *dirs)
{
    char *dir = *rel ? fmt("%s/%s", base, rel) : xstrdup(base);
    DIR *d = opendir(dir);
    struct dirent *e;
    struct list names = { 0 };
    int i;
    if (!d) die("cannot read %s: %s", dir, strerror(errno));
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) push(&names, xstrdup(e->d_name));
    closedir(d);
    if (names.n) qsort(names.v, names.n, sizeof *names.v, cmp_str);
    for (i = 0; i < names.n; i++) {
        char *relp = *rel ? fmt("%s/%s", rel, names.v[i]) : xstrdup(names.v[i]), *full = fmt("%s/%s", base, relp);
        struct stat st;
        if (lstat(full, &st) < 0) die("cannot stat %s", full);
        if (S_ISDIR(st.st_mode)) { push(dirs, relp); walk(base, relp, files, dirs); }
        else push(files, relp);
        free(full);
    }
    list_free(&names);
    free(dir);
}

static int copy_into(const char *from, const char *to, const struct stat *st)
{
    int in = open(from, O_RDONLY), out;
    char buf[65536], *tmp = fmt("%s.mag-new", to);
    ssize_t n;
    if (in < 0) { free(tmp); return -1; }
    unlink(tmp);
    out = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (out < 0) { close(in); free(tmp); return -1; }
    while ((n = read(in, buf, sizeof buf)) > 0) {
        char *p = buf;
        while (n) { ssize_t w = write(out, p, n); if (w < 0) { close(in); close(out); unlink(tmp); free(tmp); return -1; } p += w; n -= w; }
    }
    close(in);
    if (!geteuid()) fchown(out, st->st_uid, st->st_gid);
    fchmod(out, st->st_mode & 07777);
    if (close(out) < 0 || n < 0 || rename(tmp, to) < 0) { unlink(tmp); free(tmp); return -1; }
    free(tmp);
    return 0;
}

struct owner { char *path; char *pkg; };
static struct owner *owners;
static int nowners, capowners;

static int cmp_owner(const void *a, const void *b) { return strcmp(((const struct owner *)a)->path, ((const struct owner *)b)->path); }

static void load_owners(void)
{
    struct list all = db_all();
    int i, j;
    nowners = 0;
    for (i = 0; i < all.n; i++) {
        struct list f = db_read(all.v[i], "files");
        for (j = 0; j < f.n; j++) {
            if (nowners == capowners) { capowners = capowners ? capowners * 2 : 1024; owners = xrealloc(owners, capowners * sizeof *owners); }
            owners[nowners].path = f.v[j]; owners[nowners].pkg = all.v[i]; nowners++;
        }
        free(f.v);
    }
    if (nowners) qsort(owners, nowners, sizeof *owners, cmp_owner);
}

static const char *owner_of(const char *path)
{
    int lo = 0, hi = nowners - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2, c = strcmp(path, owners[mid].path);
        if (!c) return owners[mid].pkg;
        if (c < 0) hi = mid - 1; else lo = mid + 1;
    }
    return NULL;
}

static void remove_empty_parents(const char *rel)
{
    char *p = xstrdup(rel), *s;
    while ((s = strrchr(p, '/'))) {
        char *full;
        *s = 0;
        if (!strchr(p, '/')) break;
        full = fmt("%s/%s", root, p);
        if (rmdir(full) < 0) { free(full); break; }
        free(full);
    }
    free(p);
}

static void delete_files(const struct list *files)
{
    int i;
    for (i = files->n - 1; i >= 0; i--) {
        char *full = fmt("%s/%s", root, files->v[i]);
        unlink(full);
        free(full);
        remove_empty_parents(files->v[i]);
    }
}

static int same_file(const char *a, const char *b)
{
    struct stat sa, sb;
    char *ha, *hb;
    int same;
    if (lstat(a, &sa) < 0 || lstat(b, &sb) < 0) return 0;
    if (S_ISLNK(sa.st_mode) || S_ISLNK(sb.st_mode)) {
        char ta[PATH_MAX], tb[PATH_MAX];
        ssize_t na, nb;
        if (!S_ISLNK(sa.st_mode) || !S_ISLNK(sb.st_mode)) return 0;
        na = readlink(a, ta, sizeof ta - 1); nb = readlink(b, tb, sizeof tb - 1);
        return na >= 0 && na == nb && !memcmp(ta, tb, na);
    }
    if (!S_ISREG(sa.st_mode) || !S_ISREG(sb.st_mode) || sa.st_size != sb.st_size) return 0;
    ha = sha256_file(a); hb = sha256_file(b);
    same = ha && hb && !strcmp(ha, hb);
    free(ha); free(hb);
    return same;
}

/* ---- scripts ---- */

struct later { char *pkg, *script; struct list args; };
static struct later *waiting;
static int nwaiting;

/* runs one of a package's scripts inside the root. 1 if it can't yet: what its #! wants is not there */
static int script(const char *pkg, const char *name, const struct list *args)
{
    char *d = dbdir(pkg), *src = fmt("%s/%s", d, name), *text = slurp(src, NULL), *interp, *inside, *full, **av;
    pid_t pid;
    int i, rc;
    free(d); free(src);
    if (!text) return 0;
    if (strncmp(text, "#!", 2)) interp = xstrdup("/bin/sh");
    else { char *s = text + 2; while (*s == ' ') s++; interp = xstrndup(s, strcspn(s, " \t\n")); }
    free(text);
    full = fmt("%s%s", root, interp);
    rc = exists(full);
    free(full); free(interp);
    if (!rc) return 1;
    inside = fmt("/var/lib/mag/%s/%s", pkg, name);
    av = xmalloc((args->n + 2) * sizeof *av);
    av[0] = inside;
    for (i = 0; i < args->n; i++) av[i + 1] = args->v[i];
    av[args->n + 1] = NULL;
    printf("==> %s %s\n", pkg, name);
    fflush(stdout);
    pid = fork();
    if (pid < 0) die("cannot fork");
    if (*root) {
        char *dev = fmt("%s/dev", root), *null = fmt("%s/dev/null", root);
        mkpath(dev, 0755);
        if (!exists(null)) mknod(null, S_IFCHR | 0666, makedev(1, 3));
        free(dev); free(null);
    }
    if (!pid) {
        if (*root && (chroot(root) < 0 || chdir("/") < 0)) { fprintf(stderr, "%s: chroot %s: %s\n", prog, root, strerror(errno)); _exit(126); }
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execvp(av[0], av);
        fprintf(stderr, "%s: %s: %s\n", prog, av[0], strerror(errno));
        _exit(127);
    }
    rc = wait_for(pid);
    if (rc) say("%s: %s exited with %d", pkg, name, rc);
    free(inside); free(av);
    return 0;
}

static void script_or_later(const char *pkg, const char *name, const char *a1, const char *a2)
{
    struct list args = { 0 };
    if (a1) push(&args, xstrdup(a1));
    if (a2) push(&args, xstrdup(a2));
    if (!script(pkg, name, &args)) { list_free(&args); return; }
    waiting = xrealloc(waiting, (nwaiting + 1) * sizeof *waiting);
    waiting[nwaiting].pkg = xstrdup(pkg);
    waiting[nwaiting].script = xstrdup(name);
    waiting[nwaiting].args = args;
    nwaiting++;
}

/* scripts that waited for their interpreter, run once it is installed */
static void run_waiting(void)
{
    int i, left = nwaiting, progress = 1;
    while (left && progress) {
        progress = 0;
        for (i = 0; i < nwaiting; i++) {
            if (!waiting[i].pkg || script(waiting[i].pkg, waiting[i].script, &waiting[i].args)) continue;
            waiting[i].pkg = NULL;
            left--;
            progress = 1;
        }
    }
    for (i = 0; i < nwaiting; i++) if (waiting[i].pkg) say("%s: %s did not run, nothing in the root can run it", waiting[i].pkg, waiting[i].script);
    nwaiting = 0;
}

static int glob_match(const char *p, const char *s)
{
    if (!*p) return !*s;
    if (*p == '*') return glob_match(p + 1, s) || (*s && *s != '/' && glob_match(p, s + 1));
    return *s && ((*p == '?' && *s != '/') || *p == *s) && glob_match(p + 1, s + 1);
}

/* a package with a trigger runs it with the directories that changed and that it watches */
static void triggers(const struct list *changed)
{
    struct list all = db_all();
    int i, j, k;
    for (i = 0; i < all.n; i++) {
        struct list globs, args = { 0 };
        char *t = db_get(all.v[i], "triggers");
        if (!t) continue;
        globs = words(t);
        for (j = 0; j < changed->n; j++)
            for (k = 0; k < globs.n; k++)
                if (glob_match(globs.v[k], changed->v[j]) && !has(&args, changed->v[j])) push(&args, changed->v[j]);
        if (args.n) script(all.v[i], "trigger", &args);
        list_free(&globs);
        free(args.v);
        free(t);
    }
}

/* ---- port trees: CRUX ports, built here from their Pkgfile ---- */

/* the text a signify file signs, if its signature checks out with the key its first line names */
static char *signify(const char *file)
{
    char *t = slurp(file, NULL), *l2, *msg, *kname, *d, *kf = NULL, *kt = NULL, *kl, *ok = NULL;
    unsigned char sig[96], pk[64];
    if (!t || strncmp(t, "untrusted comment: ", 19) || !(l2 = strchr(t, '\n')) || !(msg = strchr(l2 + 1, '\n'))) { say("%s is not signed", file); goto out; }
    *l2++ = 0;
    *msg++ = 0;
    kname = strrchr(t, '/') ? strrchr(t, '/') + 1 : strrchr(t, ' ') + 1;
    d = confdir();
    kf = fmt("%s/keys/%s", d, kname);
    free(d);
    if (!(kt = slurp(kf, NULL)) || !(kl = strchr(kt, '\n'))) say("%s is signed with %s, which is not there", file, kf);
    else if (unbase64(kl + 1, pk) != 42 || unbase64(l2, sig) != 74 || memcmp(pk, "Ed", 2) || memcmp(sig, "Ed", 2) || memcmp(pk + 2, sig + 2, 8))
        say("%s is not signed with %s", file, kf);
    else if (!ed25519_ok(sig + 10, pk + 10, msg, strlen(msg))) say("the signature of %s does not match %s", file, kf);
    else ok = xstrdup(msg);
out:
    free(t); free(kt); free(kf);
    return ok;
}

static char *signed_sum(const char *msg, const char *file)
{
    char *want = fmt("SHA256 (%s) = ", file), *s, *v = NULL;
    for (s = strstr(msg, want); s && !v; s = strstr(s + 1, want))
        if (s == msg || s[-1] == '\n') v = xstrndup(s + strlen(want), strcspn(s + strlen(want), "\n"));
    free(want);
    return v;
}

static int has_line(const char *text, const char *line)
{
    size_t n = strlen(line);
    const char *s;
    for (s = text ? strstr(text, line) : NULL; s; s = strstr(s + 1, line))
        if ((s == text || s[-1] == '\n') && (s[n] == '\n' || !s[n])) return 1;
    return 0;
}

static char *trim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t' || *s == '"' || *s == '\'') s++;
    for (e = s + strlen(s); e > s && strchr(" \t\"'", e[-1]); ) *--e = 0;
    return s;
}

/* what the index needs of a Pkgfile: the comments on top and name, version and release */
static void port_entry(struct buf *b, const char *dir, const char *port)
{
    char *f = fmt("%s/%s/Pkgfile", dir, port), *t = slurp(f, NULL), *line, *next, *ver = NULL, *rel = "1", *desc = "", *deps = "", *s, *e;
    free(f);
    if (!t) return;
    for (line = t; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!strncmp(line, "# Description:", 14)) desc = trim(line + 14);
        else if (!strncmp(line, "# Depends on:", 13)) deps = trim(line + 13);
        else if (!strncmp(line, "version=", 8)) ver = trim(line + 8);
        else if (!strncmp(line, "release=", 8)) rel = trim(line + 8);
        else if (!strncmp(line, "build", 5)) break;
    }
    for (s = deps; *s; s++) if (*s == ',') *s = ' ';
    if (ver && (e = strstr(ver, "${name}"))) { *e = 0; ver = fmt("%s%s%s", ver, port, e + 7); }
    if (ver && !strchr(ver, '$')) {
        s = fmt("P:%s\nV:%s-r%s\nT:%s\nD:%s\nk:-1\n\n", port, ver, rel, desc, deps);
        buf_add(b, s, strlen(s));
        free(s);
    }
    free(t);
}

/* gets the files of the tree REPO lists that changed since the last time, as httpup does, and indexes them. a file
 * that does not come is left out of the REPO kept here, so the next update tries it again */
static int sync_tree(int i)
{
    char *dir = tree_dir(i), *repo = fmt("%s/REPO", dir), *tmp = fmt("%s/REPO.new", dir), *url = fmt("%s/REPO", repo_urls.v[i]), *idx = fmt("%s/INDEX", dir);
    char *old = NULL, *t = NULL, *line, *next, *dl = (char *)downloader();
    struct list urls = { 0 }, files = { 0 }, keep = { 0 }, have = { 0 }, dirs = { 0 };
    struct buf b = { 0 }, r = { 0 };
    int bad = 0, k, lost = 0;
    printf("==> %s\n", url);
    mkpath(dir, 0755);
    if (download(url, tmp)) { say("could not fetch %s", url); bad = 1; goto out; }
    old = slurp(repo, NULL);
    t = slurp(tmp, NULL);
    for (line = t; line && *line; line = next) {
        char *path, *c, *full, *base;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (strncmp(line, "f:", 2) || !(path = strchr(line + 2, ':'))) continue;
        path++;
        if (!(base = strchr(path, '/'))) continue;
        if (*++base == '.' && strcmp(base, ".signature") && strcmp(base, ".footprint")) continue;
        c = clean(path);
        if (!c || strcmp(c, path) || strpbrk(path, "\"\\'")) { say("%s has a bad path in it, %s", url, path); free(c); continue; }
        push(&keep, c);
        full = fmt("%s/%s", dir, path);
        if (!exists(full) || !has_line(old, line)) { unlink(full); push(&urls, fmt("%s/%s", repo_urls.v[i], path)); push(&files, full); }
        else free(full);
    }
    if (urls.n) printf("==> %d files\n", urls.n);
    if (urls.n && !strncmp(dl, "curl ", 5) && !getenv("MAG_FETCH")) {
        char *cfg = fmt("%s/fetch", dir), *cmd = xstrndup(dl, strlen(dl) - 3);
        struct buf c = { 0 };
        char *av[] = { "/bin/sh", "-c", "set -f; $0 --create-dirs --parallel --parallel-max 8 -K \"$1\"", cmd, cfg, NULL };
        buf_add(&c, "", 0);
        for (k = 0; k < urls.n; k++) {
            char *s = fmt("url = \"%s\"\noutput = \"%s\"\n", urls.v[k], files.v[k]);
            buf_add(&c, s, strlen(s));
            free(s);
        }
        db_put_file(cfg, (char *)c.p);
        run(av);
        unlink(cfg);
        free(cfg); free(cmd); free(c.p);
    } else for (k = 0; k < urls.n; k++) download(urls.v[k], files.v[k]);
    for (k = 0; k < files.n; k++) lost += !exists(files.v[k]);
    if (lost) { say("%d files of %s did not come, mag update tries again", lost, repo_urls.v[i]); bad = 1; }
    free(t);
    t = slurp(tmp, NULL);
    buf_add(&r, "", 0);
    for (line = t; line && *line; line = next) {
        char *path, *full;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!strncmp(line, "f:", 2) && (path = strchr(line + 2, ':'))) {
            full = fmt("%s/%s", dir, path + 1);
            k = exists(full);
            free(full);
            if (!k) continue;
        }
        buf_add(&r, line, strlen(line));
        buf_add(&r, "\n", 1);
    }
    k = open(repo, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (k < 0 || write(k, r.p, r.n) != (ssize_t)r.n || close(k) < 0) die("cannot write %s: %s", repo, strerror(errno));
    unlink(tmp);
    walk(dir, "", &have, &dirs);
    for (k = 0; k < have.n; k++)
        if (!has(&keep, have.v[k]) && strcmp(have.v[k], "REPO") && strcmp(have.v[k], "REPO.new") && strcmp(have.v[k], "INDEX")) {
            char *f = fmt("%s/%s", dir, have.v[k]);
            unlink(f);
            free(f);
        }
    buf_add(&b, "", 0);
    free(t);
    t = slurp(repo, NULL);
    for (line = t; line && *line; line = next) {
        char *pf;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (strncmp(line, "d:", 2) || strchr(line + 2, '/')) continue;
        pf = fmt("%s/Pkgfile", line + 2);
        if (has(&keep, pf)) port_entry(&b, dir, line + 2);
        free(pf);
    }
    db_put_file(idx, (char *)b.p);
out:
    list_free(&urls); list_free(&files); list_free(&keep); list_free(&have); list_free(&dirs);
    free(b.p); free(r.p); free(old); free(t); free(dir); free(repo); free(tmp); free(url); free(idx);
    return bad;
}

/* runs a shell script inside the root, with bash if it is there: Pkgfiles are written for it */
static int shell(const char *text)
{
    static const char *const shs[] = { "/bin/bash", "/usr/bin/bash", "/bin/mksh", "/usr/bin/mksh" };
    const char *sh = NULL;
    pid_t pid;
    int i;
    for (i = 0; i < 4 && !sh; i++) { char *f = fmt("%s%s", root, shs[i]); if (exists(f)) sh = shs[i]; free(f); }
    if (!sh) die("building a port needs bash, mag install bash");
    fflush(stdout);
    if ((pid = fork()) < 0) die("cannot fork");
    if (!pid) {
        if (*root && (chroot(root) < 0 || chdir("/") < 0)) { fprintf(stderr, "%s: chroot %s: %s\n", prog, root, strerror(errno)); _exit(126); }
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execl(sh, sh, "-c", text, (char *)NULL);
        _exit(127);
    }
    return wait_for(pid);
}

static const char *in_root(const char *path) { return path + strlen(root); }

static int is_archive(const char *f)
{
    static const char *const ext[] = { ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz2", ".tar.xz", ".txz", ".tar.lz", ".tar.lzma", ".tar.zst", ".zip" };
    size_t n = strlen(f);
    int i;
    for (i = 0; i < 11; i++) if (n > strlen(ext[i]) && !strcmp(f + n - strlen(ext[i]), ext[i])) return 1 + (i == 10);
    return 0;
}

/* what pkgmk does: the sources, checked against the signed sums, unpacked into $SRC, then build() puts the package in $PKG */
static void build_port(const struct pkg *p, const char *stage)
{
    char *tree = tree_dir(p->repo), *dir = fmt("%s/%s", tree, p->name), *sigf = fmt("%s/.signature", dir), *msg, *sum, *have;
    char *work = fmt("%s/var/tmp/mag/build/%s", root, p->name), *src = fmt("%s/src", work), *list = fmt("%s/sources", work), *cache = fmt("%s/var/cache/mag/src", root);
    char *s, *t, *line, *next;
    struct list files = { 0 }, dirs = { 0 };
    printf("==> building %s %s\n", p->name, p->ver);
    if (!(msg = signify(sigf))) die("not building %s", p->name);
    s = fmt("%s/Pkgfile", dir);
    sum = signed_sum(msg, "Pkgfile");
    have = sha256_file(s);
    if (!sum || !have || strcmp(sum, have)) die("%s: the Pkgfile does not match its .signature", p->name);
    free(s); free(sum); free(have);
    rmtree(work);
    rmtree(stage);
    mkpath(src, 0755);
    mkpath(stage, 0755);
    mkpath(cache, 0755);
    s = fmt("cd '%s' && . ./Pkgfile && for s in \"${source[@]}\"; do printf '%%s\\n' \"$s\"; done > '%s'", in_root(dir), in_root(list));
    if (shell(s)) die("%s: cannot read the Pkgfile", p->name);
    free(s);
    t = slurp(list, NULL);
    for (line = t; line && *line; line = next) {
        char *base, *file, *cmd;
        int remote = strstr(line, "://") != NULL, kind;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        base = strrchr(line, '/') ? strrchr(line, '/') + 1 : line;
        if (!*base || strpbrk(base, "'\\") || !strcmp(base, "..")) die("%s: a source with a bad name, %s", p->name, line);
        file = remote ? fmt("%s/%s", cache, base) : fmt("%s/%s", dir, line);
        if (!(sum = signed_sum(msg, base))) die("%s: %s is not in its .signature", p->name, base);
        have = exists(file) ? sha256_file(file) : NULL;
        if (remote && (!have || strcmp(have, sum))) {
            printf("==> fetching %s\n", line);
            free(have);
            if (download(line, file)) die("could not fetch %s", line);
            have = sha256_file(file);
        }
        if (!have || strcmp(have, sum)) die("%s: %s does not match its .signature", p->name, base);
        kind = is_archive(base);
        if (kind == 2) cmd = fmt("unzip -qo '%s' -d '%s'", in_root(file), in_root(src));
        else if (kind) cmd = fmt("tar -C '%s' -xf '%s'", in_root(src), in_root(file));
        else cmd = fmt("cp '%s' '%s/'", in_root(file), in_root(src));
        if (shell(cmd)) die("%s: cannot unpack %s", p->name, base);
        free(cmd); free(file); free(sum); free(have);
    }
    free(t);
    s = fmt("set -e\n"
            "[ -f /etc/mag/build.conf ] && . /etc/mag/build.conf\n"
            "export CFLAGS=\"${CFLAGS:--O2 -pipe}\" CXXFLAGS=\"${CXXFLAGS:-${CFLAGS:--O2 -pipe}}\" MAKEFLAGS=\"${MAKEFLAGS:--j$(nproc)}\"\n"
            "export PKG='%s' SRC='%s' PKGMK_ROOT='%s'\n"
            "cd \"$PKGMK_ROOT\"\n"
            ". ./Pkgfile\n"
            "cd \"$SRC\"\n"
            "(set -e -x; build)\n"
            "cd \"$PKG\"\n"
            "rm -f usr/share/info/dir\n"
            "if command -v strip >/dev/null; then\n"
            "  find . -type f \\( -perm -100 -o -name '*.so' -o -name '*.so.*' \\) -exec strip --strip-unneeded {} + 2>/dev/null || :\n"
            "fi\n", in_root(stage), in_root(src), in_root(dir));
    if (shell(s)) die("%s did not build, what it left is in %s", p->name, work);
    free(s);
    walk(stage, "", &files, &dirs);
    if (!files.n) die("%s built nothing", p->name);
    list_free(&files); list_free(&dirs);
    rmtree(work);
    free(tree); free(dir); free(sigf); free(msg); free(work); free(src); free(list); free(cache);
}

/* ---- installing a package ---- */

static char *pkg_file(const struct pkg *p) { return fmt("%s/var/cache/mag/pkg/%s-%s.apk", root, p->name, p->ver); }

/* the control part is checked against the index, the files against the control part, then they go into stage */
static int unpack(const struct pkg *p, const char *file, const char *stage, struct tar *ctl)
{
    int fd = open(file, O_RDONLY), ok = -1, n;
    struct in *r = xmalloc(sizeof *r);
    struct tar t;
    off_t at, data;
    unsigned char dig[32], want[64];
    char *datahash = NULL, *s;
    struct ent *info;
    memset(&t, 0, sizeof t);
    memset(ctl, 0, sizeof *ctl);
    if (fd < 0) goto out;
    in_open(r, fd, 0);
    if (gunzip(r, tar_out, &t)) goto out;
    tar_free(&t);
    at = in_tell(r);
    if (gunzip(r, tar_out, ctl)) goto out;
    data = in_tell(r);
    if (!p->csum || strlen(p->csum) < 3 || p->csum[0] != 'Q' || (p->csum[1] != '1' && p->csum[1] != '2')) { say("%s has no checksum in the index", p->name); goto out; }
    n = hash_range(fd, at, data, p->csum[1] == '1', dig);
    if ((int)unbase64(p->csum + 2, want) != n || memcmp(dig, want, n)) { say("%s: the package does not match the index", p->name); goto out; }
    if (!(info = tar_find(ctl, ".PKGINFO"))) { say("%s has no .PKGINFO", p->name); goto out; }
    s = (char *)info->data.p;
    if (strncmp(s, "datahash = ", 11)) s = strstr(s, "\ndatahash = ") ? strstr(s, "\ndatahash = ") + 1 : NULL;
    if (s) { s += 11; datahash = xstrndup(s, strcspn(s, "\n")); }
    if (!datahash) { say("%s has no datahash", p->name); goto out; }
    hash_range(fd, data, -1, 0, dig);
    s = hex(dig, 32);
    n = strcmp(s, datahash);
    free(s);
    if (n) { say("%s: the files do not match the package's own hash", p->name); goto out; }
    rmtree(stage);
    mkpath(stage, 0755);
    t.dir = stage;
    in_open(r, fd, data);
    do {
        if (gunzip(r, tar_out, &t) || t.bad) { say("%s: cannot unpack it", p->name); tar_free(&t); goto out; }
    } while (!in_eof(r));
    tar_free(&t);
    ok = 0;
out:
    free(datahash);
    free(r);
    if (fd >= 0) close(fd);
    return ok;
}

static char *pkginfo(struct tar *ctl, const char *key)
{
    struct ent *e = tar_find(ctl, ".PKGINFO");
    char *s, *want = fmt("\n%s = ", key), *v = NULL;
    if (e && (s = strstr((char *)e->data.p, want))) { s += strlen(want); v = xstrndup(s, strcspn(s, "\n")); }
    free(want);
    return v;
}

static struct list changed_dirs;

static void fetch_pkg(const struct pkg *p, const char *file)
{
    char *base = repo_base(p->repo), *url = fmt("%s/%s-%s.apk", base, p->name, p->ver);
    printf("==> fetching %s\n", url);
    if (download(url, file)) die("could not fetch %s", url);
    free(base); free(url);
}

static void install_one(struct pkg *p, int explicit, const struct list *planned)
{
    static const char *const scripts[] = { "pre-install", "post-install", "pre-upgrade", "post-upgrade", "pre-deinstall", "post-deinstall", "trigger" };
    char *file = pkg_file(p), *stage = fmt("%s/var/tmp/mag/%s", root, p->name), *oldver = db_get(p->name, "version"), *trig;
    struct list files = { 0 }, dirs = { 0 }, old, gone = { 0 }, deps = { 0 }, w, v = { 0 }, pr = { 0 };
    struct tar ctl;
    int i, bad = 0, port = kinds[p->repo] != APK;
    if (port) {
        memset(&ctl, 0, sizeof ctl);
        build_port(p, stage);
    } else {
        int fresh = !exists(file);
        if (fresh) fetch_pkg(p, file);
        if (unpack(p, file, stage, &ctl)) {
            unlink(file);
            if (fresh) die("not installing %s", p->name);
            fetch_pkg(p, file);
            if (unpack(p, file, stage, &ctl)) { unlink(file); die("not installing %s", p->name); }
        }
    }
    walk(stage, "", &files, &dirs);
    load_owners();
    old = db_read(p->name, "files");
    for (i = 0; i < files.n; i++) {
        struct stat st;
        const char *o = owner_of(files.v[i]);
        char *full = fmt("%s/%s", root, files.v[i]);
        if (o && strcmp(o, p->name)) { if (bad < 5) say("%s wants /%s, which %s has", p->name, files.v[i], o); bad++; }
        else if (!o && exists(full) && strncmp(files.v[i], "etc/", 4) && !(lstat(full, &st) == 0 && S_ISLNK(st.st_mode))) {
            char *from = fmt("%s/%s", stage, files.v[i]);
            if (!same_file(from, full)) { if (bad < 5) say("%s wants /%s, which is there already and is different", p->name, files.v[i]); bad++; }
            free(from);
        }
        free(full);
    }
    if (bad > 5) say("and %d more", bad - 5);
    if (bad && !force) die("not installing %s, %d files are in the way, -f writes over them", p->name, bad);
    bad = 0;

    for (i = 0; i < 7; i++) {
        char *n = fmt(".%s", scripts[i]);
        struct ent *e = tar_find(&ctl, n);
        if (e) db_put(p->name, scripts[i], (char *)e->data.p, e->data.n, 0755);
        else { char *d = dbdir(p->name), *f = fmt("%s/%s", d, scripts[i]); unlink(f); free(d); free(f); }
        free(n);
    }
    for (i = 0; port && i < 2; i++) {
        char *d = tree_dir(p->repo), *f = fmt("%s/%s/%s", d, p->name, scripts[i]), *t;
        size_t n;
        if ((t = slurp(f, &n))) db_put(p->name, scripts[i], t, n, 0755);
        free(d); free(f); free(t);
    }
    if (oldver) script_or_later(p->name, "pre-upgrade", p->ver, oldver);
    else script_or_later(p->name, "pre-install", p->ver, NULL);

    for (i = 0; i < dirs.n; i++) {
        char *from = fmt("%s/%s", stage, dirs.v[i]), *to = fmt("%s/%s", root, dirs.v[i]);
        struct stat st;
        if (!exists(to) && !lstat(from, &st)) {
            mkpath(to, 0755);
            chmod(to, st.st_mode & 07777);
            if (!geteuid()) lchown(to, st.st_uid, st.st_gid);
        }
        free(from); free(to);
    }
    for (i = 0; i < files.n; i++) {
        char *from = fmt("%s/%s", stage, files.v[i]), *to = fmt("%s/%s", root, files.v[i]), *slash;
        struct stat st;
        mkparent(to);
        if (lstat(from, &st) < 0) die("cannot stat %s", from);
        if (S_ISLNK(st.st_mode)) {
            char tgt[PATH_MAX];
            ssize_t n = readlink(from, tgt, sizeof tgt - 1);
            if (n < 0) die("cannot read link %s", from);
            tgt[n] = 0;
            unlink(to);
            if (symlink(tgt, to) < 0) { say("cannot link %s: %s", to, strerror(errno)); bad = 1; }
            else if (!geteuid()) lchown(to, st.st_uid, st.st_gid);
        } else if (!strncmp(files.v[i], "etc/", 4) && exists(to) && !same_file(from, to)) {
            char *alt = fmt("%s.new", to);
            printf("==> /%s is changed here, the new one is /%s.new\n", files.v[i], files.v[i]);
            if (copy_into(from, alt, &st) < 0) { say("cannot write %s: %s", alt, strerror(errno)); bad = 1; }
            free(alt);
        } else if (copy_into(from, to, &st) < 0) { say("cannot write %s: %s", to, strerror(errno)); bad = 1; }
        if ((slash = strrchr(files.v[i], '/'))) {
            char *dir = fmt("/%.*s", (int)(slash - files.v[i]), files.v[i]);
            if (!has(&changed_dirs, dir)) push(&changed_dirs, dir); else free(dir);
        }
        free(from); free(to);
    }
    if (bad) die("%s did not install cleanly", p->name);
    for (i = 0; i < old.n; i++) if (!has(&files, old.v[i])) push(&gone, old.v[i]);
    delete_files(&gone);
    rmtree(stage);

    w = words(p->deps);
    for (i = 0; i < w.n; i++) {
        struct dep d;
        const char *who = NULL;
        int j;
        dep_parse(w.v[i], &d);
        if (d.neg) continue;
        for (j = 0; j < planned->n && !who; j++) {
            struct pkg *q = newest(planned->v[j]);
            if (q && meets(&d, q->name, q->ver, q->prov)) who = q->name;
        }
        if (!who) who = installed_for(&d);
        if (who && strcmp(who, p->name) && !has(&deps, who)) push(&deps, xstrdup(who));
    }
    list_free(&w);
    push(&v, p->ver);
    push(&pr, p->prov ? p->prov : "");
    db_write(p->name, "version", &v);
    db_write(p->name, "deps", &deps);
    db_write(p->name, "provides", &pr);
    db_write(p->name, "files", &files);
    if ((trig = pkginfo(&ctl, "triggers"))) db_put(p->name, "triggers", trig, strlen(trig), 0644);
    if (explicit) db_put(p->name, "explicit", "", 0, 0644);
    if (port) db_put(p->name, "port", repo_urls.v[p->repo], strlen(repo_urls.v[p->repo]), 0644);
    else { char *d = dbdir(p->name), *f = fmt("%s/port", d); unlink(f); free(d); free(f); }
    free(trig);
    tar_free(&ctl);
    if (oldver) script_or_later(p->name, "post-upgrade", p->ver, oldver);
    else script_or_later(p->name, "post-install", p->ver, NULL);
    printf("==> installed %s %s%s%s\n", p->name, p->ver, oldver ? ", was " : "", oldver ? oldver : "");
    list_free(&files); list_free(&dirs); list_free(&old); free(gone.v); list_free(&deps); free(v.v); free(pr.v);
    free(oldver); free(file); free(stage);
}

/* ---- working out what to install ---- */

static struct list wanted;

static void plan(struct pkg *p, struct list *order, struct list *stack);

/* a port is built with build-base, pkgconf and bash, which CRUX has in core, and the -dev of what it needs that comes built from a repo */
static void plan_tool(const char *name, struct list *order, struct list *stack)
{
    struct pkg *q = newest(name);
    if (q && !installed(name) && !has(order, name)) plan(q, order, stack);
}

static void plan(struct pkg *p, struct list *order, struct list *stack)
{
    struct list w;
    int i, j, port = kinds[p->repo] != APK;
    if (has(order, p->name) || has(stack, p->name)) return;
    push(stack, p->name);
    if (port) { plan_tool("build-base", order, stack); plan_tool("pkgconf", order, stack); plan_tool("bash", order, stack); }
    w = words(p->deps);
    for (i = 0; i < w.n; i++) {
        struct dep d;
        struct pkg *c;
        int done = 0;
        dep_parse(w.v[i], &d);
        if (d.neg) continue;
        for (j = 0; j < order->n && !done; j++) {
            struct pkg *q = newest(order->v[j]);
            done = q && meets(&d, q->name, q->ver, q->prov);
        }
        if (!done && !installed_for(&d)) {
            for (j = 0, c = NULL; j < wanted.n && !c; j++) {
                struct pkg *q = newest(wanted.v[j]);
                if (q && meets(&d, q->name, q->ver, q->prov)) c = q;
            }
            if (!c && !(c = pick(&d))) die("%s needs %s, which no repo has", p->name, w.v[i]);
            plan(c, order, stack);
        }
        if (port) {
            struct pkg *q = newest(d.key);
            char *dev = fmt("%s-dev", d.key), *m = dbdir(d.key), *f = fmt("%s/port", m);
            if (q && kinds[q->repo] == APK && !exists(f)) plan_tool(dev, order, stack);
            free(dev); free(m); free(f);
        }
    }
    list_free(&w);
    stack->n--;
    push(order, p->name);
}

static int apply(const struct list *order, const struct list *want)
{
    int i;
    if (!order->n) return 0;
    printf("will install:");
    for (i = 0; i < order->n; i++) printf(" %s%s", order->v[i], kinds[newest(order->v[i])->repo] != APK ? " (built here)" : "");
    putchar('\n');
    if (dry) return 0;
    if (geteuid()) die("this needs root");
    {
        char *f = fmt("%s/etc/mag/arch", root);
        if (!exists(f)) { mkparent(f); db_put_file(f, arch); }
        free(f);
    }
    for (i = 0; i < order->n; i++) {
        struct pkg *p = newest(order->v[i]);
        install_one(p, has(want, p->name), order);
    }
    run_waiting();
    triggers(&changed_dirs);
    return 0;
}

static int cmd_install(int n, char **names)
{
    struct list order = { 0 }, stack = { 0 }, want = { 0 };
    int i;
    load_index();
    for (i = 0; i < n; i++) push(&wanted, names[i]);
    for (i = 0; i < n; i++) {
        struct pkg *p = newest(names[i]);
        if (!p) {
            struct dep d;
            dep_parse(names[i], &d);
            if (!(p = pick(&d))) die("%s is in no repo", names[i]);
        }
        push(&want, p->name);
        if (installed(p->name) && !force) {
            char *v = db_get(p->name, "version");
            int same = !strcmp(v, p->ver);
            if (same) {
                printf("%s %s is installed already\n", p->name, v);
                if (!dry) db_put(p->name, "explicit", "", 0, 0644);
            }
            free(v);
            if (same) continue;
        }
        plan(p, &order, &stack);
    }
    return apply(&order, &want);
}

static int cmd_upgrade(void)
{
    struct list all = db_all(), order = { 0 }, stack = { 0 }, want = { 0 };
    int i;
    load_index();
    for (i = 0; i < all.n; i++) { char *v = db_get(all.v[i], "port"); if (v) push(&from_ports, all.v[i]); free(v); }
    for (i = 0; i < all.n; i++) {
        struct pkg *p = newest(all.v[i]);
        char *v = db_get(all.v[i], "version"), *d = dbdir(all.v[i]), *e = fmt("%s/explicit", d);
        if (exists(e)) push(&want, all.v[i]);
        if (p && v && vercmp(p->ver, v) > 0) plan(p, &order, &stack);
        free(v); free(d); free(e);
    }
    if (!order.n) { puts("everything is up to date"); return 0; }
    return apply(&order, &want);
}

static int cmd_update(void)
{
    int i, bad = 0;
    for (i = 0; i < repo_urls.n; i++) {
        char *base, *url, *f, *tmp;
        if (kinds[i] != APK) { bad |= sync_tree(i); continue; }
        base = repo_base(i); url = fmt("%s/APKINDEX.tar.gz", base); f = index_file(i); tmp = fmt("%s.new", f);
        printf("==> %s\n", url);
        if (download(url, tmp)) { say("could not fetch %s", url); bad = 1; }
        else if (check_signed(tmp)) { say("%s is not signed by a key mag has, not using it", url); unlink(tmp); bad = 1; }
        else rename(tmp, f);
        free(base); free(url); free(f); free(tmp);
    }
    load_index();
    printf("%d packages\n", npkgs);
    return bad;
}

static int cmd_build(int n, char **names)
{
    int i;
    load_index();
    for (i = 0; i < n; i++) {
        if (!port_of(names[i])) die("%s is in no port tree", names[i]);
        push(&from_ports, names[i]);
    }
    return cmd_install(n, names);
}

static int cmd_remove(int n, char **names)
{
    int i;
    for (i = 0; i < n; i++) {
        struct list rd, files;
        char *d, *v;
        if (!installed(names[i])) die("%s is not installed", names[i]);
        rd = rdeps(names[i]);
        if (rd.n && !force) {
            int k;
            fprintf(stderr, "%s: %s is needed by", prog, names[i]);
            for (k = 0; k < rd.n; k++) fprintf(stderr, " %s", rd.v[k]);
            fputs(", -f removes it anyway\n", stderr);
            return 1;
        }
        files = db_read(names[i], "files");
        if (dry) { printf("would remove %s (%d files)\n", names[i], files.n); continue; }
        v = db_get(names[i], "version");
        script_or_later(names[i], "pre-deinstall", v, NULL);
        delete_files(&files);
        script_or_later(names[i], "post-deinstall", v, NULL);
        nwaiting = 0;
        d = dbdir(names[i]);
        rmtree(d);
        free(d); free(v);
        list_free(&files); list_free(&rd);
        printf("==> removed %s\n", names[i]);
    }
    return 0;
}

static struct list orphans(void)
{
    struct list all = db_all(), out = { 0 };
    int i;
    for (i = 0; i < all.n; i++) {
        char *d = dbdir(all.v[i]), *e = fmt("%s/explicit", d);
        struct list rd = rdeps(all.v[i]);
        if (!exists(e) && !rd.n) push(&out, all.v[i]);
        free(d); free(e);
        list_free(&rd);
    }
    return out;
}

static int cmd_autoremove(void)
{
    int total = 0;
    for (;;) {
        struct list o = orphans();
        if (!o.n) break;
        if (cmd_remove(o.n, o.v)) return 1;
        total += o.n;
        if (dry) break;
    }
    if (!total) puts("nothing to remove");
    return 0;
}

/* ---- the small commands ---- */

static int cmd_list(void)
{
    struct list all = db_all();
    int i;
    for (i = 0; i < all.n; i++) { char *v = db_get(all.v[i], "version"); printf("%s %s\n", all.v[i], v ? v : "?"); free(v); }
    return 0;
}

static int cmd_info(const char *name)
{
    struct pkg *p;
    char *v = db_get(name, "version");
    load_index();
    p = newest(name);
    if (!p && !v) die("%s is in no repo and not installed", name);
    if (p) {
        printf("%s %s\n", p->name, p->ver);
        if (p->desc) printf("  %s\n", p->desc);
        if (p->deps) printf("  needs: %s\n", p->deps);
        if (p->size) printf("  size: %s bytes\n", p->size);
        printf("  from: %s%s\n", kinds[p->repo] == CRUX ? "crux " : "", repo_urls.v[p->repo]);
    } else printf("%s\n", name);
    if (v) printf("  installed: %s\n", v); else puts("  not installed");
    free(v);
    return 0;
}

static int cmd_search(const char *word)
{
    int i, found = 0;
    load_index();
    for (i = 0; i < npkgs; i++) {
        struct pkg *p = &pkgs[i];
        if (strstr(p->name, word) || (p->desc && strstr(p->desc, word))) { printf("%s %s  %s\n", p->name, p->ver, p->desc ? p->desc : ""); found = 1; }
    }
    return !found;
}

static int cmd_files(const char *name)
{
    struct list f;
    int i;
    if (!installed(name)) die("%s is not installed", name);
    f = db_read(name, "files");
    for (i = 0; i < f.n; i++) printf("/%s\n", f.v[i]);
    return 0;
}

static int cmd_owns(const char *path)
{
    const char *o;
    char *real = realpath(path, NULL), *rel;
    size_t rl = strlen(root);
    if (!real) die("%s: %s", path, strerror(errno));
    rel = real;
    if (rl && !strncmp(rel, root, rl)) rel += rl;
    while (*rel == '/') rel++;
    load_owners();
    o = owner_of(rel);
    if (!o) { printf("%s is not owned by any package\n", path); return 1; }
    printf("%s is owned by %s\n", path, o);
    return 0;
}

static int cmd_deps(const char *name, int reverse)
{
    struct list l;
    int i;
    if (reverse) l = rdeps(name);
    else if (installed(name)) l = db_read(name, "deps");
    else {
        struct pkg *p;
        load_index();
        if (!(p = newest(name))) die("%s is in no repo", name);
        l = words(p->deps);
    }
    for (i = 0; i < l.n; i++) puts(l.v[i]);
    return 0;
}

static int cmd_fetch(int n, char **names)
{
    int i;
    load_index();
    for (i = 0; i < n; i++) {
        struct pkg *p = newest(names[i]);
        char *file, *base, *url;
        if (!p) die("%s is in no repo", names[i]);
        if (kinds[p->repo] != APK) { printf("%s comes from a port tree, it is built and not fetched\n", p->name); continue; }
        file = pkg_file(p); base = repo_base(p->repo); url = fmt("%s/%s-%s.apk", base, p->name, p->ver);
        printf("==> fetching %s\n", url);
        if (download(url, file)) die("could not fetch %s", url);
        free(file); free(base); free(url);
    }
    return 0;
}

static void usage(void)
{
    puts("Usage: mag [-nf] COMMAND [PACKAGE]...\n"
         "\n"
         "  update            get the index of every repo, checked against the keys\n"
         "  install PKG...    install packages and what they need\n"
         "  build PKG...      build them from a port tree and install them, even if a repo has them built\n"
         "  remove PKG...     take a package off\n"
         "  upgrade           install what the repos have a newer version of\n"
         "  autoremove        remove what was only installed as a dependency and is not needed now\n"
         "  list              what is installed\n"
         "  info PKG          what the repo says about it, and whether it is installed\n"
         "  search WORD       packages whose name or description has WORD\n"
         "  files PKG         the files a package put on the system\n"
         "  owns PATH         which package a file came from\n"
         "  deps PKG          what it needs, rdeps PKG for what needs it\n"
         "  fetch PKG...      only download them\n"
         "\n"
         "  -n  only say what would happen    -f  go on when files clash or something needs the package\n"
         "\n"
         "/etc/mag/repos has one repo url a line, /etc/mag/keys the public keys they are signed with, /etc/mag/arch\n"
         "which builds to get (written on the first install, the machine's own if it is not there). A line \"crux URL\" is a\n"
         "CRUX port tree, like crux https://crux.nu/ports/crux-3.8/opt; its key, opt.pub, goes in /etc/mag/keys too. What a\n"
         "repo has built wins over a port, mag build takes the port. Ports build with bash and the CFLAGS, CXXFLAGS and\n"
         "MAKEFLAGS of /etc/mag/build.conf, if it is there.\n"
         "MAG_ROOT installs somewhere else than /, MAG_ARCH overrides the arch, MAG_FETCH is the download command, which gets a file and an url (curl, else wget, else ftp)");
}

int main(int argc, char **argv)
{
    const char *r = getenv("MAG_ROOT");
    int i = 1, rc;
    if (r && strcmp(r, "/")) { char *rr = xstrdup(r), *s = rr + strlen(rr); while (s > rr + 1 && s[-1] == '/') *--s = 0; root = rr; }
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        const char *o;
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (!strcmp(argv[i], "--help")) { usage(); return 0; }
        if (!strcmp(argv[i], "--version")) { puts("mag " VERSION); return 0; }
        for (o = argv[i] + 1; *o; o++) {
            if (*o == 'n') dry = 1; else if (*o == 'f') force = 1;
            else { say("unknown option -%c", *o); return 1; }
        }
    }
    if (i >= argc || !strcmp(argv[i], "help")) { usage(); return i >= argc ? 1 : 0; }
    arch = machine();
    {
        const char *cmd = argv[i++];
        int n = argc - i;
        char **a = argv + i;
        if (strcmp(cmd, "list") && strcmp(cmd, "files") && strcmp(cmd, "owns") && strcmp(cmd, "remove") && strcmp(cmd, "del")
            && strcmp(cmd, "rdeps") && strcmp(cmd, "autoremove")) load_repos();
        if (!strcmp(cmd, "update") && !n) rc = cmd_update();
        else if (!strcmp(cmd, "install") || !strcmp(cmd, "add")) rc = n ? cmd_install(n, a) : (say("install what?"), 1);
        else if (!strcmp(cmd, "build")) rc = n ? cmd_build(n, a) : (say("build what?"), 1);
        else if (!strcmp(cmd, "remove") || !strcmp(cmd, "del")) rc = n ? cmd_remove(n, a) : (say("remove what?"), 1);
        else if (!strcmp(cmd, "upgrade") && !n) rc = cmd_upgrade();
        else if (!strcmp(cmd, "autoremove") && !n) rc = cmd_autoremove();
        else if (!strcmp(cmd, "list") && !n) rc = cmd_list();
        else if (!strcmp(cmd, "info") && n == 1) rc = cmd_info(a[0]);
        else if (!strcmp(cmd, "search") && n == 1) rc = cmd_search(a[0]);
        else if (!strcmp(cmd, "files") && n == 1) rc = cmd_files(a[0]);
        else if (!strcmp(cmd, "owns") && n == 1) rc = cmd_owns(a[0]);
        else if (!strcmp(cmd, "deps") && n == 1) rc = cmd_deps(a[0], 0);
        else if (!strcmp(cmd, "rdeps") && n == 1) rc = cmd_deps(a[0], 1);
        else if (!strcmp(cmd, "fetch") && n) rc = cmd_fetch(n, a);
        else { say("'%s' with %d argument%s makes no sense, mag help says what there is", cmd, n, n == 1 ? "" : "s"); return 1; }
    }
    fflush(stdout);
    return rc;
}
