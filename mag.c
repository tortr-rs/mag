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

#define VERSION "0.7.1"

static const char *prog = "mag";
static const char *root = "";                   /* MAG_ROOT without the trailing slash, "" is / */
static const char *arch;
static int dry, force, yes;

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

static void sha512_block(uint64_t *h, const unsigned char *p)
{
    uint64_t w[80], v[8];
    int i, j;
    for (j = 0; j < 16; j++) for (w[j] = 0, i = 0; i < 8; i++) w[j] = w[j] << 8 | p[j * 8 + i];
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

/* sha1 is 1 for sha1, 0 for sha256, 2 for sha512 */
struct hash { unsigned h[8]; uint64_t h64[8]; unsigned char b[128]; uint64_t len; int sha1; };

static void hash_init(struct hash *s, int sha1)
{
    static const unsigned i1[5] = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0 };
    static const unsigned i2[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    static const uint64_t i5[8] = { 0x6a09e667f3bcc908ull, 0xbb67ae8584caa73bull, 0x3c6ef372fe94f82bull, 0xa54ff53a5f1d36f1ull,
        0x510e527fade682d1ull, 0x9b05688c2b3e6c1full, 0x1f83d9abfb41bd6bull, 0x5be0cd19137e2179ull };
    memset(s, 0, sizeof *s);
    s->sha1 = sha1;
    if (sha1 == 2) memcpy(s->h64, i5, sizeof i5);
    else memcpy(s->h, sha1 ? i1 : i2, sha1 ? sizeof i1 : sizeof i2);
}

static void hash_block(struct hash *s, const unsigned char *p)
{
    if (s->sha1 == 2) sha512_block(s->h64, p); else if (s->sha1) sha1_block(s->h, p); else sha256_block(s->h, p);
}

static void hash_add(struct hash *s, const void *data, size_t n)
{
    const unsigned char *p = data;
    size_t bs = s->sha1 == 2 ? 128 : 64, used = s->len % bs;
    s->len += n;
    if (used) {
        size_t k = bs - used < n ? bs - used : n;
        memcpy(s->b + used, p, k);
        p += k; n -= k;
        if (used + k < bs) return;
        hash_block(s, s->b);
    }
    for (; n >= bs; p += bs, n -= bs) hash_block(s, p);
    memcpy(s->b, p, n);
}

/* the digest into out, returns its length */
static int hash_end(struct hash *s, unsigned char *out)
{
    uint64_t bits = s->len * 8;
    unsigned char c = 0x80;
    int i, big = s->sha1 == 2, w = s->sha1 == 1 ? 5 : 8;
    hash_add(s, &c, 1);
    c = 0;
    while (s->len % (big ? 128 : 64) != (big ? 112u : 56u)) hash_add(s, &c, 1);
    for (i = big ? 15 : 7; i >= 0; i--) { c = i > 7 ? 0 : bits >> (i * 8); hash_add(s, &c, 1); }
    if (big) { for (i = 0; i < 64; i++) out[i] = s->h64[i / 8] >> (56 - 8 * (i % 8)); return 64; }
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
    static unsigned char buf[65536];
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

/* ---- zstd ---- */

struct rb { const unsigned char *s; size_t n; long bit; };

static int rb_init(struct rb *b, const unsigned char *s, size_t n)
{
    int h;
    if (!n || !s[n - 1]) return -1;
    for (h = 7; !(s[n - 1] >> h & 1); h--) {}
    b->s = s; b->n = n; b->bit = (long)(n - 1) * 8 + h;
    return 0;
}

static uint64_t rb_peek(const struct rb *b, int k)
{
    long lo = b->bit - k;
    uint64_t w = 0;
    size_t at;
    int i, sh;
    if (!k) return 0;
    if (lo < 0) {
        uint64_t v = 0;
        long j;
        for (j = b->bit - 1; j >= lo; j--) v = v << 1 | (j >= 0 ? b->s[j >> 3] >> (j & 7) & 1 : 0);
        return v;
    }
    at = lo >> 3; sh = lo & 7;
    for (i = 0; i < 8 && at + i < b->n; i++) w |= (uint64_t)b->s[at + i] << (8 * i);
    return w >> sh & (((uint64_t)1 << k) - 1);
}

static uint64_t rb_get(struct rb *b, int k) { uint64_t v = rb_peek(b, k); b->bit -= k; return v; }

struct fse { unsigned char sym, nb; unsigned short base; };
struct ftab { struct fse t[512]; int al; };

static int highbit(unsigned v) { int h = -1; while (v) { v >>= 1; h++; } return h; }

static void fse_build(struct ftab *f, const short *norm, int nsym, int al)
{
    int size = 1 << al, high = size - 1, pos = 0, step = (size >> 1) + (size >> 3) + 3, s, i;
    unsigned short next[64];
    f->al = al;
    for (s = 0; s < nsym; s++) if (norm[s] == -1) f->t[high--].sym = s;
    for (s = 0; s < nsym; s++)
        for (i = 0; i < norm[s]; i++) {
            f->t[pos].sym = s;
            do pos = (pos + step) & (size - 1); while (pos > high);
        }
    for (s = 0; s < nsym; s++) next[s] = norm[s] == -1 ? 1 : norm[s];
    for (i = 0; i < size; i++) {
        unsigned n = next[f->t[i].sym]++;
        f->t[i].nb = al - highbit(n);
        f->t[i].base = (n << f->t[i].nb) - size;
    }
}

static void fse_rle(struct ftab *f, int sym) { f->al = 0; f->t[0].sym = sym; f->t[0].nb = 0; f->t[0].base = 0; }

/* a table description, read forward; the bytes it took, or -1 */
static long fse_read(struct ftab *f, const unsigned char *p, size_t n, int maxsym, int maxal)
{
    short norm[64];
    long pos = 0;
    int al, remaining, threshold, nb, sym = 0, prev0 = 0;
#define FGET(k) ((size_t)((pos + (k) + 7) >> 3) > n ? -1 : (int)((((uint32_t)p[pos >> 3] | (pos / 8 + 1 < (long)n ? (uint32_t)p[pos / 8 + 1] << 8 : 0) | (pos / 8 + 2 < (long)n ? (uint32_t)p[pos / 8 + 2] << 16 : 0)) >> (pos & 7)) & ((1u << (k)) - 1)))
    if (!n) return -1;
    al = (p[0] & 15) + 5;
    pos = 4;
    if (al > maxal) return -1;
    remaining = (1 << al) + 1; threshold = 1 << al; nb = al + 1;
    while (remaining > 1 && sym <= maxsym) {
        int max, count, v;
        if (prev0) {
            int n0 = sym;
            while ((v = FGET(2)) == 3) { n0 += 3; pos += 2; }
            if (v < 0) return -1;
            n0 += v; pos += 2;
            if (n0 > maxsym + 1) return -1;
            while (sym < n0) norm[sym++] = 0;
            if (sym > maxsym) break;
        }
        max = (2 * threshold - 1) - remaining;
        if ((v = FGET(nb)) < 0 && (v = FGET(nb - 1)) < 0) return -1;
        if ((v & (threshold - 1)) < max) { count = v & (threshold - 1); pos += nb - 1; }
        else { count = v & (2 * threshold - 1); if (count >= threshold) count -= max; pos += nb; }
        count--;
        remaining -= count < 0 ? -count : count;
        norm[sym++] = count;
        prev0 = !count;
        while (remaining < threshold) { nb--; threshold >>= 1; }
    }
#undef FGET
    if (remaining != 1 || (pos + 7) >> 3 > (long)n) return -1;
    while (sym <= maxsym) norm[sym++] = 0;
    fse_build(f, norm, maxsym + 1, al);
    return (pos + 7) >> 3;
}

struct htab { unsigned short e[2048]; int bits; };   /* sym << 8 | length */

/* a Huffman tree description: the bytes it took, or -1 */
static long huf_read(struct htab *h, const unsigned char *p, size_t n)
{
    unsigned char w[256];
    int nw = 0, i, maxbits, rank[13];
    unsigned total = 0, rest;
    long used;
    if (!n) return -1;
    if (p[0] >= 128) {
        nw = p[0] - 127;
        used = 1 + (nw + 1) / 2;
        if ((size_t)used > n) return -1;
        for (i = 0; i < nw; i++) w[i] = i & 1 ? p[1 + i / 2] & 15 : p[1 + i / 2] >> 4;
    } else {
        struct ftab f;
        struct rb b;
        long k;
        int s1, s2;
        used = 1 + p[0];
        if ((size_t)used > n || (k = fse_read(&f, p + 1, p[0], 12, 6)) < 0 || rb_init(&b, p + 1 + k, p[0] - k)) return -1;
        s1 = rb_get(&b, f.al); s2 = rb_get(&b, f.al);
        for (;;) {
            if (nw > 254) return -1;
            w[nw++] = f.t[s1].sym;
            s1 = f.t[s1].base + rb_get(&b, f.t[s1].nb);
            if (b.bit < 0) { w[nw++] = f.t[s2].sym; break; }
            if (nw > 254) return -1;
            w[nw++] = f.t[s2].sym;
            s2 = f.t[s2].base + rb_get(&b, f.t[s2].nb);
            if (b.bit < 0) { w[nw++] = f.t[s1].sym; break; }
        }
    }
    for (i = 0; i < nw; i++) { if (w[i] > 12) return -1; if (w[i]) total += 1u << (w[i] - 1); }
    if (!total || nw > 255) return -1;
    maxbits = highbit(total) + 1;
    rest = (1u << maxbits) - total;
    if (rest & (rest - 1) || maxbits > 11) return -1;
    w[nw++] = highbit(rest) + 1;
    h->bits = maxbits;
    memset(rank, 0, sizeof rank);
    for (i = 0; i < nw; i++) rank[w[i]]++;
    {
        int start = 0, c, r;
        for (r = 1; r <= maxbits; r++) { c = start; start += rank[r] << (r - 1); rank[r] = c; }
    }
    for (i = 0; i < nw; i++) {
        int len, u;
        if (!w[i]) continue;
        len = 1 << (w[i] - 1);
        for (u = rank[w[i]]; u < rank[w[i]] + len; u++) h->e[u] = i << 8 | (maxbits + 1 - w[i]);
        rank[w[i]] += len;
    }
    return used;
}

static int huf_stream(const struct htab *h, const unsigned char *p, size_t n, unsigned char *out, size_t count)
{
    struct rb b;
    size_t i;
    if (rb_init(&b, p, n)) return -1;
    for (i = 0; i < count; i++) {
        unsigned e = h->e[rb_peek(&b, h->bits)];
        out[i] = e >> 8;
        b.bit -= e & 255;
    }
    return b.bit ? -1 : 0;
}

static const short ll_def[36] = { 4, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 2, 1, 1, 1, 1, 1, -1, -1, -1, -1 };
static const short ml_def[53] = { 1, 4, 3, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1, -1, -1 };
static const short of_def[29] = { 1, 1, 1, 1, 1, 1, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, -1, -1, -1, -1, -1 };
static const unsigned ll_base[36] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 18, 20, 22, 24, 28, 32, 40, 48, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536 };
static const unsigned char ll_bits[36] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 3, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
static const unsigned ml_base[53] = { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
    35, 37, 39, 41, 43, 47, 51, 59, 67, 83, 99, 131, 259, 515, 1027, 2051, 4099, 8195, 16387, 32771, 65539 };
static const unsigned char ml_bits[53] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    1, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };

struct zst {
    unsigned char *w, lit[131072 + 8], blk[131072 + 8];
    size_t wn, cap, win, lim;
    struct htab huf;
    struct ftab ll, of, ml;
    int hufok, llok, ofok, mlok;
    uint64_t rep[3];
};

static int z_table(struct ftab *f, int *ok, int mode, const unsigned char **p, const unsigned char *end, const short *def, int ndef, int defal, int maxsym, int maxal)
{
    long k;
    if (mode == 0) fse_build(f, def, ndef, defal);
    else if (mode == 1) { if (*p >= end || **p > maxsym) return -1; fse_rle(f, *(*p)++); }
    else if (mode == 2) { if ((k = fse_read(f, *p, end - *p, maxsym, maxal)) < 0) return -1; *p += k; }
    else if (!*ok) return -1;
    *ok = 1;
    return 0;
}

static int z_block(struct zst *z, const unsigned char *p, size_t n)
{
    const unsigned char *end = p + n;
    size_t nlit, csize = 0, i, li = 0;
    int type, sf, nseq, modes;
    if (!n) return -1;
    type = p[0] & 3; sf = p[0] >> 2 & 3;
    if (type < 2) {
        if (sf == 1) { if (n < 2) return -1; nlit = (p[0] >> 4) + (p[1] << 4); p += 2; }
        else if (sf == 3) { if (n < 3) return -1; nlit = (p[0] >> 4) + (p[1] << 4) + (p[2] << 12); p += 3; }
        else { nlit = p[0] >> 3; p++; }
        if (nlit > 131072 || (size_t)(end - p) < (type ? 1 : nlit)) return -1;
        if (type) { memset(z->lit, *p, nlit); p++; } else { memcpy(z->lit, p, nlit); p += nlit; }
    } else {
        int streams = sf ? 4 : 1;
        uint32_t h;
        if (sf < 2) { if (n < 3) return -1; h = p[0] | p[1] << 8 | p[2] << 16; nlit = h >> 4 & 0x3ff; csize = h >> 14 & 0x3ff; p += 3; }
        else if (sf == 2) { if (n < 4) return -1; h = p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; nlit = h >> 4 & 0x3fff; csize = h >> 18; p += 4; }
        else { if (n < 5) return -1; h = p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24; nlit = h >> 4 & 0x3ffff; csize = (h >> 22) | p[4] << 10; p += 5; }
        if (nlit > 131072 || (size_t)(end - p) < csize) return -1;
        {
            const unsigned char *q = p, *qe = p + csize;
            p += csize;
            if (type == 2) { long k = huf_read(&z->huf, q, csize); if (k < 0) return -1; q += k; z->hufok = 1; }
            else if (!z->hufok) return -1;
            if (streams == 1) { if (huf_stream(&z->huf, q, qe - q, z->lit, nlit)) return -1; }
            else {
                size_t s[4], each = (nlit + 3) / 4, at = 0;
                int j;
                if (qe - q < 6) return -1;
                s[0] = q[0] | q[1] << 8; s[1] = q[2] | q[3] << 8; s[2] = q[4] | q[5] << 8;
                q += 6;
                if (s[0] + s[1] + s[2] > (size_t)(qe - q)) return -1;
                s[3] = (qe - q) - s[0] - s[1] - s[2];
                for (j = 0; j < 4; j++) {
                    size_t c = j < 3 ? each : nlit - 3 * each;
                    if (j == 3 && 3 * each > nlit) return -1;
                    if (huf_stream(&z->huf, q, s[j], z->lit + at, c)) return -1;
                    q += s[j]; at += c;
                }
            }
        }
    }
    if (p >= end) return -1;
    nseq = *p++;
    if (nseq >= 128) {
        if (p >= end) return -1;
        if (nseq < 255) nseq = ((nseq - 128) << 8) + *p++;
        else { if (end - p < 2) return -1; nseq = p[0] + (p[1] << 8) + 0x7f00; p += 2; }
    }
    if (nseq) {
        struct rb b;
        int sl, so, sm;
        if (p >= end) return -1;
        modes = *p++;
        if (z_table(&z->ll, &z->llok, modes >> 6, &p, end, ll_def, 36, 6, 35, 9) ||
            z_table(&z->of, &z->ofok, modes >> 4 & 3, &p, end, of_def, 29, 5, 31, 8) ||
            z_table(&z->ml, &z->mlok, modes >> 2 & 3, &p, end, ml_def, 53, 6, 52, 9) ||
            rb_init(&b, p, end - p)) return -1;
        sl = rb_get(&b, z->ll.al); so = rb_get(&b, z->of.al); sm = rb_get(&b, z->ml.al);
        while (nseq--) {
            int oc = z->of.t[so].sym, mc = z->ml.t[sm].sym, lc = z->ll.t[sl].sym;
            uint64_t off, ml, ll;
            if (oc > 31 || mc > 52 || lc > 35) return -1;
            off = ((uint64_t)1 << oc) + rb_get(&b, oc);
            ml = ml_base[mc] + rb_get(&b, ml_bits[mc]);
            ll = ll_base[lc] + rb_get(&b, ll_bits[lc]);
            if (off > 3) { z->rep[2] = z->rep[1]; z->rep[1] = z->rep[0]; z->rep[0] = off -= 3; }
            else {
                int k = off - 1 + !ll;
                if (k) {
                    off = k == 3 ? z->rep[0] - 1 : z->rep[k];
                    if (k > 1) z->rep[2] = z->rep[1];
                    z->rep[1] = z->rep[0]; z->rep[0] = off;
                } else off = z->rep[0];
            }
            if (nseq) {
                sl = z->ll.t[sl].base + rb_get(&b, z->ll.t[sl].nb);
                sm = z->ml.t[sm].base + rb_get(&b, z->ml.t[sm].nb);
                so = z->of.t[so].base + rb_get(&b, z->of.t[so].nb);
            }
            if (li + ll > nlit || z->wn + ll + ml > z->lim) return -1;
            memcpy(z->w + z->wn, z->lit + li, ll);
            z->wn += ll; li += ll;
            if (off > z->wn) return -1;
            for (i = 0; i < ml; i++, z->wn++) z->w[z->wn] = z->w[z->wn - off];
        }
        if (b.bit) return -1;
    } else if (p != end) return -1;
    if (z->wn + nlit - li > z->lim) return -1;
    memcpy(z->w + z->wn, z->lit + li, nlit - li);
    z->wn += nlit - li;
    return 0;
}

static int unzstd(struct in *r, outfn *out, void *ctx)
{
    struct zst *z = xmalloc(sizeof *z);
    int c, bad = -1, frames = 0;
    memset(z, 0, sizeof *z);
    for (;;) {
        uint32_t magic = 0;
        uint64_t fcs = 0;
        int i, fhd, single, sum, did, fb, last;
        if (frames && in_eof(r)) { bad = 0; break; }
        for (i = 0; i < 4; i++) { if ((c = in_byte(r)) < 0) goto out; magic |= (uint32_t)c << (8 * i); }
        frames++;
        if ((magic & 0xfffffff0) == 0x184d2a50) {
            uint32_t len = 0;
            for (i = 0; i < 4; i++) { if ((c = in_byte(r)) < 0) goto out; len |= (uint32_t)c << (8 * i); }
            while (len--) if (in_byte(r) < 0) goto out;
            continue;
        }
        if (magic != 0xfd2fb528 || (fhd = in_byte(r)) < 0 || fhd & 8) goto out;
        single = fhd >> 5 & 1; sum = fhd >> 2 & 1;
        if (!single) {
            int wd = in_byte(r), e;
            if (wd < 0 || (e = 10 + (wd >> 3)) > 31) goto out;
            z->win = ((size_t)1 << e) + (((size_t)1 << e) >> 3) * (wd & 7);
        }
        did = (int[]){ 0, 1, 2, 4 }[fhd & 3];
        while (did--) if (in_byte(r) < 0) goto out;
        fb = (int[]){ single, 2, 4, 8 }[fhd >> 6];
        for (i = 0; i < fb; i++) { if ((c = in_byte(r)) < 0) goto out; fcs |= (uint64_t)c << (8 * i); }
        if (fb == 2) fcs += 256;
        if (single) z->win = fcs;
        if (z->win > (size_t)1 << 31) goto out;
        if (z->cap < 2 * z->win + 3 * 131072) { free(z->w); z->cap = 2 * z->win + 3 * 131072; z->w = xmalloc(z->cap); }
        z->wn = 0; z->rep[0] = 1; z->rep[1] = 4; z->rep[2] = 8;
        z->hufok = z->llok = z->ofok = z->mlok = 0;
        do {
            uint32_t h = 0, size;
            int type;
            size_t done = z->wn;
            for (i = 0; i < 3; i++) { if ((c = in_byte(r)) < 0) goto out; h |= (uint32_t)c << (8 * i); }
            last = h & 1; type = h >> 1 & 3; size = h >> 3;
            if (type == 3 || size > 131072) goto out;
            if (z->wn + 131072 > z->cap) {
                size_t keep = z->win < z->wn ? z->win : z->wn;
                memmove(z->w, z->w + z->wn - keep, keep);
                z->wn = done = keep;
            }
            z->lim = z->wn + 131072;
            if (type == 1) {
                if ((c = in_byte(r)) < 0) goto out;
                memset(z->w + z->wn, c, size);
                z->wn += size;
            } else {
                for (i = 0; (uint32_t)i < size; i++) { if ((c = in_byte(r)) < 0) goto out; z->blk[i] = c; }
                if (type == 0) { memcpy(z->w + z->wn, z->blk, size); z->wn += size; }
                else if (z_block(z, z->blk, size)) goto out;
            }
            if (z->wn > done) out(ctx, z->w + done, z->wn - done);
        } while (!last);
        if (sum) for (i = 0; i < 4; i++) if (in_byte(r) < 0) goto out;
    }
out:
    free(z->w);
    free(z);
    return bad;
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
    char uname[33], gname[33];
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

/* owners by name, "path\tuser\tgroup": the ids are the build machine's, the names are what the package means */
static struct list named;

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
    if ((*t->uname && strcmp(t->uname, "root")) || (*t->gname && strcmp(t->gname, "root")))
        push(&named, fmt("%s\t%s\t%s", rel, *t->uname ? t->uname : "root", *t->gname ? t->gname : "root"));
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
    memcpy(t->uname, h + 265, 32); t->uname[32] = 0;
    memcpy(t->gname, h + 297, 32); t->gname[32] = 0;
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

/* a pkcs#1 v1.5 signature over digest with the key n, e; kind 1 sha1, 0 sha256, 2 sha512 */
static int rsa_check(const unsigned char *nb, size_t nlen, const unsigned char *eb, size_t elen, const unsigned char *sig, size_t siglen, const unsigned char *digest, int kind)
{
    static const unsigned char info1[] = { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 };
    static const unsigned char info256[] = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };
    static const unsigned char info512[] = { 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 };
    const unsigned char *info = kind == 1 ? info1 : kind == 2 ? info512 : info256;
    size_t ilen = kind == 1 ? sizeof info1 : kind == 2 ? sizeof info512 : sizeof info256, dlen = kind == 1 ? 20 : kind == 2 ? 64 : 32, k, i;
    unsigned n[LIMBS + 1], s[LIMBS + 1], r[LIMBS + 1], ev = 0;
    unsigned char em[LIMBS * 4];
    int top, bit;
    while (nlen && !*nb) nb++, nlen--;
    while (siglen > nlen && !*sig) sig++, siglen--;
    k = nlen;
    if (elen > 4 || siglen > k || big_from(n, nb, nlen) || big_from(s, sig, siglen) || !big_less(s, n)) return -1;
    for (i = 0; i < elen; i++) ev = ev << 8 | eb[i];
    if (!ev) return -1;
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

/* a pkcs#1 v1.5 signature over digest, checked with the public key in keyfile (pem) */
static int rsa_verify(const char *keyfile, const unsigned char *sig, size_t siglen, const unsigned char *digest, int sha1)
{
    unsigned char derbuf[4096];
    const unsigned char *p = derbuf, *end, *nb;
    size_t len, nlen, elen;
    char *pem = slurp(keyfile, NULL), *b, *e;
    if (!pem || !(b = strstr(pem, "KEY-----")) || !(e = strstr(b, "-----END")) || (size_t)(e - b) * 3 / 4 > sizeof derbuf) { free(pem); return -1; }
    *e = 0;
    end = derbuf + unbase64(b + 8, derbuf);
    free(pem);
    if (der(&p, end, 0x30, &len) || der(&p, end, 0x30, &len)) return -1;
    p += len;
    if (der(&p, end, 0x03, &len) || ++p > end || der(&p, end, 0x30, &len)) return -1;
    if (der(&p, end, 0x02, &nlen)) return -1;
    nb = p; p += nlen;
    if (der(&p, end, 0x02, &elen)) return -1;
    {
        size_t k = nlen;
        const unsigned char *q = nb;
        while (k && !*q) q++, k--;
        if (siglen != k) return -1;
    }
    return rsa_check(nb, nlen, p, elen, sig, siglen, digest, sha1);
}

/* ---- OpenPGP, for pacman repos: rsa keys from keyrings, v4 signatures over a whole file ---- */

struct pgpkey { unsigned char fp[20]; const unsigned char *n, *e; size_t nl, el; int algo; };
static struct pgpkey *pgpkeys;
static int npgpkeys, pgploaded;

/* one packet: its tag and body, or -1 */
static int pgp_packet(const unsigned char **p, const unsigned char *end, const unsigned char **body, size_t *len)
{
    const unsigned char *q = *p;
    int c, tag;
    size_t n = 0;
    if (q >= end || !(*q & 0x80)) return -1;
    c = *q++;
    if (c & 0x40) {
        tag = c & 63;
        if (q >= end) return -1;
        if (*q < 192) n = *q++;
        else if (*q < 224) { if (end - q < 2) return -1; n = ((q[0] - 192) << 8) + q[1] + 192; q += 2; }
        else if (*q == 255) { if (end - q < 5) return -1; n = (size_t)q[1] << 24 | q[2] << 16 | q[3] << 8 | q[4]; q += 5; }
        else return -1;
    } else {
        int lt = c & 3, i;
        tag = c >> 2 & 15;
        if (lt == 3) n = end - q;
        else {
            if (end - q < (1 << lt)) return -1;
            for (i = 0; i < 1 << lt; i++) n = n << 8 | *q++;
        }
    }
    if ((size_t)(end - q) < n) return -1;
    *body = q; *len = n; *p = q + n;
    return tag;
}

static int mpi(const unsigned char **p, const unsigned char *end, const unsigned char **v, size_t *n)
{
    size_t bits;
    if (end - *p < 2) return -1;
    bits = (*p)[0] << 8 | (*p)[1];
    *n = (bits + 7) / 8;
    if ((size_t)(end - *p - 2) < *n) return -1;
    *v = *p + 2;
    *p += 2 + *n;
    return 0;
}

/* the binary packets of an armored keyring, every block of it */
static unsigned char *dearmor(char *t, size_t *n)
{
    unsigned char *out = xmalloc(strlen(t) + 1);
    char *s = t, *e;
    size_t o = 0;
    while ((s = strstr(s, "-----BEGIN PGP"))) {
        if (!(s = strstr(s, "\n\n")) && !(s = strstr(s, "\n\r\n"))) break;
        s += 2;
        for (; *s && *s != '=' && *s != '-'; s = e) {
            char c;
            e = s + strcspn(s, "\n");
            c = *e; *e = 0;
            o += unbase64(s, out + o);
            *e = c;
            if (*e) e++;
        }
    }
    *n = o;
    return out;
}

static void pgp_keyring(const char *file, const struct list *revoked)
{
    size_t n;
    unsigned char *t = (unsigned char *)slurp(file, &n);
    if (t && n > 10 && !memcmp(t, "-----", 5)) { unsigned char *b = dearmor((char *)t, &n); free(t); t = b; }
    const unsigned char *p = t, *end = t + (t ? n : 0), *b;
    size_t len;
    int tag;
    while (t && (tag = pgp_packet(&p, end, &b, &len)) >= 0) {
        struct pgpkey k;
        struct hash h;
        unsigned char hd[3] = { 0x99, len >> 8, len };
        const unsigned char *q = b + 6;
        char *fp;
        if ((tag != 6 && tag != 14) || len < 8 || b[0] != 4) continue;
        if (b[5] >= 1 && b[5] <= 3) {
            if (mpi(&q, b + len, &k.n, &k.nl) || mpi(&q, b + len, &k.e, &k.el)) continue;
            k.algo = 1;
        } else if (b[5] == 22) {
            /* ed25519: its oid, then the point as 0x40 and 32 bytes */
            if (q >= b + len || q + 1 + *q > b + len || *q != 9 || memcmp(q + 1, "\x2b\x06\x01\x04\x01\xda\x47\x0f\x01", 9)) continue;
            q += 1 + *q;
            if (mpi(&q, b + len, &k.n, &k.nl) || k.nl != 33 || k.n[0] != 0x40) continue;
            k.n++; k.nl = 32; k.e = NULL; k.el = 0;
            k.algo = 22;
        } else continue;
        hash_init(&h, 1);
        hash_add(&h, hd, 3);
        hash_add(&h, b, len);
        hash_end(&h, k.fp);
        fp = hex(k.fp, 20);
        for (tag = 0; tag < revoked->n && strcasecmp(revoked->v[tag], fp); tag++) {}
        free(fp);
        if (tag < revoked->n) continue;
        if (npgpkeys % 64 == 0) pgpkeys = xrealloc(pgpkeys, (npgpkeys + 64) * sizeof *pgpkeys);
        pgpkeys[npgpkeys++] = k;
    }
}

static char *confdir(void);
static int ed25519_ok(const unsigned char *sig, const unsigned char *pk, const char *m, size_t n);

/* the .gpg keyrings in mag's keys and the ones packages put in /usr/share/pacman/keyrings, without the revoked keys */
static void pgp_load(void)
{
    char *dirs[2], *rev = fmt("%s/usr/share/pacman/keyrings", root), *c = confdir();
    struct list revoked = { 0 };
    int i;
    DIR *d;
    struct dirent *e;
    if (pgploaded++) return;
    dirs[0] = fmt("%s/keys", c); dirs[1] = rev;
    free(c);
    if ((d = opendir(rev))) {
        while ((e = readdir(d))) {
            size_t l = strlen(e->d_name);
            char *f, *t, *line, *next;
            if (l < 8 || strcmp(e->d_name + l - 8, "-revoked")) continue;
            f = fmt("%s/%s", rev, e->d_name);
            for (line = t = slurp(f, NULL); line && *line; line = next) {
                next = strchr(line, '\n');
                if (next) *next++ = 0;
                if (*line) push(&revoked, xstrdup(line));
            }
            free(t); free(f);
        }
        closedir(d);
    }
    for (i = 0; i < 2; i++) {
        if (!(d = opendir(dirs[i]))) continue;
        while ((e = readdir(d))) {
            size_t l = strlen(e->d_name);
            if (l > 4 && !strcmp(e->d_name + l - 4, ".gpg")) { char *f = fmt("%s/%s", dirs[i], e->d_name); pgp_keyring(f, &revoked); free(f); }
        }
        closedir(d);
    }
    list_free(&revoked);
    free(dirs[0]); free(dirs[1]);
}

/* sig is a binary OpenPGP signature of the file: 0 good, -1 bad, 1 no key for it */
static int pgp_verify(const char *file, const unsigned char *sig, size_t siglen)
{
    const unsigned char *p = sig, *b, *q, *issuer = NULL, *v;
    size_t len, hl, ul, vl;
    unsigned char dig[64], tr[6];
    struct hash h;
    int tag, kind, i, area, fd;
    off_t n;
    static unsigned char buf[65536];
    ssize_t r;
    if ((tag = pgp_packet(&p, sig + siglen, &b, &len)) != 2 || len < 12 || b[0] != 4 || b[1] != 0 || (b[2] != 1 && b[2] != 22)) return -1;
    kind = b[3] == 8 ? 0 : b[3] == 10 ? 2 : -1;
    if (kind < 0) return -1;
    hl = b[4] << 8 | b[5];
    if (6 + hl + 2 > len) return -1;
    ul = b[6 + hl] << 8 | b[7 + hl];
    if (8 + hl + ul + 2 > len) return -1;
    for (area = 0; area < 2 && !issuer; area++) {
        const unsigned char *s = area ? b + 8 + hl : b + 6, *se = s + (area ? ul : hl);
        while (s < se && !issuer) {
            size_t sl;
            if (*s < 192) sl = *s++;
            else if (*s < 255) { if (se - s < 2) break; sl = ((s[0] - 192) << 8) + s[1] + 192; s += 2; }
            else { if (se - s < 5) break; sl = (size_t)s[1] << 24 | s[2] << 16 | s[3] << 8 | s[4]; s += 5; }
            if (!sl || (size_t)(se - s) < sl) break;
            if ((s[0] & 127) == 33 && sl == 22 && s[1] == 4) issuer = s + 2;
            s += sl;
        }
    }
    q = b + 8 + hl + ul + 2;
    if (mpi(&q, b + len, &v, &vl)) return -1;
    pgp_load();
    for (i = 0; i < npgpkeys && (!issuer || memcmp(pgpkeys[i].fp, issuer, 20) || pgpkeys[i].algo != (b[2] == 22 ? 22 : 1)); i++) {}
    if (i == npgpkeys) {
        /* no fingerprint subpacket: the 8 byte key id instead */
        const unsigned char *s = b + 8 + hl, *se = s + ul;
        const unsigned char *id = NULL;
        while (s + 2 <= se && !id) { size_t sl = *s++; if (sl >= 192 || (size_t)(se - s) < sl) break; if ((s[0] & 127) == 16 && sl == 9) id = s + 1; s += sl; }
        for (i = 0; id && i < npgpkeys && memcmp(pgpkeys[i].fp + 12, id, 8); i++) {}
        if (!id || i == npgpkeys) return 1;
    }
    if ((fd = open(file, O_RDONLY)) < 0) return -1;
    hash_init(&h, kind);
    while ((r = read(fd, buf, sizeof buf)) > 0) hash_add(&h, buf, r);
    close(fd);
    hash_add(&h, b, 6 + hl);
    n = 6 + hl;
    tr[0] = 4; tr[1] = 0xff; tr[2] = n >> 24; tr[3] = n >> 16; tr[4] = n >> 8; tr[5] = n;
    hash_add(&h, tr, 6);
    hash_end(&h, dig);
    if (dig[0] != b[6 + hl + 2 + ul] || dig[1] != b[6 + hl + 3 + ul]) return -1;
    if (pgpkeys[i].algo == 22) {
        unsigned char rs[64];
        const unsigned char *w;
        size_t wl;
        if (vl > 32 || mpi(&q, b + len, &w, &wl) || wl > 32) return -1;
        memset(rs, 0, 64);
        memcpy(rs + 32 - vl, v, vl);
        memcpy(rs + 64 - wl, w, wl);
        return ed25519_ok(rs, pgpkeys[i].n, (const char *)dig, kind == 2 ? 64 : 32) ? 0 : -1;
    }
    return rsa_check(pgpkeys[i].n, pgpkeys[i].nl, pgpkeys[i].e, pgpkeys[i].el, v, vl, dig, kind) ? -1 : 0;
}

/* ---- ed25519, for the signify signatures of port trees ---- */

static void sha512(const unsigned char *m, size_t n, unsigned char *out)
{
    struct hash h;
    hash_init(&h, 2);
    hash_add(&h, m, n);
    hash_end(&h, out);
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

struct pkg { char *name, *ver, *desc, *csum, *deps, *prov, *size, *isize, *iif, *file, *sig, *mdeps, *base; int prio, repo; };
struct prov { char *key, *ver; struct pkg *p; };

static struct pkg *pkgs;
static int npkgs;
static struct prov *provs;
static int nprovs;
static struct list repo_urls;
static int *kinds;
enum { APK, CRUX, VOID, EXHERBO, PACMAN, AUR };
static const char *const kind_name[] = { "", "crux", "void", "exherbo", "pacman", "aur" };
#define BUILT(k) ((k) != APK && (k) != PACMAN)
/* pacman's version order once a repo is a pacman one: a machine is one or the other */
static int alpm_order;

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
        int k;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        while (*line == ' ' || *line == '\t') line++;
        for (s = line + strlen(line); s > line && (s[-1] == ' ' || s[-1] == '\t' || s[-1] == '\r' || s[-1] == '/'); ) *--s = 0;
        if (!*line || *line == '#') continue;
        kinds = xrealloc(kinds, (repo_urls.n + 1) * sizeof *kinds);
        kinds[repo_urls.n] = APK;
        for (k = CRUX; k <= AUR; k++) {
            size_t n = strlen(kind_name[k]);
            if (!strncmp(line, kind_name[k], n) && (line[n] == ' ' || line[n] == '\t')) {
                for (kinds[repo_urls.n] = k, line += n; *line == ' ' || *line == '\t'; line++) {}
                break;
            }
        }
        if (kinds[repo_urls.n] >= PACMAN) alpm_order = 1;
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

static void db_put_file(const char *f, const char *text);

/* many at once when it is curl; what did not come is fetched again one by one where it is used */
static void fetch_all(const struct list *urls, const struct list *files, const char *dir)
{
    const char *dl = downloader();
    int k;
    if (urls->n && !strncmp(dl, "curl ", 5) && !getenv("MAG_FETCH")) {
        char *cfg = fmt("%s/fetch", dir), *cmd = xstrndup(dl, strlen(dl) - 3);
        struct buf c = { 0 };
        char *av[] = { "/bin/sh", "-c", "set -f; $0 --create-dirs --parallel --parallel-max 8 -K \"$1\"", cmd, cfg, NULL };
        buf_add(&c, "", 0);
        for (k = 0; k < urls->n; k++) {
            char *s = fmt("url = \"%s\"\noutput = \"%s\"\n", urls->v[k], files->v[k]);
            buf_add(&c, s, strlen(s));
            free(s);
        }
        mkpath(dir, 0755);
        db_put_file(cfg, (char *)c.p);
        run(av);
        unlink(cfg);
        free(cfg); free(cmd); free(c.p);
    } else for (k = 0; k < urls->n; k++) download(urls->v[k], files->v[k]);
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
        case 'I': p.isize = line + 2; break;
        case 'i': p.iif = line + 2; break;
        case 'k': p.prio = atoi(line + 2); break;
        case 'F': p.file = line + 2; break;
        case 'G': p.sig = line + 2; break;
        case 'M': p.mdeps = line + 2; break;
        case 'B': p.base = line + 2; break;
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

/* rpm's order, the way pacman has it: alphanumeric runs compared, numbers as numbers, letters below numbers */
static int rpmcmp(const char *a, const char *b, const char *ae, const char *be)
{
    while (a < ae && b < be) {
        const char *x, *y;
        int num, c;
        size_t sa = 0, sb = 0;
        while (a < ae && !isalnum(*a)) a++, sa++;
        while (b < be && !isalnum(*b)) b++, sb++;
        if (a == ae || b == be) break;
        if (sa != sb) return sa < sb ? -1 : 1;
        x = a; y = b;
        if ((num = isdigit(*a))) { while (a < ae && isdigit(*a)) a++; while (b < be && isdigit(*b)) b++; }
        else { while (a < ae && isalpha(*a)) a++; while (b < be && isalpha(*b)) b++; }
        if (y == b) return num ? 1 : -1;
        if (num) {
            while (*x == '0' && x + 1 < a) x++;
            while (*y == '0' && y + 1 < b) y++;
            if (a - x != b - y) return a - x < b - y ? -1 : 1;
        }
        {
            size_t la = a - x, lb = b - y;
            c = strncmp(x, y, la < lb ? la : lb);
            if (!c && la != lb) c = la < lb ? -1 : 1;
        }
        if (c) return c < 0 ? -1 : 1;
    }
    if (a == ae && b == be) return 0;
    return (a == ae && !isalpha(*b)) || (a < ae && isalpha(*a)) ? -1 : 1;
}

/* pacman's: epoch:version-release, the release only when both have one */
static int alpm_vercmp(const char *a, const char *b)
{
    const char *ca = strchr(a, ':'), *cb = strchr(b, ':'), *ra, *rb, *ea = a + strlen(a), *eb = b + strlen(b);
    long xa = 0, xb = 0;
    int c;
    if (!strcmp(a, b)) return 0;
    if (ca) { for (const char *s = a; s < ca; s++) if (!isdigit(*s)) { ca = NULL; break; } }
    if (cb) { for (const char *s = b; s < cb; s++) if (!isdigit(*s)) { cb = NULL; break; } }
    if (ca) { xa = strtol(a, NULL, 10); a = ca + 1; }
    if (cb) { xb = strtol(b, NULL, 10); b = cb + 1; }
    if (xa != xb) return xa < xb ? -1 : 1;
    ra = strrchr(a, '-'); rb = strrchr(b, '-');
    if ((c = rpmcmp(a, b, ra ? ra : ea, rb ? rb : eb))) return c;
    return ra && rb ? rpmcmp(ra + 1, rb + 1, ea, eb) : 0;
}

static int apk_vercmp(const char *a, const char *b);
static int vercmp(const char *a, const char *b) { return alpm_order ? alpm_vercmp(a, b) : apk_vercmp(a, b); }

/* apk's order: 1.2_rc1 < 1.2 < 1.2-r1 < 1.2_p1 < 1.2a < 1.2.1 */
static int apk_vercmp(const char *a, const char *b)
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

static struct pkg *newest(const char *name);
static int installed(const char *name);

/* providers the packages asked for name themselves, like polkit-elogind-libs for polkit-elogind: these win over priority */
static struct list prefer;

static void prefer_deps(const char *name)
{
    struct pkg *p = newest(name);
    struct list w;
    int i;
    if (!p || has(&prefer, name)) return;
    push(&prefer, xstrdup(name));
    if (!p->deps) return;
    w = words(p->deps);
    for (i = 0; i < w.n; i++) {
        struct dep d;
        dep_parse(w.v[i], &d);
        if (!d.neg && newest(d.key)) prefer_deps(d.key);
    }
    list_free(&w);
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
        named = has(&prefer, p->name) || installed(p->name); bnamed = has(&prefer, best->name) || installed(best->name);
        if (named != bnamed) { if (named) best = p; continue; }
        if (p->prio != best->prio) { if (p->prio > best->prio) best = p; continue; }
        /* the same name in two repos: apk takes the newest, pacman the first repo that has it */
        if (!strcmp(p->name, best->name) && !alpm_order ? vercmp(p->ver, best->ver) > 0 : p->repo < best->repo) best = p;
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
        if (BUILT(kinds[pkgs[i].repo]) && !strcmp(pkgs[i].name, name) && (!best || vercmp(pkgs[i].ver, best->ver) > 0)) best = &pkgs[i];
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

static int owned_by_other(const char *path, const char *name)
{
    int i;
    for (i = 0; i < nowners; i++) if (!strcmp(owners[i].path, path) && strcmp(owners[i].pkg, name)) return 1;
    return 0;
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

/* ---- alpm hooks: what pacman runs around a transaction, from /usr/share/libalpm/hooks and /etc/pacman.d/hooks ---- */

/* what a run did, for the hooks: "I path", "U path", "R path", and the same for packages */
static struct list did_files, did_pkgs;

static int alpm_match(const char *p, const char *s)
{
    if (!*p) return !*s;
    if (*p == '*') return alpm_match(p + 1, s) || (*s && alpm_match(p, s + 1));
    if (*p == '[') {
        const char *q = p + 1;
        int neg = *q == '!' || *q == '^', ok = 0;
        for (q += neg; *q && (*q != ']' || q == p + 1 + neg); q++) {
            if (q[1] == '-' && q[2] && q[2] != ']') { if (*s >= *q && *s <= q[2]) ok = 1; q += 2; }
            else if (*q == *s) ok = 1;
        }
        return *q && *s && ok != neg && alpm_match(q + 1, s + 1);
    }
    return *s && (*p == '?' || *p == *s) && alpm_match(p + 1, s + 1);
}

struct trig { int ops, pkg; struct list targets; };
struct hook { char *desc, *exec; int post, needs, ntrig; struct trig trig[8]; };

static char *htrim(char *s)
{
    char *e;
    while (*s == ' ' || *s == '\t') s++;
    for (e = s + strlen(s); e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r'); ) *--e = 0;
    return s;
}

static int hook_read(const char *file, struct hook *h)
{
    char *t = slurp(file, NULL), *line, *next;
    int sec = 0;
    memset(h, 0, sizeof *h);
    if (!t) return -1;
    for (line = t; line; line = next) {
        char *key, *val, *eq;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        key = htrim(line);
        if (!*key || *key == '#') continue;
        if (!strcmp(key, "[Trigger]")) { sec = h->ntrig < 8 ? (h->ntrig++, 1) : 0; continue; }
        if (!strcmp(key, "[Action]")) { sec = 2; continue; }
        val = "";
        if ((eq = strchr(key, '='))) { *eq = 0; val = htrim(eq + 1); key = htrim(key); }
        if (sec == 1) {
            struct trig *g = &h->trig[h->ntrig - 1];
            if (!strcmp(key, "Operation")) g->ops |= !strcmp(val, "Install") ? 1 : !strcmp(val, "Upgrade") ? 2 : !strcmp(val, "Remove") ? 4 : 0;
            else if (!strcmp(key, "Type")) g->pkg = !strcmp(val, "Package");
            else if (!strcmp(key, "Target")) push(&g->targets, xstrdup(val));
        } else if (sec == 2) {
            if (!strcmp(key, "When")) h->post = !strcmp(val, "PostTransaction");
            else if (!strcmp(key, "Exec")) { free(h->exec); h->exec = xstrdup(val); }
            else if (!strcmp(key, "Description")) { free(h->desc); h->desc = xstrdup(val); }
            else if (!strcmp(key, "NeedsTargets")) h->needs = 1;
        }
    }
    free(t);
    return h->exec && h->ntrig ? 0 : -1;
}

static void hook_free(struct hook *h)
{
    int i;
    for (i = 0; i < h->ntrig; i++) list_free(&h->trig[i].targets);
    free(h->desc); free(h->exec);
}

/* the first pattern that matches decides, a ! one against */
static int hook_targets(const struct list *pats, const char *s)
{
    int i;
    for (i = 0; i < pats->n; i++) {
        const char *p = pats->v[i];
        int neg = *p == '!';
        if (alpm_match(p + neg, s)) return !neg;
    }
    return 0;
}

/* Exec split into words the way alpm does it: spaces, quotes and backslashes */
static char **hook_argv(const char *s)
{
    char **av = xmalloc((strlen(s) / 2 + 2) * sizeof *av);
    int n = 0;
    while (*s) {
        char *w = xmalloc(strlen(s) + 1), *o = w, q = 0;
        while (*s == ' ' || *s == '\t') s++;
        if (!*s) { free(w); break; }
        for (; *s && (q || (*s != ' ' && *s != '\t')); s++) {
            if (*s == '\\' && s[1] && q != '\'') { *o++ = *++s; continue; }
            if (!q && (*s == '"' || *s == '\'')) { q = *s; continue; }
            if (q && *s == q) { q = 0; continue; }
            *o++ = *s;
        }
        *o = 0;
        av[n++] = w;
    }
    av[n] = NULL;
    return av;
}

/* runs av inside the root, the lines of in on its standard input */
static int run_in_root(char **av, const struct list *in)
{
    int fd[2] = { -1, -1 }, i;
    pid_t pid;
    if (in && pipe(fd) < 0) die("cannot make a pipe");
    fflush(stdout);
    if ((pid = fork()) < 0) die("cannot fork");
    if (!pid) {
        if (in) { dup2(fd[0], 0); close(fd[0]); close(fd[1]); }
        /* in the root's / like pacman: glibc's hook is ldconfig -r . */
        if ((*root && chroot(root) < 0) || chdir("/") < 0) { fprintf(stderr, "%s: chroot %s: %s\n", prog, root, strerror(errno)); _exit(126); }
        setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
        execvp(av[0], av);
        fprintf(stderr, "%s: %s: %s\n", prog, av[0], strerror(errno));
        _exit(127);
    }
    if (in) {
        close(fd[0]);
        for (i = 0; i < in->n; i++) if (write(fd[1], in->v[i], strlen(in->v[i])) < 0 || write(fd[1], "\n", 1) < 0) break;
        close(fd[1]);
    }
    return wait_for(pid);
}

static int cmp_strp(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

static void run_hooks(int post)
{
    static const char *const where[] = { "/usr/share/libalpm/hooks", "/etc/pacman.d/hooks" };
    struct list names = { 0 }, files = { 0 };
    int i, j, k;
    if (!did_files.n && !did_pkgs.n) return;
    for (i = 0; i < 2; i++) {
        char *d = fmt("%s%s", root, where[i]);
        DIR *dir = opendir(d);
        struct dirent *e;
        while (dir && (e = readdir(dir))) {
            size_t l = strlen(e->d_name);
            char *f;
            if (l < 6 || strcmp(e->d_name + l - 5, ".hook")) continue;
            f = fmt("%s/%s", d, e->d_name);
            for (j = 0; j < names.n && strcmp(names.v[j], e->d_name); j++) {}
            if (j < names.n) { free(files.v[j]); files.v[j] = f; }
            else { push(&names, xstrdup(e->d_name)); push(&files, f); }
        }
        if (dir) closedir(dir);
        free(d);
    }
    for (i = 0; i < names.n; i++) {
        for (j = i + 1; j < names.n; j++)
            if (strcmp(names.v[j], names.v[i]) < 0) { char *t = names.v[i]; names.v[i] = names.v[j]; names.v[j] = t; t = files.v[i]; files.v[i] = files.v[j]; files.v[j] = t; }
    }
    for (i = 0; i < names.n; i++) {
        struct hook h;
        struct list hit = { 0 };
        char lnk[16];
        ssize_t ln = readlink(files.v[i], lnk, sizeof lnk - 1);
        if (ln == 9 && !strncmp(lnk, "/dev/null", 9)) continue;
        if (hook_read(files.v[i], &h)) { hook_free(&h); continue; }
        if (h.post == post)
            for (j = 0; j < h.ntrig; j++) {
                const struct list *did = h.trig[j].pkg ? &did_pkgs : &did_files;
                for (k = 0; k < did->n; k++) {
                    const char *e = did->v[k];
                    int op = *e == 'I' ? 1 : *e == 'U' ? 2 : 4;
                    if (h.trig[j].ops & op && hook_targets(&h.trig[j].targets, e + 2) && !has(&hit, e + 2)) push(&hit, xstrdup(e + 2));
                }
            }
        if (hit.n) {
            char **av = hook_argv(h.exec);
            int rc;
            if (hit.n > 1) qsort(hit.v, hit.n, sizeof *hit.v, cmp_strp);
            printf("==> %s\n", h.desc ? h.desc : names.v[i]);
            if (av[0] && (rc = run_in_root(av, h.needs ? &hit : NULL))) say("%s exited with %d", names.v[i], rc);
            for (k = 0; av[k]; k++) free(av[k]);
            free(av);
        }
        list_free(&hit);
        hook_free(&h);
    }
    list_free(&names); list_free(&files);
}

/* after a run on a pacman machine, its hooks */
static void after_run(void)
{
    if (!alpm_order) return;
    run_hooks(1);
    list_free(&did_files); list_free(&did_pkgs);
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
    char *old = NULL, *t = NULL, *line, *next;
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
    fetch_all(&urls, &files, dir);
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

/* ---- Void's srcpkgs and Exherbo's exheres: a git tree, fetched whole, built with the tree's own helpers ---- */

static int match(const char *p, const char *s)
{
    if (*p == '*') return match(p + 1, s) || (*s && match(p, s + 1));
    if (!*p) return !*s;
    return *s && (*p == '?' || *p == *s) && match(p + 1, s + 1);
}

struct var { char *k, *v; };

static const char *var_get(const struct var *vs, int n, const char *k)
{
    while (n--) if (!strcmp(vs[n].k, k)) return vs[n].v;
    return NULL;
}

/* $x and ${x} of the variables set above it; anything harder stays as it is */
static char *expand(const char *v, const struct var *vs, int n)
{
    struct buf b = { 0 };
    buf_add(&b, "", 0);
    while (*v) {
        if (*v == '$') {
            const char *s = v + 1 + (v[1] == '{'), *e, *val;
            char *k;
            for (e = s; isalnum((unsigned char)*e) || *e == '_'; e++) {}
            if (e > s && (v[1] != '{' || *e == '}')) {
                k = xstrndup(s, e - s);
                val = var_get(vs, n, k);
                free(k);
                if (val) { buf_add(&b, val, strlen(val)); v = e + (v[1] == '{'); continue; }
            }
        }
        buf_add(&b, v++, 1);
    }
    return (char *)b.p;
}

/* the variables a recipe sets at the top level, outside its functions, ifs and cases */
static int top_vars(char *t, struct var **out)
{
    struct var *vs = NULL;
    int n = 0, infn = 0, j;
    char *line, *next, *s;
    for (s = t; (s = strstr(s, "\\\n")); ) s[0] = s[1] = ' ';
    for (line = t; line && *line; line = next) {
        char *k, *v, *val;
        int add;
        size_t l;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        l = strlen(line);
        if (infn) { infn = *line != '}'; continue; }
        if (!isspace((unsigned char)*line) && strstr(line, "()") && l && line[l - 1] == '{') { infn = 1; continue; }
        if (!strncmp(line, "require ", 8)) { vs = xrealloc(vs, (n + 1) * sizeof *vs); vs[n].k = xstrdup("require"); vs[n++].v = xstrdup(line + 8); continue; }
        for (k = line; isalnum((unsigned char)*k) || *k == '_'; k++) {}
        if (k == line || (*k != '=' && (k[0] != '+' || k[1] != '='))) continue;
        add = *k == '+';
        *k = 0;
        v = k + 1 + add;
        if (*v == '"' || *v == '\'') {
            char q = *v++, *e;
            for (;;) {
                for (e = v; *e && (*e != q || (q == '"' && e > v && e[-1] == '\\')); e++) {}
                if (*e || !next) { *e = 0; break; }
                next[-1] = '\n';
                e = strchr(next, '\n');
                next = e ? (*e = 0, e + 1) : NULL;
            }
        } else v[strcspn(v, " \t#;")] = 0;
        val = expand(v, vs, n);
        for (j = n - 1; j >= 0 && strcmp(vs[j].k, line); j--) {}
        if (j >= 0 && add) { char *s = fmt("%s%s", vs[j].v, val); free(vs[j].v); free(val); vs[j].v = s; }
        else if (j >= 0) { free(vs[j].v); vs[j].v = val; }
        else { vs = xrealloc(vs, (n + 1) * sizeof *vs); vs[n].k = xstrdup(line); vs[n++].v = val; }
    }
    *out = vs;
    return n;
}

static void vars_free(struct var *vs, int n)
{
    while (n--) { free(vs[n].k); free(vs[n].v); }
    free(vs);
}

static void entry(struct buf *b, const char *name, const char *ver, const char *desc, const char *deps, const char *prov, const char *path)
{
    char *s = fmt("P:%s\nV:%s\nT:%s\nD:%s\np:%s\nC:%s\nk:-1\n\n", name, ver, desc ? desc : "", deps, prov ? prov : "", path ? path : "");
    char *c;
    for (c = s; *c; c++) if (*c == '\t') *c = ' ';
    buf_add(b, s, strlen(s));
    free(s);
}

static void void_deps(struct buf *d, const char *s)
{
    struct list w = words(s);
    int i;
    for (i = 0; i < w.n; i++) {
        char *n = w.v[i], *dash;
        if (!strncmp(n, "virtual?", 8)) n += 8;
        n[strcspn(n, "<>=")] = 0;
        if ((dash = strrchr(n, '-')) && strchr(dash, '_') && isdigit((unsigned char)dash[1])) *dash = 0;
        if (*n && !strchr(n, '$')) { buf_add(d, " ", 1); buf_add(d, n, strlen(n)); }
        if (!strcmp(n, "automake") || !strcmp(n, "libtool")) buf_add(d, " autoconf", 9);
    }
    list_free(&w);
}

static int void_arch_ok(const char *archs)
{
    const char *m = !strcmp(arch, "x86") ? "i686-musl" : !strcmp(arch, "x86_64") ? "x86_64-musl" : arch;
    struct list w = words(archs);
    int i, pos = 0, in = 0, out = 0;
    for (i = 0; i < w.n; i++) {
        if (*w.v[i] == '~') out |= match(w.v[i] + 1, m);
        else { pos = 1; in |= match(w.v[i], m); }
    }
    list_free(&w);
    return !out && (!pos || in);
}

static void void_entry(struct buf *b, const char *dir, const char *name, const char *prov)
{
    static const char *const tools[][2] = { { "cmake", "cmake" }, { "meson", "meson" }, { "perl-module", "perl" }, { "cargo", "cargo" }, { "go", "go" },
                                            { "python3-module", "python3 py3-setuptools" }, { "python3-pep517", "python3 py3-build py3-installer" } };
    char *f = fmt("%s/srcpkgs/%s/template", dir, name), *t = slurp(f, NULL), *ver;
    const char *v, *r, *a, *bs;
    struct var *vs;
    struct buf d = { 0 };
    int n, i;
    free(f);
    if (!t) return;
    n = top_vars(t, &vs);
    v = var_get(vs, n, "version");
    r = var_get(vs, n, "revision");
    a = var_get(vs, n, "archs");
    if (v && !strchr(v, '$') && !var_get(vs, n, "broken") && !(a && strcmp(a, "noarch") && !void_arch_ok(a))) {
        buf_add(&d, "", 0);
        void_deps(&d, var_get(vs, n, "hostmakedepends") ? var_get(vs, n, "hostmakedepends") : "");
        void_deps(&d, var_get(vs, n, "makedepends") ? var_get(vs, n, "makedepends") : "");
        void_deps(&d, var_get(vs, n, "depends") ? var_get(vs, n, "depends") : "");
        if ((bs = var_get(vs, n, "build_style")))
            for (i = 0; i < 7; i++) if (!strcmp(bs, tools[i][0])) { buf_add(&d, " ", 1); buf_add(&d, tools[i][1], strlen(tools[i][1])); }
        ver = fmt("%s-r%s", v, r ? r : "1");
        entry(b, name, ver, var_get(vs, n, "short_desc"), (char *)d.p + (d.n > 0), prov, NULL);
        free(ver);
        free(d.p);
    }
    vars_free(vs, n);
    free(t);
}

static void void_index(struct buf *b, const char *dir)
{
    char *sp = fmt("%s/srcpkgs", dir);
    struct list names = { 0 }, subs = { 0 }, mains = { 0 };
    DIR *d = opendir(sp);
    struct dirent *e;
    int i, j;
    while (d && (e = readdir(d))) if (e->d_name[0] != '.') push(&names, xstrdup(e->d_name));
    if (d) closedir(d);
    if (names.n) qsort(names.v, names.n, sizeof *names.v, cmp_str);
    for (i = 0; i < names.n; i++) {
        char *f = fmt("%s/%s", sp, names.v[i]), to[256];
        ssize_t k = readlink(f, to, sizeof to - 1);
        if (k > 0) { to[k] = 0; push(&subs, xstrdup(names.v[i])); push(&mains, xstrdup(to)); }
        free(f);
    }
    for (i = 0; i < names.n; i++) {
        struct buf p = { 0 };
        if (has(&subs, names.v[i])) continue;
        buf_add(&p, "", 0);
        for (j = 0; j < subs.n; j++) if (!strcmp(mains.v[j], names.v[i])) { if (p.n) buf_add(&p, " ", 1); buf_add(&p, subs.v[j], strlen(subs.v[j])); }
        void_entry(b, dir, names.v[i], (char *)p.p);
        free(p.p);
    }
    list_free(&names); list_free(&subs); list_free(&mains);
    free(sp);
}

/* the build and run dependencies of an exheres, without what an option turns on: those are off here */
static void exherbo_deps(struct buf *d, const char *s)
{
    struct list w = words(s);
    int i, ann = 0, use = 1, off = 0, depth = 0, offat = 0;
    for (i = 0; i < w.n; i++) {
        char *t = w.v[i], *n;
        size_t l = strlen(t);
        if (!strncmp(t, "[[", 2)) { ann++; continue; }
        if (ann) { if (!strcmp(t, "]]")) ann--; continue; }
        if (!strcmp(t, "(")) { depth++; continue; }
        if (!strcmp(t, ")")) { if (off && depth == offat) off = 0; depth--; continue; }
        if (l > 1 && t[l - 1] == '?') { if (!off) { off = 1; offat = depth + 1; } continue; }
        if (l > 1 && t[l - 1] == ':' && !strchr(t, '/')) { t[l - 1] = 0; use = !strcmp(t, "build") || !strcmp(t, "run") || !strcmp(t, "build+run"); continue; }
        if (!use || off || *t == '!' || !(n = strrchr(t, '/'))) continue;
        n++;
        n[strcspn(n, "[:")] = 0;
        if (*n && !strchr(n, '$')) { buf_add(d, " ", 1); buf_add(d, n, strlen(n)); }
    }
    list_free(&w);
}

static void exherbo_entry(struct buf *b, const char *dir, const char *rel, const char *pn, const char *file)
{
    char *f = fmt("%s/%s", dir, rel), *t = slurp(f, NULL), *ver = xstrndup(file + strlen(pn) + 1, strlen(file) - strlen(pn) - 1 - 10);
    const char *pl, *rq, *plat = !strcmp(arch, "x86") ? "x86" : "amd64";
    struct var *vs;
    struct buf d = { 0 };
    int n, ok = 1;
    free(f);
    if (!t || strstr(ver, "scm")) { free(t); free(ver); return; }
    n = top_vars(t, &vs);
    if ((pl = var_get(vs, n, "PLATFORMS"))) {
        struct list w = words(pl);
        int i;
        for (i = 0, ok = 0; i < w.n; i++) ok |= !strcmp(w.v[i] + (*w.v[i] == '~'), plat);
        list_free(&w);
    }
    if (ok) {
        buf_add(&d, "", 0);
        exherbo_deps(&d, var_get(vs, n, "DEPENDENCIES") ? var_get(vs, n, "DEPENDENCIES") : "");
        if ((rq = var_get(vs, n, "require"))) {
            if (strstr(rq, "autotools")) buf_add(&d, " autoconf automake libtool", 26);
            if (strstr(rq, "cmake")) buf_add(&d, " cmake", 6);
            if (strstr(rq, "meson")) buf_add(&d, " meson", 6);
        }
        entry(b, pn, ver, var_get(vs, n, "SUMMARY"), (char *)d.p + (d.n > 0), NULL, rel);
        free(d.p);
    }
    vars_free(vs, n);
    free(t);
    free(ver);
}

static void exherbo_index(struct buf *b, const char *dir)
{
    char *pd = fmt("%s/packages", dir);
    struct list cats = { 0 };
    DIR *d = opendir(pd), *d2, *d3;
    struct dirent *e;
    int i;
    while (d && (e = readdir(d))) if (e->d_name[0] != '.') push(&cats, xstrdup(e->d_name));
    if (d) closedir(d);
    for (i = 0; i < cats.n; i++) {
        char *cd = fmt("%s/%s", pd, cats.v[i]);
        if ((d2 = opendir(cd))) {
            while ((e = readdir(d2))) {
                char *pn = xstrdup(e->d_name), *dd = fmt("%s/%s", cd, pn);
                struct dirent *e3;
                if (*pn != '.' && (d3 = opendir(dd))) {
                    while ((e3 = readdir(d3))) {
                        size_t l = strlen(e3->d_name);
                        if (l > strlen(pn) + 11 && !strncmp(e3->d_name, pn, strlen(pn)) && e3->d_name[strlen(pn)] == '-' && !strcmp(e3->d_name + l - 10, ".exheres-0")) {
                            char *rel = fmt("packages/%s/%s/%s", cats.v[i], pn, e3->d_name);
                            exherbo_entry(b, dir, rel, pn, e3->d_name);
                            free(rel);
                        }
                    }
                    closedir(d3);
                }
                free(pn); free(dd);
            }
            closedir(d2);
        }
        free(cd);
    }
    list_free(&cats);
    free(pd);
}

/* github and gitlab give a tarball of a branch; a line can also be the tarball itself */
static char *archive_url(const char *u)
{
    size_t n = strlen(u);
    const char *b = strrchr(u, '/');
    if ((n > 7 && !strcmp(u + n - 7, ".tar.gz")) || (n > 4 && !strcmp(u + n - 4, ".tgz"))) return xstrdup(u);
    if (strstr(u, "://github.com/")) return fmt("%s/archive/refs/heads/master.tar.gz", u);
    return fmt("%s/-/archive/master/%s-master.tar.gz", u, b ? b + 1 : u);
}

static int sync_archive(int i)
{
    char *dir = tree_dir(i), *url = archive_url(repo_urls.v[i]), *tgz = fmt("%s/tree.tar.gz", dir), *tmp = fmt("%s/new", dir), *tree = fmt("%s/tree", dir), *idx = fmt("%s/INDEX", dir), *top = NULL;
    struct in *r = xmalloc(sizeof *r);
    struct tar t;
    struct buf b = { 0 };
    DIR *d;
    struct dirent *e;
    int fd, bad = 0;
    printf("==> %s\n", url);
    mkpath(dir, 0755);
    if (download(url, tgz)) { say("could not fetch %s", url); bad = 1; goto out; }
    rmtree(tmp);
    mkpath(tmp, 0755);
    memset(&t, 0, sizeof t);
    t.dir = tmp;
    if ((fd = open(tgz, O_RDONLY)) < 0) die("cannot read %s", tgz);
    in_open(r, fd, 0);
    do {
        if (gunzip(r, tar_out, &t) || t.bad) { bad = 1; break; }
    } while (!in_eof(r));
    tar_free(&t);
    close(fd);
    unlink(tgz);
    if (!bad && (d = opendir(tmp))) {
        while ((e = readdir(d))) if (e->d_name[0] != '.') { if (top) bad = 1; else top = fmt("%s/%s", tmp, e->d_name); }
        closedir(d);
    }
    if (bad || !top) { say("%s did not unpack into one directory", url); bad = 1; goto out; }
    rmtree(tree);
    if (rename(top, tree) < 0) die("cannot rename %s: %s", top, strerror(errno));
    buf_add(&b, "", 0);
    if (kinds[i] == VOID) void_index(&b, tree); else exherbo_index(&b, tree);
    db_put_file(idx, (char *)b.p);
out:
    rmtree(tmp);
    free(r); free(b.p); free(dir); free(url); free(tgz); free(tmp); free(tree); free(idx); free(top);
    return bad;
}

static const char void_sh[] =
    "export XBPS_COMMONDIR=$MAG_TREE/common XBPS_SRCPKGDIR=$MAG_TREE/srcpkgs XBPS_BUILDSTYLEDIR=$MAG_TREE/common/build-style\n"
    "case $MAG_ARCH in x86) XBPS_MACHINE=i686-musl XBPS_WORDSIZE=32 ;; *) XBPS_MACHINE=$MAG_ARCH-musl XBPS_WORDSIZE=64 ;; esac\n"
    "export XBPS_MACHINE XBPS_TARGET_MACHINE=$XBPS_MACHINE XBPS_TARGET_LIBC=musl XBPS_WORDSIZE XBPS_TARGET_WORDSIZE=\n"
    "export XBPS_BUILDDIR=$MAG_WORK XBPS_SRCDISTDIR=$MAG_SRC XBPS_STATEDIR=$MAG_WORK/.xbps XBPS_MAKEJOBS=$(nproc)\n"
    ". $XBPS_COMMONDIR/build-profiles/$XBPS_MACHINE.sh\n"
    "export XBPS_TRIPLET XBPS_CROSS_TRIPLET= CROSS_BUILD=\n"
    "msg_normal() { printf '==> %b' \"$*\"; }\n"
    "msg_warn() { printf 'warning: %b' \"$*\" >&2; }\n"
    "msg_red() { msg_warn \"$@\"; }\n"
    "msg_verbose() { :; }\n"
    "msg_error() { printf '%b' \"$*\" >&2; exit 1; }\n"
    "for f in archive install misc options python replace-interpreter vsed; do . $XBPS_COMMONDIR/environment/setup/$f.sh; done\n"
    ". $XBPS_SRCPKGDIR/$MAG_PORT/template\n"
    "for f in $build_options_default; do eval \"build_option_$f=1\"; done\n"
    "if [ -n \"$build_style\" ]; then\n"
    "    [ ! -r $XBPS_COMMONDIR/environment/build-style/$build_style.sh ] || . $XBPS_COMMONDIR/environment/build-style/$build_style.sh\n"
    "    . $XBPS_BUILDSTYLEDIR/$build_style.sh\n"
    "fi\n"
    ". $XBPS_SRCPKGDIR/$MAG_PORT/template\n"
    "sourcepkg=$pkgname pkgver=$pkgname-${version}_$revision\n"
    "wrksrc=$XBPS_BUILDDIR/$pkgname-$version\n"
    "FILESDIR=$XBPS_SRCPKGDIR/$pkgname/files PATCHESDIR=$XBPS_SRCPKGDIR/$pkgname/patches\n"
    "export XBPS_WRAPPERDIR=$XBPS_STATEDIR/wrappers XBPS_BUILDHELPERDIR=$XBPS_COMMONDIR/build-helper\n"
    "if [ \"$MAG_STEP\" = list ]; then\n"
    "    exec > \"$MAG_OUT\"\n"
    "    set -- $checksum\n"
    "    for f in $distfiles; do\n"
    "        c=${f#*>} c=${c##*/}\n"
    "        printf '%s\\t%s/%s\\t%s\\n' \"${f%>*}\" \"$pkgname-$version\" \"$c\" \"$1\"\n"
    "        shift\n"
    "    done\n"
    "    exit 0\n"
    "fi\n"
    "[ -z \"$broken\" ] || msg_error \"$pkgver is broken in Void: $broken\\n\"\n"
    "[ -f /etc/mag/build.conf ] && . /etc/mag/build.conf\n"
    "export CFLAGS=\"${CFLAGS:--O2 -pipe}\" CXXFLAGS=\"${CXXFLAGS:-${CFLAGS:--O2 -pipe}}\" LDFLAGS\n"
    "export CC=cc CXX=c++ CPP=cpp LD=ld AR=ar AS=as RANLIB=ranlib STRIP=strip NM=nm OBJDUMP=objdump OBJCOPY=objcopy READELF=readelf PKG_CONFIG=pkg-config\n"
    "[ -z \"$disable_parallel_build\" ] || XBPS_MAKEJOBS=1\n"
    "makejobs=-j$XBPS_MAKEJOBS DESTDIR=$MAG_DEST PKGDESTDIR=$MAG_DEST\n"
    "mkdir -p \"$XBPS_STATEDIR\" \"$XBPS_WRAPPERDIR\" \"$DESTDIR\" || exit 1\n"
    "for f in $build_helper; do . $XBPS_BUILDHELPERDIR/$f.sh || exit 1; done\n"
    "cd_wrksrc() { if [ -d \"$wrksrc/$build_wrksrc\" ]; then cd \"$wrksrc/$build_wrksrc\"; elif [ -d \"$wrksrc\" ]; then cd \"$wrksrc\"; fi; }\n"
    "run() { (set -E -x; trap 'exit 1' ERR; \"$@\") || msg_error \"$pkgver: $1 failed\\n\"; }\n"
    "hooks() { local f; for f in \"$@\"; do [ -r $XBPS_COMMONDIR/hooks/$f.sh ] || continue; unset -f hook; . $XBPS_COMMONDIR/hooks/$f.sh; cd_wrksrc; run hook; done; }\n"
    "step() {\n"
    "    local s=$1\n"
    "    shift\n"
    "    cd_wrksrc\n"
    "    hooks $(for h in \"$@\"; do echo pre-$s/$h; done)\n"
    "    if declare -f pre_$s >/dev/null; then cd_wrksrc; run pre_$s; fi\n"
    "    cd_wrksrc\n"
    "    if declare -f do_$s >/dev/null; then run do_$s\n"
    "    else hooks do-$s/00-distfiles do-$s/00-patches\n"
    "    fi\n"
    "    if declare -f post_$s >/dev/null; then cd_wrksrc; run post_$s; fi\n"
    "}\n"
    "mkdir -p \"$wrksrc\"\n"
    "step extract\n"
    "step patch\n"
    ". $XBPS_COMMONDIR/environment/configure/gnu-configure-args.sh\n"
    "step configure 01-override-config\n"
    "step build\n"
    "step install\n"
    "cd \"$DESTDIR\" || exit 1\n"
    "if [ -d usr/lib64 ] && [ ! -L usr/lib64 ]; then mkdir -p usr/lib; cp -a usr/lib64/. usr/lib/; rm -rf usr/lib64; fi\n"
    "find . -name '*.la' -delete\n"
    "rm -f usr/share/info/dir\n"
    "if command -v strip >/dev/null; then\n"
    "    find . -type f \\( -perm -100 -o -name '*.so' -o -name '*.so.*' \\) -exec strip --strip-unneeded {} + 2>/dev/null || :\n"
    "fi\n"
    "find . -depth -type d -empty -delete\n";


static const char exherbo_sh[] =
    "shopt -s extglob\n"
    "die() { echo \"${PNV:-mag}: $*\" >&2; exit 1; }\n"
    "nonfatal() { \"$@\"; }\n"
    "edo() { echo \"$*\" >&2; \"$@\" || die \"$* failed\"; }\n"
    "einfo() { echo \" * $*\"; }\n"
    "elog() { einfo \"$@\"; }\n"
    "ewarn() { echo \" * $*\" >&2; }\n"
    "eerror() { ewarn \"$@\"; }\n"
    "ebegin() { einfo \"$@\"; }\n"
    "eend() { return ${1:-0}; }\n"
    "has() { local x=$1 i; shift; for i in \"$@\"; do [[ $i == \"$x\" ]] && return 0; done; return 1; }\n"
    "hasq() { has \"$@\"; }\n"
    "illegal_in_global_scope() { :; }\n"
    "esandbox() { :; }\n"
    "expecting_tests() { false; }\n"
    "CHOST=$(cc -dumpmachine)\n"
    "exhost() {\n"
    "    case $1 in\n"
    "    --target|--host|--build) echo \"$CHOST\" ;;\n"
    "    --tool-prefix) echo ;;\n"
    "    --is-native) return 0 ;;\n"
    "    *) echo \"$CHOST\" ;;\n"
    "    esac\n"
    "}\n"
    "has_version() { local p=${1##*/}; p=${p%%[:\\[]*}; [[ -d /var/lib/mag/$p ]]; }\n"
    "best_version() { local p=${1##*/}; p=${p%%[:\\[]*}; [[ -f /var/lib/mag/$p/version ]] && echo \"$1-$(cat /var/lib/mag/$p/version)\"; }\n"
    "\n"
    "vcmp() {\n"
    "    local IFS=._- a b i x y\n"
    "    a=($1) b=($2)\n"
    "    for ((i = 0; i < ${#a[@]} || i < ${#b[@]}; i++)); do\n"
    "        x=${a[i]:-0} y=${b[i]:-0}\n"
    "        [[ $x == \"$y\" ]] && continue\n"
    "        if [[ $x =~ ^[0-9]+$ && $y =~ ^[0-9]+$ ]]; then (( 10#$x > 10#$y )); return; fi\n"
    "        [[ $x > $y ]]; return\n"
    "    done\n"
    "    return 1\n"
    "}\n"
    "ever() {\n"
    "    local c=$1 v\n"
    "    shift\n"
    "    case $c in\n"
    "    is_scm) v=${1:-$PV}; [[ $v == scm || $v == *-scm ]] ;;\n"
    "    major) v=${1:-$PV}; echo \"${v%%[._-]*}\" ;;\n"
    "    range)\n"
    "        local a=${1%-*} b=${1#*-} i=1 out= p\n"
    "        [[ $1 == *-* ]] || b=$a\n"
    "        [[ -z $b ]] && b=99\n"
    "        v=${2:-$PV}\n"
    "        for p in ${v//[._-]/ }; do\n"
    "            if (( i >= a && i <= b )); then out+=${out:+.}$p; fi\n"
    "            ((i++))\n"
    "        done\n"
    "        echo \"$out\" ;;\n"
    "    at_least) v=${2:-$PV}; [[ $v == \"$1\" ]] || vcmp \"$v\" \"$1\" ;;\n"
    "    replace) v=${3:-$PV}; local n=$1 r=$2 i=0 out= ch; for ((k=0; k<${#v}; k++)); do ch=${v:k:1}; if [[ $ch == [._-] ]]; then ((++i)); [[ $i == \"$n\" ]] && ch=$r; fi; out+=$ch; done; echo \"$out\" ;;\n"
    "    replace_all) v=${2:-$PV}; echo \"${v//[._-]/$1}\" ;;\n"
    "    delete) ever replace \"$1\" '' \"${2:-$PV}\" ;;\n"
    "    delete_all) v=${1:-$PV}; echo \"${v//[._-]/}\" ;;\n"
    "    split) v=${1:-$PV}; echo \"${v//[._-]/ }\" ;;\n"
    "    split_all) v=${1:-$PV}; echo \"${v//[._-]/ }\" ;;\n"
    "    remainder) v=${1:-$PV}; echo \"${v#*[._-]}\" ;;\n"
    "    *) die \"ever $c is not known here\" ;;\n"
    "    esac\n"
    "}\n"
    "\n"
    "declare -A EXP\n"
    "exlib_of() { local f=${BASH_SOURCE[2]##*/}; echo \"${f%.exlib}\"; }\n"
    "myexparam() {\n"
    "    local b= x=$(exlib_of) k v\n"
    "    [[ $1 == -b ]] && shift\n"
    "    k=${1%%=*} v=${1#*=}\n"
    "    [[ $1 == *=* ]] || v=\n"
    "    if [[ $v == '[' ]]; then\n"
    "        shift; v=\n"
    "        while [[ $# -gt 0 && $1 != ']' ]]; do v+=${v:+ }$1; shift; done\n"
    "    fi\n"
    "    k=${k%\\[\\]}\n"
    "    [[ -v EXP[$x:$k] ]] || EXP[$x:$k]=$v\n"
    "}\n"
    "exparam() {\n"
    "    local b= var= x=$(exlib_of) k\n"
    "    [[ $1 == -b ]] && { b=1; shift; }\n"
    "    [[ $1 == -v ]] && { var=$2; shift 2; }\n"
    "    k=${1%\\[@\\]}\n"
    "    if [[ -n $b ]]; then [[ ${EXP[$x:$k]} == true ]]; return; fi\n"
    "    if [[ -n $var ]]; then\n"
    "        if [[ $1 == *'[@]' ]]; then eval \"$var=(${EXP[$x:$k]})\"; else printf -v \"$var\" '%s' \"${EXP[$x:$k]}\"; fi\n"
    "    else echo \"${EXP[$x:$k]}\"\n"
    "    fi\n"
    "}\n"
    "declare -A LOADED\n"
    "require() {\n"
    "    local name f d k v\n"
    "    while [[ $# -gt 0 ]]; do\n"
    "        name=$1; shift\n"
    "        if [[ $1 == '[' ]]; then\n"
    "            shift\n"
    "            while [[ $# -gt 0 && $1 != ']' ]]; do\n"
    "                k=${1%%=*} v=${1#*=}\n"
    "                shift\n"
    "                if [[ $v == '[' ]]; then\n"
    "                    v=\n"
    "                    while [[ $1 != ']' ]]; do v+=${v:+ }$1; shift; done\n"
    "                    shift\n"
    "                fi\n"
    "                EXP[$name:$k]=$v\n"
    "            done\n"
    "            shift\n"
    "        fi\n"
    "        [[ -n ${LOADED[$name]} ]] && continue\n"
    "        LOADED[$name]=1\n"
    "        f=\n"
    "        for d in \"$PKGDIR\" \"$MAG_TREE/packages/$CATEGORY\" \"$MAG_TREE/exlibs\"; do\n"
    "            [[ -f $d/$name.exlib ]] && { f=$d/$name.exlib; break; }\n"
    "        done\n"
    "        [[ -n $f ]] || die \"no exlib $name\"\n"
    "        source \"$f\"\n"
    "    done\n"
    "}\n"
    "export_exlib_phases() {\n"
    "    local x=$(exlib_of) p\n"
    "    for p in \"$@\"; do eval \"$p() { ${x}_$p \\\"\\$@\\\"; }\"; done\n"
    "}\n"
    "\n"
    "declare -A OPT\n"
    "for o in ncurses truetype crypt openssl ssl bash-completion vim-syntax parts:binaries parts:configuration parts:data parts:development parts:documentation parts:libraries libc:musl providers:eudev providers:openssl providers:libressl providers:elfutils providers:ijg-jpeg providers:jpeg-turbo providers:gtk3 providers:qt5 providers:pkgconf; do OPT[$o]=1; done\n"
    "case $MAG_ARCH in x86) OPT[platform:x86]=1 ;; *) OPT[platform:amd64]=1 ;; esac\n"
    "option() { local o=$1; [[ $o == '!'* ]] && { ! option \"${o#!}\"; return; }; [[ -n ${OPT[$o]} ]]; }\n"
    "optionq() { option \"$@\"; }\n"
    "optionv() { option \"$1\" && echo \"${1##*:}\"; }\n"
    "option_enable() {\n"
    "    set -- $*\n"
    "    local o=$1 f=${2:-${1##*:}} v=$3\n"
    "    if option \"$o\"; then echo \"--enable-$f${v:+=$v}\"; else echo \"--disable-$f\"; fi\n"
    "}\n"
    "option_with() {\n"
    "    set -- $*\n"
    "    local o=$1 f=${2:-${1##*:}} v=$3\n"
    "    if option \"$o\"; then echo \"--with-$f${v:+=$v}\"; else echo \"--without-$f\"; fi\n"
    "}\n"
    "\n"
    "into() { DESTTREE=$1; }\n"
    "insinto() { INSDESTTREE=$1; }\n"
    "exeinto() { EXEDESTTREE=$1; }\n"
    "docinto() { DOCDESTTREE=$1; }\n"
    "insopts() { :; }\n"
    "exeopts() { :; }\n"
    "dodir() { local d; for d; do mkdir -p \"$IMAGE/$d\"; done; }\n"
    "keepdir() { dodir \"$@\"; local d; for d; do touch \"$IMAGE/$d/.keep\"; done; }\n"
    "doins() {\n"
    "    local r= f\n"
    "    [[ $1 == -r ]] && { r=-r; shift; }\n"
    "    mkdir -p \"$IMAGE/$INSDESTTREE\"\n"
    "    for f; do cp -pP $r \"$f\" \"$IMAGE/$INSDESTTREE/\" || die \"doins $f\"; done\n"
    "}\n"
    "newins() { mkdir -p \"$IMAGE/$INSDESTTREE\"; cp -p \"$1\" \"$IMAGE/$INSDESTTREE/$2\" || die \"newins $1\"; }\n"
    "doexe() { local f; mkdir -p \"$IMAGE/$EXEDESTTREE\"; for f; do install -m755 \"$f\" \"$IMAGE/$EXEDESTTREE/\" || die \"doexe $f\"; done; }\n"
    "newexe() { mkdir -p \"$IMAGE/$EXEDESTTREE\"; install -m755 \"$1\" \"$IMAGE/$EXEDESTTREE/$2\" || die \"newexe $1\"; }\n"
    "dobin() { local f; mkdir -p \"$IMAGE/usr/$CHOST/bin\"; for f; do install -m755 \"$f\" \"$IMAGE/usr/$CHOST/bin/\" || die \"dobin $f\"; done; }\n"
    "newbin() { mkdir -p \"$IMAGE/usr/$CHOST/bin\"; install -m755 \"$1\" \"$IMAGE/usr/$CHOST/bin/$2\" || die \"newbin $1\"; }\n"
    "dosbin() { dobin \"$@\"; }\n"
    "newsbin() { newbin \"$@\"; }\n"
    "dolib() { local f; mkdir -p \"$IMAGE/usr/$CHOST/lib\"; for f; do cp -pP \"$f\" \"$IMAGE/usr/$CHOST/lib/\" || die \"dolib $f\"; done; }\n"
    "dolib.so() { dolib \"$@\"; }\n"
    "dolib.a() { dolib \"$@\"; }\n"
    "doheader() { local f; mkdir -p \"$IMAGE/usr/$CHOST/include\"; for f; do cp -p \"$f\" \"$IMAGE/usr/$CHOST/include/\" || die \"doheader $f\"; done; }\n"
    "dodoc() {\n"
    "    local r= f\n"
    "    [[ $1 == -r ]] && { r=-r; shift; }\n"
    "    mkdir -p \"$IMAGE/usr/share/doc/$PNVR/$DOCDESTTREE\"\n"
    "    for f; do [[ -e $f ]] && cp -p $r \"$f\" \"$IMAGE/usr/share/doc/$PNVR/$DOCDESTTREE/\"; done\n"
    "    return 0\n"
    "}\n"
    "newdoc() { mkdir -p \"$IMAGE/usr/share/doc/$PNVR\"; cp -p \"$1\" \"$IMAGE/usr/share/doc/$PNVR/$2\"; }\n"
    "doman() {\n"
    "    local f s\n"
    "    for f; do\n"
    "        s=${f##*.}\n"
    "        [[ $s == [0-9n]* ]] || continue\n"
    "        mkdir -p \"$IMAGE/usr/share/man/man${s:0:1}\"\n"
    "        cp -p \"$f\" \"$IMAGE/usr/share/man/man${s:0:1}/\" || die \"doman $f\"\n"
    "    done\n"
    "}\n"
    "newman() { local s=${2##*.}; mkdir -p \"$IMAGE/usr/share/man/man${s:0:1}\"; cp -p \"$1\" \"$IMAGE/usr/share/man/man${s:0:1}/$2\"; }\n"
    "dosym() { mkdir -p \"$IMAGE/$(dirname \"$2\")\"; ln -sfn \"$1\" \"$IMAGE/$2\"; }\n"
    "emagicdocs() {\n"
    "    local f\n"
    "    for f in README* AUTHORS ChangeLog NEWS THANKS TODO BUGS FAQ CHANGES* \"${DEFAULT_SRC_INSTALL_EXTRA_DOCS[@]}\"; do\n"
    "        [[ -f $f && -s $f ]] && dodoc \"$f\"\n"
    "    done\n"
    "    return 0\n"
    "}\n"
    "alternatives_for() { :; }\n"
    "expart() { :; }\n"
    "here_to() { mkdir -p \"$IMAGE/$1\"; cat > \"$IMAGE/$1/$2\"; chmod \"$3\" \"$IMAGE/$1/$2\"; }\n"
    "hereins() { here_to \"$INSDESTTREE\" \"$1\" 644; }\n"
    "hereexe() { here_to \"$EXEDESTTREE\" \"$1\" 755; }\n"
    "herebin() { here_to \"usr/$CHOST/bin\" \"$1\" 755; }\n"
    "hereenvd() { here_to etc/env.d \"$1\" 644; }\n"
    "hereconfd() { here_to etc/conf.d \"$1\" 644; }\n"
    "hereinitd() { here_to etc/init.d \"$1\" 755; }\n"
    "heredoc() { here_to \"usr/share/doc/$PNVR\" \"$1\" 644; }\n"
    "\n"
    "expatch() {\n"
    "    local p f o=\n"
    "    [[ $1 == -p* ]] && { o=$1; shift; }\n"
    "    for p; do\n"
    "        if [[ -d $p ]]; then for f in \"$p\"/*; do expatch $o \"$f\"; done; continue; fi\n"
    "        [[ -f $p ]] || continue\n"
    "        echo \"patching with ${p##*/}\"\n"
    "        if [[ -n $o ]]; then patch $o -s -N < \"$p\" || die \"patch ${p##*/}\"\n"
    "        else patch -p1 -s -N < \"$p\" || patch -p0 -s -N < \"$p\" || die \"patch ${p##*/}\"; fi\n"
    "    done\n"
    "}\n"
    "emake() { edo make ${MAKEFLAGS:+-j$JOBS} \"$@\"; }\n"
    "econf() {\n"
    "    local src=${ECONF_SOURCE:-.}\n"
    "    edo \"$src/configure\" --prefix=/usr/$CHOST --bindir=/usr/$CHOST/bin --sbindir=/usr/$CHOST/bin --libdir=/usr/$CHOST/lib \\\n"
    "        --libexecdir=/usr/$CHOST/libexec --includedir=/usr/$CHOST/include --datarootdir=/usr/share --datadir=/usr/share \\\n"
    "        --mandir=/usr/share/man --infodir=/usr/share/info --docdir=/usr/share/doc/$PNVR --sysconfdir=/etc --localstatedir=/var \\\n"
    "        --build=$CHOST --host=$CHOST --disable-dependency-tracking \"$@\"\n"
    "}\n"
    "unpack() {\n"
    "    local f\n"
    "    for f; do\n"
    "        [[ $f == */* ]] || f=$FETCHEDDIR/$f\n"
    "        case $f in\n"
    "        *.tar|*.tar.*|*.tgz|*.tbz2|*.txz) edo tar -xf \"$f\" ;;\n"
    "        *.zip) edo unzip -qo \"$f\" ;;\n"
    "        *.gz) gunzip -c \"$f\" > \"$(basename \"${f%.gz}\")\" ;;\n"
    "        *.xz) xz -dc \"$f\" > \"$(basename \"${f%.xz}\")\" ;;\n"
    "        *.bz2) bzip2 -dc \"$f\" > \"$(basename \"${f%.bz2}\")\" ;;\n"
    "        *) cp \"$f\" . ;;\n"
    "        esac\n"
    "    done\n"
    "}\n"
    "\n"
    "default_pkg_setup() { :; }\n"
    "default_src_unpack() { cd \"$WORKBASE\"; [[ -z $A ]] || unpack $A; }\n"
    "default_src_prepare() { expatch \"${DEFAULT_SRC_PREPARE_PATCHES[@]}\"; }\n"
    "default_src_configure() {\n"
    "    local a=() s\n"
    "    [[ -x ${ECONF_SOURCE:-.}/configure ]] || return 0\n"
    "    for s in \"${DEFAULT_SRC_CONFIGURE_OPTION_ENABLES[@]}\"; do a+=($(option_enable \"$s\")); done\n"
    "    for s in \"${DEFAULT_SRC_CONFIGURE_OPTION_WITHS[@]}\"; do a+=($(option_with \"$s\")); done\n"
    "    for s in \"${DEFAULT_SRC_CONFIGURE_OPTIONS[@]}\"; do set -- $s; option \"$1\" && shift && a+=(\"$@\"); done\n"
    "    for s in \"${DEFAULT_SRC_CONFIGURE_TESTS[@]}\"; do set -- $s; [[ -n $2 ]] && a+=(\"$2\"); done\n"
    "    econf \"${DEFAULT_SRC_CONFIGURE_PARAMS[@]}\" \"${a[@]}\"\n"
    "}\n"
    "default_src_compile() { [[ -f Makefile || -f GNUmakefile || -f makefile ]] && emake \"${DEFAULT_SRC_COMPILE_PARAMS[@]}\"; return 0; }\n"
    "default_src_install() {\n"
    "    if [[ -f Makefile || -f GNUmakefile || -f makefile ]]; then emake -j1 DESTDIR=\"$IMAGE\" \"${DEFAULT_SRC_INSTALL_PARAMS[@]}\" install; fi\n"
    "    emagicdocs\n"
    "}\n"
    "for p in pkg_setup src_unpack src_prepare src_configure src_compile src_install; do eval \"$p() { default_$p \\\"\\$@\\\"; }\"; done\n"
    "default() { default_$PHASE \"$@\"; }\n"
    "\n"
    "PKGDIR=$(dirname \"$MAG_FILE\")\n"
    "CATEGORY=$(basename \"$(dirname \"$PKGDIR\")\")\n"
    "PN=$(basename \"$PKGDIR\")\n"
    "f=$(basename \"$MAG_FILE\" .exheres-0)\n"
    "PVR=${f#$PN-} PV=${PVR%-r+([0-9])} PR=r0\n"
    "[[ $PVR == *-r+([0-9]) ]] && PR=${PVR##*-}\n"
    "PNV=$PN-$PV PNVR=$PN-$PVR\n"
    "FILES=$PKGDIR/files WORKBASE=$MAG_WORK/work WORK=$WORKBASE/$PNV IMAGE=$MAG_DEST TEMP=$MAG_WORK/temp FETCHEDDIR=$MAG_SRC/$PN ROOT=/\n"
    "export PN PV PR PVR PNV PNVR CATEGORY FILES WORKBASE IMAGE TEMP FETCHEDDIR ROOT CHOST\n"
    "mkdir -p \"$WORKBASE\" \"$TEMP\" \"$IMAGE\"\n"
    "mkdir -p \"$TEMP/bin\"\n"
    "for t in cc c++ cpp gcc g++ ar as ld nm strip objcopy objdump readelf ranlib pkg-config; do\n"
    "    command -v $t >/dev/null && ln -sf \"$(command -v $t)\" \"$TEMP/bin/$CHOST-$t\"\n"
    "done\n"
    "PATH=$TEMP/bin:$PATH\n"
    "source \"$MAG_FILE\"\n"
    "\n"
    "ex_downloads() {\n"
    "    local skip=0 w out=() d=() mirrors\n"
    "    set -- $DOWNLOADS\n"
    "    while [[ $# -gt 0 ]]; do\n"
    "        w=$1; shift\n"
    "        case $w in\n"
    "        *'?') if option \"${w%\\?}\"; then d+=(0); else d+=(1); fi; shift ;;\n"
    "        '(') d+=(0) ;;\n"
    "        ')') unset 'd[${#d[@]}-1]' ;;\n"
    "        '->') [[ \" ${d[*]} \" == *' 1 '* ]] || out[${#out[@]}-1]=\"${out[${#out[@]}-1]} $1\"; shift ;;\n"
    "        *) [[ \" ${d[*]} \" == *' 1 '* ]] || out+=(\"$w\") ;;\n"
    "        esac\n"
    "    done\n"
    "    for w in \"${out[@]}\"; do\n"
    "        set -- $w\n"
    "        local u=$1 n=${2:-${1##*/}}\n"
    "        if [[ $u == mirror://* ]]; then\n"
    "            local m=${u#mirror://} rest\n"
    "            rest=${m#*/} m=${m%%/*}\n"
    "            u=$(awk -v m=\"$m\" '$1 == m { print $2; exit }' \"$MAG_TREE/metadata/mirrors.conf\")${rest}\n"
    "        fi\n"
    "        printf '%s\\t%s/%s\\t\\n' \"$u\" \"$PN\" \"$n\"\n"
    "    done\n"
    "}\n"
    "if [[ $MAG_STEP == list ]]; then ex_downloads > \"$MAG_OUT\"; exit 0; fi\n"
    "A=$(ex_downloads | cut -f2 | sed 's|.*/||' | tr '\\n' ' ')\n"
    "[ -f /etc/mag/build.conf ] && . /etc/mag/build.conf\n"
    "export CFLAGS=\"${CFLAGS:--O2 -pipe}\" CXXFLAGS=\"${CXXFLAGS:-${CFLAGS:--O2 -pipe}}\" LDFLAGS JOBS=${MAKEFLAGS#-j}\n"
    "JOBS=${JOBS:-$(nproc)}\n"
    "export CC=cc CXX=c++ CPP=cpp LD=ld AR=ar AS=as RANLIB=ranlib STRIP=strip NM=nm PKG_CONFIG=pkg-config\n"
    "for PHASE in pkg_setup src_unpack src_prepare src_configure src_compile src_install; do\n"
    "    if [[ $PHASE == src_unpack ]]; then cd \"$WORKBASE\"; else cd \"$WORK\" 2>/dev/null || cd \"$WORKBASE\"; fi\n"
    "    echo \"==> $PHASE\"\n"
    "    $PHASE\n"
    "done\n"
    "cd \"$IMAGE\" || exit 1\n"
    "if [[ -d usr/$CHOST ]]; then\n"
    "    cp -a \"usr/$CHOST/.\" usr/\n"
    "    rm -rf \"usr/$CHOST\"\n"
    "    grep -rlI \"/$CHOST\" usr/lib usr/share 2>/dev/null | while read -r f; do sed -i -e \"s|/usr/$CHOST|/usr|g\" -e \"s|}/$CHOST|}|g\" \"$f\"; done\n"
    "fi\n"
    "find . -name '*.la' -delete\n"
    "rm -f usr/share/info/dir\n"
    "if command -v strip >/dev/null; then\n"
    "    find . -type f \\( -perm -100 -o -name '*.so' -o -name '*.so.*' \\) -exec strip --strip-unneeded {} + 2>/dev/null || :\n"
    "fi\n"
    "find . -depth -type d -empty -delete\n";


/* what xbps-src or paludis would do: the sources, checked against the checksums Void has (Exherbo has none), then the
 * phases, with the helpers of the tree */
static void build_tree(const struct pkg *p, const char *stage)
{
    int k = kinds[p->repo], told = 0;
    char *dir = tree_dir(p->repo), *tree = fmt("%s/tree", dir), *work = fmt("%s/var/tmp/mag/build/%s", root, p->name);
    char *cache = fmt("%s/var/cache/mag/src", root), *list = fmt("%s/sources", work), *file = fmt("%s/%s", tree, p->csum ? p->csum : "");
    const char *sh = k == VOID ? void_sh : exherbo_sh;
    const char *vars[] = { "MAG_TREE", "MAG_PORT", "MAG_FILE", "MAG_ARCH", "MAG_WORK", "MAG_DEST", "MAG_SRC", "MAG_OUT", "MAG_STEP" };
    char *t, *line, *next;
    struct list files = { 0 }, dirs = { 0 };
    int i;
    printf("==> building %s %s\n", p->name, p->ver);
    rmtree(work);
    rmtree(stage);
    mkpath(work, 0755);
    mkpath(stage, 0755);
    mkpath(cache, 0755);
    setenv("MAG_TREE", in_root(tree), 1);
    setenv("MAG_PORT", p->name, 1);
    setenv("MAG_FILE", in_root(file), 1);
    setenv("MAG_ARCH", arch, 1);
    setenv("MAG_WORK", in_root(work), 1);
    setenv("MAG_DEST", in_root(stage), 1);
    setenv("MAG_SRC", in_root(cache), 1);
    setenv("MAG_OUT", in_root(list), 1);
    setenv("MAG_STEP", "list", 1);
    if (shell(sh)) die("%s: cannot read what it is built from", p->name);
    unsetenv("MAG_STEP");
    t = slurp(list, NULL);
    for (line = t; line && *line; line = next) {
        char *rel, *sum, *c, *f, *have, *base;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!(rel = strchr(line, '\t'))) continue;
        *rel++ = 0;
        if ((sum = strchr(rel, '\t'))) *sum++ = 0; else sum = "";
        c = clean(rel);
        if (!c || strcmp(c, rel) || strpbrk(rel, "'\\")) die("%s: a source with a bad name, %s", p->name, rel);
        free(c);
        base = strrchr(rel, '/') ? strrchr(rel, '/') + 1 : rel;
        if (*sum == '@') die("%s: the checksum of %s is of what is in it, which mag cannot check", p->name, base);
        f = fmt("%s/%s", cache, rel);
        have = exists(f) ? sha256_file(f) : NULL;
        if (!have || (*sum && strcmp(have, sum))) {
            printf("==> fetching %s\n", line);
            free(have);
            mkparent(f);
            if (download(line, f)) die("could not fetch %s", line);
            have = sha256_file(f);
        }
        if (*sum && (!have || strcmp(have, sum))) { unlink(f); die("%s: %s does not match the checksum in its template", p->name, base); }
        if (!*sum && !told++) printf("==> Exherbo has no checksums: the sources of %s are as good as the connection they came over\n", p->name);
        free(f); free(have);
    }
    free(t);
    if (shell(sh)) die("%s did not build, what it left is in %s", p->name, work);
    for (i = 0; i < 9; i++) unsetenv(vars[i]);
    walk(stage, "", &files, &dirs);
    if (!files.n) die("%s built nothing", p->name);
    list_free(&files); list_free(&dirs);
    rmtree(work);
    free(dir); free(tree); free(work); free(cache); free(list); free(file);
}

/* ---- pacman repos (Artix, Arch): the database read into mag's index, packages checked against it and their signature ---- */

static int unpack_any(struct in *r, outfn *out, void *ctx)
{
    int c = in_byte(r);
    if (c < 0) return -1;
    r->pos--;
    return c == 0x1f ? gunzip(r, out, ctx) : c == 0x28 ? unzstd(r, out, ctx) : -1;
}

/* the database's name: .../system/os is system.db */
static char *pac_name(int i)
{
    char *u = xstrdup(repo_urls.v[i]), *s = strrchr(u, '/'), *n;
    if (s && !strcmp(s + 1, "os")) { *s = 0; s = strrchr(u, '/'); }
    n = xstrdup(s ? s + 1 : u);
    free(u);
    return n;
}

static void field(struct buf *b, int k, const char *v)
{
    char h[2] = { k, ':' };
    if (!v || !*v) return;
    buf_add(b, h, 2); buf_add(b, v, strlen(v)); buf_add(b, "\n", 1);
}

static void pac_entry(struct buf *b, char *t)
{
    static const char *const keys[] = { "%NAME%", "%VERSION%", "%DESC%", "%FILENAME%", "%SHA256SUM%", "%PGPSIG%", "%CSIZE%", "%BASE%", "%ISIZE%" };
    char *line, *next, *key = "", *v[9] = { 0 };
    struct buf deps = { 0 }, prov = { 0 };
    int k;
    for (line = t; line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (*line == '%') { key = line; continue; }
        if (!*line) continue;
        for (k = 0; k < 9 && strcmp(key, keys[k]); k++) {}
        if (k < 9) { if (!v[k]) v[k] = line; }
        else if (!strcmp(key, "%DEPENDS%")) { buf_add(&deps, " ", 1); buf_add(&deps, line, strlen(line)); }
        else if (!strcmp(key, "%CONFLICTS%")) { buf_add(&deps, " !", 2); buf_add(&deps, line, strlen(line)); }
        else if (!strcmp(key, "%PROVIDES%")) { buf_add(&prov, " ", 1); buf_add(&prov, line, strlen(line)); }
    }
    if (v[0] && v[1] && v[3] && v[4]) {
        field(b, 'P', v[0]); field(b, 'V', v[1]); field(b, 'T', v[2]); field(b, 'F', v[3]); field(b, 'C', v[4]);
        field(b, 'G', v[5]); field(b, 'S', v[6]); field(b, 'B', v[7]); field(b, 'I', v[8]);
        if (deps.n) field(b, 'D', (char *)deps.p + 1);
        if (prov.n) field(b, 'p', (char *)prov.p + 1);
        buf_add(b, "\n", 1);
    }
    free(deps.p); free(prov.p);
}

static int sync_pacman(int i)
{
    char *name = pac_name(i), *base = repo_base(i), *url = fmt("%s/%s.db", base, name), *d = tree_dir(i), *db = fmt("%s/%s.db", d, name), *ix = fmt("%s/INDEX", d), *tmp = fmt("%s.new", ix);
    struct in *r = xmalloc(sizeof *r);
    struct tar t;
    struct buf b = { 0 };
    int fd = -1, bad = 1, j;
    memset(&t, 0, sizeof t);
    printf("==> %s\n", url);
    mkpath(d, 0755);
    if (download(url, db)) say("could not fetch %s", url);
    else if ((fd = open(db, O_RDONLY)) >= 0) {
        in_open(r, fd, 0);
        if (unpack_any(r, tar_out, &t) || t.bad) say("%s is broken", url);
        else {
            for (j = 0; j < t.nents; j++) {
                size_t l = strlen(t.ents[j].name);
                if (l > 5 && !strcmp(t.ents[j].name + l - 5, "/desc") && t.ents[j].data.p) pac_entry(&b, (char *)t.ents[j].data.p);
            }
            db_put_file(tmp, b.n ? (char *)b.p : "");
            bad = rename(tmp, ix) < 0;
        }
        close(fd);
    }
    tar_free(&t);
    free(r); free(b.p); free(name); free(base); free(url); free(d); free(db); free(ix); free(tmp);
    return bad;
}

static void ent_add(struct tar *t, char *name, char *data)
{
    t->ents = xrealloc(t->ents, (t->nents + 1) * sizeof *t->ents);
    t->ents[t->nents].name = name;
    memset(&t->ents[t->nents].data, 0, sizeof t->ents[t->nents].data);
    buf_add(&t->ents[t->nents].data, data, strlen(data));
    t->nents++;
    free(data);
}

/* checked against the index and its signature, unpacked into stage; .INSTALL's functions become mag's scripts */
static int pac_extract(const char *name, const char *file, const char *stage, struct tar *ctl);

static int pac_unpack(const struct pkg *p, const char *file, const char *stage, struct tar *ctl)
{
    unsigned char *sig;
    char *sum = sha256_file(file);
    size_t n;
    int v;
    if (!sum || !p->csum || strcmp(sum, p->csum)) { say("%s: the package does not match the index", p->name); free(sum); return -1; }
    free(sum);
    if (p->sig) {
        sig = xmalloc(strlen(p->sig) + 4);
        n = unbase64(p->sig, sig);
    } else {
        /* the database left it out: the .sig next to the package */
        char *base = repo_base(p->repo), *url = fmt("%s/%s.sig", base, p->file), *sf = fmt("%s.sig", file);
        if (!exists(sf) && download(url, sf)) { say("%s is not signed", p->name); free(base); free(url); free(sf); return -1; }
        sig = (unsigned char *)slurp(sf, &n);
        free(base); free(url); free(sf);
        if (!sig) return -1;
    }
    v = pgp_verify(file, sig, n);
    free(sig);
    if (v > 0) { say("%s is signed by a key mag does not have", p->name); return -1; }
    if (v) { say("%s: the signature does not match", p->name); return -1; }
    return pac_extract(p->name, file, stage, ctl);
}

static int pac_extract(const char *name, const char *file, const char *stage, struct tar *ctl)
{
    static const char *const fn[][2] = { { "pre-install", "pre_install" }, { "post-install", "post_install" }, { "pre-upgrade", "pre_upgrade" },
        { "post-upgrade", "post_upgrade" }, { "pre-deinstall", "pre_remove" }, { "post-deinstall", "post_remove" } };
    static const char *const meta[] = { ".PKGINFO", ".MTREE", ".BUILDINFO", ".INSTALL", ".CHANGELOG" };
    struct in *r;
    struct tar t;
    char *f, *inst;
    int fd, ok = -1, i;
    memset(ctl, 0, sizeof *ctl);
    if ((fd = open(file, O_RDONLY)) < 0) return -1;
    r = xmalloc(sizeof *r);
    memset(&t, 0, sizeof t);
    rmtree(stage);
    mkpath(stage, 0755);
    t.dir = stage;
    in_open(r, fd, 0);
    do if (unpack_any(r, tar_out, &t) || t.bad) { say("%s: cannot unpack it", name); goto out; } while (!in_eof(r));
    f = fmt("%s/.INSTALL", stage);
    if ((inst = slurp(f, NULL)))
        for (i = 0; i < 6; i++) ent_add(ctl, fmt(".%s", fn[i][0]), fmt("#!/bin/bash\n%s\ndeclare -F %s >/dev/null || exit 0\n%s \"$@\"\n", inst, fn[i][1], fn[i][1]));
    free(inst); free(f);
    for (i = 0; i < 5; i++) { f = fmt("%s/%s", stage, meta[i]); unlink(f); free(f); }
    ok = 0;
out:
    tar_free(&t);
    free(r);
    close(fd);
    return ok;
}

static long id_of(const char *file, const char *name);

/* ---- the AUR: its metadata dump is the index, a PKGBUILD is built with makepkg as nobody ---- */

static void to_buf(void *ctx, const unsigned char *p, size_t n) { buf_add(ctx, p, n); }

/* a JSON string at s (on its quote) into o, without newlines; returns what follows it */
static const char *js_str(const char *s, struct buf *o)
{
    o->n = 0;
    buf_add(o, "", 0);
    for (s++; *s && *s != '"'; s++) {
        char c = *s;
        if (c == '\\' && s[1]) {
            c = *++s;
            if (c == 'u' && isxdigit(s[1]) && isxdigit(s[2]) && isxdigit(s[3]) && isxdigit(s[4])) {
                char h[5] = { s[1], s[2], s[3], s[4], 0 }, u[3];
                unsigned v = strtoul(h, NULL, 16);
                s += 4;
                if (v < 0x80) { c = v < 0x20 ? ' ' : v; buf_add(o, &c, 1); }
                else if (v < 0x800) { u[0] = 0xc0 | v >> 6; u[1] = 0x80 | (v & 63); buf_add(o, u, 2); }
                else if (v < 0xd800 || v > 0xdfff) { u[0] = 0xe0 | v >> 12; u[1] = 0x80 | (v >> 6 & 63); u[2] = 0x80 | (v & 63); buf_add(o, u, 3); }
                continue;
            }
            if (c == 'n' || c == 't' || c == 'r' || c == 'b' || c == 'f') c = ' ';
        }
        if (c == '\n' || c == '\r') c = ' ';
        buf_add(o, &c, 1);
    }
    return *s ? s + 1 : s;
}

static const char *js_ws(const char *s) { while (*s == ' ' || *s == '\n' || *s == '\r' || *s == '\t' || *s == ',') s++; return s; }

static int sync_aur(int i)
{
    char *url = fmt("%s/packages-meta-ext-v1.json.gz", repo_urls.v[i]), *d = tree_dir(i), *gz = fmt("%s/meta.json.gz", d), *ix = fmt("%s/INDEX", d), *tmp = fmt("%s.new", ix);
    struct in *r = xmalloc(sizeof *r);
    struct buf js = { 0 }, out = { 0 }, key = { 0 }, val = { 0 }, f[4] = { { 0 } }, l[3] = { { 0 } };
    int fd = -1, bad = 1, k;
    printf("==> %s\n", url);
    mkpath(d, 0755);
    if (download(url, gz)) say("could not fetch %s", url);
    else if ((fd = open(gz, O_RDONLY)) >= 0) {
        const char *s;
        in_open(r, fd, 0);
        if (gunzip(r, to_buf, &js) || !js.p) { say("%s is broken", url); goto out; }
        s = js_ws((char *)js.p);
        if (*s++ != '[') { say("%s is not the list it should be", url); goto out; }
        for (;;) {
            s = js_ws(s);
            if (*s != '{') break;
            for (k = 0; k < 4; k++) { f[k].n = 0; buf_add(&f[k], "", 0); }
            for (k = 0; k < 3; k++) { l[k].n = 0; buf_add(&l[k], "", 0); }
            for (s++;;) {
                const char *kn;
                int which = -1, list = -1, neg = 0;
                s = js_ws(s);
                if (*s == '}') { s++; break; }
                if (*s != '"') goto out;
                s = js_ws(js_str(s, &key));
                if (*s++ != ':') goto out;
                s = js_ws(s);
                kn = (char *)key.p;
                which = !strcmp(kn, "Name") ? 0 : !strcmp(kn, "Version") ? 1 : !strcmp(kn, "Description") ? 2 : !strcmp(kn, "PackageBase") ? 3 : -1;
                list = !strcmp(kn, "Depends") ? 0 : !strcmp(kn, "Conflicts") ? (neg = 1, 0) : !strcmp(kn, "MakeDepends") || !strcmp(kn, "CheckDepends") ? 1 : !strcmp(kn, "Provides") ? 2 : -1;
                if (*s == '"') {
                    s = js_str(s, &val);
                    if (which >= 0) { f[which].n = 0; buf_add(&f[which], val.p, val.n); }
                } else if (*s == '[') {
                    for (s++;;) {
                        s = js_ws(s);
                        if (*s == ']') { s++; break; }
                        if (*s != '"') goto out;
                        s = js_str(s, &val);
                        if (list >= 0 && val.n && !strchr((char *)val.p, ' ')) {
                            if (l[list].n) buf_add(&l[list], " ", 1);
                            if (neg) buf_add(&l[list], "!", 1);
                            buf_add(&l[list], val.p, val.n);
                        }
                    }
                } else while (*s && *s != ',' && *s != '}') s++;
            }
            if (f[0].n && f[1].n) {
                field(&out, 'P', (char *)f[0].p); field(&out, 'V', (char *)f[1].p); field(&out, 'T', (char *)f[2].p);
                field(&out, 'B', (char *)f[3].p); field(&out, 'D', (char *)l[0].p); field(&out, 'M', (char *)l[1].p); field(&out, 'p', (char *)l[2].p);
                buf_add(&out, "\n", 1);
            }
        }
        db_put_file(tmp, out.n ? (char *)out.p : "");
        bad = rename(tmp, ix) < 0;
    }
out:
    if (fd >= 0) close(fd);
    free(r); free(js.p); free(out.p); free(key.p); free(val.p);
    for (k = 0; k < 4; k++) free(f[k].p);
    for (k = 0; k < 3; k++) free(l[k].p);
    free(url); free(d); free(gz); free(ix); free(tmp);
    return bad;
}

/* the snapshot of the package base, built by makepkg as nobody inside the root; the package it made goes into stage */
static void build_aur(const struct pkg *p, const char *stage, struct tar *ctl)
{
    const char *base = p->base ? p->base : p->name;
    char *top = fmt("%s/var/cache/mag/aur", root), *dir = fmt("%s/%s", top, base), *tgz = fmt("%s/%s.tar.gz", top, base),
        *url = fmt("%s/cgit/aur.git/snapshot/%s.tar.gz", repo_urls.v[p->repo], base), *in = fmt("/var/cache/mag/aur/%s", base), *outd, *built = NULL, *sh;
    struct list files = { 0 }, dirs = { 0 };
    struct in *r = xmalloc(sizeof *r);
    struct tar t;
    long uid = id_of("passwd", "nobody"), gid = id_of("group", "nobody");
    int fd, i;
    DIR *od;
    struct dirent *e;
    char *av[] = { "/usr/bin/setpriv", "--reuid=nobody", "--regid=nobody", "--clear-groups", "/bin/bash", "-c", NULL, NULL };
    if (uid < 0 || gid < 0) die("%s: there is no nobody here to build as", p->name);
    rmtree(dir);
    mkpath(top, 0755);
    printf("==> %s\n", url);
    if (download(url, tgz)) die("could not fetch %s", url);
    memset(&t, 0, sizeof t);
    t.dir = top;
    if ((fd = open(tgz, O_RDONLY)) < 0) die("cannot read %s", tgz);
    in_open(r, fd, 0);
    if (gunzip(r, tar_out, &t) || t.bad) die("%s: the snapshot is broken", p->name);
    close(fd);
    tar_free(&t);
    free(r);
    unlink(tgz);
    walk(dir, "", &files, &dirs);
    lchown(dir, uid, gid);
    for (i = 0; i < files.n; i++) { char *f = fmt("%s/%s", dir, files.v[i]); lchown(f, uid, gid); free(f); }
    for (i = 0; i < dirs.n; i++) { char *f = fmt("%s/%s", dir, dirs.v[i]); lchown(f, uid, gid); free(f); }
    list_free(&files); list_free(&dirs);
    printf("==> building %s from the AUR in %s\n", p->name, in);
    sh = fmt("cd '%s' && export HOME=$PWD BUILDDIR=$PWD/build PKGDEST=$PWD/out SRCDEST=$PWD/src GNUPGHOME=$PWD/.gnupg && mkdir -p out src .gnupg && chmod 700 .gnupg && "
        "for k in $(sed -n 's/^[[:space:]]*validpgpkeys = //p' .SRCINFO); do gpg --batch -q --keyserver hkps://keyserver.ubuntu.com --recv-keys \"$k\" || :; done; "
        "makepkg --nodeps --noconfirm --noprogressbar -f", in);
    av[6] = sh;
    if (run_in_root(av, NULL)) die("%s did not build; what makepkg left is in %s", p->name, in);
    free(sh);
    outd = fmt("%s/out", dir);
    /* NAME-VERSION-RELEASE-ARCH.pkg.tar.*: the version can be newer than the index says, a -git one sets its own */
    if ((od = opendir(outd))) {
        while ((e = readdir(od)) && !built) {
            char *n = xstrdup(e->d_name), *x = strstr(n, ".pkg.tar"), *c;
            int dashes = 0;
            if (x && !strstr(n, ".sig")) {
                for (*x = 0, c = x; c > n && dashes < 3; ) if (*--c == '-') dashes++;
                if (dashes == 3) { *c = 0; if (!strcmp(n, p->name)) built = fmt("%s/%s", outd, e->d_name); }
            }
            free(n);
        }
        closedir(od);
    }
    if (!built) die("%s: makepkg made no package called that", p->name);
    if (pac_extract(p->name, built, stage, ctl)) die("%s: cannot unpack what makepkg made", p->name);
    free(built); free(outd); free(top); free(dir); free(tgz); free(url); free(in);
}

/* ---- installing a package ---- */

static char *pkg_file(const struct pkg *p)
{
    if (kinds[p->repo] == PACMAN) return fmt("%s/var/cache/mag/pkg/%s", root, p->file);
    return fmt("%s/var/cache/mag/pkg/%s-%s.apk", root, p->name, p->ver);
}

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
    char *base = repo_base(p->repo), *url = kinds[p->repo] == PACMAN ? fmt("%s/%s", base, p->file) : fmt("%s/%s-%s.apk", base, p->name, p->ver);
    printf("==> fetching %s\n", url);
    if (download(url, file)) die("could not fetch %s", url);
    free(base); free(url);
}

/* is the file at full still what the package put there, by the sums mag kept of its /etc files */
static int etc_untouched(const struct list *sums, const char *rel, const char *full)
{
    int i, same = 0;
    char *sum;
    for (i = 0; i < sums->n; i++) {
        const char *sp = strchr(sums->v[i], ' ');
        if (!sp || strcmp(sp + 1, rel)) continue;
        if ((sum = sha256_file(full))) { same = !strncmp(sums->v[i], sum, sp - sums->v[i]); free(sum); }
        break;
    }
    return same;
}

/* the id of NAME in the root's passwd or group file, or -1 */
static long id_of(const char *file, const char *name)
{
    char *f = fmt("%s/etc/%s", root, file), *t = slurp(f, NULL), *line, *next;
    long id = -1;
    size_t n = strlen(name);
    for (line = t; line && *line && id < 0; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (!strncmp(line, name, n) && line[n] == ':') {
            char *c = strchr(line + n + 1, ':');
            if (c) id = strtol(c + 1, NULL, 10);
        }
    }
    free(t); free(f);
    return id;
}

/* the owner a file of the package gets here: by the names in the package, once its pre-install made the users */
static int owner_here(const char *rel, struct stat *st)
{
    int i;
    size_t n = strlen(rel);
    for (i = 0; i < named.n; i++) {
        char *u, *g;
        long id;
        if (strncmp(named.v[i], rel, n) || named.v[i][n] != '\t') continue;
        u = named.v[i] + n + 1;
        g = strchr(u, '\t');
        if (!g) return 0;
        *g = 0;
        if ((id = !strcmp(u, "root") ? 0 : id_of("passwd", u)) >= 0) st->st_uid = id;
        *g = '\t';
        if ((id = !strcmp(g + 1, "root") ? 0 : id_of("group", g + 1)) >= 0) st->st_gid = id;
        return 1;
    }
    return 0;
}

static void install_one(struct pkg *p, int explicit, const struct list *planned)
{
    static const char *const scripts[] = { "pre-install", "post-install", "pre-upgrade", "post-upgrade", "pre-deinstall", "post-deinstall", "trigger" };
    char *file = pkg_file(p), *stage = fmt("%s/var/tmp/mag/%s", root, p->name), *oldver = db_get(p->name, "version"), *trig;
    struct list files = { 0 }, dirs = { 0 }, old, gone = { 0 }, deps = { 0 }, w, v = { 0 }, pr = { 0 }, sums, newsums = { 0 };
    struct tar ctl;
    int i, bad = 0, port = BUILT(kinds[p->repo]);
    int (*un)(const struct pkg *, const char *, const char *, struct tar *) = kinds[p->repo] == PACMAN ? pac_unpack : unpack;
    list_free(&named);
    if (port) {
        memset(&ctl, 0, sizeof ctl);
        if (kinds[p->repo] == AUR) build_aur(p, stage, &ctl);
        else if (kinds[p->repo] == CRUX) build_port(p, stage); else build_tree(p, stage);
    } else {
        int fresh = !exists(file);
        if (fresh) fetch_pkg(p, file);
        if (un(p, file, stage, &ctl)) {
            unlink(file);
            if (fresh) die("not installing %s", p->name);
            fetch_pkg(p, file);
            if (un(p, file, stage, &ctl)) { unlink(file); die("not installing %s", p->name); }
        }
    }
    walk(stage, "", &files, &dirs);
    load_owners();
    old = db_read(p->name, "files");
    for (i = 0; i < files.n; i++) {
        struct stat st;
        const char *o = owner_of(files.v[i]);
        char *full = fmt("%s/%s", root, files.v[i]);
        /* a package upgraded in the same run may be letting go of the file, as chamesle-base did of /sbin/service */
        if (o && strcmp(o, p->name) && !has(planned, o)) { if (bad < 5) say("%s wants /%s, which %s has", p->name, files.v[i], o); bad++; }
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

    sums = db_read(p->name, "etcsums");
    for (i = 0; i < dirs.n; i++) {
        char *from = fmt("%s/%s", stage, dirs.v[i]), *to = fmt("%s/%s", root, dirs.v[i]);
        struct stat st;
        if (lstat(from, &st)) { free(from); free(to); continue; }
        if (!exists(to)) {
            owner_here(dirs.v[i], &st);
            mkpath(to, 0755);
            chmod(to, st.st_mode & 07777);
            if (!geteuid()) lchown(to, st.st_uid, st.st_gid);
        } else if (owner_here(dirs.v[i], &st) && !geteuid()) lchown(to, st.st_uid, st.st_gid);
        free(from); free(to);
    }
    for (i = 0; i < files.n; i++) {
        char *from = fmt("%s/%s", stage, files.v[i]), *to = fmt("%s/%s", root, files.v[i]), *slash;
        struct stat st;
        mkparent(to);
        if (lstat(from, &st) < 0) die("cannot stat %s", from);
        owner_here(files.v[i], &st);
        if (S_ISLNK(st.st_mode)) {
            char tgt[PATH_MAX];
            ssize_t n = readlink(from, tgt, sizeof tgt - 1);
            if (n < 0) die("cannot read link %s", from);
            tgt[n] = 0;
            unlink(to);
            if (symlink(tgt, to) < 0) { say("cannot link %s: %s", to, strerror(errno)); bad = 1; }
            else if (!geteuid()) lchown(to, st.st_uid, st.st_gid);
        } else if (!strncmp(files.v[i], "etc/", 4) && exists(to) && !same_file(from, to) && !etc_untouched(&sums, files.v[i], to)) {
            char *alt = fmt("%s.new", to);
            printf("==> /%s is changed here, the new one is /%s.new\n", files.v[i], files.v[i]);
            if (copy_into(from, alt, &st) < 0) { say("cannot write %s: %s", alt, strerror(errno)); bad = 1; }
            free(alt);
        } else if (copy_into(from, to, &st) < 0) { say("cannot write %s: %s", to, strerror(errno)); bad = 1; }
        if (!strncmp(files.v[i], "etc/", 4) && S_ISREG(st.st_mode)) {
            char *sum = sha256_file(from);
            if (sum) { push(&newsums, fmt("%s %s", sum, files.v[i])); free(sum); }
        }
        /* the directory and the ones above it: shared-mime-info watches /usr/share/mime for files in packages/ */
        for (slash = strchr(files.v[i], '/'); slash; slash = strchr(slash + 1, '/')) {
            char *dir = fmt("/%.*s", (int)(slash - files.v[i]), files.v[i]);
            if (!has(&changed_dirs, dir)) push(&changed_dirs, dir); else free(dir);
        }
        free(from); free(to);
    }
    if (bad) die("%s did not install cleanly", p->name);
    for (i = 0; i < old.n; i++) if (!has(&files, old.v[i]) && !owned_by_other(old.v[i], p->name)) push(&gone, old.v[i]);
    if (alpm_order) {
        for (i = 0; i < files.n; i++) push(&did_files, fmt("%c %s", oldver && has(&old, files.v[i]) ? 'U' : 'I', files.v[i]));
        for (i = 0; i < dirs.n; i++) push(&did_files, fmt("%c %s/", oldver ? 'U' : 'I', dirs.v[i]));
        for (i = 0; i < gone.n; i++) push(&did_files, fmt("R %s", gone.v[i]));
        push(&did_pkgs, fmt("%c %s", oldver ? 'U' : 'I', p->name));
    }
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
    db_write(p->name, "etcsums", &newsums);
    if ((trig = pkginfo(&ctl, "triggers"))) db_put(p->name, "triggers", trig, strlen(trig), 0644);
    if (explicit) db_put(p->name, "explicit", "", 0, 0644);
    if (port) db_put(p->name, "port", repo_urls.v[p->repo], strlen(repo_urls.v[p->repo]), 0644);
    else { char *d = dbdir(p->name), *f = fmt("%s/port", d); unlink(f); free(d); free(f); }
    free(trig);
    tar_free(&ctl);
    if (oldver) script_or_later(p->name, "post-upgrade", p->ver, oldver);
    else script_or_later(p->name, "post-install", p->ver, NULL);
    printf("==> installed %s %s%s%s\n", p->name, p->ver, oldver ? ", was " : "", oldver ? oldver : "");
    list_free(&files); list_free(&dirs); list_free(&old); list_free(&sums); list_free(&newsums); free(gone.v); list_free(&deps); free(v.v); free(pr.v);
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

/* the name a Void or Exherbo dependency goes by in the repos: Void's -devel is their -dev, and what comes built wins */
static char *port_dep(int kind, const char *w)
{
    static const char *const alias[][2] = { { "pkg-config", "pkgconf" }, { "liblzma", "xz" }, { "libuuid", "util-linux" }, { "gettext-tiny", "gettext" } };
    char *n = xstrdup(w), *c[3] = { 0 }, *best = NULL;
    size_t l = strlen(n);
    int i, dev = kind == VOID && l > 6 && !strcmp(n + l - 6, "-devel");
    struct pkg *q;
    if (dev) n[l - 6] = 0;
    for (i = 0; i < 4; i++) if (!strcmp(n, alias[i][0])) { free(n); n = xstrdup(alias[i][1]); break; }
    if (dev) { c[0] = fmt("%s-dev", n); if (!strncmp(n, "lib", 3)) c[1] = fmt("%s-dev", n + 3); }
    c[2] = xstrdup(n);
    for (i = 0; i < 3 && !best; i++) if (c[i] && (q = newest(c[i])) && kinds[q->repo] == APK) best = c[i];
    for (i = 0; i < 3 && !best; i++) if (c[i] && newest(c[i])) best = c[i];
    best = xstrdup(best ? best : n);
    for (i = 0; i < 3; i++) free(c[i]);
    free(n);
    return best;
}

static void plan(struct pkg *p, struct list *order, struct list *stack)
{
    struct list w;
    int i, j, k = kinds[p->repo], port = BUILT(k), tree = k == VOID || k == EXHERBO;
    char *all;
    if (has(order, p->name) || has(stack, p->name)) return;
    push(stack, p->name);
    if (port && k != AUR) { plan_tool("build-base", order, stack); plan_tool("pkgconf", order, stack); plan_tool("bash", order, stack); }
    if (tree) { plan_tool("tar", order, stack); plan_tool("xz", order, stack); }
    if (k == AUR) { plan_tool("base-devel", order, stack); plan_tool("git", order, stack); }
    all = fmt("%s %s", p->deps ? p->deps : "", p->mdeps ? p->mdeps : "");
    w = words(all);
    free(all);
    for (i = 0; i < w.n; i++) {
        struct dep d;
        struct pkg *c;
        int done = 0;
        if (tree) { char *m = port_dep(k, w.v[i]); dep_parse(m, &d); free(m); }
        else dep_parse(w.v[i], &d);
        if (d.neg || !strcmp(d.key, p->name)) continue;
        for (j = 0; j < order->n && !done; j++) {
            struct pkg *q = newest(order->v[j]);
            done = q && meets(&d, q->name, q->ver, q->prov);
        }
        if (!done && !installed_for(&d)) {
            for (j = 0, c = NULL; j < wanted.n && !c; j++) {
                struct pkg *q = newest(wanted.v[j]);
                if (q && meets(&d, q->name, q->ver, q->prov)) c = q;
            }
            if (!c && !(c = pick(&d))) {
                if (!tree) die("%s needs %s, which no repo has", p->name, w.v[i]);
                say("%s wants %s, which no repo has, building without it", p->name, w.v[i]);
                continue;
            }
            plan(c, order, stack);
        }
        if (port && k != AUR) {
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

/* install_if: a package that comes by itself once all it names is installed or coming, like foo-openrc with openrc and foo */
static int coming(const char *tok, const struct list *order)
{
    struct dep d;
    int j;
    dep_parse(tok, &d);
    for (j = 0; j < order->n; j++) {
        struct pkg *q = newest(order->v[j]);
        if (q && meets(&d, q->name, q->ver, q->prov)) return !d.neg;
    }
    return d.neg ? !installed_for(&d) : installed_for(&d) != NULL;
}

/* Artix keeps a daemon's OpenRC service in NAME-openrc (or BASE-openrc), which nothing depends on: it comes along */
static int plan_openrc(struct list *order, struct list *stack)
{
    int i, k, more = 0;
    for (i = 0; alpm_order && i < order->n; i++) {
        struct pkg *p = newest(order->v[i]), *s;
        const char *names[2];
        if (!p) continue;
        names[0] = p->name; names[1] = p->base;
        for (k = 0; k < 2; k++) {
            char *n;
            if (!names[k] || (k && !strcmp(names[0], names[1]))) continue;
            n = fmt("%s-openrc", names[k]);
            if (!has(order, n) && !installed(n) && (s = newest(n))) { plan(s, order, stack); more = 1; }
            free(n);
        }
    }
    return more;
}

static void plan_install_ifs(struct list *order, struct list *stack)
{
    int i, j, ok, more = 1;
    while (more) {
        more = plan_openrc(order, stack);
        for (i = 0; i < npkgs; i++) {
            struct pkg *p = &pkgs[i];
            struct list w;
            if (!p->iif || has(order, p->name) || newest(p->name) != p || installed(p->name)) continue;
            w = words(p->iif);
            for (j = 0, ok = 1; j < w.n && ok; j++) ok = coming(w.v[j], order);
            list_free(&w);
            if (ok) { plan(p, order, stack); more = 1; }
        }
    }
}

/* the directories changed by a run that did not get to its triggers, so the next run runs them */
static char *pending_file(void) { return fmt("%s/var/lib/mag/.triggers", root); }

static void pending_save(void)
{
    char *f = pending_file();
    struct buf b = { 0 };
    int i;
    buf_add(&b, "", 0);
    for (i = 0; i < changed_dirs.n; i++) { buf_add(&b, changed_dirs.v[i], strlen(changed_dirs.v[i])); buf_add(&b, "\n", 1); }
    mkparent(f);
    db_put_file(f, (char *)b.p);
    free(b.p); free(f);
}

static void pending_load(void)
{
    char *f = pending_file(), *t = slurp(f, NULL), *line, *next;
    for (line = t; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (*line && !has(&changed_dirs, line)) push(&changed_dirs, xstrdup(line));
    }
    free(t); free(f);
}

static const char *bold(void) { return isatty(1) ? "\033[1m" : ""; }
static const char *plain(void) { return isatty(1) ? "\033[0m" : ""; }

static const char *hsize(double b)
{
    static char s[2][32];
    static int k;
    const char *u[] = { "B", "KiB", "MiB", "GiB" };
    int i = 0;
    for (; b >= 1024 && i < 3; i++) b /= 1024;
    k ^= 1;
    snprintf(s[k], sizeof s[k], i ? "%.1f %s" : "%.0f %s", b, u[i]);
    return s[k];
}

static char *repo_label(int i)
{
    const char *u = repo_urls.v[i], *s;
    if (kinds[i] == PACMAN) return pac_name(i);
    if (kinds[i] == AUR) return xstrdup("aur");
    s = strrchr(u, '/');
    return xstrdup(s && s[1] ? s + 1 : u);
}

/* y/n on a terminal; -y or MAG_YES says yes without asking */
static int ask(const char *what)
{
    char c[16];
    ssize_t n;
    const char *e = getenv("MAG_YES");
    if (yes || (e && *e) || !isatty(0)) return 1;
    printf("%s? [Y/n] ", what);
    fflush(stdout);
    if ((n = read(0, c, sizeof c - 1)) <= 0) { putchar('\n'); return 0; }
    return *c == '\n' || *c == 'y' || *c == 'Y';
}

static int apply(const struct list *order, const struct list *want)
{
    int i;
    if (!dry && !geteuid()) {
        pending_load();
        if (!order->n && changed_dirs.n) {
            char *f = pending_file();
            puts("running the triggers a run before this one did not get to");
            triggers(&changed_dirs);
            unlink(f); free(f);
        }
    }
    if (!order->n) return 0;
    {
        double dl = 0, in = 0;
        int w = 0, wv = 0;
        for (i = 0; i < order->n; i++) {
            struct pkg *p = newest(order->v[i]);
            if ((int)strlen(p->name) > w) w = strlen(p->name);
            if ((int)strlen(p->ver) > wv) wv = strlen(p->ver);
        }
        printf("%sinstall (%d)%s\n", bold(), order->n, plain());
        for (i = 0; i < order->n; i++) {
            struct pkg *p = newest(order->v[i]);
            char *old = db_get(p->name, "version"), *from = repo_label(p->repo);
            printf("  %-*s  %-*s  %s", w, p->name, wv, p->ver, from);
            if (BUILT(kinds[p->repo])) printf(", built here");
            if (old) printf(", was %s", old);
            putchar('\n');
            if (!BUILT(kinds[p->repo]) && p->size) dl += atof(p->size);
            if (p->isize) in += atof(p->isize);
            free(old); free(from);
        }
        printf("\ndownload %s", hsize(dl));
        printf(", installed %s\n", hsize(in));
    }
    if (dry) return 0;
    if (geteuid()) die("this needs root");
    if (!ask("install")) return 1;
    {
        char *f = fmt("%s/etc/mag/arch", root);
        if (!exists(f)) { mkparent(f); db_put_file(f, arch); }
        free(f);
    }
    {
        struct list urls = { 0 }, files = { 0 };
        char *dir = NULL;
        for (i = 0; i < order->n; i++) {
            struct pkg *p = newest(order->v[i]);
            char *file, *base;
            if (BUILT(kinds[p->repo]) || exists(file = pkg_file(p))) continue;
            base = repo_base(p->repo);
            if (!dir) { dir = xstrdup(file); *strrchr(dir, '/') = 0; }
            push(&urls, kinds[p->repo] == PACMAN ? fmt("%s/%s", base, p->file) : fmt("%s/%s-%s.apk", base, p->name, p->ver));
            push(&files, file);
            if (kinds[p->repo] == PACMAN && !p->sig) { push(&urls, fmt("%s/%s.sig", base, p->file)); push(&files, fmt("%s.sig", file)); }
            free(base);
        }
        if (urls.n > 1) { printf("==> fetching %d files\n", urls.n); fetch_all(&urls, &files, dir); }
        list_free(&urls); list_free(&files); free(dir);
    }
    for (i = 0; i < order->n; i++) {
        struct pkg *p = newest(order->v[i]);
        install_one(p, has(want, p->name), order);
        pending_save();
    }
    run_waiting();
    triggers(&changed_dirs);
    after_run();
    {
        char *f = pending_file();
        unlink(f); free(f);
    }
    return 0;
}

static int cmd_install(int n, char **names)
{
    struct list order = { 0 }, stack = { 0 }, want = { 0 };
    int i;
    load_index();
    for (i = 0; i < n; i++) push(&wanted, names[i]);
    for (i = 0; i < n; i++) prefer_deps(names[i]);
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
    plan_install_ifs(&order, &stack);
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
    plan_install_ifs(&order, &stack);
    if (!order.n) { puts("everything is up to date"); return 0; }
    return apply(&order, &want);
}

static int cmd_update(void)
{
    int i, bad = 0;
    for (i = 0; i < repo_urls.n; i++) {
        char *base, *url, *f, *tmp;
        if (kinds[i] == PACMAN) { bad |= sync_pacman(i); continue; }
        if (kinds[i] == AUR) { bad |= sync_aur(i); continue; }
        if (kinds[i] != APK) { bad |= kinds[i] == CRUX ? sync_tree(i) : sync_archive(i); continue; }
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
        if (!port_of(names[i])) {
            int j;
            for (j = 0; j < npkgs; j++) {
                struct list pv;
                if (!BUILT(kinds[pkgs[j].repo]) || !pkgs[j].prov) continue;
                pv = words(pkgs[j].prov);
                if (has(&pv, names[i])) names[i] = pkgs[j].name;
                list_free(&pv);
            }
        }
        if (!port_of(names[i])) die("%s is in no port tree", names[i]);
        push(&from_ports, names[i]);
    }
    return cmd_install(n, names);
}

static int cmd_remove(int n, char **names)
{
    int i;
    for (i = 0; alpm_order && !dry && i < n; i++) {
        struct list files = installed(names[i]) ? db_read(names[i], "files") : (struct list){ 0 };
        int k;
        for (k = 0; k < files.n; k++) push(&did_files, fmt("R %s", files.v[k]));
        push(&did_pkgs, fmt("R %s", names[i]));
        list_free(&files);
    }
    if (!dry) {
        printf("%sremove (%d)%s\n ", bold(), n, plain());
        for (i = 0; i < n; i++) printf(" %s", names[i]);
        putchar('\n');
        if (!ask("remove")) return 1;
    }
    run_hooks(0);
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
    if (!dry) after_run();
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
    char *v = db_get(name, "version"), *port = db_get(name, "port");
    load_index();
    if (port) push(&from_ports, xstrdup(name));
    free(port);
    p = newest(name);
    if (!p && !v) die("%s is in no repo and not installed", name);
    if (p) {
        printf("%s %s\n", p->name, p->ver);
        if (p->desc) printf("  %s\n", p->desc);
        if (p->deps) printf("  needs: %s\n", p->deps);
        if (p->size) printf("  size: %s bytes\n", p->size);
        printf("  from: %s%s%s\n", kind_name[kinds[p->repo]], kinds[p->repo] != APK ? " " : "", repo_urls.v[p->repo]);
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
        if (BUILT(kinds[p->repo])) { printf("%s comes from a port tree, it is built and not fetched\n", p->name); continue; }
        file = pkg_file(p); base = repo_base(p->repo); url = fmt("%s/%s-%s.apk", base, p->name, p->ver);
        printf("==> fetching %s\n", url);
        if (download(url, file)) die("could not fetch %s", url);
        free(file); free(base); free(url);
    }
    return 0;
}

static void usage(void)
{
    puts("Usage: mag [-nfy] COMMAND [PACKAGE]...\n"
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
         "  -y  do not ask before installing or removing\n"
         "\n"
         "/etc/mag/repos has one repo url a line, /etc/mag/keys the public keys they are signed with, /etc/mag/arch\n"
         "which builds to get (written on the first install, the machine's own if it is not there). A line \"crux URL\" is a\n"
         "CRUX port tree, like crux https://crux.nu/ports/crux-3.8/opt; its key, opt.pub, goes in /etc/mag/keys too.\n"
         "\"void https://github.com/void-linux/void-packages\" builds Void's templates, \"exherbo https://gitlab.exherbo.org/exherbo/arbor\"\n"
         "Exherbo's exheres; those two come whole as a tarball on mag update and are not signed. What a\n"
         "repo has built wins over a port, mag build takes the port. Ports build with bash and the CFLAGS, CXXFLAGS and\n"
         "MAKEFLAGS of /etc/mag/build.conf, if it is there.\n"
         "\"pacman URL\" is a pacman repo like Artix's and Arch's, pacman https://geo.mirror.pkgbuild.com/extra/os: its\n"
         "packages are checked against the OpenPGP keyrings in /etc/mag/keys (*.gpg) and /usr/share/pacman/keyrings, and the\n"
         "hooks in /usr/share/libalpm/hooks run after them. A name in two pacman repos comes from the first one, as in pacman.\n"
         "\"aur https://aur.archlinux.org\" is the AUR: a PKGBUILD is built by makepkg as nobody in /var/cache/mag/aur.\n"
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
            if (*o == 'n') dry = 1; else if (*o == 'f') force = 1; else if (*o == 'y') yes = 1;
            else { say("unknown option -%c", *o); return 1; }
        }
    }
    {
        /* -y and the rest after the command too: mag install -y foo */
        int j, k = i;
        for (j = i; j < argc; j++) {
            if (argv[j][0] == '-' && argv[j][1] && strspn(argv[j] + 1, "nfy") == strlen(argv[j] + 1) && j > i) {
                const char *o;
                for (o = argv[j] + 1; *o; o++) { if (*o == 'n') dry = 1; else if (*o == 'f') force = 1; else yes = 1; }
            } else argv[k++] = argv[j];
        }
        argc = k;
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
