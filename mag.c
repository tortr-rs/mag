/* mag: the package manager, one C file on c.h. a recipe is a plain file in a repo, category/name, like dev-vcs/git:
 *
 *     desc: the stupid content tracker
 *     version: 2.47.0
 *     url: https://example.org/git-${version}.tar.xz
 *     sha256: <hash>
 *     deps: sys-libs/zlib dev-libs/openssl
 *     steps:
 *         ./configure --prefix=$PREFIX
 *         make -j$JOBS
 *         make DESTDIR=$DESTDIR install
 *
 * the steps are plain sh. build.sh builds this, "mag help" says the rest */
#include "c.h"

#define VERSION "0.1"

static const char *prog = "mag";
static const char *root = "";                   /* MAG_ROOT without the trailing slash, "" is / */
static char **repos;
static int nrepos;
static int dry, force, keep;

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
static char *strtok_r(char *s, const char *delim, char **save)
{
    char *e;
    if (!s) s = *save;
    if (!s) return NULL;
    s += strspn(s, delim);
    if (!*s) { *save = NULL; return NULL; }
    e = s + strcspn(s, delim);
    if (*e) *e++ = 0; else e = NULL;
    *save = e;
    return s;
}
static int cmp_str(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

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

static int exists(const char *p) { struct stat st; return lstat(p, &st) == 0; }

static int run(char *const argv[], const char *dir)
{
    int st;
    pid_t pid;
    fflush(stdout);
    pid = fork();
    if (pid < 0) die("cannot fork");
    if (!pid) {
        if (dir && chdir(dir) < 0) { fprintf(stderr, "%s: cannot enter %s\n", prog, dir); _exit(126); }
        execvp(argv[0], argv);
        fprintf(stderr, "%s: %s: %s\n", prog, argv[0], strerror(errno));
        _exit(127);
    }
    while (waitpid(pid, &st, 0) < 0 && errno == EINTR) {}
    return (st & 0x7f) ? 128 + (st & 0x7f) : (st >> 8) & 255;
}

/* ---- sha256 ---- */

static const unsigned k256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be,
    0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa,
    0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f,
    0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(unsigned *h, const unsigned char *p)
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

/* the hash of a file as 64 hex digits, NULL if it can't be read */
static char *sha256_file(const char *path)
{
    unsigned h[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    unsigned char buf[64], tail[128];
    unsigned long long total = 0;
    size_t have = 0, i;
    int fd = open(path, O_RDONLY);
    char *hex = xmalloc(65);
    ssize_t r;
    if (fd < 0) { free(hex); return NULL; }
    while ((r = read(fd, buf + have, 64 - have)) > 0) {
        have += r; total += r;
        if (have == 64) { sha_block(h, buf); have = 0; }
    }
    close(fd);
    if (r < 0) { free(hex); return NULL; }
    memcpy(tail, buf, have);
    tail[have++] = 0x80;
    while (have % 64 != 56) tail[have++] = 0;
    for (i = 0; i < 8; i++) tail[have++] = (total * 8) >> (56 - 8 * i);
    for (i = 0; i < have; i += 64) sha_block(h, tail + i);
    for (i = 0; i < 8; i++) sprintf(hex + i * 8, "%08x", h[i]);
    return hex;
}


/* ---- sha512, for pkgsrc's distinfo ---- */

static const unsigned long long k512[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
    0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
    0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
    0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
    0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
    0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
    0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
    0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL };

#define ROR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static void sha512_block(unsigned long long *h, const unsigned char *p)
{
    unsigned long long w[80], v[8];
    int i, j;
    for (i = 0; i < 16; i++) { w[i] = 0; for (j = 0; j < 8; j++) w[i] = w[i] << 8 | p[i * 8 + j]; }
    for (i = 16; i < 80; i++) {
        unsigned long long s0 = ROR64(w[i - 15], 1) ^ ROR64(w[i - 15], 8) ^ (w[i - 15] >> 7), s1 = ROR64(w[i - 2], 19) ^ ROR64(w[i - 2], 61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    memcpy(v, h, sizeof v);
    for (i = 0; i < 80; i++) {
        unsigned long long t1 = v[7] + (ROR64(v[4], 14) ^ ROR64(v[4], 18) ^ ROR64(v[4], 41)) + ((v[4] & v[5]) ^ (~v[4] & v[6])) + k512[i] + w[i];
        unsigned long long t2 = (ROR64(v[0], 28) ^ ROR64(v[0], 34) ^ ROR64(v[0], 39)) + ((v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]));
        v[7] = v[6]; v[6] = v[5]; v[5] = v[4]; v[4] = v[3] + t1; v[3] = v[2]; v[2] = v[1]; v[1] = v[0]; v[0] = t1 + t2;
    }
    for (i = 0; i < 8; i++) h[i] += v[i];
}

static char *sha512_file(const char *path)
{
    unsigned long long h[8] = { 0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL };
    unsigned char buf[128], tail[256];
    unsigned long long total = 0;
    size_t have = 0, i;
    int fd = open(path, O_RDONLY);
    char *hex = xmalloc(129);
    ssize_t r;
    if (fd < 0) { free(hex); return NULL; }
    while ((r = read(fd, buf + have, 128 - have)) > 0) {
        have += r; total += r;
        if (have == 128) { sha512_block(h, buf); have = 0; }
    }
    close(fd);
    if (r < 0) { free(hex); return NULL; }
    memcpy(tail, buf, have);
    tail[have++] = 0x80;
    while (have % 128 != 112) tail[have++] = 0;
    for (i = 0; i < 8; i++) tail[have++] = 0;
    for (i = 0; i < 8; i++) tail[have++] = (total * 8) >> (56 - 8 * i);
    for (i = 0; i < have; i += 128) sha512_block(h, tail + i);
    for (i = 0; i < 8; i++) sprintf(hex + i * 16, "%016llx", h[i]);
    return hex;
}

/* ---- recipes ---- */

struct recipe {
    char *id, *file, *dir, *desc, *version, *url, *sha, *sha512, *steps, *cache, *options;
    struct list deps, alts;
};

static char *trim(char *s)
{
    size_t n;
    while (*s == ' ' || *s == '\t') s++;
    n = strlen(s);
    while (n && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r' || s[n - 1] == '\n')) s[--n] = 0;
    return s;
}

static char *subst_version(const char *s, const char *version)
{
    char *out = xmalloc(strlen(s) + strlen(version) * 4 + 1), *o = out;
    while (*s) {
        if (!strncmp(s, "${version}", 10)) { o += sprintf(o, "%s", version); s += 10; }
        else *o++ = *s++;
    }
    *o = 0;
    return out;
}

static struct recipe *parse_recipe(const char *id, const char *file, const char *dir)
{
    char *text = slurp(file, NULL), *line, *next;
    struct recipe *r;
    struct list steps = { 0 };
    int in_steps = 0, i;
    size_t total = 0;
    if (!text) return NULL;
    r = xmalloc(sizeof *r);
    memset(r, 0, sizeof *r);
    r->id = xstrdup(id); r->file = xstrdup(file); r->dir = xstrdup(dir);
    for (line = text; line; line = next) {
        char *colon, *key, *val;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (in_steps) {
            if (!*line || *line == ' ' || *line == '\t') {
                char *s = line;
                if (*s == '\t') s++; else { int k; for (k = 0; k < 4 && *s == ' '; k++) s++; }
                push(&steps, xstrdup(s));
                continue;
            }
            in_steps = 0;
        }
        if (!*line || *line == '#' || *line == ' ' || *line == '\t') continue;
        colon = strchr(line, ':');
        if (!colon) die("%s: not a recipe line: %s", file, line);
        *colon = 0;
        key = trim(line); val = trim(colon + 1);
        if (!strcmp(key, "desc")) r->desc = xstrdup(val);
        else if (!strcmp(key, "version")) r->version = xstrdup(val);
        else if (!strcmp(key, "url")) r->url = xstrdup(val);
        else if (!strcmp(key, "sha256")) r->sha = xstrdup(val);
        else if (!strcmp(key, "deps")) {
            char *w;
            for (w = val; *w; ) {
                char *e;
                while (*w == ' ' || *w == '\t' || *w == ',') w++;
                if (!*w) break;
                e = w;
                while (*e && *e != ' ' && *e != '\t' && *e != ',') e++;
                push(&r->deps, strndup(w, e - w));
                w = e;
            }
        } else if (!strcmp(key, "steps")) { in_steps = 1; if (*val) push(&steps, xstrdup(val)); }
        else die("%s: unknown field '%s'", file, key);
    }
    while (steps.n && !*trim(steps.v[steps.n - 1])) steps.n--;
    for (i = 0; i < steps.n; i++) total += strlen(steps.v[i]) + 1;
    r->steps = xmalloc(total + 1);
    r->steps[0] = 0;
    for (i = 0; i < steps.n; i++) { strcat(r->steps, steps.v[i]); strcat(r->steps, "\n"); }
    if (!r->version) r->version = xstrdup("0");
    if (!r->desc) r->desc = xstrdup("");
    if (r->url) { char *u = subst_version(r->url, r->version); free(r->url); r->url = u; }
    free(text);
    return r;
}

/* ---- pkgsrc packages: a directory with a Makefile and a distinfo, read as they are ----
 * the Makefile is parsed here, not run: assignments, ${VAR} with a few modifiers, .if with the usual tests, .include of
 * Makefile.common and of buildlink3.mk files (those are the dependencies). what is not understood is skipped,
 * and a package that needs the mk/ framework for more than that says so when it fails to build */

/* PROVIDES in a repo: "pkgsrc/id our/id" per line, "-" drops the dependency, "needs pkgsrc/id our/id" adds one the Makefile leaves out. it is how a pkgsrc package gets our zlib and not a second one */
static struct list prov_from, prov_to, need_for, need_dep;

static void load_provides(const char *repo)
{
    char *f = fmt("%s/PROVIDES", repo), *text = slurp(f, NULL), *line, *next;
    free(f);
    if (!text) return;
    for (line = text; line; line = next) {
        char *sp;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        line = trim(line);
        if (!*line || *line == '#') continue;
        if (!strncmp(line, "needs ", 6)) {
            char *a = trim(line + 6), *b = strpbrk(a, " \t");
            if (!b) continue;
            *b = 0;
            push(&need_for, xstrdup(a)); push(&need_dep, xstrdup(trim(b + 1)));
            continue;
        }
        sp = strpbrk(line, " \t");
        if (!sp) continue;
        *sp = 0;
        push(&prov_from, xstrdup(line)); push(&prov_to, xstrdup(trim(sp + 1)));
    }
    free(text);
}

static void dep_add(struct recipe *r, const char *id)
{
    int i;
    for (i = 0; i < prov_from.n; i++) if (!strcmp(prov_from.v[i], id)) { id = prov_to.v[i]; break; }
    if (!strcmp(id, "-") || !strncmp(id, "mk/", 3) || has(&r->deps, id)) return;
    push(&r->deps, xstrdup(id));
}

struct vars { char **k, **v; int n, cap; };

static const char *var_get(const struct vars *vs, const char *k)
{
    int i;
    for (i = vs->n - 1; i >= 0; i--) if (!strcmp(vs->k[i], k)) return vs->v[i];
    return NULL;
}
static void var_set(struct vars *vs, const char *k, const char *v)
{
    int i;
    for (i = 0; i < vs->n; i++) if (!strcmp(vs->k[i], k)) { free(vs->v[i]); vs->v[i] = xstrdup(v); return; }
    if (vs->n == vs->cap) { vs->cap = vs->cap ? vs->cap * 2 : 64; vs->k = xrealloc(vs->k, vs->cap * sizeof *vs->k); vs->v = xrealloc(vs->v, vs->cap * sizeof *vs->v); }
    vs->k[vs->n] = xstrdup(k); vs->v[vs->n++] = xstrdup(v);
}

static int glob_match(const char *p, const char *s)
{
    for (; *p; p++, s++) {
        if (*p == '*') { while (p[1] == '*') p++; for (;; s++) { if (glob_match(p + 1, s)) return 1; if (!*s) return 0; } }
        if (!*s) return 0;
        if (*p == '?') continue;
        if (*p != *s) return 0;
    }
    return !*s;
}

static char *expand(const struct vars *vs, const char *s, int depth);

/* one modifier on a value, words separated by spaces */
static char *apply_mod(const struct vars *vs, char *val, const char *mod, size_t len, int depth)
{
    char *m = strndup(mod, len), *out = xmalloc(strlen(val) * 2 + 1024), *o = out, *w, *save, *copy = xstrdup(val);
    *out = 0;
    if (m[0] == '=' ) {
        char *sub = expand(vs, m + 1, depth + 1);
        for (w = strtok_r(copy, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) o += sprintf(o, "%s%s%s", o == out ? "" : " ", w, sub);
        free(sub);
    } else if (m[0] == 'M' || m[0] == 'N') {
        int want = m[0] == 'M';
        char *pat = expand(vs, m + 1, depth + 1);
        for (w = strtok_r(copy, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) if (glob_match(pat, w) == want) o += sprintf(o, "%s%s", o == out ? "" : " ", w);
        free(pat);
    } else if ((m[0] == 'S' || m[0] == 'C') && m[1]) {
        char d = m[1], *a = m + 2, *b = strchr(a, d), *c, *flags;
        if (b) { *b++ = 0; c = strchr(b, d); if (c) { *c++ = 0; flags = c; } else flags = ""; } else { b = ""; flags = ""; }
        {
            int g = strchr(flags, 'g') != NULL, al = strlen(a);
            char *p = copy;
            if (a[0] == '^') { a++; al--; o += sprintf(o, "%s", b); if (!strncmp(p, a, al)) p += al; sprintf(o, "%s", p); }
            else {
                int done = 0;
                while (*p) {
                    if ((!done || g) && al && !strncmp(p, a, al)) { o += sprintf(o, "%s", b); p += al; done = 1; }
                    else *o++ = *p++;
                }
                *o = 0;
            }
        }
    } else if (!strncmp(m, "ts", 2)) {
        char sep = m[2] == '\\' && m[3] == 'n' ? '\n' : m[2] ? m[2] : (m[2] = 0, ' ');
        int first = 1;
        if (!m[2] && !strcmp(m, "ts")) sep = ' ';
        for (w = strtok_r(copy, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) { if (!first) *o++ = sep; o += sprintf(o, "%s", w); first = 0; }
        *o = 0;
    } else if (!strcmp(m, "Q")) {
        const char *p;
        for (p = copy; *p; p++) { if (strchr(" \t\n'\"\\$`&|;<>()*?[]#~!", *p)) *o++ = '\\'; *o++ = *p; }
        *o = 0;
    } else if (!strcmp(m, "tl") || !strcmp(m, "tu")) {
        int up = m[1] == 'u';
        char *p;
        for (p = copy; *p; p++) *p = up ? toupper((unsigned char)*p) : tolower((unsigned char)*p);
        strcpy(out, copy);
    } else if (m[0] == 'u' && !m[1]) strcpy(out, copy);
    else strcpy(out, copy);
    free(m); free(copy);
    return out;
}

static char *expand(const struct vars *vs, const char *s, int depth)
{
    size_t cap = strlen(s) * 2 + 256, n = 0;
    char *out = xmalloc(cap);
    if (depth > 20) { out[0] = 0; return out; }
    while (*s) {
        if (s[0] == '$' && s[1] == '$') { out[n++] = '$'; s += 2; }
        else if (s[0] == '$' && (s[1] == '{' || s[1] == '(')) {
            char open = s[1], close = open == '{' ? '}' : ')';
            const char *p = s + 2, *name_end;
            int d = 1;
            char *name, *val, *tmp;
            const char *got;
            while (*p && d) { if (*p == open) d++; else if (*p == close) d--; p++; }
            name_end = s + 2;
            while (name_end < p - 1 && *name_end != ':') name_end++;
            name = strndup(s + 2, name_end - (s + 2));
            got = var_get(vs, name);
            if (name_end[0] == ':' && name_end[1] == 'L' && (name_end + 2 == p - 1 || name_end[2] == ':')) { val = expand(vs, name, depth + 1); name_end += 2; }
            else val = got ? expand(vs, got, depth + 1) : xstrdup("");
            while (name_end < p - 1) {
                const char *me = name_end + 1;
                int dd = 0;
                while (me < p - 1 && (*me != ':' || dd)) { if (*me == '{') dd++; else if (*me == '}') dd--; me++; }
                if (me - (name_end + 1) == 2 && !strncmp(name_end + 1, "ts", 2) && me < p - 1 && *me == ':') me++;
                tmp = apply_mod(vs, val, name_end + 1, me - (name_end + 1), depth);
                free(val); val = tmp;
                name_end = me;
            }
            if (n + strlen(val) + 2 > cap) { cap = (n + strlen(val)) * 2 + 2; out = xrealloc(out, cap); }
            memcpy(out + n, val, strlen(val)); n += strlen(val);
            free(name); free(val);
            s = p;
        } else {
            if (n + 2 > cap) { cap *= 2; out = xrealloc(out, cap); }
            out[n++] = *s++;
        }
    }
    out[n] = 0;
    return out;
}

/* a condition from .if / .elif */
static int cond_term(const struct vars *vs, char *t)
{
    int neg = 0;
    char *e;
    int r;
    t = trim(t);
    while (*t == '!') { neg = !neg; t = trim(t + 1); }
    if (*t == '(' && t[strlen(t) - 1] == ')') { t[strlen(t) - 1] = 0; return neg ^ cond_term(vs, t + 1); }
    if (!strncmp(t, "defined(", 8)) { t[strlen(t) - 1] = 0; r = var_get(vs, trim(t + 8)) != NULL; }
    else if (!strncmp(t, "empty(", 6)) {
        char *a = xstrdup(t + 6), *tmp;
        a[strlen(a) - 1] = 0;
        tmp = fmt("${%s}", a);
        e = expand(vs, tmp, 0);
        r = !*trim(e);
        free(e); free(tmp); free(a);
    } else if (!strncmp(t, "target(", 7)) { char *k; t[strlen(t) - 1] = 0; k = fmt("TARGET.%s", trim(t + 7)); r = var_get(vs, k) != NULL; free(k); }
    else if (!strncmp(t, "exists(", 7) || !strncmp(t, "make(", 5)) r = 0;
    else {
        char *eq = strstr(t, "=="), *ne = strstr(t, "!="), *op = eq && (!ne || eq < ne) ? eq : ne;
        if (op) {
            char *a, *b, *ea, *eb;
            int same;
            a = strndup(t, op - t); b = xstrdup(op + 2);
            ea = expand(vs, trim(a), 0); eb = expand(vs, trim(b), 0);
            { char *x = trim(ea), *y = trim(eb); size_t l;
              if (*x == '"') { x++; l = strlen(x); if (l && x[l - 1] == '"') x[l - 1] = 0; }
              if (*y == '"') { y++; l = strlen(y); if (l && y[l - 1] == '"') y[l - 1] = 0; }
              same = !strcmp(x, y); }
            r = op == eq ? same : !same;
            free(a); free(b); free(ea); free(eb);
        } else {
            e = expand(vs, t, 0);
            r = *trim(e) && strcmp(trim(e), "0");
            free(e);
        }
    }
    return neg ? !r : r;
}
static int cond_eval(const struct vars *vs, const char *c)
{
    char *s = xstrdup(c), *p, *or_;
    int r = 0, depth = 0;
    /* split on || at depth 0, then && */
    for (p = s, or_ = NULL; *p; p++) {
        if (*p == '(') depth++; else if (*p == ')') depth--;
        else if (!depth && p[0] == '|' && p[1] == '|') { *p = 0; r = r || cond_eval(vs, s); s = p + 2; p++; or_ = p; }
    }
    if (or_) { r = r || cond_eval(vs, s); return r; }
    {
        char *t = s, *q;
        int res = 1;
        depth = 0;
        for (q = s; ; q++) {
            if (*q == '(') depth++; else if (*q == ')') depth--;
            if (!*q || (!depth && q[0] == '&' && q[1] == '&')) {
                int end = !*q;
                *q = 0;
                res = res && cond_term(vs, t);
                if (end) break;
                t = q + 2; q++;
            }
        }
        return res;
    }
}

/* PKG_OPTIONS, what bsd.options.mk works out in pkgsrc: the suggested options, then PKG_DEFAULT_OPTIONS, then the package's own variable, each word adding an option or, with a minus, taking it off */
static void words_into(struct list *l, const char *text)
{
    char *c = xstrdup(text), *save, *w;
    for (w = strtok_r(c, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) push(l, xstrdup(w));
    free(c);
}
static void opts_apply(struct list *sel, const struct list *sup, const char *text)
{
    struct list ws = { 0 };
    int i, j;
    words_into(&ws, text);
    for (i = 0; i < ws.n; i++) {
        const char *name = ws.v[i] + (ws.v[i][0] == '-');
        if (!has(sup, name)) continue;
        if (ws.v[i][0] == '-') { for (j = 0; j < sel->n; j++) if (!strcmp(sel->v[j], name)) { memmove(sel->v + j, sel->v + j + 1, (sel->n - j - 1) * sizeof *sel->v); sel->n--; break; } }
        else if (!has(sel, name)) push(sel, xstrdup(name));
    }
}
static void compute_options(struct vars *vs)
{
    struct list sup = { 0 }, sel = { 0 }, groups = { 0 };
    const char *g;
    char *e, *vname, *out;
    int i, j, len = 0;
    static const char *const gvars[] = { "PKG_OPTIONS_OPTIONAL_GROUPS", "PKG_OPTIONS_REQUIRED_GROUPS", "PKG_OPTIONS_NONEMPTY_SETS", "PKG_OPTIONS_ONEOF_SETS", NULL };
    if ((g = var_get(vs, "PKG_SUPPORTED_OPTIONS"))) { e = expand(vs, g, 0); words_into(&sup, e); free(e); }
    for (i = 0; gvars[i]; i++) if ((g = var_get(vs, gvars[i]))) { e = expand(vs, g, 0); words_into(&groups, e); free(e); }
    for (i = 0; i < groups.n; i++) {
        char *k = fmt("PKG_OPTIONS_GROUP.%s", groups.v[i]), *k2 = fmt("PKG_OPTIONS_SET.%s", groups.v[i]);
        if ((g = var_get(vs, k))) { e = expand(vs, g, 0); words_into(&sup, e); free(e); }
        if ((g = var_get(vs, k2))) { e = expand(vs, g, 0); words_into(&sup, e); free(e); }
        free(k); free(k2);
    }
    if ((g = var_get(vs, "PKG_SUGGESTED_OPTIONS"))) { e = expand(vs, g, 0); opts_apply(&sel, &sup, e); free(e); }
    if ((g = var_get(vs, "PKG_DEFAULT_OPTIONS"))) { e = expand(vs, g, 0); opts_apply(&sel, &sup, e); free(e); }
    if ((g = var_get(vs, "PKG_OPTIONS_VAR"))) {
        vname = expand(vs, g, 0);
        if ((g = var_get(vs, vname))) { e = expand(vs, g, 0); opts_apply(&sel, &sup, e); free(e); }
        free(vname);
    }
    for (j = 0; j < sel.n; j++) len += strlen(sel.v[j]) + 1;
    out = xmalloc(len + 1);
    out[0] = 0;
    for (j = 0; j < sel.n; j++) { if (j) strcat(out, " "); strcat(out, sel.v[j]); }
    var_set(vs, "PKG_OPTIONS", out);
    free(out);
}

/* /etc/mag.conf in the root: pkgsrc's mk.conf, plain VAR=value lines. JOBS, CFLAGS and the like for every build, PKG_DEFAULT_OPTIONS and PKG_OPTIONS.name and CONFIGURE_ARGS.name (extra configure arguments) and SERIAL.name=yes (build with -j1) for the pkgsrc packages */
static struct vars conf;
static void read_makefile(struct vars *vs, const char *file, const char *pkgdir, const char *repo, struct list *bl, int depth);
static void load_conf(void)
{
    char *f = fmt("%s/etc/mag.conf", root);
    struct list bl = { 0 };
    if (exists(f)) read_makefile(&conf, f, ".", ".", &bl, 0);
    free(f);
}
static const char *conf_get(const char *k) { return var_get(&conf, k); }

/* .for var in words ... .endfor: the body is written out once for each word, before the file is read */
static char *unroll_for(char *text)
{
    size_t cap = strlen(text) * 4 + 64, n = 0;
    char *out = xmalloc(cap), *p = text;
    out[0] = 0;
    while (*p) {
        char *eol = strchr(p, '\n'), *l = p;
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char *ln = xmalloc(len + 1);
        memcpy(ln, p, len); ln[len] = 0;
        l = ln; while (*l == ' ' || *l == '\t') l++;
        if (!strncmp(l, ".for ", 5)) {
            char *var = l + 5, *in = strstr(var, " in "), *body, *q, *words, *w, *sv;
            int depth = 1;
            size_t blen;
            if (!in) { free(ln); break; }
            *in = 0;
            words = xstrdup(in + 4);
            q = eol ? eol + 1 : p + len;
            body = q;
            while (*q) {
                char *e2 = strchr(q, '\n'), *t = q;
                while (*t == ' ' || *t == '\t') t++;
                if (!strncmp(t, ".for ", 5)) depth++;
                else if (!strncmp(t, ".endfor", 7) && !--depth) break;
                q = e2 ? e2 + 1 : q + strlen(q);
            }
            blen = (size_t)(q - body);
            for (w = strtok_r(words, " \t", &sv); w; w = strtok_r(NULL, " \t", &sv)) {
                char *b = xmalloc(blen + 1), *r, *pat = fmt("${%s}", trim(var));
                memcpy(b, body, blen); b[blen] = 0;
                for (r = b; (r = strstr(r, pat)); ) {
                    size_t pl = strlen(pat), wl = strlen(w), tail = strlen(r + pl) + 1;
                    char *nb = xmalloc(strlen(b) + wl + 1);
                    memcpy(nb, b, (size_t)(r - b)); memcpy(nb + (r - b), w, wl); memcpy(nb + (r - b) + wl, r + pl, tail);
                    r = nb + (r - b) + wl; free(b); b = nb;
                }
                free(pat);
                if (n + strlen(b) + 2 >= cap) { cap = (cap + strlen(b)) * 2; out = realloc(out, cap); }
                strcpy(out + n, b); n += strlen(b); free(b);
            }
            free(words);
            p = *q ? (strchr(q, '\n') ? strchr(q, '\n') + 1 : q + strlen(q)) : q;
            free(ln);
            continue;
        }
        if (n + len + 2 >= cap) { cap = (cap + len) * 2; out = realloc(out, cap); }
        memcpy(out + n, p, len); n += len;
        if (eol) out[n++] = '\n';
        out[n] = 0;
        p = eol ? eol + 1 : p + len;
        free(ln);
    }
    return out;
}

static void read_makefile(struct vars *vs, const char *file, const char *pkgdir, const char *repo, struct list *bl, int depth)
{
    char *text = slurp(file, NULL), *line, *next, *raw;
    int skip[32], taken[32], sp = 0;
    int i;
    char tgt[64] = "";
    if (!text || depth > 6) { free(text); return; }
    raw = text; text = unroll_for(raw); free(raw);
    memset(skip, 0, sizeof skip); memset(taken, 0, sizeof taken);
    for (line = text; line; line = next) {
        char *l, *op, *k, *v;
        size_t len;
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        /* continuation lines */
        while ((len = strlen(line)) && line[len - 1] == '\\' && next) {
            char *n2 = strchr(next, '\n');
            line[len - 1] = ' ';
            if (n2) *n2 = 0;
            memmove(line + len, next, strlen(next) + 1);
            next = n2 ? n2 + 1 : NULL;
            if (!n2) break;
        }
        int tabbed = line[0] == '\t';
        l = trim(line);
        if (*l == '#' || !*l) continue;
        if (*l == '.') {
            char *dir = trim(l + 1);
            int skipping = 0;
            for (i = 0; i < sp; i++) if (skip[i]) skipping = 1;
            if (!strncmp(dir, "if", 2) && dir[2] != 'n' ? 1 : (!strncmp(dir, "ifdef", 5) || !strncmp(dir, "ifndef", 6) || !strncmp(dir, "if ", 3) || !strncmp(dir, "if(", 3) || !strncmp(dir, "if!", 3))) {
                char *c;
                int r = 0;
                if (!strncmp(dir, "ifdef", 5)) { c = trim(dir + 5); r = var_get(vs, c) != NULL; }
                else if (!strncmp(dir, "ifndef", 6)) { c = trim(dir + 6); r = var_get(vs, c) == NULL; }
                else r = skipping ? 0 : cond_eval(vs, dir + 2);
                if (sp < 31) { skip[sp] = !r; taken[sp] = r; sp++; }
            } else if (!strncmp(dir, "elif", 4)) {
                if (sp) { int r = !taken[sp - 1] && cond_eval(vs, dir + 4); skip[sp - 1] = !r; if (r) taken[sp - 1] = 1; }
            } else if (!strncmp(dir, "else", 4)) { if (sp) { skip[sp - 1] = taken[sp - 1]; taken[sp - 1] = 1; } }
            else if (!strncmp(dir, "endif", 5)) { if (sp) sp--; }
            else if (!skipping && !strncmp(dir, "include", 7)) {
                char *q = strchr(dir, '"'), *e2;
                char *inc;
                if (!q) continue;
                inc = xstrdup(q + 1);
                e2 = strchr(inc, '"');
                if (e2) *e2 = 0;
                {
                    char *x = expand(vs, inc, 0);
                    free(inc); inc = x;
                }
                if (strstr(inc, "/buildlink3.mk") && !strncmp(inc, "../../", 6)) {
                    char *d = xstrdup(inc + 6);
                    char *sl = strstr(d, "/buildlink3.mk");
                    *sl = 0;
                    if (!has(bl, d)) push(bl, d); else free(d);
                } else if (strstr(inc, "mk/bsd.options.mk")) {
                    compute_options(vs);
                } else if (!strncmp(inc, "../../mk/", 9) || !strncmp(inc, "../mk/", 6)) {
                    /* the framework is not read, but what it stands for can be a dependency: PROVIDES says which */
                    if (strstr(inc, ".buildlink3.mk")) { char *d = xstrdup(inc + 6); if (!has(bl, d)) push(bl, d); else free(d); }
                } else if (strstr(inc, "lang/python/pyversion.mk")) {
                } else if (strstr(inc, "devel/meson/build.mk")) { var_set(vs, "MAG_MESON", "yes");
                } else if (strstr(inc, "devel/cmake/build.mk")) { var_set(vs, "USE_CMAKE", "yes");
                } else if (inc[0] != '/') {
                    char *here = xstrdup(file), *sl = strrchr(here, '/'), *p;
                    if (sl) *sl = 0; else strcpy(here, ".");
                    p = fmt("%s/%s", here, inc);
                    free(here);
                    read_makefile(vs, p, pkgdir, repo, bl, depth + 1);
                    free(p);
                }
                free(inc);
            }
            continue;
        }
        for (i = 0; i < sp; i++) if (skip[i]) break;
        if (i < sp) continue;
        if (tabbed && *tgt) {
            char *key = fmt("TARGET.%s", tgt);
            const char *old = var_get(vs, key);
            char *nv;
            while (*l == '@' || *l == '-') l++;
            nv = old ? fmt("%s\n%s", old, l) : xstrdup(l);
            var_set(vs, key, nv); free(nv); free(key);
            continue;
        }
        tgt[0] = 0;
        if (!strncmp(l, "do-", 3) || !strncmp(l, "pre-", 4) || !strncmp(l, "post-", 5)) {
            char *c = strchr(l, ':');
            if (c && c[1] != '=' && !strchr(l, ' ') ) { snprintf(tgt, sizeof tgt, "%.*s", (int)(c - l), l); continue; }
        }
        /* VAR op value */
        {
            char *p = l;
            while (*p && *p != '=' && *p != ' ' && *p != '\t' && *p != '+' && *p != '?' && *p != ':' && *p != '!') p++;
            k = strndup(l, p - l);
            while (*p == ' ' || *p == '\t') p++;
            if (!strncmp(p, "+=", 2)) { op = "+="; p += 2; }
            else if (!strncmp(p, "?=", 2)) { op = "?="; p += 2; }
            else if (!strncmp(p, ":=", 2)) { op = ":="; p += 2; }
            else if (!strncmp(p, "!=", 2)) { op = "!="; p += 2; }
            else if (*p == '=') { op = "="; p++; }
            else { free(k); continue; }
            v = trim(p);
            { char *h; for (h = v; *h; h++) if (*h == '#' && (h == v || h[-1] == ' ' || h[-1] == '\t')) { *h = 0; break; } }
            v = trim(v);
        }
        if (!strcmp(op, "?=")) { if (!var_get(vs, k)) var_set(vs, k, v); }
        else if (!strcmp(op, "+=")) {
            const char *old = var_get(vs, k);
            char *nv = old ? fmt("%s %s", old, v) : xstrdup(v);
            var_set(vs, k, nv); free(nv);
        } else if (!strcmp(op, ":=")) { char *e = expand(vs, v, 0); var_set(vs, k, e); free(e); }
        else if (!strcmp(op, "!=")) { /* a shell command: not run */ var_set(vs, k, ""); }
        else var_set(vs, k, v);
        free(k);
    }
    free(text);
}

/* sites.mk: MASTER_SITE_GNU and the rest, read from the pkgsrc root if it is there */
static void load_sites(struct vars *vs, const char *repo)
{
    char *f = fmt("%s/mk/fetch/sites.mk", repo);
    struct list bl = { 0 };
    if (exists(f)) read_makefile(vs, f, repo, repo, &bl, 0);
    free(f);
}

static char *distinfo_hash(const char *text, const char *algo, const char *file)
{
    char *key = fmt("%s (%s) = ", algo, file), *p = text ? strstr(text, key) : NULL, *e, *out;
    free(key);
    if (!p) return NULL;
    p = strchr(p, '=') + 2;
    e = p + strcspn(p, " \n\r");
    out = strndup(p, e - p);
    return out;
}

static const char *const tool_pkgs[][2] = {
    { "gmake", "devel/gmake" }, { "bison", "devel/bison" }, { "m4", "devel/m4" }, { "flex", "devel/flex" }, { "pkg-config", "devel/pkgconf" },
    { "perl", "lang/perl5" }, { "autoconf", "devel/autoconf" }, { "automake", "devel/automake" }, { "libtool", "devel/libtool-base" },
    { "gettext", "devel/gettext-tools" }, { "msgfmt", "devel/gettext-tools" }, { "patch", "devel/patch" }, { "yacc", "devel/byacc" },
    { "cmake", "devel/cmake" }, { "ninja", "devel/samurai" }, { NULL, NULL } };

static struct recipe *parse_pkgsrc(const char *id, const char *dir, const char *repo)
{
    struct vars vs = { 0 };
    struct list bl = { 0 };
    struct recipe *r;
    char *mf = fmt("%s/Makefile", dir), *di = fmt("%s/distinfo", dir), *dtext, *distname, *pkgname, *sufx, *sites, *distfiles, *dfile, *tok, *save, *s, *w, *x, *steps, *cmd;
    const char *g;
    int i;
    var_set(&vs, "OPSYS", "Linux"); var_set(&vs, "MACHINE_ARCH", "x86_64"); var_set(&vs, "LOWER_OPSYS", "linux");
    var_set(&vs, "MACHINE_PLATFORM", "Linux-x86_64"); var_set(&vs, "PKGSRC_COMPILER", "clang"); var_set(&vs, "OPSYS_VERSION", "0");
    { int ci; for (ci = 0; ci < conf.n; ci++) var_set(&vs, conf.k[ci], conf.v[ci]); }
    var_set(&vs, ".CURDIR", dir); var_set(&vs, "PKGSRCDIR", repo);
    {
        static const char *const sh[][2] = {
            { "WRKDIR", "$SRC/.." }, { "FILESDIR", "$RECIPE_DIR/files" }, { "PATCHDIR", "patches" }, { "DESTDIR", "$DESTDIR" }, { "PREFIX", "$PREFIX" },
            { "LOCALBASE", "$ROOT$PREFIX" }, { "SSLBASE", "$ROOT$PREFIX" }, { "PYTHON_VERSION", "312" }, { "PYPKGPREFIX", "py312" }, { "PYVERSSUFFIX", "3.12" }, { "PYTHONBIN", "python3.12" }, { "TOOL_PYTHONBIN", "python3.12" }, { "PYLIB", "lib/python3.12" }, { "PYSITELIB", "lib/python3.12/site-packages" }, { "BUILDLINK_PREFIX.openssl", "$ROOT$PREFIX" }, { "PKGMANDIR", "man" }, { "SETENV", "env" }, { "TOOLS_SHELL", "/bin/sh" }, { "SH", "/bin/sh" },
            { "CP", "cp" }, { "MV", "mv" }, { "RM", "rm" }, { "LN", "ln" }, { "MKDIR", "mkdir -p" }, { "ECHO", "echo" }, { "SED", "sed" },
            { "CHMOD", "chmod" }, { "TRUE", "true" }, { "CAT", "cat" }, { "TEST", "test" }, { "TOUCH", "touch" }, { "MAKE", "make" },
            { "BSD_INSTALL_PROGRAM", "install -m 755" }, { "BSD_INSTALL_PROGRAM_DIR", "install -d -m 755" }, { "BSD_INSTALL_SCRIPT", "install -m 755" }, { "BSD_INSTALL_SCRIPT_DIR", "install -d -m 755" }, { "BSD_INSTALL_LIB", "install -m 755" }, { "BSD_INSTALL_LIB_DIR", "install -d -m 755" }, { "BSD_INSTALL_DATA", "install -m 644" }, { "BSD_INSTALL_DATA_DIR", "install -d -m 755" }, { "BSD_INSTALL_MAN", "install -m 644" }, { "BSD_INSTALL_MAN_DIR", "install -d -m 755" }, { "BSD_INSTALL_GAME", "install -m 755" }, { "BSD_INSTALL_GAME_DIR", "install -d -m 755" }, { "INSTALL", "install" }, { "FIND", "find" }, { "BUILDLINK_X11_DIR", "/nonexistent/buildlink" }, { "BUILDLINK_DIR", "/nonexistent/buildlink" }, { "ECHO_MSG", "echo" }, { "STEP_MSG", "echo" }, { "WARNING_MSG", "echo" }, { "PHASE_MSG", "echo" }, { "ERROR_MSG", "echo" }, { "FAIL_MSG", "echo" }, { "INFO_MSG", "echo" }, { "XARGS", "xargs" }, { "AWK", "awk" }, { "GREP", "grep" }, { "EGREP", "grep -E" }, { "HEAD", "head" }, { "TAIL", "tail" }, { "TR", "tr" }, { "SORT", "sort" }, { "WC", "wc" }, { "CMP", "cmp" }, { "DIFF", "diff" }, { "BASENAME", "basename" }, { "DIRNAME", "dirname" }, { "PWD", "pwd" }, { "TOOLS_PLATFORM.pwd", "/bin/pwd" }, { "INSTALL_PROGRAM", "install -m 755" }, { "INSTALL_LIB", "install -m 755" }, { "INSTALL_LIB_DIR", "install -d -m 755" }, { "INSTALL_GAME", "install -m 755" }, { "INSTALL_GAME_DATA", "install -m 644" }, { "INSTALL_SCRIPT", "install -m 755" }, { "INSTALL_DATA", "install -m 644" },
            { "INSTALL_MAN", "install -m 644" }, { "INSTALL_PROGRAM_DIR", "install -d -m 755" }, { "INSTALL_DATA_DIR", "install -d -m 755" },
            { "INSTALL_SCRIPT_DIR", "install -d -m 755" }, { "INSTALL_MAN_DIR", "install -d -m 755" }, { "CC", "cc" }, { "LIBTOOL", "libtool" }, { "COMPILER_RPATH_FLAG", "-Wl,-rpath," }, { "PKG_SYSCONFDIR", "/etc" }, { "VARBASE", "/var" }, { "MACHINE_GNU_ARCH", "x86_64" }, { "MACHINE_GNU_PLATFORM", "x86_64-pc-linux-gnu" }, { "PKG_SHELL", "" }, { "BINMODE", "755" }, { "NONBINMODE", "644" }, { "LIBMODE", "644" }, { "SHAREMODE", "644" }, { "MANMODE", "644" }, { "DIRMODE", "755" }, { "BINOWN", "$(id -un)" }, { "BINGRP", "$(id -gn)" }, { "SHAREOWN", "$(id -un)" }, { "SHAREGRP", "$(id -gn)" }, { "MANOWN", "$(id -un)" }, { "MANGRP", "$(id -gn)" }, { "REAL_ROOT_USER", "root" }, { "REAL_ROOT_GROUP", "root" }, { "RUN", "" }, { "RCD_SCRIPTS_DIR", "/etc/rc.d" }, { NULL, NULL }
        };
        int k;
        for (k = 0; sh[k][0]; k++) var_set(&vs, sh[k][0], sh[k][1]);
    }
    load_sites(&vs, repo);
    {
        char *sk = fmt("PKG_SYSCONFDIR.%s", strrchr(id, '/') ? strrchr(id, '/') + 1 : id);
        if (conf_get(sk)) var_set(&vs, "PKG_SYSCONFDIR", conf_get(sk));
        free(sk);
    }
    read_makefile(&vs, mf, dir, repo, &bl, 0);
    free(mf);
    if (!(g = var_get(&vs, "DISTNAME")) && !var_get(&vs, "PKGNAME")) { free(di); return NULL; }
    r = xmalloc(sizeof *r);
    memset(r, 0, sizeof *r);
    r->id = xstrdup(id); r->file = fmt("%s/Makefile", dir); r->dir = xstrdup(dir);
    distname = expand(&vs, var_get(&vs, "DISTNAME") ? var_get(&vs, "DISTNAME") : "${PKGNAME}", 0);
    pkgname = expand(&vs, var_get(&vs, "PKGNAME") ? var_get(&vs, "PKGNAME") : "${DISTNAME}", 0);
    {
        char *dash = strrchr(pkgname, '-');
        const char *rev = var_get(&vs, "PKGREVISION");
        r->version = xstrdup(dash ? dash + 1 : "0");
        var_set(&vs, "PKGVERSION_NOREV", r->version); var_set(&vs, "PKGNAME", pkgname); var_set(&vs, "DISTNAME", distname);
        var_set(&vs, "PKGBASE", dash ? (x = strndup(pkgname, dash - pkgname), x) : pkgname); var_set(&vs, "PKGVERSION", r->version);
        if (rev && *rev && strcmp(rev, "0")) { char *v2 = fmt("%snb%s", r->version, rev); free(r->version); r->version = v2; var_set(&vs, "PKGVERSION", v2); }
    }
    if (!var_get(&vs, "WRKSRC")) var_set(&vs, "WRKSRC", "${WRKDIR}/${DISTNAME}");
    if (var_get(&vs, "PKG_OPTIONS") && *var_get(&vs, "PKG_OPTIONS")) r->options = xstrdup(var_get(&vs, "PKG_OPTIONS"));
    r->desc = var_get(&vs, "COMMENT") ? expand(&vs, var_get(&vs, "COMMENT"), 0) : xstrdup("");
    if (!var_get(&vs, "EXTRACT_SUFX")) var_set(&vs, "EXTRACT_SUFX", ".tar.gz");
    sufx = expand(&vs, var_get(&vs, "EXTRACT_SUFX") ? var_get(&vs, "EXTRACT_SUFX") : ".tar.gz", 0);
    distfiles = var_get(&vs, "DISTFILES") ? expand(&vs, var_get(&vs, "DISTFILES"), 0) : fmt("%s%s", distname, sufx);
    sites = var_get(&vs, "MASTER_SITES") ? expand(&vs, var_get(&vs, "MASTER_SITES"), 0) : xstrdup("");
    dfile = xstrdup(trim(distfiles));
    dfile[strcspn(dfile, " \t")] = 0;
    { char *c = strchr(dfile, ':'); if (c) *c = 0; }
    if (var_get(&vs, "DISTINFO_FILE")) { char *e = expand(&vs, var_get(&vs, "DISTINFO_FILE"), 0); free(di); di = e[0] == '/' ? e : fmt("%s/%s", dir, e); if (di != e) free(e); }
    dtext = slurp(di, NULL);
    free(di);
    {
        const char *sub = var_get(&vs, "DIST_SUBDIR");
        char *dkey = sub ? fmt("%s/%s", sub, dfile) : xstrdup(dfile);
        r->sha512 = distinfo_hash(dtext, "SHA512", dkey);
        free(dkey);
    }
    {
        /* github.mk: a site of the form https://github.com/account/ gets the project and tag or release put on by the framework */
        char *site1 = xstrdup(sites), *sp = strchr(site1, ' ');
        const char *proj = var_get(&vs, "GITHUB_PROJECT"), *tag = var_get(&vs, "GITHUB_TAG"), *rel = var_get(&vs, "GITHUB_RELEASE");
        char *base = xstrdup(strrchr(id, '/') + 1), *ver = xstrdup(r->version), *nb;
        char *key = fmt("SITES.%s", dfile);
        const char *own = var_get(&vs, key);
        if (sp) *sp = 0;
        if ((nb = strstr(ver, "nb"))) *nb = 0;
        if (!strncmp(site1, "https://github.com/", 19) && site1[strlen(site1) - 1] == '/' && strchr(site1 + 19, '/') == site1 + strlen(site1) - 1) {
            char *p = proj ? expand(&vs, proj, 0) : xstrdup(base), *t = tag ? expand(&vs, tag, 0) : xstrdup(ver), *rl = rel ? expand(&vs, rel, 0) : NULL;
            if (rl && *rl) r->url = fmt("%s%s/releases/download/%s/%s", site1, p, rl, dfile);
            else {
                size_t tl = strlen(t);
                int hex = tl >= 7, i2;
                for (i2 = 0; i2 < (int)tl; i2++) if (!isxdigit((unsigned char)t[i2]) || isupper((unsigned char)t[i2])) hex = 0;
                if (hex && !var_get(&vs, "DISTFILES")) { char *d2 = fmt("%s-%s%s", distname, t, sufx); free(dfile); dfile = d2; }
                r->url = fmt("%s%s/archive/%s%s", site1, p, t, sufx);
                r->cache = xstrdup(dfile);
            }
            free(p); free(t); free(rl);
        } else if (own) {
            char *e = expand(&vs, own, 0), *sv2;
            for (tok = strtok_r(e, " \t", &sv2); tok; tok = strtok_r(NULL, " \t", &sv2)) {
                char *u = tok[0] == '-' ? xstrdup(tok + 1) : fmt("%s%s%s", tok, tok[strlen(tok) - 1] == '/' ? "" : "/", dfile);
                if (!r->url) r->url = u; else push(&r->alts, u);
                if (tok[0] == '-') r->cache = xstrdup(dfile);
            }
            free(e);
        }
        free(site1); free(base); free(key); free(ver);
    }
    if ((var_get(&vs, "DISTFILES") && !*trim(distfiles)) || (!r->sha512 && var_get(&vs, "TARGET.do-extract"))) { free(r->url); r->url = NULL; r->alts.n = 0; }
    else if (!r->url) {
        char *c2 = xstrdup(sites);
        for (tok = strtok_r(c2, " \t", &save); tok; tok = strtok_r(NULL, " \t", &save)) {
            char *u;
            if (strncmp(tok, "http", 4) && strncmp(tok, "ftp", 3) && strncmp(tok, "file:", 5)) continue;
            u = fmt("%s%s%s", tok, tok[strlen(tok) - 1] == '/' ? "" : "/", dfile);
            if (!r->url) r->url = u; else push(&r->alts, u);
        }
        free(c2);
    }
    if (r->url && r->sha512) push(&r->alts, fmt("https://ftp.netbsd.org/pub/pkgsrc/distfiles/%s%s%s", var_get(&vs, "DIST_SUBDIR") ? var_get(&vs, "DIST_SUBDIR") : "", var_get(&vs, "DIST_SUBDIR") ? "/" : "", dfile));
    /* the dependencies: DEPENDS and BUILD_DEPENDS lines look like pkg>=1.0:../../category/pkg, and buildlink3 includes */
    {
        static const char *const names[] = { "DEPENDS", "BUILD_DEPENDS", "TOOL_DEPENDS", "BUILD_TOOL_DEPENDS", NULL };
        for (i = 0; names[i]; i++) {
            if (!(g = var_get(&vs, names[i]))) continue;
            s = expand(&vs, g, 0);
            for (w = strtok_r(s, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) {
                char *c = strstr(w, ":../../");
                if (!c) continue;
                x = xstrdup(c + 7);
                dep_add(r, x); free(x);
            }
            free(s);
        }
    }
    for (i = 0; i < bl.n; i++) dep_add(r, bl.v[i]);
    for (i = 0; i < need_for.n; i++) if (!strcmp(need_for.v[i], id)) dep_add(r, need_dep.v[i]);
    if ((g = var_get(&vs, "USE_TOOLS"))) {
        int j;
        s = expand(&vs, g, 0);
        for (w = strtok_r(s, " \t", &save); w; w = strtok_r(NULL, " \t", &save)) {
            char *c = strchr(w, ':');
            if (c && !strcmp(c + 1, "test")) continue;
            if (c) *c = 0;
            for (j = 0; tool_pkgs[j][0]; j++) if (!strcmp(w, tool_pkgs[j][0])) dep_add(r, tool_pkgs[j][1]);
        }
        free(s);
    }
    {
        char *pdir = fmt("%s/%s", dir, var_get(&vs, "PATCHDIR") ? var_get(&vs, "PATCHDIR") : "patches");
        DIR *pd2 = opendir(pdir);
        struct dirent *pe;
        int has_patch = 0;
        if (pd2) { while ((pe = readdir(pd2))) if (!strncmp(pe->d_name, "patch-", 6)) has_patch = 1; closedir(pd2); }
        if (has_patch && strcmp(id, "devel/nbpatch") && strcmp(id, "pkgtools/libnbcompat") && strcmp(id, "devel/bmake") && strcmp(id, "pkgtools/bootstrap-mk-files")) dep_add(r, "devel/nbpatch");
        free(pdir);
    }
    /* the steps: patches, configure, build, install, each from the variables pkgsrc has for it */
    {
        const char *prefix_args = "";
        char *cfg = var_get(&vs, var_get(&vs, "MAG_MESON") ? "MESON_ARGS" : "CONFIGURE_ARGS") ? expand(&vs, var_get(&vs, var_get(&vs, "MAG_MESON") ? "MESON_ARGS" : "CONFIGURE_ARGS"), 0) : xstrdup("");
        char *ckey = fmt("CONFIGURE_ARGS.%s", strrchr(id, '/') ? strrchr(id, '/') + 1 : id);
        if (conf_get(ckey)) cfg = fmt("%s %s", cfg, conf_get(ckey));
        free(ckey);
        ckey = fmt("SERIAL.%s", strrchr(id, '/') ? strrchr(id, '/') + 1 : id);
        int serial = conf_get(ckey) != NULL;
        free(ckey);
        char *mflags = fmt("%s%s%s %s", var_get(&vs, "USE_BSD_MAKEFILE") ? "BINDIR=$PREFIX/bin MANDIR=$PREFIX/man LIBDIR=$PREFIX/lib BINOWN=$(id -un) BINGRP=$(id -gn) MANOWN=$(id -un) MANGRP=$(id -gn) LIBOWN=$(id -un) LIBGRP=$(id -gn) " : "", var_get(&vs, "USE_LIBTOOL") ? "LIBTOOL=libtool " : "", var_get(&vs, "MAKE_FLAGS") ? expand(&vs, var_get(&vs, "MAKE_FLAGS"), 0) : "", var_get(&vs, "BUILD_MAKE_FLAGS") ? expand(&vs, var_get(&vs, "BUILD_MAKE_FLAGS"), 0) : "");
        char *menv = var_get(&vs, "MAKE_ENV") ? expand(&vs, var_get(&vs, "MAKE_ENV"), 0) : xstrdup("");
        char *cenv = var_get(&vs, "CONFIGURE_ENV") ? expand(&vs, var_get(&vs, "CONFIGURE_ENV"), 0) : xstrdup("");
        char *btarget = var_get(&vs, "BUILD_TARGET") ? expand(&vs, var_get(&vs, "BUILD_TARGET"), 0) : xstrdup("");
        char *itarget = var_get(&vs, "INSTALL_TARGET") ? expand(&vs, var_get(&vs, "INSTALL_TARGET"), 0) : xstrdup("install");
        char *wrksrc = var_get(&vs, "WRKSRC") ? expand(&vs, var_get(&vs, "WRKSRC"), 0) : NULL;
        int gnu = var_get(&vs, "GNU_CONFIGURE") != NULL, cmake = var_get(&vs, "USE_CMAKE") != NULL, meson = var_get(&vs, "MAG_MESON") != NULL, hasconfig = gnu || var_get(&vs, "HAS_CONFIGURE") != NULL;
        const char *make = "bmake";
        char *pd = var_get(&vs, "PATCHDIR") ? expand(&vs, var_get(&vs, "PATCHDIR"), 0) : xstrdup("patches");
        size_t cap = 4096;
        (void)prefix_args;
        if ((g = var_get(&vs, "USE_TOOLS")) && strstr(g, "gmake")) make = "gmake";
        else if (!var_get(&vs, "TARGET.do-build") && !var_get(&vs, "NO_BUILD") && strcmp(id, "devel/bmake")) dep_add(r, "devel/bmake");
        {
            char *mk = fmt("MAKE.%s", strrchr(id, '/') ? strrchr(id, '/') + 1 : id);
            if (conf_get(mk)) make = conf_get(mk);
            free(mk);
        }
        var_set(&vs, "MAKE", make);
        if (var_get(&vs, "MAG_MESON")) { dep_add(r, "devel/samurai"); dep_add(r, "devel/meson"); }
        if (var_get(&vs, "USE_CMAKE")) dep_add(r, "devel/cmake");
        if (var_get(&vs, "USE_LIBTOOL")) dep_add(r, "dev-build/libtool");
        { int ti; for (ti = 0; ti < vs.n; ti++) if (!strncmp(vs.k[ti], "TARGET.", 7)) cap += strlen(vs.v[ti]) * 4; }
        steps = xmalloc(cap + strlen(cfg) + strlen(mflags) + strlen(menv) + strlen(cenv) + 1024);
        steps[0] = 0;
        cmd = steps;
        cmd += sprintf(cmd, "export BSD_INSTALL_PROGRAM='install -m 755' BSD_INSTALL_PROGRAM_DIR='install -d -m 755' BSD_INSTALL_SCRIPT='install -m 755' BSD_INSTALL_SCRIPT_DIR='install -d -m 755' BSD_INSTALL_LIB='install -m 755' BSD_INSTALL_LIB_DIR='install -d -m 755' BSD_INSTALL_DATA='install -m 644' BSD_INSTALL_DATA_DIR='install -d -m 755' BSD_INSTALL_MAN='install -m 644' BSD_INSTALL_MAN_DIR='install -d -m 755'\n");
        if (!var_get(&vs, "TARGET.do-extract")) cmd += sprintf(cmd, "ln -sfn src \"$SRC/../%s\"\n", distname);
        int noget = !r->url && var_get(&vs, "TARGET.do-extract");
        if (!noget && wrksrc && !strncmp(wrksrc, "$SRC/../", 8) && !strchr(wrksrc + 8, '/') && strcmp(wrksrc + 8, distname)) cmd += sprintf(cmd, "ln -sfn src \"%s\"\n", wrksrc);
        if (wrksrc && strstr(wrksrc, "/") ) {
            char *rel = strstr(wrksrc, distname);
            if (rel && rel[strlen(distname)] == '/') cmd += sprintf(cmd, "cd %s\n", rel + strlen(distname) + 1);
        }
        char *hook[16] = { 0 };
        static const char *const hn[] = { "do-extract", "post-extract", "pre-configure", "do-configure", "post-configure", "pre-build", "do-build", "post-build", "pre-install", "do-install", "post-install", NULL };
        int hi, own_extract = var_get(&vs, "TARGET.do-extract") != NULL;
        for (hi = 0; hn[hi]; hi++) {
            char *key = fmt("TARGET.%s", hn[hi]);
            if (var_get(&vs, key)) hook[hi] = expand(&vs, var_get(&vs, key), 0);
            free(key);
        }
        if (hook[0]) {
            cmd += sprintf(cmd, "%s\n", hook[0]);
            if (noget && wrksrc && !strncmp(wrksrc, "$SRC/../", 8)) cmd += sprintf(cmd, "[ -e %s ] || ln -sfn src %s\n", wrksrc, wrksrc);
            if (wrksrc && !strncmp(wrksrc, "$SRC/../", 8)) cmd += sprintf(cmd, "cd %s\n", wrksrc);
        }
        if (hook[1]) cmd += sprintf(cmd, "%s\n", hook[1]);
        cmd += sprintf(cmd, "P=patch; command -v nbpatch >/dev/null && P=nbpatch\nfor p in \"$RECIPE_DIR\"/%s/patch-*; do [ -f \"$p\" ] || continue; $P -p0 < \"$p\"; done\n", pd);
        {
            char *cls = var_get(&vs, "SUBST_CLASSES") ? expand(&vs, var_get(&vs, "SUBST_CLASSES"), 0) : NULL, *csave, *cw;
            if (cls) for (cw = strtok_r(cls, " \t", &csave); cw; cw = strtok_r(NULL, " \t", &csave)) {
                char *k = fmt("SUBST_STAGE.%s", cw), *st = var_get(&vs, k) ? expand(&vs, var_get(&vs, k), 0) : xstrdup("pre-configure"), *sed, *files, *vars, *vsave, *vw;
                int ok = !strcmp(st, "pre-configure") || !strcmp(st, "post-patch") || !strcmp(st, "post-extract") || !strcmp(st, "pre-patch");
                free(k); free(st);
                if (!ok) continue;
                k = fmt("SUBST_SED.%s", cw); sed = var_get(&vs, k) ? expand(&vs, var_get(&vs, k), 0) : xstrdup(""); free(k);
                k = fmt("SUBST_FILES.%s", cw); files = var_get(&vs, k) ? expand(&vs, var_get(&vs, k), 0) : xstrdup(""); free(k);
                k = fmt("SUBST_VARS.%s", cw); vars = var_get(&vs, k) ? expand(&vs, var_get(&vs, k), 0) : xstrdup(""); free(k);
                { char *sv = xstrdup(sed); free(sed); sed = sv; }
                for (vw = strtok_r(vars, " \t", &vsave); vw; vw = strtok_r(NULL, " \t", &vsave)) {
                    char *ve = fmt("${%s}", vw), *val = expand(&vs, ve, 0), *tmp = fmt("%s -e \"s|@%s@|%s|g\"", sed, vw, val);
                    free(ve); free(val); free(sed); sed = tmp;
                }
                if (*sed && *trim(files)) cmd += sprintf(cmd, "sed -i %s %s\n", sed, files);
                free(sed); free(files); free(vars);
            }
            free(cls);
        }
        if (hook[2]) cmd += sprintf(cmd, "%s\n", hook[2]);
        if (hook[3]) cmd += sprintf(cmd, "%s\n", hook[3]);
        else if (hasconfig && !cmake && !meson) {
            const char *scr = var_get(&vs, "CONFIGURE_SCRIPT") ? var_get(&vs, "CONFIGURE_SCRIPT") : "./configure";
            if (gnu || (!var_get(&vs, "CONFIGURE_SCRIPT") && !strstr(cfg, "--prefix="))) cmd += sprintf(cmd, "%s %s %s %s --sysconfdir=/etc --localstatedir=/var %s\n", cenv, scr, strstr(cfg, "--prefix=") ? "" : "--prefix=$PREFIX", strstr(cfg, "--mandir=") ? "" : "--mandir=$PREFIX/man", cfg);
            else cmd += sprintf(cmd, "%s %s %s\n", cenv, scr, cfg);
        }
        if (hook[4]) cmd += sprintf(cmd, "%s\n", hook[4]);
        if (meson && !hook[3]) cmd += sprintf(cmd, "%s meson setup --prefix=$PREFIX --libdir=lib --libexecdir=libexec --mandir=man --sysconfdir=/etc --buildtype=plain --wrap-mode=nodownload \"-Dc_args=$CFLAGS $CPPFLAGS -Wno-unused-command-line-argument\" \"-Dc_link_args=$LDFLAGS\" %s . mag-build\nsamu -C mag-build\n", cenv, cfg);
        else if (cmake && !hook[3]) cmd += sprintf(cmd, "mkdir -p mag-build && cd mag-build && %s cmake -G Ninja -DCMAKE_INSTALL_PREFIX=$PREFIX -DCMAKE_INSTALL_LIBDIR=lib %s ..\nsamu\n", cenv, cfg);
        else {
            if (hook[5]) cmd += sprintf(cmd, "%s\n", hook[5]);
            if (hook[6]) cmd += sprintf(cmd, "%s\n", hook[6]);
            else if (!var_get(&vs, "NO_BUILD")) cmd += sprintf(cmd, "%s%s %s %s %s %s\n", var_get(&vs, "USE_BSD_MAKEFILE") ? "env -u DESTDIR " : "", menv, make, serial || (var_get(&vs, "MAKE_JOBS_SAFE") && !strcmp(var_get(&vs, "MAKE_JOBS_SAFE"), "no")) ? "-j1" : "-j$JOBS", mflags, btarget);
            if (hook[7]) cmd += sprintf(cmd, "%s\n", hook[7]);
        }
        {
            char *dirs = var_get(&vs, "INSTALLATION_DIRS") ? expand(&vs, var_get(&vs, "INSTALLATION_DIRS"), 0) : NULL;
            char *dsave, *dw;
            if (dirs) for (dw = strtok_r(dirs, " \t", &dsave); dw; dw = strtok_r(NULL, " \t", &dsave)) cmd += sprintf(cmd, "mkdir -p $DESTDIR%s%s\n", dw[0] == '/' || dw[0] == '$' ? "" : "$PREFIX/", dw);
            free(dirs);
        }
        if (var_get(&vs, "AUTO_MKDIRS")) cmd += sprintf(cmd, "mkdir -p $DESTDIR$PREFIX/bin $DESTDIR$PREFIX/sbin $DESTDIR$PREFIX/lib $DESTDIR$PREFIX/share $DESTDIR$PREFIX/man/man1 $DESTDIR$PREFIX/man/man5 $DESTDIR$PREFIX/man/man8\n");
        if (hook[8]) cmd += sprintf(cmd, "(cd \"$RECIPE_DIR\" || exit 1\n%s\n)\n", hook[8]);
        if (hook[9]) cmd += sprintf(cmd, "(cd \"$RECIPE_DIR\" || exit 1\n%s\n)\n", hook[9]);
        else if (cmake) cmd += sprintf(cmd, "DESTDIR=$DESTDIR samu install\n");
        else if (meson) cmd += sprintf(cmd, "DESTDIR=$DESTDIR samu -C mag-build install\n");
        else cmd += sprintf(cmd, "%s %s DESTDIR=$DESTDIR %s %s\n", menv, make, mflags, itarget);
        if (hook[10]) cmd += sprintf(cmd, "(cd \"$RECIPE_DIR\" || exit 1\n%s\n)\n", hook[10]);
        for (hi = 0; hn[hi]; hi++) free(hook[hi]);
        r->steps = r->url || own_extract ? steps : xstrdup("true\n");
        free(cfg); free(mflags); free(menv); free(cenv); free(btarget); free(itarget); free(wrksrc); free(pd);
    }
    free(dtext); free(distname); free(pkgname); free(sufx); free(distfiles); free(dfile); free(sites);
    (void)repo;
    return r;
}

/* cat/name inside one repo: a file, a directory with a file called recipe in it, or a pkgsrc package */
static struct recipe *try_repo(const char *repo, const char *id)
{
    char *p = fmt("%s/%s", repo, id);
    struct recipe *r = NULL;
    struct stat st;
    if (stat(p, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            char *f = fmt("%s/recipe", p), *mk = fmt("%s/Makefile", p);
            if (exists(f)) r = parse_recipe(id, f, p);
            else if (exists(mk)) r = parse_pkgsrc(id, p, repo);
            free(f); free(mk);
        }
        else r = parse_recipe(id, p, repo);
    }
    free(p);
    return r;
}

static struct recipe *find_recipe(const char *name)
{
    struct list hits = { 0 };
    int i;
    if (strchr(name, '/')) {
        for (i = 0; i < nrepos; i++) { struct recipe *r = try_repo(repos[i], name); if (r) return r; }
        return NULL;
    }
    for (i = 0; i < nrepos; i++) {
        DIR *d = opendir(repos[i]);
        struct dirent *e;
        if (!d) continue;
        while ((e = readdir(d))) {
            char *id;
            struct recipe *r;
            if (e->d_name[0] == '.') continue;
            id = fmt("%s/%s", e->d_name, name);
            r = try_repo(repos[i], id);
            if (r && !has(&hits, id)) push(&hits, id); else free(id);
        }
        closedir(d);
    }
    if (hits.n > 1) {
        fprintf(stderr, "%s: '%s' is more than one package:", prog, name);
        for (i = 0; i < hits.n; i++) fprintf(stderr, " %s", hits.v[i]);
        fputc('\n', stderr);
        exit(1);
    }
    if (hits.n == 1) {
        for (i = 0; i < nrepos; i++) { struct recipe *r = try_repo(repos[i], hits.v[0]); if (r) return r; }
    }
    return NULL;
}

/* ---- the database of what is installed: var/lib/mag/category/name/{version,files,deps,explicit} ---- */

static char *dbdir(const char *id) { return fmt("%s/var/lib/mag/%s", root, id); }

static char *db_version(const char *id)
{
    char *d = dbdir(id), *f = fmt("%s/version", d), *v = slurp(f, NULL);
    free(d); free(f);
    if (v) trim(v);
    return v;
}

static int installed(const char *id) { char *v = db_version(id); free(v); return v != NULL; }

static struct list db_read(const char *id, const char *what)
{
    struct list l = { 0 };
    char *d = dbdir(id), *f = fmt("%s/%s", d, what), *t = slurp(f, NULL), *line, *next;
    free(d); free(f);
    if (!t) return l;
    for (line = t; line && *line; line = next) {
        next = strchr(line, '\n');
        if (next) *next++ = 0;
        if (*line) push(&l, xstrdup(line));
    }
    free(t);
    return l;
}

static void db_write(const char *id, const char *what, const struct list *l)
{
    char *d = dbdir(id), *f;
    FILE *fp;
    int i;
    mkpath(d, 0755);
    f = fmt("%s/%s", d, what);
    fp = fopen(f, "w");
    if (!fp) die("cannot write %s: %s", f, strerror(errno));
    for (i = 0; i < l->n; i++) fprintf(fp, "%s\n", l->v[i]);
    fclose(fp);
    free(d); free(f);
}

static struct list db_all(void)
{
    struct list l = { 0 };
    char *base = fmt("%s/var/lib/mag", root);
    DIR *cd = opendir(base);
    struct dirent *c;
    if (cd) {
        while ((c = readdir(cd))) {
            char *cp;
            DIR *nd;
            struct dirent *n;
            if (c->d_name[0] == '.') continue;
            cp = fmt("%s/%s", base, c->d_name);
            nd = opendir(cp);
            if (nd) {
                while ((n = readdir(nd))) if (n->d_name[0] != '.') push(&l, fmt("%s/%s", c->d_name, n->d_name));
                closedir(nd);
            }
            free(cp);
        }
        closedir(cd);
    }
    free(base);
    if (l.n) qsort(l.v, l.n, sizeof *l.v, cmp_str);
    return l;
}

/* the packages that list id among their deps */
static struct list rdeps(const char *id)
{
    struct list all = db_all(), out = { 0 };
    int i;
    for (i = 0; i < all.n; i++) {
        struct list d = db_read(all.v[i], "deps");
        if (strcmp(all.v[i], id) && has(&d, id)) push(&out, all.v[i]);
    }
    return out;
}

/* ---- fetching and building ---- */

static char *distfile(const struct recipe *r)
{
    const char *b = r->cache ? r->cache : strrchr(r->url, '/');
    if (r->cache) return fmt("%s/var/cache/mag/%s", root, r->cache);
    return fmt("%s/var/cache/mag/%s", root, b ? b + 1 : r->url);
}

static char *dist_sum(const struct recipe *r, const char *file) { return r->sha512 ? sha512_file(file) : sha256_file(file); }

/* MAG_FETCH if set, else the first of curl, wget and ftp on PATH. It gets the output file and the url */
static const char *downloader(void)
{
    static const char *cmds[][2] = { { "curl", "curl -fsSL -o" }, { "wget", "wget -q -O" }, { "ftp", "ftp -o" } };
    const char *env = getenv("MAG_FETCH"), *pa = getenv("PATH");
    int i;
    if (env) return env;
    /* this curl hands LibreSSL an empty CApath and fails to load a bundle unless it gets a directory too */
    if (!access("/etc/ssl/cert.pem", R_OK)) cmds[0][1] = "curl -fsSL --cacert /etc/ssl/cert.pem --capath /etc/ssl -o";
    for (i = 0; i < 3; i++) {
        char *p = xstrdup(pa ? pa : "/usr/bin:/bin"), *sv, *d;
        for (d = strtok_r(p, ":", &sv); d; d = strtok_r(NULL, ":", &sv)) {
            char *f = fmt("%s/%s", d, cmds[i][0]);
            int ok = !access(f, X_OK);
            free(f);
            if (ok) { free(p); return cmds[i][1]; }
        }
        free(p);
    }
    return "curl -fsSL -o";
}

static int fetch(const struct recipe *r)
{
    char *file, *sum, *tmp;
    const char *want = r->sha512 ? r->sha512 : r->sha;
    int i, got = 0;
    if (!r->url) return 0;
    if (!want) die("%s has no checksum", r->id);
    file = distfile(r);
    sum = dist_sum(r, file);
    if (sum && !strcmp(sum, want)) { free(sum); free(file); return 0; }
    if (sum) { say("%s: the cached file does not match, fetching again", r->id); unlink(file); }
    free(sum);
    {
        char *dir = xstrdup(file), *sl = strrchr(dir, '/');
        const char *cmd = downloader();
        *sl = 0;
        mkpath(dir, 0755);
        free(dir);
        tmp = fmt("%s.part", file);
        for (i = -1; i < r->alts.n && !got; i++) {
            const char *url = i < 0 ? r->url : r->alts.v[i];
            char *av[7];
            printf("==> fetching %s\n", url);
            av[0] = "/bin/sh"; av[1] = "-c"; av[2] = "set -f; $0 \"$1\" \"$2\""; av[3] = (char *)cmd;
            av[4] = tmp; av[5] = (char *)url; av[6] = NULL;
            if (run(av, NULL)) { unlink(tmp); continue; }
            sum = dist_sum(r, tmp);
            if (sum && !strcmp(sum, want)) { rename(tmp, file); got = 1; }
            else {
                say("%s: wrong %s from %s", r->id, r->sha512 ? "sha512" : "sha256", url);
                say("  recipe: %s", want);
                say("  file:   %s", sum ? sum : "unreadable");
                unlink(tmp);
            }
            free(sum);
            sum = NULL;
        }
        if (!got) die("could not fetch %s", r->url);
    }
    free(tmp); free(file);
    return 0;
}

static int is_archive(const char *name)
{
    static const char *const ext[] = { ".tar", ".tar.gz", ".tgz", ".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".tar.zst", ".tar.lz", NULL };
    size_t n = strlen(name);
    int i;
    for (i = 0; ext[i]; i++) { size_t l = strlen(ext[i]); if (n > l && !strcmp(name + n - l, ext[i])) return 1; }
    return 0;
}

static char *workdir(const struct recipe *r)
{
    char *w = fmt("%s/var/tmp/mag/%s", root, r->id), *s;
    for (s = w + strlen(root) + strlen("/var/tmp/mag/"); *s; s++) if (*s == '/') *s = '-';
    return w;
}

static void rmtree(const char *path)
{
    char *av[] = { "rm", "-rf", (char *)path, NULL };
    run(av, NULL);
}

/* builds the recipe, returns the stage directory its files were installed into */
static char *build(const struct recipe *r)
{
    char *work = workdir(r), *src, *stage, *file = NULL;
    const char *sh = getenv("MAG_SH"), *jobs = getenv("MAG_JOBS"), *prefix = getenv("MAG_PREFIX");
    char *av[4];
    rmtree(work);
    src = fmt("%s/src", work); stage = fmt("%s/stage", work);
    if (mkpath(src, 0755) < 0 || mkpath(stage, 0755) < 0) die("cannot make %s: %s", work, strerror(errno));
    if (r->url) {
        file = distfile(r);
        if (is_archive(file)) {
            char *x[] = { "tar", "-xf", file, "-C", src, "--strip-components=1", NULL };
            printf("==> unpacking %s\n", file);
            if (run(x, NULL)) die("could not unpack %s", file);
        } else {
            char *b = strrchr(file, '/') + 1, *to = fmt("%s/%s", src, b), *x[] = { "cp", file, to, NULL };
            if (run(x, NULL)) die("could not copy %s", file);
        }
    }
    setenv("DESTDIR", stage, 1);
    setenv("SRC", src, 1);
    setenv("NAME", strrchr(r->id, '/') + 1, 1);
    setenv("VERSION", r->version, 1);
    setenv("RECIPE_DIR", r->dir, 1);
    setenv("PREFIX", prefix ? prefix : "/usr", 1);
    setenv("ROOT", root, 1);
    if (*root) { char *m = fmt("%s/usr/share/mk", root); setenv("MAKESYSPATH", m, 1); free(m); }
    if (*root) {
        /* a root that is not / holds the dependencies: the compiler, the linker and the shell have to look there too */
        const char *pa = getenv("PATH"), *cp = getenv("CPPFLAGS"), *lf = getenv("LDFLAGS");
        char *v;
        v = fmt("%s/usr/bin:%s/bin:%s", root, root, pa ? pa : "/usr/bin:/bin"); setenv("PATH", v, 1); free(v);
        v = fmt("-I%s/usr/include %s", root, cp ? cp : ""); setenv("CPPFLAGS", v, 1); free(v);
        v = fmt("-L%s/usr/lib %s", root, lf ? lf : ""); setenv("LDFLAGS", v, 1); free(v);
        v = fmt("-I%s/usr/include %s", root, getenv("CFLAGS") ? getenv("CFLAGS") : conf_get("CFLAGS") ? conf_get("CFLAGS") : "-O2"); setenv("CFLAGS", v, 1); free(v);
        v = fmt("%s/usr/lib/pkgconfig:%s/usr/share/pkgconfig", root, root); setenv("PKG_CONFIG_PATH", v, 1); setenv("PKG_CONFIG_LIBDIR", v, 1); setenv("PKG_CONFIG_SYSROOT_DIR", root, 1); free(v);
    }
    if (*root) {
        /* once the root has a musl in it, what is built there is built for it: clang aimed at the root, the loader and the libraries by their path in the root so the programs run on this machine too. mag relocate puts the real paths back */
        char *crt = fmt("%s/usr/lib/crt1.o", root), *so = fmt("%s/usr/lib/libc.so", root);
        if (exists(crt) && exists(so)) {
            char *bin = fmt("%s/tools", work), *cc = fmt("%s/cc", bin), *real = NULL, *pa = getenv("PATH"), *pcopy = xstrdup(pa ? pa : "/usr/bin"), *tok, *sv, *script, *np;
            static const char *const names[] = { "gcc", "clang", "c99", "cpp-unused", NULL };
            int ni;
            for (tok = strtok_r(pcopy, ":", &sv); tok && !real; tok = strtok_r(NULL, ":", &sv)) {
                char *c = fmt("%s/clang", tok);
                if (exists(c) && strncmp(tok, root, strlen(root))) real = c; else free(c);
            }
            free(pcopy);
            if (!real) die("no clang in PATH: it is the compiler for a musl root");
            mkpath(bin, 0755);
            script = fmt("#!/bin/sh\nn=$#\nwhile [ $n -gt 0 ]; do x=$1; shift; n=$((n - 1)); case $x in -lgcc|-lgcc_s|-lgcc_eh) ;; *) set -- \"$@\" \"$x\";; esac; done\nl=\"-fuse-ld=lld -rtlib=compiler-rt -Wl,--dynamic-linker=%s -Wl,-rpath,%s/usr/lib\"\ncase \" $* \" in *\" -c \"*|*\" -E \"*|*\" -S \"*) l=;; esac\nexec %s --target=x86_64-linux-musl --sysroot=%s -nostdlibinc -isystem %s/usr/include -Wno-unused-command-line-argument $l \"$@\"\n", so, root, real, root, root);
            { FILE *f = fopen(cc, "w"); if (!f) die("cannot write %s", cc); fputs(script, f); fclose(f); chmod(cc, 0755); }
            for (ni = 0; names[ni]; ni++) { char *l = fmt("%s/%s", bin, names[ni]); unlink(l); symlink("cc", l); free(l); }
            np = fmt("%s:%s", bin, getenv("PATH")); setenv("PATH", np, 1); free(np);
            setenv("CC", "cc", 1);
            free(real); free(script); free(bin); free(cc);
        }
        free(crt); free(so);
    }
    if (!jobs) jobs = conf_get("JOBS") ? conf_get("JOBS") : conf_get("MAKE_JOBS");
    setenv("JOBS", jobs ? jobs : "4", 1);
    {
        static const char *const fl[] = { "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS", NULL };
        int fi;
        for (fi = 0; fl[fi]; fi++) if (conf_get(fl[fi]) && !getenv(fl[fi])) setenv(fl[fi], conf_get(fl[fi]), 1);
    }
    printf("==> building %s %s\n", r->id, r->version);
    av[0] = (char *)(sh ? sh : "/bin/sh"); av[1] = "-ec"; av[2] = r->steps; av[3] = NULL;
    if (run(av, src)) die("%s: the steps failed, left in %s", r->id, work);
    free(src); free(file); free(work);
    return stage;
}

/* ---- installing and removing ---- */

static void walk(const char *base, const char *rel, struct list *out)
{
    char *dir = *rel ? fmt("%s/%s", base, rel) : xstrdup(base);
    DIR *d = opendir(dir);
    struct dirent *e;
    struct list names = { 0 };
    int i;
    if (!d) die("cannot read %s: %s", dir, strerror(errno));
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) push(&names, xstrdup(e->d_name));
    closedir(d);
    qsort(names.v, names.n, sizeof *names.v, cmp_str);
    for (i = 0; i < names.n; i++) {
        char *relp = *rel ? fmt("%s/%s", rel, names.v[i]) : xstrdup(names.v[i]), *full = fmt("%s/%s", base, relp);
        struct stat st;
        if (lstat(full, &st) < 0) die("cannot stat %s", full);
        if (S_ISDIR(st.st_mode)) walk(base, relp, out);
        else if (strcmp(relp, "usr/share/info/dir")) push(out, relp);
        free(full);
    }
    free(dir);
}

static int copy_into(const char *from, const char *to, mode_t mode)
{
    int in = open(from, O_RDONLY), out;
    char buf[65536], *tmp = fmt("%s.mag-new", to);
    ssize_t n;
    if (in < 0) return -1;
    unlink(tmp);
    out = open(tmp, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (out < 0) { close(in); return -1; }
    while ((n = read(in, buf, sizeof buf)) > 0) {
        char *p = buf;
        while (n) { ssize_t w = write(out, p, n); if (w < 0) { close(in); close(out); unlink(tmp); return -1; } p += w; n -= w; }
    }
    close(in);
    fchmod(out, mode & 07777);
    if (close(out) < 0 || n < 0) { unlink(tmp); return -1; }
    if (rename(tmp, to) < 0) { unlink(tmp); return -1; }
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
    }
    qsort(owners, nowners, sizeof *owners, cmp_owner);
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
        int depth = 0;
        const char *c;
        *s = 0;
        for (c = p; *c; c++) if (*c == '/') depth++;
        if (depth < 1) break;
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

/* the same file in both places: same link target, or same contents */
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

static int install_stage(const struct recipe *r, const char *stage, int explicit)
{
    struct list files = { 0 }, old, kept = { 0 };
    int i, bad = 0;
    char *oldver = db_version(r->id);
    walk(stage, "", &files);
    load_owners();
    old = db_read(r->id, "files");
    for (i = 0; i < files.n; i++) {
        const char *o = owner_of(files.v[i]);
        char *full = fmt("%s/%s", root, files.v[i]);
        if (o && strcmp(o, r->id)) { say("%s wants %s, which %s has", r->id, files.v[i], o); bad++; }
        else if (!o && exists(full) && strncmp(files.v[i], "etc/", 4)) {
            char *from = fmt("%s/%s", stage, files.v[i]);
            if (!same_file(from, full)) { if (bad < 5) say("%s wants %s, which is there already and is different", r->id, files.v[i]); bad++; }
            free(from);
        }
        free(full);
    }
    if (bad > 5) say("and %d more", bad - 5);
    if (bad && !force) die("not installing %s, %d files are in the way, -f writes over them", r->id, bad);
    bad = 0;
    for (i = 0; i < files.n; i++) {
        char *from = fmt("%s/%s", stage, files.v[i]), *to = fmt("%s/%s", root, files.v[i]), *dir = xstrdup(to), *sl = strrchr(dir, '/');
        struct stat st;
        *sl = 0;
        mkpath(dir, 0755);
        if (lstat(from, &st) < 0) die("cannot stat %s", from);
        if (S_ISLNK(st.st_mode)) {
            char tgt[PATH_MAX];
            ssize_t n = readlink(from, tgt, sizeof tgt - 1);
            if (n < 0) die("cannot read link %s", from);
            tgt[n] = 0;
            unlink(to);
            if (symlink(tgt, to) < 0) { say("cannot link %s: %s", to, strerror(errno)); bad = 1; }
        } else if (!strncmp(files.v[i], "etc/", 4) && exists(to)) {
            char *a = sha256_file(from), *b = sha256_file(to), *alt = fmt("%s.new", to);
            if (a && b && strcmp(a, b)) {
                printf("==> %s is already there, the new one is %s.new\n", files.v[i], files.v[i]);
                if (copy_into(from, alt, st.st_mode) < 0) { say("cannot write %s: %s", alt, strerror(errno)); bad = 1; }
            }
            free(a); free(b); free(alt);
        } else if (copy_into(from, to, st.st_mode) < 0) { say("cannot write %s: %s", to, strerror(errno)); bad = 1; }
        free(from); free(to); free(dir);
    }
    if (bad) die("%s did not install cleanly", r->id);
    for (i = 0; i < old.n; i++) if (!has(&files, old.v[i])) push(&kept, old.v[i]);
    delete_files(&kept);
    {
        struct list v = { 0 }, d = r->deps;
        char *e;
        push(&v, r->version);
        db_write(r->id, "version", &v);
        db_write(r->id, "deps", &d);
        db_write(r->id, "files", &files);
        e = fmt("%s/explicit", dbdir(r->id));
        if (explicit) { FILE *f = fopen(e, "w"); if (f) fclose(f); }
    }
    printf("==> installed %s %s%s%s\n", r->id, r->version, oldver ? ", was " : "", oldver ? oldver : "");
    free(oldver);
    return 0;
}

/* ---- working out what to install ---- */

static void plan(const char *name, const char *from, struct list *order, struct list *seen, struct list *stack)
{
    struct recipe *r = find_recipe(name);
    int i;
    if (!r) die("no recipe for %s%s%s", name, from ? ", wanted by " : "", from ? from : "");
    if (has(stack, r->id)) die("%s needs itself through %s", r->id, from ? from : "?");
    if (has(seen, r->id)) return;
    push(stack, r->id);
    for (i = 0; i < r->deps.n; i++) {
        struct recipe *d = find_recipe(r->deps.v[i]);
        if (!d) die("no recipe for %s, wanted by %s", r->deps.v[i], r->id);
        if (strcmp(d->id, r->id) && !installed(d->id)) plan(d->id, r->id, order, seen, stack);
    }
    stack->n--;
    push(seen, r->id);
    push(order, r->id);
}

static int cmd_install(int n, char **names)
{
    struct list order = { 0 }, seen = { 0 }, stack = { 0 }, want = { 0 };
    int i;
    for (i = 0; i < n; i++) {
        struct recipe *r = find_recipe(names[i]);
        if (!r) die("no recipe for %s", names[i]);
        push(&want, r->id);
        if (installed(r->id) && !force) {
            char *v = db_version(r->id);
            if (!strcmp(v, r->version)) { printf("%s %s is installed already\n", r->id, v); free(v); continue; }
            free(v);
        }
        plan(r->id, NULL, &order, &seen, &stack);
    }
    if (!order.n) return 0;
    printf("will install:");
    for (i = 0; i < order.n; i++) printf(" %s", order.v[i]);
    putchar('\n');
    if (dry) return 0;
    for (i = 0; i < order.n; i++) {
        struct recipe *r = find_recipe(order.v[i]);
        char *stage;
        fetch(r);
        stage = build(r);
        install_stage(r, stage, has(&want, r->id));
        if (!keep) { char *w = workdir(r); rmtree(w); free(w); }
    }
    return 0;
}

static int cmd_remove(int n, char **names)
{
    int i;
    for (i = 0; i < n; i++) {
        struct recipe *r = find_recipe(names[i]);
        const char *id = r ? r->id : names[i];
        struct list rd, files;
        char *d;
        if (!installed(id)) die("%s is not installed", id);
        rd = rdeps(id);
        if (rd.n && !force) {
            int k;
            fprintf(stderr, "%s: %s is needed by", prog, id);
            for (k = 0; k < rd.n; k++) fprintf(stderr, " %s", rd.v[k]);
            fputs(", -f removes it anyway\n", stderr);
            return 1;
        }
        files = db_read(id, "files");
        if (dry) { printf("would remove %s (%d files)\n", id, files.n); continue; }
        delete_files(&files);
        d = dbdir(id);
        rmtree(d);
        {
            char *cat = xstrdup(d), *sl = strrchr(cat, '/');
            *sl = 0;
            rmdir(cat);
            free(cat);
        }
        free(d);
        printf("==> removed %s\n", id);
    }
    return 0;
}

static int cmd_upgrade(void)
{
    struct list all = db_all(), todo = { 0 };
    int i;
    for (i = 0; i < all.n; i++) {
        struct recipe *r = find_recipe(all.v[i]);
        char *v = db_version(all.v[i]);
        if (r && strcmp(r->version, v)) push(&todo, all.v[i]);
        free(v);
    }
    if (!todo.n) { puts("everything is up to date"); return 0; }
    return cmd_install(todo.n, todo.v);
}

/* what is installed, needed by nothing and not asked for by name */
static struct list orphans(void)
{
    struct list all = db_all(), out = { 0 };
    int i;
    for (i = 0; i < all.n; i++) {
        char *d = dbdir(all.v[i]), *e = fmt("%s/explicit", d);
        struct list rd = rdeps(all.v[i]);
        if (!exists(e) && !rd.n) push(&out, all.v[i]);
        free(d); free(e);
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
    for (i = 0; i < all.n; i++) { char *v = db_version(all.v[i]); printf("%s %s\n", all.v[i], v); free(v); }
    return 0;
}

static int cmd_info(const char *name)
{
    struct recipe *r = find_recipe(name);
    char *v;
    int i;
    if (!r) die("no recipe for %s", name);
    v = db_version(r->id);
    printf("%s %s\n", r->id, r->version);
    if (*r->desc) printf("  %s\n", r->desc);
    if (r->url) printf("  source: %s\n", r->url);
    if (r->options) printf("  options: %s\n", r->options);
    if (r->deps.n) { printf("  deps:"); for (i = 0; i < r->deps.n; i++) printf(" %s", r->deps.v[i]); putchar('\n'); }
    printf("  recipe: %s\n", r->file);
    if (v) printf("  installed: %s\n", v); else puts("  not installed");
    return 0;
}

static int cmd_search(const char *word)
{
    int i;
    for (i = 0; i < nrepos; i++) {
        DIR *cd = opendir(repos[i]);
        struct dirent *c;
        if (!cd) continue;
        while ((c = readdir(cd))) {
            char *cp;
            DIR *nd;
            struct dirent *e;
            if (c->d_name[0] == '.') continue;
            cp = fmt("%s/%s", repos[i], c->d_name);
            nd = opendir(cp);
            if (nd) {
                while ((e = readdir(nd))) {
                    char *id;
                    struct recipe *r;
                    if (e->d_name[0] == '.') continue;
                    id = fmt("%s/%s", c->d_name, e->d_name);
                    r = try_repo(repos[i], id);
                    if (r && (strstr(id, word) || strstr(r->desc, word))) printf("%s %s  %s\n", id, r->version, r->desc);
                    free(id);
                }
                closedir(nd);
            }
            free(cp);
        }
        closedir(cd);
    }
    return 0;
}

static int cmd_files(const char *name)
{
    struct recipe *r = find_recipe(name);
    const char *id = r ? r->id : name;
    struct list f;
    int i;
    if (!installed(id)) die("%s is not installed", id);
    f = db_read(id, "files");
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
    struct recipe *r = find_recipe(name);
    const char *id = r ? r->id : name;
    int i;
    if (reverse) {
        struct list rd = rdeps(id);
        for (i = 0; i < rd.n; i++) puts(rd.v[i]);
        return 0;
    }
    if (!r) die("no recipe for %s", name);
    for (i = 0; i < r->deps.n; i++) puts(r->deps.v[i]);
    return 0;
}

static int cmd_hash(int n, char **files)
{
    int i, bad = 0;
    for (i = 0; i < n; i++) {
        char *h = sha256_file(files[i]);
        if (!h) { say("%s: %s", files[i], strerror(errno)); bad = 1; continue; }
        printf("%s  %s\n", h, files[i]);
        free(h);
    }
    return bad;
}

static int cmd_sync(void)
{
    const char *url = getenv("MAG_SYNC_URL"), *cmd = downloader();
    char *file = fmt("%s/var/cache/mag/pkgsrc.tar.xz", root), *part = fmt("%s.part", file), *tmp = fmt("%s/usr/pkgsrc.sync", root), *tree = fmt("%s/usr/pkgsrc", root), *from = fmt("%s/pkgsrc", tmp);
    char *dl[] = { "/bin/sh", "-c", "set -f; $0 \"$1\" \"$2\"", (char *)cmd, part, (char *)(url ? url : "https://ftp.netbsd.org/pub/pkgsrc/current/pkgsrc.tar.xz"), NULL };
    char *un[] = { "tar", "-xf", file, "-C", tmp, NULL };
    char *rm[] = { "rm", "-rf", tree, NULL };
    char *dir = xstrdup(file);
    *strrchr(dir, '/') = 0;
    if (mkpath(dir, 0755) < 0) die("cannot make %s: %s", dir, strerror(errno));
    printf("==> fetching %s\n", dl[5]);
    if (run(dl, NULL)) { unlink(part); die("could not fetch %s", dl[5]); }
    if (rename(part, file)) die("cannot write %s: %s", file, strerror(errno));
    rmtree(tmp);
    if (mkpath(tmp, 0755) < 0) die("cannot make %s: %s", tmp, strerror(errno));
    printf("==> unpacking into %s\n", tree);
    if (run(un, NULL)) { rmtree(tmp); die("could not unpack %s", file); }
    run(rm, NULL);
    if (rename(from, tree)) { rmtree(tmp); die("cannot move the tree to %s: %s", tree, strerror(errno)); }
    rmdir(tmp);
    unlink(file);
    free(dir);
    return 0;
}

static int cmd_fetch(int n, char **names)
{
    int i;
    for (i = 0; i < n; i++) {
        struct recipe *r = find_recipe(names[i]);
        if (!r) die("no recipe for %s", names[i]);
        fetch(r);
    }
    return 0;
}

/* programs built in a root carry its path as their loader and library path; this puts the ones a real system has back, in place and padded with NULs */
static void reloc_file(const char *path, const char *from, const char *to)
{
    size_t len, fl = strlen(from), tl = strlen(to), i;
    char *buf = slurp(path, &len);
    int changed = 0;
    if (!buf) return;
    if (len < 64 || memcmp(buf, "\177ELF", 4)) { free(buf); return; }
    for (i = 0; i + fl <= len; i++) {
        if (buf[i] == from[0] && !memcmp(buf + i, from, fl)) {
            size_t end = i + fl;
            while (end < len && buf[end] && buf[end] != ':') end++;
            memmove(buf + i + tl, buf + i + fl, end - (i + fl));
            memcpy(buf + i, to, tl);
            memset(buf + end - (fl - tl), 0, fl - tl);
            changed = 1;
            i += tl;
        }
    }
    if (changed) {
        struct stat st;
        int ro = stat(path, &st) == 0 && !(st.st_mode & 0200);
        FILE *f;
        if (ro) chmod(path, st.st_mode | 0200);
        f = fopen(path, "r+b");
        if (f) { fwrite(buf, 1, len, f); fclose(f); }
        if (ro) chmod(path, st.st_mode);
    }
    free(buf);
}
static void reloc_walk(const char *dir, const char *from1, const char *to1, const char *from2, const char *to2)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char *p;
        struct stat st;
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        p = fmt("%s/%s", dir, e->d_name);
        if (lstat(p, &st) == 0) {
            if (S_ISDIR(st.st_mode)) { if (strcmp(e->d_name, "tmp") && strcmp(e->d_name, "cache")) reloc_walk(p, from1, to1, from2, to2); }
            else if (S_ISREG(st.st_mode) && st.st_size > 64) { reloc_file(p, from1, to1); reloc_file(p, from2, to2); }
        }
        free(p);
    }
    closedir(d);
}
static int cmd_relocate(const char *from)
{
    const char *base = from ? from : root;
    char *so = fmt("%s/usr/lib/libc.so", base), *lib = fmt("%s/usr/lib", base), *skip = fmt("%s/var", root);
    char *dirs[] = { "usr", "bin", "sbin", "lib", NULL };
    int i;
    (void)skip;
    for (i = 0; dirs[i]; i++) { char *d = fmt("%s/%s", root, dirs[i]); reloc_walk(d, so, "/lib/ld-musl-x86_64.so.1", lib, "/usr/lib"); free(d); }
    free(so); free(lib); free(skip);
    return 0;
}

static int cmd_build(const char *name)
{
    struct recipe *r = find_recipe(name);
    char *stage;
    if (!r) die("no recipe for %s", name);
    fetch(r);
    stage = build(r);
    printf("==> the files are in %s\n", stage);
    return 0;
}

static void usage(void)
{
    puts("Usage: mag [-nfk] COMMAND [PACKAGE]...\n"
         "\n"
         "  install PKG...    fetch, build and install, dependencies first\n"
         "  remove PKG...     take a package off\n"
         "  upgrade           reinstall what the repos have a newer version of\n"
         "  autoremove        remove what was only installed as a dependency and is not needed now\n"
         "  list              what is installed\n"
         "  info PKG          what a recipe says, and whether it is installed\n"
         "  search WORD       recipes whose name or desc has WORD\n"
         "  files PKG         the files a package put on the system\n"
         "  owns PATH         which package a file came from\n"
         "  deps PKG          its dependencies, rdeps PKG for what needs it\n"
         "  fetch PKG...      only download and check the sources\n"
         "  build PKG         build into a stage directory, install nothing\n"
         "  sync              download the pkgsrc tree to /usr/pkgsrc\n"
         "  hash FILE...      sha256 of files, for writing recipes\n"
         "\n"
         "  -n  only say what would happen    -f  go on when files clash or something needs the package\n"
         "  -k  keep the build directory\n"
         "\n"
         "MAG_ROOT installs somewhere else than /, MAG_REPO is a list of repos split by colons (default\n"
         "/usr/share/mag/repo:/usr/pkgsrc), MAG_SYNC_URL is where sync gets the tree,\n"
         "MAG_FETCH is the download command, which gets a file and an url (default curl, else wget, else ftp), MAG_PREFIX is $PREFIX for the steps, /usr, and MAG_JOBS is $JOBS, 4");
}

int main(int argc, char **argv)
{
    const char *r = getenv("MAG_ROOT"), *rp = getenv("MAG_REPO");
    char *rr, *s;
    int i = 1, rc;
    root = "";
    if (r && strcmp(r, "/")) { rr = xstrdup(r); s = rr + strlen(rr); while (s > rr + 1 && s[-1] == '/') *--s = 0; root = rr; }
    rp = rp && *rp ? rp : "/usr/share/mag/repo:/usr/pkgsrc";
    rr = xstrdup(rp);
    for (s = rr; s; ) {
        char *e = strchr(s, ':');
        if (e) *e++ = 0;
        if (*s) { repos = xrealloc(repos, (nrepos + 1) * sizeof *repos); repos[nrepos++] = s; load_provides(s); }
        s = e;
    }
    load_conf();
    for (; i < argc && argv[i][0] == '-' && argv[i][1]; i++) {
        const char *o;
        if (!strcmp(argv[i], "--")) { i++; break; }
        if (!strcmp(argv[i], "--help")) { usage(); return 0; }
        if (!strcmp(argv[i], "--version")) { puts("mag " VERSION); return 0; }
        for (o = argv[i] + 1; *o; o++) {
            if (*o == 'n') dry = 1; else if (*o == 'f') force = 1; else if (*o == 'k') keep = 1;
            else { say("unknown option -%c", *o); return 1; }
        }
    }
    if (i >= argc || !strcmp(argv[i], "help")) { usage(); return i >= argc ? 1 : 0; }
    {
        const char *cmd = argv[i++];
        int n = argc - i;
        char **a = argv + i;
        if (!strcmp(cmd, "install") || !strcmp(cmd, "add")) rc = n ? cmd_install(n, a) : (say("install what?"), 1);
        else if (!strcmp(cmd, "remove") || !strcmp(cmd, "del")) rc = n ? cmd_remove(n, a) : (say("remove what?"), 1);
        else if (!strcmp(cmd, "upgrade")) rc = cmd_upgrade();
        else if (!strcmp(cmd, "autoremove")) rc = cmd_autoremove();
        else if (!strcmp(cmd, "list")) rc = cmd_list();
        else if (!strcmp(cmd, "info") && n == 1) rc = cmd_info(a[0]);
        else if (!strcmp(cmd, "search") && n == 1) rc = cmd_search(a[0]);
        else if (!strcmp(cmd, "files") && n == 1) rc = cmd_files(a[0]);
        else if (!strcmp(cmd, "owns") && n == 1) rc = cmd_owns(a[0]);
        else if (!strcmp(cmd, "deps") && n == 1) rc = cmd_deps(a[0], 0);
        else if (!strcmp(cmd, "rdeps") && n == 1) rc = cmd_deps(a[0], 1);
        else if (!strcmp(cmd, "fetch") && n) rc = cmd_fetch(n, a);
        else if (!strcmp(cmd, "build") && n == 1) rc = cmd_build(a[0]);
        else if (!strcmp(cmd, "relocate") && n <= 1) rc = cmd_relocate(n ? a[0] : NULL);
        else if (!strcmp(cmd, "sync") && !n) rc = cmd_sync();
        else if (!strcmp(cmd, "hash") && n) rc = cmd_hash(n, a);
        else { say("'%s' with %d argument%s makes no sense, mag help says what there is", cmd, n, n == 1 ? "" : "s"); return 1; }
    }
    fflush(stdout);
    return rc;
}
