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

/* ---- recipes ---- */

struct recipe {
    char *id, *file, *dir, *desc, *version, *url, *sha, *steps;
    struct list deps;
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

/* cat/name inside one repo, as a file or as a directory with a file called recipe in it */
static struct recipe *try_repo(const char *repo, const char *id)
{
    char *p = fmt("%s/%s", repo, id);
    struct recipe *r = NULL;
    struct stat st;
    if (stat(p, &st) == 0) {
        if (S_ISDIR(st.st_mode)) { char *f = fmt("%s/recipe", p); r = parse_recipe(id, f, p); free(f); }
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
    const char *b = strrchr(r->url, '/');
    return fmt("%s/var/cache/mag/%s", root, b ? b + 1 : r->url);
}

static int fetch(const struct recipe *r)
{
    char *file, *sum, *tmp;
    if (!r->url) return 0;
    if (!r->sha) die("%s has no sha256", r->id);
    file = distfile(r);
    sum = sha256_file(file);
    if (sum && !strcmp(sum, r->sha)) { free(sum); free(file); return 0; }
    if (sum) { say("%s: the cached file does not match, fetching again", r->id); unlink(file); }
    free(sum);
    {
        char *dir = xstrdup(file), *sl = strrchr(dir, '/');
        const char *cmd = getenv("MAG_FETCH");
        char *av[7];
        int rc;
        *sl = 0;
        mkpath(dir, 0755);
        free(dir);
        tmp = fmt("%s.part", file);
        printf("==> fetching %s\n", r->url);
        av[0] = "/bin/sh"; av[1] = "-c"; av[2] = "set -f; $0 \"$1\" \"$2\""; av[3] = (char *)(cmd ? cmd : "curl -fsSL -o");
        av[4] = tmp; av[5] = r->url; av[6] = NULL;
        rc = run(av, NULL);
        if (rc) { unlink(tmp); die("could not fetch %s", r->url); }
        rename(tmp, file);
    }
    sum = sha256_file(file);
    if (!sum || strcmp(sum, r->sha)) {
        say("%s: wrong sha256", r->id);
        say("  recipe: %s", r->sha);
        say("  file:   %s", sum ? sum : "unreadable");
        unlink(file);
        exit(1);
    }
    free(sum); free(tmp); free(file);
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
    setenv("JOBS", jobs ? jobs : "4", 1);
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
        else push(out, relp);
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
        if (o && strcmp(o, r->id)) { say("%s wants %s, which %s has", r->id, files.v[i], o); bad = 1; }
        else if (!o && exists(full) && strncmp(files.v[i], "etc/", 4)) { say("%s wants %s, which is there already", r->id, files.v[i]); bad = 1; }
        free(full);
    }
    if (bad && !force) die("not installing %s, -f goes ahead anyway", r->id);
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
        if (!installed(d->id)) plan(d->id, r->id, order, seen, stack);
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
         "  hash FILE...      sha256 of files, for writing recipes\n"
         "\n"
         "  -n  only say what would happen    -f  go on when files clash or something needs the package\n"
         "  -k  keep the build directory\n"
         "\n"
         "MAG_ROOT installs somewhere else than /, MAG_REPO is a list of repos split by colons (default\n"
         "/usr/share/mag/repo), MAG_FETCH is the download command, which gets a file and an url (default\n"
         "curl -fsSL -o), MAG_PREFIX is $PREFIX for the steps, /usr, and MAG_JOBS is $JOBS, 4");
}

int main(int argc, char **argv)
{
    const char *r = getenv("MAG_ROOT"), *rp = getenv("MAG_REPO");
    char *rr, *s;
    int i = 1, rc;
    root = "";
    if (r && strcmp(r, "/")) { rr = xstrdup(r); s = rr + strlen(rr); while (s > rr + 1 && s[-1] == '/') *--s = 0; root = rr; }
    rp = rp && *rp ? rp : "/usr/share/mag/repo";
    rr = xstrdup(rp);
    for (s = rr; s; ) {
        char *e = strchr(s, ':');
        if (e) *e++ = 0;
        if (*s) { repos = xrealloc(repos, (nrepos + 1) * sizeof *repos); repos[nrepos++] = s; }
        s = e;
    }
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
        else if (!strcmp(cmd, "hash") && n) rc = cmd_hash(n, a);
        else { say("'%s' with %d argument%s makes no sense, mag help says what there is", cmd, n, n == 1 ? "" : "s"); return 1; }
    }
    fflush(stdout);
    return rc;
}
