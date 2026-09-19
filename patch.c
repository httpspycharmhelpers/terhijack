/*
 * thj_patch - TerHijack --all binary-level interception shim.
 *
 * Placed in place of a real binary (the original is kept as <name>.thj_orig
 * next to it). On every invocation it consults the state file (records,
 * one per line, TAB-separated, '#' starts a comment):
 *
 *   name\tOUT\tpayload   -> print payload, exit 0
 *   name\tBLOCK          -> refuse access to /proc and /sys args (stderr
 *                           "Permission denied", exit 1); everything else
 *                           is passed through to the real binary
 *   name\tFAKE\tmap      -> for `type name` lookups answer "name is path";
 *                           map is a comma list of "name=path"; other args
 *                           are passed through
 *   (no record)          -> execute the real binary at <argv0>.thj_orig
 *
 * State file: $THJ_DAT_FILE, else $HOME/.thj_patch.dat.
 *
 * The real binary must exist at "<argv0>.thj_orig"; when it is missing the
 * shim refuses to exec anything (prevents a symlink->shim infinite loop).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

static char *read_state(const char *path, size_t *len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    *len = got;
    return buf;
}

static char *state_path(void)
{
    const char *env = getenv("THJ_DAT_FILE");
    if (env && *env) return strdup(env);
    const char *home = getenv("HOME");
    if (home && *home) {
        size_t n = strlen(home) + 16;
        char *p = malloc(n);
        if (!p) return NULL;
        snprintf(p, n, "%s/.thj_patch.dat", home);
        return p;
    }
    return strdup(".thj_patch.dat");
}

/*
 * find the record for `name`; returns type token (OUT/BLOCK/FAKE) and, for
 * OUT, points *payload at the (first TAB +) payload region of `data`.
 */
static const char *lookup(const char *data, const char *name,
                          const char **payload)
{
    *payload = NULL;
    const char *line = data;
    while (line && *line) {
        const char *nl = strchr(line, '\n');
        size_t ll = nl ? (size_t)(nl - line) : strlen(line);
        if (ll > 0 && *line != '#') {
            const char *t1 = memchr(line, '\t', ll);
            const char *t2 = t1 ? memchr(t1 + 1, '\t',
                                         ll - (size_t)(t1 - line) - 1)
                                : NULL;
            if (t1) {
                size_t nlen = (size_t)(t1 - line);
                const char *rest = t1 + 1;
                size_t tlen = t2 ? (size_t)(t2 - rest)
                                 : ll - (size_t)(rest - line);
                if (nlen == strlen(name) &&
                    strncmp(line, name, nlen) == 0) {
                    static const char *kinds[] = {"OUT", "BLOCK", "FAKE"};
                    for (unsigned k = 0; k < 3; k++) {
                        if (tlen == strlen(kinds[k]) &&
                            strncmp(rest, kinds[k], tlen) == 0) {
                            size_t pl = t2 ? ll - (size_t)((t2 + 1) - line)
                                           : 0;
                            char *dp = malloc(pl + 1);
                            if (!dp) return NULL;
                            if (pl) memcpy(dp, t2 + 1, pl);
                            dp[pl] = '\0';
                            *payload = dp;
                            return kinds[k];
                        }
                    }
                }
            }
        }
        line = nl ? nl + 1 : NULL;
    }
    return NULL;
}

int main(int argc, char **argv)
{
    const char *arg0 = argv[0];
    const char *slash = strrchr(arg0, '/');
    const char *name = slash ? slash + 1 : arg0;

    char *sp = state_path();
    if (!sp) return 127;
    size_t dlen = 0;
    char *data = read_state(sp, &dlen);
    free(sp);

    const char *payload = NULL;
    const char *ty = NULL;
    if (data) {
        ty = lookup(data, name, &payload);
        if (ty && strcmp(ty, "OUT") != 0 && strcmp(ty, "BLOCK") != 0 &&
            strcmp(ty, "FAKE") != 0)
            ty = NULL;
    }

    if (ty && strcmp(ty, "OUT") == 0) {
        if (payload) {
            puts(payload);
            free((void *)payload);
        }
        free(data);
        return 0;
    }

    if (ty && strcmp(ty, "BLOCK") == 0) {
        for (int i = 1; i < argc; i++) {
            if (strncmp(argv[i], "/proc", 5) == 0 ||
                strncmp(argv[i], "/sys", 4) == 0) {
                fprintf(stderr, "%s: %s: Permission denied\n", name,
                        argv[i]);
                free((void *)payload);
                free(data);
                return 1;
            }
        }
    }

    if (ty && strcmp(ty, "FAKE") == 0 && payload) {
        int handled = 0;
        for (int i = 1; i < argc; i++) {
            if (*argv[i] == '-') continue;
            const char *p = payload;
            while (*p) {
                const char *comma = strchr(p, ',');
                size_t seg = comma ? (size_t)(comma - p) : strlen(p);
                const char *eq = memchr(p, '=', seg);
                if (eq) {
                    if ((size_t)(eq - p) == strlen(argv[i]) &&
                        strncmp(p, argv[i], (size_t)(eq - p)) == 0) {
                        size_t pathlen = comma
                                             ? (size_t)(comma - (eq + 1))
                                             : strlen(eq + 1);
                        printf("%s is %.*s\n", argv[i], (int)pathlen,
                               eq + 1);
                        handled = 1;
                        break;
                    }
                }
                if (!comma) break;
                p = comma + 1;
            }
            if (handled) break;
        }
        if (handled) { free((void *)payload); free(data); return 0; }
    }

    free((void *)payload);
    free(data);

    /* fall through: run the real binary saved next to us.
     *
     * argv[0] may carry the full path (<argv0>.thj_orig works) OR be a bare
     * command name (bash passes the typed name when a symlink in $PATH is
     * exec'd). Cover both: try argv[0].thj_orig, then scan $PATH for
     * <dir>/<name>.thj_orig. A backup is always created by the installer, so
     * we never exec an unbacked shim (which would symlink-loop). */
    char *real = NULL;
    if (slash) {
        size_t rl = strlen(arg0) + 10;
        real = malloc(rl);
        if (!real) return 127;
        snprintf(real, rl, "%s.thj_orig", arg0);
        if (access(real, X_OK) != 0) {
            free(real);
            real = NULL;
        }
    }
    if (!real) {
        const char *path = getenv("PATH");
        if (!path) path = "/bin:/usr/bin";
        char *pc = strdup(path);
        if (pc) {
            char *save = NULL;
            for (char *tok = strtok_r(pc, ":", &save); tok;
                 tok = strtok_r(NULL, ":", &save)) {
                const char *dir = *tok ? tok : ".";
                size_t rl = strlen(dir) + strlen(name) + 14;
                char *cand = malloc(rl);
                if (!cand) break;
                snprintf(cand, rl, "%s/%s.thj_orig", dir, name);
                if (access(cand, X_OK) == 0) {
                    real = cand;
                    break;
                }
                free(cand);
            }
            free(pc);
        }
    }
    if (!real) {
        fprintf(stderr, "%s: real binary not found\n", name);
        return 127;
    }
    argv[0] = real;
    execv(real, argv);
    perror("thj_patch exec");
    free(real);
    return 127;
}