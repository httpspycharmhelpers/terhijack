/*
 * TerHijack v1.1 - per-session terminal command hijacker (bash/zsh)
 *
 * Hooks arbitrary commands inside the CURRENT shell session: rewrite their
 * output (--output), transparently replace them with another command
 * (--recommand), pass caller arguments through to the replacement (-a/--arg),
 * and intercept whole compound lines such as "a && b && c" by shadowing each
 * segment as a function whose exit code short-circuits the chain (&& aborts,
 * || short-circuits, ';' segments are neutered). A fresh session is clean.
 *
 * usage:
 *   eval "$(terhijack --init)"                    once per session
 *   hijack -c "id -Z" -o "root"                   fake output
 *   hijack -c "su" -r "mysu" -a                   args pass through
 *   hijack -c "cd / && rm f && echo ok" -o "x"    whole line hijacked
 *   hijack -c "ls/pwd/id" -o "x"                  several commands at once
 *   hijack --list | -x "cmd ..." | --clear
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <unistd.h>

#define THJ_VERSION "1.1"

/* ------------------------------------------------------------------ */
/* utils                                                              */
/* ------------------------------------------------------------------ */

static void *xmalloc(size_t n)
{
    void *p = malloc(n);
    if (!p) { fprintf(stderr, "terhijack: out of memory\n"); exit(2); }
    return p;
}

static char *xstrdup(const char *s)
{
    char *p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

static char *sh_quote(const char *s)
{
    size_t n = strlen(s);
    char *o = xmalloc(n * 4 + 3), *p = o;
    *p++ = '\'';
    for (size_t i = 0; i < n; i++) {
        if (s[i] == '\'') {
            *p++ = '\''; *p++ = '\\'; *p++ = '\''; *p++ = '\'';
        } else {
            *p++ = s[i];
        }
    }
    *p++ = '\''; *p = '\0';
    return o;
}

static char *trim(char *s)
{
    while (isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

static void squeeze_ws(char *s)
{
    char *r = s, *w = s;

    int in_ws = 0;
    while (*r) {
        if (isspace((unsigned char)*r)) {
            if (!in_ws && w != s) { *w++ = ' '; in_ws = 1; }
        } else { *w++ = *r; in_ws = 0; }
        r++;
    }
    if (w > s && w[-1] == ' ') w--;
    *w = '\0';
}

/* split "a && b || c ; d | e" into segments on the shell operators */
static char **split_compound(const char *s, size_t *cnt)
{
    char **out = NULL;
    size_t n = 0, cap = 0;
    static const char *ops[] = {" && ", " || ", " ; ", " | "};
    const char *start = s;
    for (;;) {
        const char *best = NULL;
        int which = -1;
        for (int k = 0; k < 4; k++) {
            const char *hit = strstr(start, ops[k]);
            if (hit && (!best || hit < best)) { best = hit; which = k; }
        }
        size_t len = best ? (size_t)(best - start) : strlen(start);
        char *seg = xmalloc(len + 1);
        memcpy(seg, start, len);
        seg[len] = '\0';
        char *t = trim(seg);
        if (*t) {
            if (n == cap) {
                cap = cap ? cap * 2 : 8;
                out = realloc(out, cap * sizeof(char *));
            }
            out[n++] = xstrdup(t);
        }
        free(seg);
        if (!best) break;
        start = best + strlen(ops[which]);
    }
    *cnt = n;
    return out;
}

static char *first_word(const char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    const char *e = s;
    while (*e && !isspace((unsigned char)*e)) e++;
    size_t n = (size_t)(e - s);
    char *o = xmalloc(n + 1);
    memcpy(o, s, n);
    o[n] = '\0';
    return o;
}

static int valid_name(const char *s)
{
    if (!*s) return 0;
    if (!(isalnum((unsigned char)*s) || *s == '_')) return 0;
    for (const char *p = s; *p; p++)
        if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '.' ||
              *p == '+' || *p == '-'))
            return 0;
    return 1;
}

static int has_metachar(const char *s)
{
    return strpbrk(s, "&|;") != NULL;
}

/* 'ls/pwd/id' -> list. A real path (starts with / or contains " /") is not. */
static int is_cmdlist(const char *s)
{
    if (!strchr(s, '/')) return 0;
    if (*s == '/') return 0;
    if (strstr(s, " /")) return 0;
    return 1;
}

static char **split_list(const char *s, size_t *cnt)
{
    char **out = NULL;
    size_t n = 0, cap = 0;
    const char *start = s;
    for (const char *p = s;; p++) {
        if (*p == '/' || *p == '\0') {
            size_t len = (size_t)(p - start);
            char *seg = xmalloc(len + 1);
            memcpy(seg, start, len);
            seg[len] = '\0';
            char *t = trim(seg);
            if (*t) {
                if (n == cap) {
                    cap = cap ? cap * 2 : 8;
                    out = realloc(out, cap * sizeof(char *));
                }
                out[n++] = xstrdup(t);
            }
            free(seg);
            if (*p == '\0') break;
            start = p + 1;
        }
    }
    *cnt = n;
    return out;
}

/* ------------------------------------------------------------------ */
/* session state ($THJ_STATE = bash `declare -p` output of arrays)    */
/* ------------------------------------------------------------------ */

typedef struct {
    char *pat, *ty, *pay, *match; /* match: x exact | a arg-penetrate |        */
} Entry;                          /*        c0/c1 compound segment (rc for &&) */

static Entry *ents = NULL;   /* function hooks (per-command) */
static size_t nents = 0, cap_ents = 0;

static void ents_push(Entry **e, size_t *n, size_t *cap,
                      const char *pat, const char *ty, const char *pay,
                      const char *match)
{
    if (*n == *cap) {
        *cap = *cap ? *cap * 2 : 16;
        *e = realloc(*e, *cap * sizeof(Entry));
        if (!*e) { fprintf(stderr, "terhijack: out of memory\n"); exit(2); }
    }
    (*e)[*n].pat   = xstrdup(pat);
    (*e)[*n].ty    = xstrdup(ty);
    (*e)[*n].pay   = xstrdup(pay);
    (*e)[*n].match = xstrdup(match ? match : "x");
    (*n)++;
}

typedef struct { char *b; size_t n, cap; } Buf;

static void buf_put(Buf *b, const char *s, size_t n)
{
    if (b->n + n + 1 > b->cap) {
        b->cap = (b->n + n + 1) * 2;
        b->b = realloc(b->b, b->cap);
        if (!b->b) { fprintf(stderr, "terhijack: out of memory\n"); exit(2); }
    }
    memcpy(b->b + b->n, s, n);
    b->n += n;
    b->b[b->n] = '\0';
}

/* parse one `declare -a __THJ_<var>=( [0]="v" ... )` line */
static char **parse_declare_array(const char *st, const char *var, size_t *cnt)
{
    *cnt = 0;
    if (!st) return NULL;
    char marker[64];
    snprintf(marker, sizeof(marker), "__THJ_%s=(", var);
    const char *q = strstr(st, marker);
    if (!q) return NULL;
    q += strlen(marker);

    char **out = NULL;
    size_t n = 0, cap = 0;
    Buf b = {0};

    while (*q && *q != ')') {
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == '[') {
            q++;
            while (isdigit((unsigned char)*q)) q++;
            if (*q != ']') break;
            q++;
        }
        if (*q != '=') break;
        q++;
        if (*q != '"') break;
        q++;
        b.n = 0;
        while (*q && *q != '"') {
            if (*q == '\\' && q[1]) {
                char c = q[1];
                if (c == '"' || c == '\\' || c == '$' || c == '`')
                    buf_put(&b, &c, 1);
                else
                    buf_put(&b, q, 2);
                q += 2;
            } else {
                buf_put(&b, q, 1);
                q++;
            }
        }
        if (*q != '"') break;
        q++;
        if (n == cap) {
            cap = cap ? cap * 2 : 8;
            out = realloc(out, cap * sizeof(char *));
            if (!out) { fprintf(stderr, "terhijack: out of memory\n"); exit(2); }
        }
        out[n++] = xstrdup(b.b ? b.b : "");
    }
    free(b.b);
    *cnt = n;
    return out;
}

static int has_state(void)
{
    const char *st = getenv("THJ_STATE");
    return st && *st;
}

static void load_state(void)
{
    const char *st = getenv("THJ_STATE");
    if (!st || !*st) return;

    size_t np = 0, nt = 0, na = 0, nm = 0;
    char **p  = parse_declare_array(st, "P",  &np);
    char **t  = parse_declare_array(st, "T",  &nt);
    char **a  = parse_declare_array(st, "A",  &na);
    char **m  = parse_declare_array(st, "M",  &nm);

    size_t n = np > nt ? np : nt;
    if (na > n) n = na;
    for (size_t i = 0; i < n; i++) {
        const char *pt = i < np ? p[i] : "";
        const char *ty = i < nt ? t[i] : "";
        const char *py = i < na ? a[i] : "";
        const char *mc = i < nm ? m[i] : "x";
        if (*pt && *ty && *py)
            ents_push(&ents, &nents, &cap_ents, pt, ty, py, mc);
    }

    for (size_t i = 0; i < np; i++) free(p[i]);
    for (size_t i = 0; i < nt; i++) free(t[i]);
    for (size_t i = 0; i < na; i++) free(a[i]);
    for (size_t i = 0; i < nm; i++) free(m[i]);
    free(p); free(t); free(a); free(m);
}

/* ------------------------------------------------------------------ */
/* shell code emission                                                */
/* ------------------------------------------------------------------ */

static const char RUNTIME[] =
"# ---- TerHijack runtime (auto-generated) ----\n"
"__terhijack_dispatch() {\n"
"  local __t_fn=\"$1\"; shift\n"
"  local __t_save=(\"$@\")\n"
"  local __t_cmp\n"
"  if [ \"$#\" -gt 0 ]; then __t_cmp=\"$__t_fn $*\"; else __t_cmp=\"$__t_fn\"; fi\n"
"  local __t_ty=\"\" __t_pl=\"\" __t_rc=0 __t_rarr=()\n"
"  if [ -n \"${__THJ_P+x}\" ]; then\n"
"    local __t_i __t_p __t_m __t_wc\n"
"    for __t_i in \"${!__THJ_P[@]}\"; do\n"
"      __t_p=\"${__THJ_P[__t_i]}\"\n"
"      __t_m=\"${__THJ_M[__t_i]:-x}\"\n"
"      if [ \"$__t_m\" = \"a\" ]; then\n"
"        if [ \"$__t_cmp\" = \"$__t_p\" ]; then\n"
"          __t_ty=\"${__THJ_T[__t_i]}\"; __t_pl=\"${__THJ_A[__t_i]}\"; break\n"
"        elif [ \"${__t_cmp#\"$__t_p \"}\" != \"$__t_cmp\" ]; then\n"
"          __t_ty=\"${__THJ_T[__t_i]}\"; __t_pl=\"${__THJ_A[__t_i]}\"\n"
"          local __t_wifsv=\"$IFS\" __t_wifsf=\"\"\n"
"          case $- in *f*) __t_wifsf=y ;; *) ;; esac\n"
"          set -f; IFS=' '; set -- $__t_p; __t_wc=$#\n"
"          IFS=\"$__t_wifsv\"; [ -n \"$__t_wifsf\" ] || set +f\n"
"          __t_rarr=(\"${__t_save[@]:$((__t_wc-1))}\")\n"
"          break\n"
"        fi\n"
"      elif [ \"$__t_cmp\" = \"$__t_p\" ]; then\n"
"        __t_ty=\"${__THJ_T[__t_i]}\"; __t_pl=\"${__THJ_A[__t_i]}\"\n"
"        case \"$__t_m\" in c1) __t_rc=1 ;; *) __t_rc=0 ;; esac\n"
"        break\n"
"      fi\n"
"    done\n"
"  elif [ -n \"${__THJ_SER:-}\" ]; then\n"
"    local __t_rec __t_ifs=\"$IFS\" __t_hadf=\"\" __t_p __t_m __t_wc\n"
"    case $- in *f*) __t_hadf=y ;; esac\n"
"    set -f\n"
"    IFS=$'\\x1e'\n"
"    for __t_rec in $__THJ_SER; do\n"
"      IFS=$'\\x1f'\n"
"      set -- $__t_rec\n"
"      __t_p=\"${1:-}\"\n"
"      __t_m=\"${4:-x}\"\n"
"      if [ \"$__t_m\" = \"a\" ]; then\n"
"        if [ \"$__t_cmp\" = \"$__t_p\" ]; then\n"
"          __t_ty=\"${2:-}\"; __t_pl=\"${3:-}\"; break\n"
"        elif [ \"${__t_cmp#\"$__t_p \"}\" != \"$__t_cmp\" ]; then\n"
"          __t_ty=\"${2:-}\"; __t_pl=\"${3:-}\"\n"
"          local __t_wifsv=\"$IFS\" __t_wifsf=\"\"\n"
"          case $- in *f*) __t_wifsf=y ;; *) ;; esac\n"
"          set -f; IFS=' '; set -- $__t_p; __t_wc=$#\n"
"          IFS=\"$__t_wifsv\"; [ -n \"$__t_wifsf\" ] || set +f\n"
"          __t_rarr=(\"${__t_save[@]:$((__t_wc-1))}\")\n"
"          break\n"
"        fi\n"
"      elif [ \"$__t_cmp\" = \"$__t_p\" ]; then\n"
"        __t_ty=\"${2:-}\"; __t_pl=\"${3:-}\"\n"
"        case \"$__t_m\" in c1) __t_rc=1 ;; *) __t_rc=0 ;; esac\n"
"        break\n"
"      fi\n"
"    done\n"
"    IFS=\"$__t_ifs\"\n"
"    [ -n \"$__t_hadf\" ] || set +f\n"
"  fi\n"
"  if [ -n \"$__t_ty\" ]; then\n"
"    case \"$__t_ty\" in\n"
"      out)\n"
"        printf '%s\\n' \"$__t_pl\"\n"
"        return $__t_rc\n"
"        ;;\n"
"      rec)\n"
"        set -- ${__t_rarr[@]+\"${__t_rarr[@]}\"}\n"
"        local __t_body=\"$(declare -f \"$__t_fn\" 2>/dev/null)\"\n"
"        unset -f \"$__t_fn\" 2>/dev/null\n"
"        eval \"$__t_pl \\\"\\$@\\\"\"\n"
"        if [ -n \"$__t_body\" ]; then eval \"$__t_body\"; fi\n"
"        return $__t_rc\n"
"        ;;\n"
"    esac\n"
"  fi\n"
"  if [ \"${#__t_save[@]}\" -gt 0 ]; then\n"
"    command \"$__t_fn\" \"${__t_save[@]}\"\n"
"  else\n"
"    command \"$__t_fn\"\n"
"  fi\n"
"  return 0\n"
"}\n"
"__terhijack_rebuild() {\n"
"  local __t_n __t_i __t_seen=\" \" __t_s=\"\"\n"
"  if [ -n \"${__THJ_FN+x}\" ]; then\n"
"    for __t_n in \"${__THJ_FN[@]}\"; do\n"
"      unset -f \"$__t_n\" 2>/dev/null\n"
"    done\n"
"  fi\n"
"  __THJ_FN=()\n"
"  if [ -n \"${__THJ_P+x}\" ]; then\n"
"    for __t_i in \"${!__THJ_P[@]}\"; do\n"
"      __t_n=\"${__THJ_P[__t_i]%%[[:space:]]*}\"\n"
"      case \"$__t_seen\" in *\" $__t_n \"*) ;; *)\n"
"        __t_seen=\"$__t_seen$__t_n \"\n"
"        __THJ_FN+=(\"$__t_n\")\n"
"        eval \"$__t_n() { __terhijack_dispatch '$__t_n' \\\"\\$@\\\"; }\"\n"
"        ;;\n"
"      esac\n"
"      [ -z \"$__t_s\" ] || __t_s+=$'\\x1e'\n"
"      __t_s+=\"${__THJ_P[__t_i]}\"$'\\x1f'\"${__THJ_T[__t_i]}\"$'\\x1f'\"${__THJ_A[__t_i]}\"$'\\x1f'\"${__THJ_M[__t_i]:-x}\"\n"
"    done\n"
"  fi\n"
"  export __THJ_SER=\"$__t_s\"\n"
"  if [ -n \"${BASH_VERSION:-}\" ]; then\n"
"    for __t_n in \"${__THJ_FN[@]}\"; do\n"
"      export -f \"$__t_n\" 2>/dev/null\n"
"    done\n"
"    export -f __terhijack_dispatch __terhijack_rebuild 2>/dev/null\n"
"  fi\n"
"}\n";

static const char BOOTSTRAP[] =
"# ---- TerHijack bootstrap: defines hijack() ----\n"
"__THJ_BIN=\"$(command -v terhijack 2>/dev/null)\"\n"
"hijack() {\n"
"  if [ -z \"${__THJ_BIN:-}\" ]; then\n"
"    __THJ_BIN=\"$(command -v terhijack 2>/dev/null)\"\n"
"  fi\n"
"  if [ -z \"${__THJ_BIN:-}\" ]; then\n"
"    echo \"terhijack: binary not found in PATH\" >&2\n"
"    return 127\n"
"  fi\n"
"  local __t_st=\"\"\n"
"  __t_st=\"$(declare -p __THJ_P __THJ_T __THJ_A __THJ_M 2>/dev/null)\"\n"
"  case \"${1:-}\" in\n"
"    -l|--list)\n"
"      THJ_STATE=\"$__t_st\" \"$__THJ_BIN\" \"$@\"\n"
"      ;;\n"
"    *)\n"
"      local __t_out __t_rc\n"
"      __t_out=\"$(THJ_STATE=\"$__t_st\" \"$__THJ_BIN\" \"$@\")\"\n"
"      __t_rc=$?\n"
"      if [ \"$__t_rc\" -eq 0 ] && [ -n \"$__t_out\" ]; then\n"
"        eval \"$__t_out\"\n"
"      fi\n"
"      return \"$__t_rc\"\n"
"      ;;\n"
"  esac\n"
"}\n";

/* emit authoritative full-state assignment (state was available) */
static void emit_full_assign(void)
{
    static const char *V[4] = {"P", "T", "A", "M"};
    static const int  F[4] = {1, 2, 3, 4};
    Entry *E[4] = {ents, ents, ents, ents};
    size_t  C[4] = {nents, nents, nents, nents};

    for (int k = 0; k < 4; k++) {
        printf("__THJ_%s=(", V[k]);
        for (size_t i = 0; i < C[k]; i++) {
            const char *val;
            switch (F[k]) {
            case 1: val = E[k][i].pat;
                break;
            case 2: val = E[k][i].ty;
                break;
            case 3: val = E[k][i].pay;
                break;
            default:
                val = E[k][i].match;
                break;
            }
            char *q = sh_quote(val);
            printf("%s%s", i ? " " : "", q);
            free(q);
        }
        fputs(")\n", stdout);
    }
}

static void emit_guard(const char *var)
{
    printf("[ -n \"${__THJ_%s+x}\" ] || __THJ_%s=()\n", var, var);
}

/* no session state was available: append-only, never clobber arrays */
static void emit_appends(void)
{
    if (nents) {
        emit_guard("P"); emit_guard("T"); emit_guard("A"); emit_guard("M");
        for (size_t i = 0; i < nents; i++) {
            char *q = sh_quote(ents[i].pat);
            printf("__THJ_P+=(%s)\n", q); free(q);
            q = sh_quote(ents[i].ty);
            printf("__THJ_T+=(%s)\n", q); free(q);
            q = sh_quote(ents[i].pay);
            printf("__THJ_A+=(%s)\n", q); free(q);
            q = sh_quote(ents[i].match);
            printf("__THJ_M+=(%s)\n", q); free(q);
        }
    }
}

static void mode_emit(void)
{
    if (has_state())
        emit_full_assign();
    else
        emit_appends();
    fputs("__terhijack_rebuild\n", stdout);
}

/* register one pattern in the right store; dedup-update */
static void register_ent(const char *pat, const char *ty, const char *pay,
                         const char *match)
{
    for (size_t i = 0; i < nents; i++) {
        if (strcmp(ents[i].pat, pat) == 0) {
            free(ents[i].ty);
            free(ents[i].pay);
            free(ents[i].match);
            ents[i].ty    = xstrdup(ty);
            ents[i].pay   = xstrdup(pay);
            ents[i].match = xstrdup(match);
            return;
        }
    }
    ents_push(&ents, &nents, &cap_ents, pat, ty, pay, match);
}

static void register_one(const char *pat, const char *ty, const char *pay,
                         const char *match, char *verb_out, size_t verb_sz)
{
    if (has_metachar(pat)) {
        /* compound line: shadow the first segment (rc aborts && chains) and
         * neuter any ';'-joined sibling segments so nothing real runs */
        size_t ns = 0;
        char **segs = split_compound(pat, &ns);
        int have_semi = strstr(pat, " ; ") != NULL;
        size_t done = 0;
        for (size_t j = 0; j < ns; j++) {
            if (j == 0) {
                register_ent(segs[j], ty, pay,
                             strstr(pat, " && ") ? "c1" : "c0");
                done++;
            } else if (have_semi) {
                register_ent(segs[j], "rec", ":", "x");
                done++;
            }
        }
        for (size_t j = 0; j < ns; j++) free(segs[j]);
        free(segs);
        if (done) {
            snprintf(verb_out, verb_sz, "hooked %zu segment(s) of", done);
            return;
        }
    }

    char *fw = first_word(pat);
    if (!valid_name(fw)) {
        fprintf(stderr,
            "terhijack: cannot hook '%s' (bad command name)\n", fw);
        free(fw);
        exit(2);
    }
    free(fw);

    register_ent(pat, ty, pay, match);
    snprintf(verb_out, verb_sz, "hooked");
}

static void mode_add(int argc, char **cmds, const char *out, const char *rec,
                     int argmode)
{
    load_state();
    const char *ty = out ? "out" : "rec";
    const char *pay = out ? out : rec;
    const char *match = argmode ? "a" : "x";

    fputs(RUNTIME, stdout);
    for (int k = 0; k < argc; k++) {
        char *work = xstrdup(cmds[k]);
        squeeze_ws(work);
        char *pat = trim(work);
        if (!*pat) { free(work); continue; }

        if (is_cmdlist(pat)) {
            size_t nc = 0;
            char **segs = split_list(pat, &nc);
            for (size_t j = 0; j < nc; j++) {
                char *sw = xstrdup(segs[j]);
                squeeze_ws(sw);
                char *sp = trim(sw);
                if (*sp) {
                    char verb[16];
                    register_one(sp, ty, pay, match, verb, sizeof(verb));
                    printf("# terhijack: %s '%s'\n", verb, sp);
                }
                free(sw);
                free(segs[j]);
            }
            free(segs);
        } else {
            char verb[16];
            register_one(pat, ty, pay, match, verb, sizeof(verb));
            printf("# terhijack: %s '%s'\n", verb, pat);
        }
        free(work);
    }
    mode_emit();
}

static void mode_remove(const char *ap)
{
    if (!has_state()) {
        fprintf(stderr, "terhijack: run inside an initialized session "
                        "(eval \"$(terhijack --init)\")\n");
        exit(1);
    }
    load_state();
    char *work = xstrdup(ap);
    squeeze_ws(work);
    char *pat = trim(work);

    size_t w = 0, found = 0;
    for (size_t i = 0; i < nents; i++) {
        if (strcmp(ents[i].pat, pat) == 0) { found = 1; continue; }
        ents[w++] = ents[i];
    }
    nents = w;

    if (!found && has_metachar(pat)) {
        /* removing a compound line by its full text: drop every segment */
        size_t ns = 0;
        char **segs = split_compound(pat, &ns);
        w = 0;
        for (size_t i = 0; i < nents; i++) {
            int drop = 0;
            for (size_t j = 0; j < ns; j++)
                if (strcmp(ents[i].pat, segs[j]) == 0) drop = 1;
            if (drop) { found = 1; continue; }
            ents[w++] = ents[i];
        }
        nents = w;
        for (size_t j = 0; j < ns; j++) free(segs[j]);
        free(segs);
    }

    if (!found) {
        fprintf(stderr, "terhijack: no such hijack: %s\n", pat);
        free(work);
        exit(1);
    }
    fputs(RUNTIME, stdout);
    mode_emit();
    printf("# terhijack: removed '%s'\n", pat);
    free(work);
}

static void mode_clear(void)
{
    if (!has_state()) {
        fprintf(stderr, "terhijack: run inside an initialized session "
                        "(eval \"$(terhijack --init)\")\n");
        exit(1);
    }
    load_state();
    nents = 0;
    fputs(RUNTIME, stdout);
    mode_emit();
    fputs("# terhijack: all hooks cleared\n", stdout);
}

static void mode_list(void)
{
    load_state();
    for (size_t i = 0; i < nents; i++) {
        char flag[8] = "";
        if (strcmp(ents[i].match, "a") == 0) snprintf(flag, sizeof(flag), " [arg]");
        else if (ents[i].match[0] == 'c') snprintf(flag, sizeof(flag), " [line]");
        printf("[*] %-22s%s -> %-5s %s\n", ents[i].pat, flag,
               ents[i].ty, ents[i].pay);
    }
    printf("total: %zu hook(s) active in this session\n", nents);
}

static void mode_init(void)
{
    fputs(BOOTSTRAP, stdout);
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

static void usage(FILE *f)
{
    fputs(
"TerHijack " THJ_VERSION " - per-session command hijacker (bash/zsh)\n"
"\n"
"usage:\n"
"  eval \"$(terhijack --init)\"           one-time bootstrap, defines hijack()\n"
"  hijack -c \"id -Z\" -o \"root\"          rewrite a command's output\n"
"  hijack -c \"su\" -r \"mysu\" -a          replace command, pass args through\n"
"  hijack -c \"a && b && c\" -r \"echo x\"  hijack whole compound lines\n"
"  hijack -c \"ls/pwd/id\" -o \"x\"         several commands at once\n"
"  hijack --list | -x \"cmd\" | --clear\n"
"\n"
"options:\n"
"  -c, --command CMD     command line(s) to hijack; reusable; '/' lists\n"
"  -o, --output TEXT     force CMD's output to become TEXT\n"
"  -r, --recommand CMD   run CMD instead whenever the pattern matches\n"
"  -a, --arg             argument penetration: caller args are appended\n"
"                        to --recommand CMD (prefix match, not exact)\n"
"  -x, --remove PAT      remove one hijack from this session\n"
"  -l, --list            list active hijacks\n"
"      --clear           drop every hijack\n"
"      --init            print the shell bootstrap\n"
"  -h, --help            show this help\n"
"  -V, --version         show version\n"
"\n"
"hooks live only inside the current session; a new session is clean.\n",
    f);
}

int main(int argc, char **argv)
{
    char **cmds = NULL;
    size_t ncmds = 0, capcmds = 0;
    const char *opt_out = NULL, *opt_rec = NULL, *opt_rem = NULL;
    int m_arg = 0, m_list = 0, m_clear = 0, m_init = 0, m_help = 0, m_ver = 0;

    static const struct option longopts[] = {
        {"command",   required_argument, 0, 'c'},
        {"output",    required_argument, 0, 'o'},
        {"recommand", required_argument, 0, 'r'},
        {"remove",    required_argument, 0, 'x'},
        {"arg",       no_argument,       0, 'a'},
        {"list",      no_argument,       0, 'l'},
        {"clear",     no_argument,       0, 'C'},
        {"init",      no_argument,       0, 'I'},
        {"help",      no_argument,       0, 'h'},
        {"version",   no_argument,       0, 'V'},
        {0, 0, 0, 0}
    };

    int c;
    while ((c = getopt_long(argc, argv, "c:o:r:x:alChV", longopts, NULL)) != -1) {
        switch (c) {
        case 'c':
            if (ncmds == capcmds) {
                capcmds = capcmds ? capcmds * 2 : 8;
                cmds = realloc(cmds, capcmds * sizeof(char *));
                if (!cmds) { fprintf(stderr, "terhijack: out of memory\n"); return 2; }
            }
            cmds[ncmds++] = xstrdup(optarg);
            break;
        case 'o': opt_out = optarg; break;
        case 'r': opt_rec = optarg; break;
        case 'x': opt_rem = optarg; break;
        case 'a': m_arg = 1; break;
        case 'l': m_list = 1; break;
        case 'C': m_clear = 1; break;
        case 'I': m_init = 1; break;
        case 'h': m_help = 1; break;
        case 'V': m_ver = 1; break;
        default:
            usage(stderr);
            return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "terhijack: unexpected argument: %s\n", argv[optind]);
        return 2;
    }

    if (m_help)  { usage(stdout); return 0; }
    if (m_ver)   { printf("TerHijack %s\n", THJ_VERSION); return 0; }
    if (m_init)  { mode_init(); return 0; }
    if (m_list)  { mode_list(); return 0; }
    if (m_clear) { mode_clear(); return 0; }
    if (opt_rem) { mode_remove(opt_rem); return 0; }

    if (ncmds == 0) {
        fprintf(stderr, "terhijack: missing --command (try --help)\n");
        return 2;
    }
    if (opt_out && opt_rec) {
        fprintf(stderr, "terhijack: --output and --recommand are mutually exclusive\n");
        return 2;
    }
    if (!opt_out && !opt_rec) {
        fprintf(stderr, "terhijack: need one of --output TEXT / --recommand CMD\n");
        return 2;
    }

    if (isatty(STDOUT_FILENO))
        fprintf(stderr,
            "terhijack: tip - run  eval \"$(terhijack --init)\"  first, "
            "then use: hijack ...\n");

    mode_add((int)ncmds, cmds, opt_out, opt_rec, m_arg);

    for (size_t i = 0; i < ncmds; i++) free(cmds[i]);
    free(cmds);
    return 0;
}