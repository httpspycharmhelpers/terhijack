/*
 * thj_ptrace - TerHijack syscall-interception engine prototype (aarch64).
 *
 * Runs a command tree (the whole fork/vfork/clone/exec lineage) under ptrace
 * and rewrites, at the KERNEL BOUNDARY:
 *
 *   - getuid/geteuid/getgid/getegid/getgroups -> 0
 *   - read() of /proc/self/attr/current        -> fake SELinux context
 *   - read() of /proc/self/status              -> Uid/Gid/Groups/Context/Caps
 *       lines rewritten to a root-looking, self-consistent answer
 *
 * Because every patch happens in the tracee's registers / memory at syscall
 * exit, nothing above the tracer can distinguish the fake from a real root
 * session: `id`, `id -Z`, `/usr/bin/id -u`, `cat /proc/self/attr/current`,
 * `grep Uid /proc/self/status`, python os.getuid(), absolute-paths, and every
 * descendant process the command spawns (pts follows the whole child tree).
 *
 * build:  cc -O2 -Wall -Wextra -std=c99 -o thj_ptrace thj_ptrace.c
 * usage:  thj_ptrace [--ctx <selinux-context>] [--] <command> [args...]
 *
 * Env override: THJ_CTX (default: u:r:shell:s0)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <elf.h>
#include <asm/ptrace.h>

#ifdef __aarch64__
#define SYS_NR_REG(r) ((r).regs[8])   /* syscall number lives in x8 */
#define SYS_RET_REG(r) ((r).regs[0])  /* return value   lives in x0 */
#else
#error "thj_ptrace currently targets aarch64 only"
#endif

#ifndef __NR_openat
#define __NR_openat 56
#endif
#ifndef __NR_read
#define __NR_read 63
#endif
#ifndef __NR_close
#define __NR_close 57
#endif

/* aarch64 has no `open` syscall (openat only) */
#define IS_OPEN(nr) 0

#define THJ_PTRACE_OPS \
    (PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | \
     PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC | PTRACE_O_TRACEEXIT)

#define MAX_TRACEES 64

/* ---- tracee memory helpers ------------------------------------------ */

static long peek_word(pid_t pid, unsigned long addr)
{
    errno = 0;
    long w = ptrace(PTRACE_PEEKDATA, pid, (void *)addr, NULL);
    return (w == -1 && errno != 0) ? -1 : w;
}

static int read_str(pid_t pid, unsigned long addr, char *out, size_t max)
{
    /* read a NUL-terminated string from tracee memory (worst case max) */
    size_t n = 0;
    while (n < max) {
        long w = peek_word(pid, addr + n);
        if (w < 0) return -1;
        unsigned char b[8];
        memcpy(b, &w, 8);
        for (int k = 0; k < 8 && n < max; k++, n++) {
            out[n] = (char)b[k];
            if (b[k] == '\0') return (int)n;
        }
    }
    out[(max > 0) ? max - 1 : 0] = '\0';
    return (int)n;
}

static int write_bytes(pid_t pid, unsigned long addr, const char *data, size_t len)
{
    /* overwrite tracee bytes in place, preserving the untouched tail words */
    size_t off = 0;
    while (off < len) {
        long w = peek_word(pid, addr + off);
        if (w < 0) return -1;
        unsigned char b[8];
        memcpy(b, &w, 8);
        size_t take = (len - off < 8) ? len - off : 8;
        memcpy(b, data + off, take);
        memcpy(&w, b, 8);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + off), (void *)w) < 0)
            return -1;
        off += take;
    }
    return 0;
}

/* ---- proc faking ---------------------------------------------------- */

enum fd_type { T_NONE = 0, T_ATTR, T_STATUS };

struct tracee {
    int   alive;
    pid_t pid;
    int   in_syscall;
    long  pending_nr;          /* syscall that must have its exit patched */
    int   pending_op;          /* non-zero: exit is an open() we care about */
    long  read_fd;
    unsigned long read_buf;
    long  read_cnt;
    struct { int fd; enum fd_type type; } fd_tab[256];
};

static struct tracee g_tr[MAX_TRACEES];

static struct tracee *tr_get(pid_t pid, int create)
{
    int i, free_i = -1;
    for (i = 0; i < MAX_TRACEES; i++) {
        if (g_tr[i].alive && g_tr[i].pid == pid)
            return &g_tr[i];
        if (!g_tr[i].alive && free_i < 0)
            free_i = i;
    }
    if (!create || free_i < 0) return NULL;
    i = free_i;
    memset(&g_tr[i], 0, sizeof(g_tr[i]));
    g_tr[i].alive = 1;
    g_tr[i].pid = pid;
    g_tr[i].in_syscall = 0;
    g_tr[i].pending_nr = -1;
    g_tr[i].read_fd = -1;
    return &g_tr[i];
}

static void tr_del(pid_t pid)
{
    for (int i = 0; i < MAX_TRACEES; i++)
        if (g_tr[i].alive && g_tr[i].pid == pid)
            memset(&g_tr[i], 0, sizeof(g_tr[i]));
}

static int tr_live(void)
{
    int n = 0;
    for (int i = 0; i < MAX_TRACEES; i++)
        if (g_tr[i].alive) n++;
    return n;
}

static int is_self_proc_path(const char *p, pid_t self, const char *what)
{
    /* accept /proc/self/<what>, /proc/thread-self/<what> and
     * /proc/<ownpid>/<what> */
    const char *tail = NULL;
    if (strncmp(p, "/proc/self/", 11) == 0)
        tail = p + 11;
    else if (strncmp(p, "/proc/thread-self/", 18) == 0)
        tail = p + 18;
    else if (strncmp(p, "/proc/", 6) == 0) {
        const char *slash = strchr(p + 6, '/');
        if (!slash) return 0;
        char pidbuf[16];
        size_t pl = (size_t)(slash - (p + 6));
        if (pl >= sizeof(pidbuf)) return 0;
        memcpy(pidbuf, p + 6, pl);
        pidbuf[pl] = '\0';
        if (atol(pidbuf) != (long)self) return 0;
        tail = slash + 1;
    }
    if (!tail) return 0;
    return strcmp(tail, what) == 0;
}

static char g_fake_ctx[256] = "u:r:shell:s0";

static char *g_fake_status = NULL;
static size_t g_fake_status_len = 0;

static void build_fake_status(void)
{
    /* snapshot the supervisor's own /proc/self/status (identical session
     * uid/groups) and rewrite the root-visible fields. */
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return;
    char line[1024];
    size_t cap = 16384, n = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return; }
    buf[0] = '\0';

    while (fgets(line, sizeof(line), f)) {
        const char *repl = NULL;
        if      (strncmp(line, "Uid:", 4) == 0)
            repl = "Uid:\t0\t0\t0\t0\n";
        else if (strncmp(line, "Gid:", 4) == 0)
            repl = "Gid:\t0\t0\t0\t0\n";
        else if (strncmp(line, "Groups:", 7) == 0)
            repl = "Groups:\t0\n";
        else if (strncmp(line, "Context:", 8) == 0) {
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "Context:\t%s\n", g_fake_ctx);
            repl = tmp;
        } else if (strncmp(line, "CapInh:", 7) == 0)
            repl = "CapInh:\t0000000000000000\n";
        else if (strncmp(line, "CapPrm:", 7) == 0)
            repl = "CapPrm:\t000001ffffffffff\n";
        else if (strncmp(line, "CapEff:", 7) == 0)
            repl = "CapEff:\t000001ffffffffff\n";
        else if (strncmp(line, "CapBnd:", 7) == 0)
            repl = "CapBnd:\t000001ffffffffff\n";
        else if (strncmp(line, "CapAmb:", 7) == 0)
            repl = "CapAmb:\t000001ffffffffff\n";

        const char *use = repl ? repl : line;
        size_t l = strlen(use);
        if (n + l < cap) {
            memcpy(buf + n, use, l);
            n += l;
        }
    }
    fclose(f);
    g_fake_status = buf;
    g_fake_status_len = n;
}

static int is_fakable(long nr)
{
    return nr == __NR_getuid || nr == __NR_geteuid ||
           nr == __NR_getgid || nr == __NR_getegid ||
           nr == __NR_getgroups;
}

/* ---- regs helpers --------------------------------------------------- */

static int get_regs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec io = { regs, sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
}

static int set_regs(pid_t pid, struct user_pt_regs *regs)
{
    struct iovec io = { regs, sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &io);
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: thj_ptrace [--ctx <selinux-context>] [--] <command> [args...]\n"
        "  runs <command> and its whole child tree under ptrace, forcing a\n"
        "  root-looking answer at the kernel boundary: getuid/geteuid/getgid/\n"
        "  getegid/getgroups return 0, /proc/self/attr/current serves the fake\n"
        "  SELinux context, and /proc/self/status gets root Uid/Gid/Groups/\n"
        "  Context/Cap lines. every fork/vfork/clone/exec descendant is traced.\n"
        "  env: THJ_CTX overrides the context (default u:r:shell:s0)\n");
}

int main(int argc, char **argv)
{
    const char *ctx = getenv("THJ_CTX");
    if (ctx && ctx[0])
        snprintf(g_fake_ctx, sizeof(g_fake_ctx), "%s", ctx);

    int cmd0 = 1;
    if (argc >= 3 && strcmp(argv[1], "--ctx") == 0) {
        snprintf(g_fake_ctx, sizeof(g_fake_ctx), "%s", argv[2]);
        cmd0 = 3;
    }
    if (cmd0 < argc && strcmp(argv[cmd0], "--") == 0)
        cmd0++;
    if (cmd0 >= argc) { usage(stderr); return 2; }

    pid_t pid = fork();
    if (pid < 0) { perror("thj_ptrace: fork"); return 1; }

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("thj_ptrace: ptrace(TRACEME)");
            exit(1);
        }
        raise(SIGSTOP);
        execvp(argv[cmd0], &argv[cmd0]);
        perror("thj_ptrace: execvp");
        exit(127);
    }

    build_fake_status();
    if (!tr_get(pid, 1)) return 1;

    int patched_regs = 0, patched_proc = 0;
    int status = 0;
    int dbg = getenv("THJ_DEBUG") ? 1 : 0;

    for (;;) {
        pid_t who = waitpid(-1, &status, 0);
        if (who < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD && tr_live() == 0) break;
            perror("thj_ptrace: waitpid");
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (dbg) fprintf(stderr, "# exit pid=%d status=%d\n", who, status);
            tr_del(who);
            if (tr_live() == 0) break;
            continue;
        }
        if (!WIFSTOPPED(status)) continue;

        int sig = WSTOPSIG(status);
        unsigned event = (unsigned)(status >> 16);

        struct tracee *tr = tr_get(who, 1);
        if (dbg)
            fprintf(stderr, "# stop pid=%d sig=%d event=%u\n", who, sig, event);

        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long child = 0;
            ptrace(PTRACE_GETEVENTMSG, who, NULL, (void *)&child);
            if (child && !tr_get((pid_t)child, 0)) {
                tr_get((pid_t)child, 1);            /* pre-register new branch */
                ptrace(PTRACE_SETOPTIONS, (pid_t)child, NULL,
                       (void *)(unsigned long)THJ_PTRACE_OPS);
            }
        } else if (event == PTRACE_EVENT_EXEC) {
            tr->in_syscall = 0;                     /* fresh program, fresh fds */
            tr->pending_nr = -1;
            tr->pending_op = 0;
            tr->read_fd = -1;
            memset(tr->fd_tab, 0, sizeof(tr->fd_tab));
        } else if (event == PTRACE_EVENT_EXIT) {
            /* tracee about to die; nothing to patch */
        } else if (event == PTRACE_EVENT_STOP) {
            /* group-stop from SEIZE-style events; ignore */
        } else if (sig == SIGSTOP) {
            /* brand-new task (original TRACEME stop or a forked child) */
            tr->in_syscall = 0;
            tr->pending_nr = -1;
            ptrace(PTRACE_SETOPTIONS, who, NULL,
                   (void *)(unsigned long)THJ_PTRACE_OPS);
        } else if (sig == (SIGTRAP | 0x80)) {
            struct user_pt_regs regs;
            if (get_regs(who, &regs) < 0) break;
            long nr = (long)SYS_NR_REG(regs);

            if (!tr->in_syscall) {
                /* ---------------- syscall ENTRY ---------------- */
                tr->in_syscall = 1;
                tr->pending_nr = is_fakable(nr) ? nr : -1;
                tr->pending_op = 0;
                if (dbg)
                    fprintf(stderr, "#    ENTRY nr=%ld pend=%ld\n", nr,
                            tr->pending_nr);
                if (nr == __NR_openat || IS_OPEN(nr)) {
                    unsigned long path_addr = (nr == __NR_openat)
                        ? (unsigned long)regs.regs[1]  /* openat: a1 */
                        : (unsigned long)regs.regs[0]; /* open:   a0 */
                    char p[512];
                    if (read_str(who, path_addr, p, sizeof(p)) >= 0) {
                        if (is_self_proc_path(p, who, "attr/current"))
                            tr->pending_op = T_ATTR;
                        else if (is_self_proc_path(p, who, "status"))
                            tr->pending_op = T_STATUS;
                    }
                } else if (nr == __NR_read) {
                    tr->read_fd = (long)regs.regs[0];
                    tr->read_buf = (unsigned long)regs.regs[1];
                    tr->read_cnt = (long)regs.regs[2];
                } else if (nr == __NR_close) {
                    long fd = (long)regs.regs[0];
                    if (fd >= 0 && fd < 256)
                        tr->fd_tab[fd].type = T_NONE;
                }
            } else {
                /* ---------------- syscall EXIT ---------------- */
                tr->in_syscall = 0;
                long ret = (long)SYS_RET_REG(regs);

                if (dbg)
                    fprintf(stderr, "#    EXIT  pid=%d nr=%ld pend=%ld ret=%ld\n",
                            who, nr, tr->pending_nr, ret);

                if (tr->pending_nr >= 0 && nr == tr->pending_nr) {
                    SYS_RET_REG(regs) = 0;   /* getuid/getgid... = 0 */
                    set_regs(who, &regs);
                    patched_regs++;
                    if (dbg) fprintf(stderr, "#    =>REG-PATCHED\n");
                } else if ((nr == __NR_openat || IS_OPEN(nr)) &&
                           tr->pending_op != 0) {
                    if (ret >= 0 && ret < 256) {
                        tr->fd_tab[ret].fd = (int)ret;
                        tr->fd_tab[ret].type = (enum fd_type)tr->pending_op;
                    }
                } else if (nr == __NR_read && ret >= 0) {
                    enum fd_type t = (tr->read_fd >= 0 && tr->read_fd < 256)
                        ? tr->fd_tab[tr->read_fd].type : T_NONE;
                    const char *fake = NULL;
                    size_t flen = 0;
                    if (t == T_ATTR) {
                        fake = g_fake_ctx;
                        flen = strlen(fake);
                    } else if (t == T_STATUS && g_fake_status) {
                        fake = g_fake_status;
                        flen = g_fake_status_len;
                    }
                    if (fake && (unsigned long)tr->read_cnt >= flen) {
                        if (write_bytes(who, tr->read_buf, fake, flen) == 0) {
                            char nul = '\0';
                            write_bytes(who, tr->read_buf + flen, &nul, 1);
                            SYS_RET_REG(regs) = (long)flen;
                            set_regs(who, &regs);
                            patched_proc++;
                            if (tr->read_fd >= 0 && tr->read_fd < 256)
                                tr->fd_tab[tr->read_fd].type = T_NONE;
                        }
                    }
                }
                tr->pending_nr = -1;
                tr->pending_op = 0;
                tr->read_fd = -1; tr->read_buf = 0; tr->read_cnt = 0;
            }
        } else if (sig == SIGTRAP) {
            /* plain TRAP (e.g. int3 / re-sent SIGTRAP); let it run */
        }

        /* any stop whose sig matches a pending signal is forwarded raw --
         * the others are the synthetic ptrace stops where we must resume
         * the syscall state machine without injecting the signal. */
        if (sig == SIGSTOP) {
            ptrace(PTRACE_SYSCALL, who, NULL, NULL);
        } else if (sig == (SIGTRAP | 0x80) || sig == SIGTRAP) {
            ptrace(PTRACE_SYSCALL, who, NULL, NULL);
        } else if (event == PTRACE_EVENT_STOP) {
            ptrace(PTRACE_SYSCALL, who, NULL, NULL);
        } else {
            ptrace(PTRACE_SYSCALL, who, NULL, (void *)(unsigned long)sig);
        }
    }

    fprintf(stderr, "# thj_ptrace: patched %d reg + %d proc answer(s)\n",
            patched_regs, patched_proc);
    free(g_fake_status);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}