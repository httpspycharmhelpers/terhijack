/*
 * thj_ptrace - TerHijack ptrace layer prototype (aarch64).
 *
 * A minimal supervisor that runs a command under ptrace and rewrites the
 * result of uid/gid syscalls at the kernel boundary -- the same trick the
 * aFakeSU/proot layer needs, reduced to the smallest proof:
 *
 *     getuid / geteuid / getgid / getegid  -> 0
 *
 * Because the value is patched in the tracee's registers at syscall EXIT,
 * NOTHING above the tracer can see the real uid: `id`, `/usr/bin/id -u`,
 * python's os.getuid(), stripped statics, suid-style probes -- all of them
 * are fed the fake value.
 *
 * build:  cc -O2 -Wall -Wextra -std=c99 -o thj_ptrace thj_ptrace.c
 * usage:  ./thj_ptrace [--] <command> [args...]
 *
 * prototype note: only uid/gid getters are patched right now; open/chdir
 * path rewriting and multi-child supervision come next.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <elf.h>
#include <asm/ptrace.h>

#ifdef __aarch64__
#define SYS_NR_REG(r) ((r).regs[8])   /* syscall number lives in x8 */
#define SYS_RET_REG(r) ((r).regs[0])  /* return value lives in x0   */
#else
#error "thj_ptrace prototype currently targets aarch64"
#endif

static int is_fakable(long nr)
{
    return nr == __NR_getuid || nr == __NR_geteuid ||
           nr == __NR_getgid || nr == __NR_getegid ||
           nr == __NR_getgroups;
}

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
    fprintf(f, "usage: thj_ptrace [--] <command> [args...]\n"
               "  runs <command> under ptrace and forces getuid/geteuid/\n"
               "  getgid/getegid to return 0 (kernel-boundary fake root)\n");
}

int main(int argc, char **argv)
{
    if (argc < 2) { usage(stderr); return 2; }
    int cmd0 = 1;
    if (strcmp(argv[1], "--") == 0) {
        if (argc < 3) { usage(stderr); return 2; }
        cmd0 = 2;
    }

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

    /* parent: supervise */
    int status = 0;
    int in_syscall = 0;      /* alternating entry/exit per PTRACE_SYSCALL */
    long pending_nr = -1;    /* syscall whose exit we want to patch */
    unsigned long patched = 0;

    for (;;) {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) continue;
            perror("thj_ptrace: waitpid");
            break;
        }
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        int sig = 0;
        if (WIFSTOPPED(status)) sig = WSTOPSIG(status);

        if (sig == SIGSTOP) {
            /* child raised SIGSTOP right after TRACEME: install options,
             * then one PTRACE_SYSCALL to finish the exec and enter the
             * syscall loop. */
            ptrace(PTRACE_SETOPTIONS, pid, NULL,
                   (void *)(unsigned long)(
                       PTRACE_O_TRACESYSGOOD |
                       PTRACE_O_TRACEEXEC |
                       PTRACE_O_TRACEEXIT));
            in_syscall = 0;
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (sig == (SIGTRAP | 0x80)) {
            /* syscall entry/exit stop thanks to TRACESYSGOOD */
            struct user_pt_regs regs;
            if (get_regs(pid, &regs) < 0) {
                perror("thj_ptrace: GETREGSET");
                break;
            }
            long nr = (long)SYS_NR_REG(regs);
            if (!in_syscall) {
                /* entry */
                in_syscall = 1;
                pending_nr = is_fakable(nr) ? nr : -1;
            } else {
                /* exit */
                in_syscall = 0;
                if (pending_nr >= 0 && (long)SYS_NR_REG(regs) == pending_nr) {
                    SYS_RET_REG(regs) = 0;      /* pretend uid/gid = 0 */
                    if (set_regs(pid, &regs) < 0) {
                        perror("thj_ptrace: SETREGSET");
                        break;
                    }
                    patched++;
                }
                pending_nr = -1;
            }
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        if (sig == SIGTRAP) {
            /* exec event (also arrives via TRACEEXEC as plain SIGTRAP on
             * some kernels): resume tracing */
            ptrace(PTRACE_SYSCALL, pid, NULL, NULL);
            continue;
        }

        ptrace(PTRACE_SYSCALL, pid, NULL, (void *)(unsigned long)sig);
    }

    fprintf(stderr, "# thj_ptrace: patched %lu uid/gid getter(s)\n", patched);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}