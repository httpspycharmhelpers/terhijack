# TerHijack

> Per-session **command takeover** engine for Android/Termux (bash)
>
> Not a "fake permissions" gimmick and not a simple output rewriter. Within a
> session, every command — builtin or external, part of a compound chain or a
> pipeline, wrapped with any argument combination — is subject to the
> interception layer you define.

**For authorized security research, education, and use on your own devices
only. Misuse is against the law in most jurisdictions. You are responsible
for what you run it on.**

---

## What this is, precisely

TerHijack is a layered interception system:

1. **Core engine** (`terhijack` / `hijack`) — intercepts commands inside the
   current bash session: rewrite output, replace the command, pass caller
   arguments through, take over entire compound chains, and even shadow
   builtins.
2. **Disguise suite** (`root_disguise.sh`) — builds a fully self-consistent
   fake-root environment on top: identity, SELinux, processes, networking,
   filesystem, `/proc`, plus self-hiding of the tool.
3. **Collaboration layer** (being integrated with aFakeSU / embedded proot) —
   planned `ptrace` syscall interception so even **non-shell processes**
   cannot bypass the disguise.

Nothing survives the session. A fresh shell is completely clean.

---

## Core engine

### Interception modes

| Mode | Example | Effect |
|------|---------|--------|
| `-o/--output` | `hijack -c "id -Z" -o "root"` | rewrite a command's output |
| `-r/--recommand` | `hijack -c "whoami" -r "echo root"` | transparently run another command instead |
| `-a/--arg` | `hijack -c "su" -r "mysu" -a` | **argument penetration**: append the caller's args to the replacement (prefix match) |
| Compound chains | `hijack -c "a && b && c" -r "echo x"` | **take over the whole chain**: `&&` aborts, `\|\|` short-circuits, `;` siblings are neutered |
| `/` lists | `hijack -c "ls/pwd/id" -o "x"` | register several commands at once |
| Builtin takeover | `hijack -c "exit" -o "MOCK"` | `exit`, `logout`, `cd`, `echo` and other builtins are shadowed too |

Long options (`--command --output --recommand --arg --list --clear --init
--remove`) are aliases for the short ones.

### Usage

```bash
eval "$(terhijack --init)"                       # bootstrap once per session
hijack -c "id -Z" -o "root"                      # rewrite output
hijack -c "echo $$" -r "echo root"               # replace command
hijack -c "su" -r "mysu" -a                      # replace + pass args through
hijack -c "cd / && rm f && echo ok" -r "echo x"  # whole chain taken over
hijack -c "ls/pwd/id" -o "x"                     # several commands at once
hijack --list                                    # show active hooks
hijack -x "id -Z"                                # remove one hook
hijack --clear                                   # drop every hook
```

### What "degree of takeover" means here

- **Argument-aware**: with `-a`, replacement functions receive the **real
  caller arguments**, enabling per-flag answers (e.g. `id` returning precise
  values for `-u`, `-g`, `-G`, `-n`, `-Z`, `-z`, `-a` and any short-flag
  combination).
- **No collateral damage**: exact matching only hits the identical argument
  vector; unwrapped invocations pass through to the real binary (`command`).
- **Cross-process**: exported functions + a serialized state string
  (`__THJ_SER`) let child bash processes inherit every hook.
- **Truly suppressed, not faked**: compound chains short-circuit via exit
  codes, so the real commands never run (verified: `touch` side effects are
  suppressed, not just the output masked).
- **Builtin-safe runtime**: word counting uses pure parameter expansion — the
  runtime does not depend on `echo`/`printf` in matching paths, so shadowing
  builtins does not break the dispatcher.
- **Recursion-safe replacements**: the triggering function is temporarily
  unshadowed while the replacement runs, so a payload that itself calls the
  hijacked name (e.g. `echo` inside a `-r` chain) hits the real command.
- **Self-hijack is possible and articulate**: hooking `hijack`/`terhijack`
  locks the management layer (recoverable with a re-`--init`); hooking a
  widely used builtin has predictable cascade effects. Intentionally supported.

### Mechanics

```
hijack() wrapper → binary (C) parses args + serialized session state
                → emits declarative state + runtime
__terhijack_dispatch: exact | prefix (-a) match →
     out  : print fake output
     rec  : eval replacement (+ caller args), real command re-enabled
            for same-named calls inside the payload
     else : passthrough via `command`
__terhijack_rebuild: unset old shims → reinstall shadow functions
__THJ_SER serialization + export -f → child bash inheritance
```

No `DEBUG` trap, no `extdebug`, no ptrace (yet) — everything is portable
bash function shadowing with declared session state.

---

## Disguise suite (`root_disguise.sh`)

One command turns the session into a *self-consistent* fake-root machine.
Not per-command spot fixes — an **environment where every probe returns a
coherent story**.

### Coverage (40+ hooks)

**Identity**
- `id` with full GNU flag support (`-u -g -G -n -Z -z -a`, combined shorts)
   → `uid=0(root)` + faked SELinux context everywhere
- `whoami`, `logname`, `groups` all `root`; env rewritten
  (`HOME=/root USER=root LOGNAME=root SHELL=/bin/bash PATH`, `HISTFILE`,
  `MAIL`, `PWD`) and PS1 becomes a root-style `#`

**Filesystem**
- `cat` is **path-aware**: `/etc/os-release`, `/etc/hostname`, `/etc/hosts`,
  `/etc/resolv.conf`, `/etc/environment`, `/etc/motd` each return bespoke
  faked content
- **`/proc` deep fakery**: `/proc/<pid>/status` is regenerated per real PID
  with `Uid/Gid 0 0 0 0`, `CapPrm/CapEff` full, `TracerPid: 0`;
  `/proc/<pid>/attr/current` returns the faked context; `environ`, `cmdline`,
  `comm` forged
- `ls`/`stat` present root-owned file views; `head`/`tail`/`grep`/`getent`
  pass through with filtering; `chown`/`chmod` respond like root

**SELinux**
- `getenforce` → `Enforcing`; `sestatus`, `chcon`, `setenforce`,
  `matchpathcon`, `seinfo` all answer coherently

**System / process / network**
- `hostname`, `uname` (kernel + arch), `uptime`, `ps`, `mount`, `df`, `free`,
  `netstat`, `ss`, `ifconfig`, `ip`

**Accounts / management**
- `sudo`, `passwd`, `crontab`, `w`, `who`, `last`, `lastb`, `history` (a
  plausible root admin history)

**Self-hiding**
- `which`, `type`, `find` filter out `terhijack`, `__root_*`, `__thj_*`
  traces and report "normal"-looking paths for hooked coreutils

```bash
bash root_disguise.sh     # enter a "looks like root" session
id            # uid=0(root) ...
cat /proc/1/status        # Uid: 0 0 0 0, CapEff full
type terhijack            # not found  (trace hidden)
hijack --clear            # one-command restore
```

---

## Test breadth & iteration history

`test.sh` holds **40 assertions** across every mode and its long-flag
aliases, built by repeatedly breaking the tool in real use:

| Area | What is verified |
|------|------------------|
| Output / replace / arg-pass | all three modes, short + long flags |
| Compound commands | `&&` chain takeover, `;` neutralization, real side-effects suppressed |
| `cat /proc/*` | not mis-split by the `/`-list heuristic |
| Builtin takeover | `echo`-level infrastructure commands |
| Argument boundaries | exact match does not leak to other invocations; `-a` passes multiple and space-containing args |
| Session boundaries | child bash inherits; `--clear` restores functions; fresh session clean |
| Leak surface | quoted/escaped payloads evaluated safely |

**Iterations driven by your requirements / bug reports:**
- Compound `&&` lines were mis-handled by the original DEBUG-trap approach →
  rewritten as segment shadowing + exit-code short-circuiting.
- `cat /proc/version` was once split by the `/` heuristic → added the
  `" /"` guard so real paths stay intact.
- `-a` initially lost the caller's arguments → fixed by explicitly splicing
  `"$@"` into the replacement eval.
- `/proc/<pid>/status` dynamic UID/GID/Caps, SELinux context, and trace
  self-hiding were hardened across reported rounds.

---

## Roadmap: the aFakeSU / proot layer

The shell layer is provably bypassable by anything that resolves commands
outside function shadowing (see Risks). The final layer, in progress with the
aFakeSU project (which embeds a proot/termux tree), is **`ptrace`
syscall-interception**: trace every child, translate paths, and fake return
values at the kernel interface. That closes the bypass surface for **any
process**, shell or not.

```
  bash session: function shadowing + dispatch   (done)
  disguise:     40+ coherent __root_* payloads   (done)
  syscalls:     proot-style ptrace interception  (roadmap)
```

---

## Risks — read before use

1. **Arbitrary code execution by design**: `-r` replacements are `eval`'d in
   the session. A hook can run any command inside the victim shell, inheriting
   its environment, state, and hook control. This is the tool's nature, not a
   bug — assume any session running TerHijack is fully controllable by whoever
   defines the payloads.
2. **Session-only illusion, easily bypassed** — verified vectors:
   - absolute paths — `$(/usr/bin/id -u)` leaks the real UID
   - non-bash interpreters — `sh -c '<hooked yes> ; <bare command>'` does not
     inherit functions; mksh/dash output leaks through
   - native syscalls — `python3 -c 'import os; print(os.getuid())'` reads the
     real value from the kernel
   - SUID/exec'd binaries resolved by full path
3. **Builtin shadowing is sharp**: hooking `echo`/`printf` catches every
   occurrence, including inside payloads (mitigated by the unshadow-during-
   eval rule) and the output branch still leans on `printf`.
4. **Hooking `hijack`/`terhijack` locks the management layer** until a
   re-`--init`; hooks persist through `--clear` once the wrapper is shadowed.
5. **Termux quirk**: `/tmp` is not writable — download-style payloads must
   land in `$PREFIX/tmp` or `$HOME`.
6. **Payloads using the hijacked command cascade-trigger** (e.g. a `-r` chain
   on `echo` containing `echo`); design triggers around non-builtin commands
   where possible.

## Intended use

- Authorized penetration-testing / red-team exercises on systems you own or
  are permitted to test.
- Education: understanding how output/identity spoofing, OPSEC self-consistency,
  and shell-level interception work (and where they break).
- Prototyping the syscall-level interception in the aFakeSU collaboration.

Any other use — credential fishing, hiding tooling on shared systems, social
engineering — is both against this project's stated purpose and, in most
contexts, illegal. Keep it on your own devices.

---

## Build & test

```bash
make            # cc -O2 -Wall -Wextra -std=c99 -> ./terhijack
make install    # installs to $PREFIX/bin/terhijack
bash test.sh    # 40 functional assertions
```

Requires bash ≥ 4 (arrays, `"${!arr[@]}"`). zsh: function shadowing works;
`-a` and chain segmentation rely on bash extensions.

## License

GPL-3.0. For research and education on your own devices — nothing more.