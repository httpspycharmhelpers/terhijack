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
2. **Binary-level layer** (`--all` / `thj_patch`) — **ELF patch**: replaces the
   real binaries (`id cat head tail grep ls mount ps who last hostname whoami
   uptime free df uname`) with a shim that answers `OUT`/`BLOCK`/`FAKE`
   records — outliving the shell. Reversible with `--restore`.
3. **Disguise suite** (`root_disguise.sh`) — builds a fully self-consistent
   fake-root environment on top: identity, SELinux, processes, networking,
   filesystem, `/proc`, plus self-hiding of the tool.
4. **Collaboration layer** (being integrated with aFakeSU / embedded proot) —
   planned `ptrace` syscall interception so even **non-shell processes**
   cannot bypass the disguise.

Sessions are clean by default; persistence is opt-in (`--bash`, `--all`).

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
--remove --bash --all --restore`) are aliases for the short ones.

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
# --- persistence ---
terhijack --bash > ~/hooked-bash                 # wrapper: hooks every new bash
alias bash="$HOME/hooked-bash"
hijack --all                                     # patch real binaries (ELF shim)
hijack --restore                                 # undo the binary patch
```

### Persistence & binary-level layer

Two opt-in mechanisms make hooks survive the current shell; both are
default-off and fully reversible.

**`terhijack --bash` — persistent bash wrapper.** Generates a small script
that, when used as `bash`, `eval`s `--init`, reloads the saved hook state and
then `exec`s the real bash. `THJ_REAL_BASH` / `THJ_BIN` / `THJ_STATE_FILE`
override resolution. Place it earlier in `PATH` or `alias bash=...` to hook
every new bash; management (`hijack ...`) works normally inside wrapped
sessions.

**`hijack --all` — binary-level ELF patch.** Takes the real binaries
(`id cat head tail grep ls mount ps who last hostname whoami uptime free df
uname`), keeps each as `<name>.thj_orig`, and puts the `thj_patch` shim in
their place. Invocations dispatch on a `.dat` state file (records,
`name<TAB>TYPE<TAB>payload`):
- `OUT` — print a fake payload (`id` → `uid=0(root) ...`) and exit 0
- `BLOCK` — refuse `/proc` & `/sys` access with `Permission denied`
- `FAKE` — answer `type <name>` with the real (backup) path
- (no record) — transparently run the real binary from the backup
Called with active session hooks (`hijack --all`) it installs exactly those;
called bare (`terhijack --all`) it installs defaults (`id`→root, cat/head/
tail/grep/ls→block). `hijack --restore` restores every backup and clears the
state. Env overrides for safe experimentation: `THJ_DAT_FILE`, `THJ_PFX`
(where the binaries live — point it at a throwaway dir in tests).

**State files.** Set `THJ_STATE_FILE` (bash-hook TSV) and/or `THJ_DAT_FILE`
(shim `.dat`) and every `hijack` call re-persists them; `__thj_load_file` /
the `--bash` wrapper restore them. Nothing writes to disk unless one of these
is set.

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

`test.sh` holds **52 assertions** across every mode and its long-flag
aliases, built by repeatedly breaking the tool in real use:

| Area | What is verified |
|------|------------------|
| Output / replace / arg-pass | all three modes, short + long flags |
| Compound commands | `&&` chain takeover, `;` neutralization, real side-effects suppressed |
| `cat /proc/*` | not mis-split by the `/`-list heuristic |
| Path-vs-list disambiguation | `cat /proc/x`, `cat ~/x`, `cat ./x` stay single hooks; `ls/pwd/id` still splits |
| Builtin takeover | `echo`-level infrastructure commands |
| Argument boundaries | exact match does not leak to other invocations; `-a` passes multiple and space-containing args |
| Session boundaries | child bash inherits; `--clear` restores functions; fresh session clean |
| Leak surface | quoted/escaped payloads evaluated safely |
| Persistence (`--bash`) | hooks + management survive a fresh `bash` via the wrapper |
| Binary layer (`--all`) | OUT/BLOCK/FAKE/pass behaviors; `--restore` fully reverts |

**Iterations driven by your requirements / bug reports:**
- Compound `&&` lines were mis-handled by the original DEBUG-trap approach →
  rewritten as segment shadowing + exit-code short-circuiting.
- `cat /proc/version` was once split by the `/` heuristic → added the
  `" /"` guard so real paths stay intact.
- `-a` initially lost the caller's arguments → fixed by explicitly splicing
  `"$@"` into the replacement eval.
- `/proc/<pid>/status` dynamic UID/GID/Caps, SELinux context, and trace
  self-hiding were hardened across reported rounds.
- `~/test` and `cat ~/x` were wrongly split into `~`/`test`/`cat` by the
  `/`-list feature → every `/` segment must now be a clean command name, and
  `~`/`.`-paths are excluded; `hijack -c "~/test"` is rejected instead of
  silently mis-registered. (v1.2)

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
  binary layer: thj_patch ELF shim (--all)      (done, v1.2)
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
7. **`--all` touches real binaries** (`$PREFIX/bin/...` → shim, original kept
   as `*.thj_orig`). It is disabled-at-checkout by design and reversible with
   `--restore`, but if a backup goes missing the shim refuses to exec rather
   than loop. Test with a `THJ_PFX` throwaway dir first.
8. **`--bash` wrapper changes every new bash**, including automation that
   spawns `bash`; combined with `THJ_STATE_FILE` it makes hooks durable across
   sessions, so a bad payload can follow you. Prefer session-scoped hooks for
   one-off work.

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
make            # cc -O2 -Wall -Wextra -std=c99 -> ./terhijack + ./thj_patch
make install    # installs both to $PREFIX/bin/
bash test.sh    # 52 functional assertions
```

Requires bash ≥ 4 (arrays, `"${!arr[@]}"`). zsh: function shadowing works;
`-a` and chain segmentation rely on bash extensions.

## License

GPL-3.0. For research and education on your own devices — nothing more.