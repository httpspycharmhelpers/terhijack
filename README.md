# TerHijack

> per-session terminal command hijacker for Android/Termux (bash/zsh)
> 会话级终端命令劫持器，仅供安全研究 / 教育 / 渗透测试使用

## What it does

Hooks arbitrary commands **inside the current shell session only**:

| mode | example | effect |
|------|---------|--------|
| `-o/--output` | `hijack -c "id -Z" -o "root"` | rewrite a command's output |
| `-r/--recommand` | `hijack -c "su" -r "mysu"` | transparently run another command instead |
| `-a/--arg` | `hijack -c "su" -r "mysu" -a` | pass the caller's args through (prefix match) |
| compound lines | `hijack -c "a && b && c" -r "echo x"` | hijack whole `&&` / `\|\|` / `;` chains |
| `/` lists | `hijack -c "ls/pwd/id" -o "x"` | hook several commands at once |

A freshly opened session is completely clean — nothing survives.

## How it works

`--init` bootstraps a `hijack()` wrapper into the session. Each hook is
registered as a shell **function shadowing** the real command; a small
dispatch (`__terhijack_dispatch`) decides by exact / prefix (`-a`) match
whether to print the fake output, run the replacement, or pass through to the
real binary. Compound lines are split per segment and shadowed segment-wise:
the first segment runs the payload and returns a code that **short-circuits
the chain** (`&&` aborts, `\|\|` skips, `;` siblings are neutered), so nothing
real ever executes. Child `bash` processes inherit the hooks through exported
functions + a serialized state string (`__THJ_SER`), and the whole state dies
with the session.

## Usage

```bash
eval "$(terhijack --init)"                       # bootstrap once per session
hijack -c "id -Z" -o "root"                      # fake output
hijack -c "echo $$" -r "echo root"               # replace command
hijack -c "su" -r "mysu" -a                      # replace + args pass through
hijack -c "cd / && rm f && echo ok" -r "echo x"  # whole line hijacked
hijack -c "ls/pwd/id" -o "x"                     # several commands
hijack --list                                    # list active hooks
hijack -x "ld -Z"                                # remove one
hijack --clear                                   # drop every hook
```

## Build & test

```bash
make            # cc -O2 -Wall -Wextra -std=c99 -> ./terhijack
make install    # installs to $PREFIX/bin/terhijack
bash test.sh    # 40 functional assertions
```

Needs bash >= 4 (arrays), works on Android/Termux and any Linux. zsh support
is partial (function shadowing works; `-a` and segmentation rely on bash
extensions).

## Disclaimer

Non-root penetration-training tool for your own devices only. 仅供娱乐,
请勿用于非法用途。