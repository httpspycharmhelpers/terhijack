#!/data/data/com.termux/files/usr/bin/bash
# TerHijack v1.2 functional test suite
set -u
cd "$(dirname "$0")"
BIN="$PWD/terhijack"
export PATH="$PWD:$PATH"
fail=0

t() { # name expected actual
  if [ "$2" = "$3" ]; then
    printf 'ok   - %s\n' "$1"
  else
    printf 'FAIL - %s\n       expected [%s]\n       got      [%s]\n' "$1" "$2" "$3"
    fail=1
  fi
}

eval "$("$BIN" --init)"

### A. function hooks (v1.0 regressions)
hijack -c "id -Z" -o "root"
t "id -Z hijacked"        "root" "$(id -Z)"
t "long flags equivalent" "root" "$(hijack --command 'id -Z' --output root; id -Z)"
t "passthrough id -u"     "$(command id -u)" "$(id -u)"

hijack -c "echo $$" -r "echo root"
t "echo \$\$ masked via rec" "root" "$(echo $$)"
hijack --command 'whoami' --recommand 'echo root'
t "rec long flag"            "root" "$(whoami)"

hijack -c "pwd" -o "/data/rooted"
t "pwd hijacked"   "/data/rooted" "$(pwd)"
hijack -x "pwd"
t "pwd restored"   "$PWD" "$(pwd)"

hijack -c "ls -la --color" -o "hijacked-ls"
t "exact ls args match"  "hijacked-ls" "$(ls -la --color)"
t "plain ls untouched"   "$(command ls | head -c20)" "$(ls | head -c20)"

hijack -c "id -Z" -o "u:r:magisk:s0"
t "dup pattern updated" "u:r:magisk:s0" "$(id -Z)"

out="$(hijack --list)"
case "$out" in *"id -Z"*"whoami"*"-la --color"*) t "list shows hooks" y y ;; *) t "list shows hooks" y n ;; esac

hijack -x "whoami"
out="$(hijack --list)"
case "$out" in *whoami*) t "remove works" n y ;; *) t "remove works" y y ;; esac
t "whoami back to real" "$(command whoami)" "$(whoami)"

t "child bash inherits hook" "u:r:magisk:s0" "$(bash -c 'id -Z')"

### B. BUGFIX: cat /proc interception (both modes)
hijack -c "cat /proc/version" -o "FakeVersion"
t "cat /proc out-mode"   "FakeVersion" "$(cat /proc/version)"
hijack -x "cat /proc/version"
hijack -c "cat /proc/cpuinfo" -r "echo FakeCPU"
t "cat /proc rec-mode"   "FakeCPU" "$(cat /proc/cpuinfo)"
t "other cats passthrough" "$(echo real)" "$(cat <(echo real))"
hijack -x "cat /proc/cpuinfo"

### C. NEW: compound && ; lines (segment shadowing, chain short-circuit)
F="$HOME/.thj_marker_$$"
rm -f "$F"
hijack -c "touch $F && echo chainok" -o "FAKECHAIN"
out="$(touch $F && echo chainok)"
t "compound && out-hook"     "FAKECHAIN" "$out"
[ -e "$F" ] && real=n || real=y
t "real cmds suppressed"     "y" "$real"

hijack -c "cd / && tonuh L.txt && rm L.txt && echo '写入成功'" -r "echo '写入成功'"
t "verbatim user example"    "写入成功" "$(cd / && tonuh L.txt && rm L.txt && echo '写入成功')"

hijack -c "true ; echo semiok" -r "echo SEMI"
t "semicolon line hook"      "SEMI" "$(true ; echo semiok)"

hijack --clear
t "no DEBUG trap installed" "" "$(trap -p DEBUG)"

### D. NEW: -a/--arg penetration
mkdir -p "$HOME/.thjbin"
printf '#!/data/data/com.termux/files/usr/bin/bash\necho "mysu:$*"\n' > "$HOME/.thjbin/mysu"
chmod +x "$HOME/.thjbin/mysu"
export PATH="$HOME/.thjbin:$PATH"

hijack -c "su" -r "mysu" -a
t "-a su system -> mysu system" "mysu:system" "$(su system)"
t "-a bare su"                  "mysu:"       "$(su)"
t "-a multiple args"            "mysu:system reboot -f" "$(su system reboot -f)"
hijack -x "su"
t "-a removed (no fn)"          "file" "$(type -t su)"

hijack -c "getenforce" -o "Enforcing" --arg
t "-a with out mode"            "Enforcing"   "$(getenforce Permissive)"

hijack --clear

### E. NEW: '/' multi-command + repeated -c
hijack -c "aa/bb/cc" -o "X"
t "multi / #1"  "X" "$(aa)"
t "multi / #2"  "X" "$(bb)"
t "multi / #3"  "X" "$(cc)"
hijack --clear

hijack -c "q1" -c "q2" -o "Y"
t "repeat -c #1" "Y" "$(q1)"
t "repeat -c #2" "Y" "$(q2)"

hijack --clear
hijack -c "ping" -r "mysu" -a
out="$(bash -c 'export PATH="$HOME/.thjbin:$PATH"; ping -c 4 8.8.8.8')"
t "child bash inherits -a"  "mysu:-c 4 8.8.8.8" "$out"

hijack -c "aa && bb" -o "CHAIN"
out="$(bash -c 'aa && bb')"
t "child bash inherits && chain" "CHAIN" "$out"
hijack --clear

### F. path patterns must NOT be split by '/'
hijack --clear
hijack -c "cat /proc/version" -o "FakeVersion"
out="$(hijack --list | grep -c '^\[\*\]')"
t "'/' list not misdetected" "1" "$out"
t "path pattern intact"      "FakeVersion" "$(cat /proc/version)"

### F2. '~' and relative paths must NOT be split by '/'
hijack --clear
hijack -c "cat ./x" -o "FakeRel"
t "'./' not split"     "1" "$(hijack --list | grep -c '^\[\*\]')"
t "'./' pattern works" "FakeRel" "$(cd "$HOME"; cat ./x)"
hijack --clear
hijack -c "cat ~/test" -o "FakeHome"
t "'~/' not split"     "1" "$(hijack --list | grep -c '^\[\*\]')"
hijack --clear

### G. cleanup & isolation
hijack --clear
t "clear restores id"  "$(declare -F id >/dev/null && echo hooked || echo clean)" "clean"
t "clear restores ls"  "$(declare -F ls  >/dev/null && echo hooked || echo clean)" "clean"
fresh="$(env -i "$BASH" -c 'type -t id')"
t "new session unaffected" "file" "$fresh"

hijack -c "id -Z" -o "it's \"root\""
t "payload quoted safely" 'it'"'"'s "root"' "$(id -Z)"
hijack --clear

### H. NEW: --bash persistent wrapper (hooks auto-load into fresh bash)
TS="$HOME/.thj_test_state_$$"
WS="$HOME/.thj_test_wrap_$$"
hijack --clear
hijack -c "id -Z" -o "root-wrapped"
THJ_STATE_FILE="$TS" hijack -c "id" -o "uid=0(root)"
"$BIN" --bash > "$WS"; chmod +x "$WS"
out="$(THJ_STATE_FILE="$TS" "$BASH" "$WS" -c 'id')"
t "--bash loads hooks" "uid=0(root)" "$out"
out="$(THJ_STATE_FILE="$TS" "$BASH" "$WS" -c 'hijack --list' | grep -c '^\[\*\]')"
t "--bash management survives exec" "2" "$out"
rm -f "$TS" "$WS"

### I. NEW: --all / --restore binary-level patch (THJ_PFX sandbox)
SD="$HOME/.thj_test_sb_$$"
mkdir -p "$SD/bin"
printf '#!/data/data/com.termux/files/usr/bin/bash\necho "REAL-ID"\n' > "$SD/bin/id"
printf '#!/data/data/com.termux/files/usr/bin/bash\necho "REAL-CAT:$*"\n' > "$SD/bin/cat"
chmod +x "$SD/bin/id" "$SD/bin/cat"
D="$SD/thj.dat"
export THJ_DAT_FILE="$D"
out="$(THJ_PFX="$SD/bin" "$BASH" -c 'source <("'"$BIN"'" --all)' )"
case "$out" in *ready*) t "--all installs shims" y y ;; *) t "--all installs shims" y n ;; esac
hijack --clear
t "OUT   id forced"   "uid=0(root) gid=0(root) groups=0(root)" "$(PATH="$SD/bin:$PATH" id)"
t "PASS  cat passes"  "REAL-CAT:foo" "$(PATH="$SD/bin:$PATH" cat foo)"
PATH="$SD/bin:$PATH" cat /proc/version 2>/dev/null; rc=$?
t "BLOCK /proc denied" "1" "$rc"
out="$(THJ_DAT_FILE="$D" "$BASH" -c 'exec -a type "$HOME/.thj_patch" id')"
t "FAKE  type id"     "$SD/bin/id.thj_orig" "${out#id is }"
hijack --clear
THJ_PFX="$SD/bin" "$BASH" -c 'source <("'"$BIN"'" --restore)'
t "restore id back"   "REAL-ID" "$(PATH="$SD/bin:$PATH" id)"
t "restore no backup" "n" "$([ -e "$SD/bin/id.thj_orig" ] && echo y || echo n)"
unset THJ_DAT_FILE
rm -rf "$SD"

### J. NEW: ptrace layer prototype (thj_ptrace) - kernel-boundary uid fake
if [ -x "$PWD/thj_ptrace" ]; then
    t "ptrace id -u = 0"              "0" "$("$PWD/thj_ptrace" id -u 2>/dev/null)"
    t "ptrace abs /usr/bin/id -u = 0" "0" "$("$PWD/thj_ptrace" /usr/bin/id -u 2>/dev/null)"
    if command -v python3 >/dev/null 2>&1; then
        t "ptrace python os.getuid = 0" "0" "$("$PWD/thj_ptrace" python3 -c 'import os; print(os.getuid())' 2>/dev/null)"
    fi
else
    printf 'skip - thj_ptrace not built (make all)\n'
fi

exit $fail
