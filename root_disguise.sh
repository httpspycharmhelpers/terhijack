#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  root_disguise.sh — 通用 Root 身份伪装脚本 v3
#  基于 TerHijack，零泄漏，适配任何 Android/Termux 设备
#  仅供安全研究 / 教育 / 渗透测试使用
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

# ─── 自动检测设备信息 ─────────────────────────────────────────────
# 真实用户名（用于 ls 输出替换）
__REAL_USER="${USER:-$(id -un 2>/dev/null || echo root)}"
__REAL_UID="$(id -u 2>/dev/null || echo 0)"
# 真实 home 目录
__REAL_HOME="${HOME:-/data/data/com.termux/files/home}"
# 真实 Android 属性
__REAL_MODEL="$(getprop ro.product.model 2>/dev/null || echo 'Android Device')"
__REAL_ANDROID_VER="$(getprop ro.build.version.release 2>/dev/null || echo '13')"
__REAL_KERNEL="$(uname -r 2>/dev/null || echo '5.15.0-generic')"
__REAL_ARCH="$(uname -m 2>/dev/null || echo 'aarch64')"
__REAL_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{print $7; exit}' || echo '10.0.2.15')"

# ─── 伪装配置（可通过环境变量覆盖）─────────────────────────────────
DISGUISE_HOSTNAME="${DISGUISE_HOSTNAME:-$(hostname 2>/dev/null || echo 'localhost')}"
DISGUISE_KERNEL="${DISGUISE_KERNEL:-Linux ${DISGUISE_HOSTNAME} ${__REAL_KERNEL} #1 SMP Ubuntu 22.04.3 ${__REAL_ARCH}}"
DISGUISE_DISTRIB="${DISGUISE_DISTRIB:-Ubuntu}"
DISGUISE_RELEASE="${DISGUISE_RELEASE:-22.04.3 LTS}"
DISGUISE_CODENAME="${DISGUISE_CODENAME:-jammy}"
DISGUISE_SHELL="${DISGUISE_SHELL:-/bin/bash}"
DISGUISE_SELINUX_CTX="${DISGUISE_SELINUX_CTX:-u:r:root:s0}"
DISGUISE_SELINUX_OBJ="${DISGUISE_SELINUX_OBJ:-u:object_r:system_file:s0}"

# ─── 查找 terhijack ──────────────────────────────────────────────
THJ=""
for _c in "${__THJ_BIN:-}" "./terhijack" "${THJ_BIN:-}" \
          "${PREFIX:-}/bin/terhijack" "$HOME/bin/terhijack" \
          /data/local/tmp/terhijack; do
  [ -n "$_c" ] && [ -x "$_c" ] && { THJ="$_c"; break; }
done
[ -x "$THJ" ] || { echo "terhijack: not found" >&2; exit 127; }
export __THJ_BIN="$THJ"
echo "[*] Using: $THJ"

# ─── 初始化 hijack ───────────────────────────────────────────────
eval "$("$THJ" --init 2>/dev/null)"


# ╔══════════════════════════════════════════════════════════════╗
# ║                     伪 装 函 数 库                          ║
# ╚══════════════════════════════════════════════════════════════╝

# ── id（GNU coreutils 完整支持）────────────────────────────────────
__root_id() {
  local _ctx="$DISGUISE_SELINUX_CTX"
  local _uid=0 _user="root" _gid=0 _group="root"
  local _do_user=false _do_group=false _do_groups=false _do_name=false
  local _do_ctx=false _do_zero=false _do_all=false _has_flag=false

  while [ $# -gt 0 ]; do
    case "$1" in
      -u|--uid)           _do_user=true; _has_flag=true ;;
      -g|--gid)           _do_group=true; _has_flag=true ;;
      -G|--groups)        _do_groups=true; _has_flag=true ;;
      -n|--name)          _do_name=true; _has_flag=true ;;
      -Z|--context)       _do_ctx=true; _has_flag=true ;;
      -z|--zero)          _do_zero=true; _has_flag=true ;;
      -a|--all)           _do_all=true; _has_flag=true ;;
      --help|--version)   command id "$@" 2>/dev/null; return $? ;;
      -*) local _ch="${1#-}"; local _i=0
        while [ $_i -lt ${#_ch} ]; do
          case "${_ch:$_i:1}" in
            u) _do_user=true ;; g) _do_group=true ;; G) _do_groups=true ;;
            n) _do_name=true ;; Z) _do_ctx=true ;; z) _do_zero=true ;;
            a) _do_all=true ;;
          esac; _i=$((_i+1))
        done; _has_flag=true ;;
      *) _has_flag=true ;;
    esac; shift
  done

  if ! $_has_flag; then
    echo "uid=0(${_user}) gid=0(${_group}) groups=0(${_group}) context=${_ctx}"; return
  fi
  $_do_all && { echo "uid=0(${_user}) gid=0(${_group}) groups=0(${_group}) context=${_ctx}"; return; }

  local _sep=" "; $_do_zero && _sep=$'\0'
  local _out=""
  if $_do_user; then
    $_do_name && _out="${_user}" || _out="${_uid}"
  fi
  if $_do_group; then
    local _v; $_do_name && _v="${_group}" || _v="${_gid}"
    [ -n "$_out" ] && _out="${_out}${_sep}"; _out="${_out}${_v}"
  fi
  if $_do_groups; then
    local _v; $_do_name && _v="root" || _v="0"
    [ -n "$_out" ] && _out="${_out}${_sep}"; _out="${_out}${_v}"
  fi
  if $_do_ctx; then
    [ -n "$_out" ] && _out="${_out}${_sep}"; _out="${_out}${_ctx}"
  fi
  echo "$_out"
}

# ── SELinux 命令 ──────────────────────────────────────────────────
__root_getenforce() { echo "Enforcing"; }
__root_sestatus() {
  printf '%s\n' \
    "SELinux status:                 enabled" \
    "SELinuxfs mount:                /sys/fs/selinux" \
    "Loaded policy name:             targeted" \
    "Current mode:                   enforcing" \
    "Mode from config file:          enforcing" \
    "Policy MLS status:              enabled" \
    "Max kernel policy version:      33"
}
__root_chcon() { echo "chcon: cannot change security context"; return 1; }
__root_setenforce() { echo "setenforce: set enforcing not permitted"; return 1; }
__root_matchpathcon() { printf '%s %s\n' "$DISGUISE_SELINUX_OBJ" "${2:-${1:-/}}"; }
__root_seinfo() {
  printf '%s\n' \
    "   Policy Version:  33" \
    "   Permissions: 382" \
    "   Types: 4776" \
    "   Users: 8" \
    "   Booleans: 334"
}

# ── cat 拦截（核心：所有敏感文件读取）─────────────────────────────
__root_cat() {
  local _f="" _opts=()
  for _a in "$@"; do
    case "$_a" in
      -*) _opts+=("$_a") ;;
      *)  [ -z "$_f" ] && _f="$_a" ;;
    esac
  done

  case "$_f" in
    # ── /etc 系统文件 ──
    /etc/passwd)
      printf '%s\n' "root:x:0:0:root:/root:/bin/bash" \
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin" \
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin" \
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin" \
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin" \
        "sshd:x:107:65534::/run/sshd:/usr/sbin/nologin" ;;
    /etc/shadow)
      printf '%s\n' 'root:$6$rounds=656000$redacted:19000:0:99999:7:::' \
        'daemon:*:19000:0:99999:7:::' 'sshd:*:19000:0:99999:7:::' ;;
    /etc/group)
      printf '%s\n' "root:x:0:" "daemon:x:1:" "bin:x:2:" "sys:x:3:" \
        "sudo:x:27:" "users:x:100:" "nogroup:x:65534:" ;;
    /etc/sudoers|/etc/sudoers.d/*)
      printf '%s\n' "root    ALL=(ALL:ALL) ALL" \
        'Defaults    secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' ;;
    /etc/os-release)
      printf '%s\n' "NAME=\"${DISGUISE_DISTRIB}\"" "VERSION=\"${DISGUISE_RELEASE}\"" \
        "ID=${DISGUISE_CODENAME}" "PRETTY_NAME=\"${DISGUISE_DISTRIB} ${DISGUISE_RELEASE}\"" ;;
    /etc/lsb-release)
      printf '%s\n' "DISTRIB_ID=${DISGUISE_CODENAME}" "DISTRIB_RELEASE=22.04" \
        "DISTRIB_DESCRIPTION=\"${DISGUISE_DISTRIB} ${DISGUISE_RELEASE}\"" ;;
    /etc/hostname)   echo "$DISGUISE_HOSTNAME" ;;
    /etc/hosts)      printf '127.0.0.1\tlocalhost\n127.0.1.1\t%s\n::1\t\tlocalhost\n' "$DISGUISE_HOSTNAME" ;;
    /etc/resolv.conf) printf 'nameserver 8.8.8.8\nnameserver 8.8.4.4\n' ;;
    /etc/environment) printf 'PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"\nLANG=en_US.UTF-8\n' ;;
    /etc/motd)
      printf 'Welcome to %s %s (GNU/Linux %s %s)\n\n  System load:  0.08\n  Usage of /:   24.7%% of 58.42GB\n  Memory usage: 31%%\n  IPv4 address for eth0: %s\n' \
        "$DISGUISE_DISTRIB" "$DISGUISE_RELEASE" "$__REAL_KERNEL" "$__REAL_ARCH" "$__REAL_IP" ;;

    # ── /proc 状态/身份 ──
    /proc/[0-9]*/status|/proc/self/status|/proc/$$/status|/proc/[0-9]*/attr/current|/proc/self/attr/current|/proc/$$/attr/current)
      case "$_f" in
        */attr/current) echo "$DISGUISE_SELINUX_CTX" ;;
        */status)
          local _pid; _pid=$(echo "$_f" | sed 's|/proc/\([0-9]*\)/.*|\1|')
          printf '%s\n' "Name:\tbash" "Tgid:\t${_pid}" "Pid:\t${_pid}" \
            "PPid:\t1" "TracerPid:\t0" "Uid:\t0\t0\t0\t0" "Gid:\t0\t0\t0\t0" \
            "FDSize:\t256" "Groups:\t0 " "Threads:\t1" \
            "CapPrm:\t0000003fffffffff" "CapEff:\t0000003fffffffff" ;;
      esac ;;
    /proc/[0-9]*/environ|/proc/self/environ|/proc/$$/environ)
      printf 'HOME=/root\x00USER=root\x00SHELL=/bin/bash\x00' ;;
    /proc/[0-9]*/cmdline|/proc/self/cmdline|/proc/$$/cmdline)
      printf 'bash\x00' ;;
    /proc/[0-9]*/comm|/proc/self/comm|/proc/$$/comm)
      echo "bash" ;;

    # ── /proc 系统信息 ──
    /proc/meminfo)
      printf '%s\n' "MemTotal:        3933056 kB" "MemFree:         1867264 kB" \
        "MemAvailable:    2411264 kB" "Buffers:          123456 kB" \
        "Cached:           665088 kB" "SwapTotal:       2097152 kB" "SwapFree:        2096128 kB" ;;
    /proc/cpuinfo)
      printf '%s\n' "processor\t: 0" "model name\t: ARMv8 Processor rev 4 (v8l)" \
        "BogoMIPS\t: 48.00" "Features\t: fp asimd evtstrm aes pmull sha1 sha2 crc32" \
        "CPU implementer\t: 0x51" "CPU architecture: 8" ;;
    /proc/version)    echo "$DISGUISE_KERNEL" ;;
    /proc/loadavg)    printf '0.08 0.03 0.01 1/500 1\n' ;;
    /proc/uptime)     printf '3686400.00 7372800.00\n' ;;
    /proc/stat)
      printf '%s\n' "cpu  12345 0 5678 90123 0 0 0 0 0 0" \
        "cpu0 12345 0 5678 90123 0 0 0 0 0 0" \
        "ctxt 0" "btime 1700000000" "processes 1000" "procs_running 1" ;;
    /proc/filesystems)
      printf '%s\n' "nodev\tsysfs" "nodev\ttmpfs" "nodev\tproc" \
        "nodev\tdevpts" "\text4" "\tvfat" ;;
    /proc/diskstats)
      printf '%s\n' " 259    0 sda 42865 3120 1548232 12340 5214 8765 570624 45670 0 8760 57010" ;;

    # ── /proc 挂载 ──
    /proc/mounts|/proc/self/mounts|/proc/[0-9]*/mounts)
      printf '%s\n' "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)" \
        "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)" \
        "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)" \
        "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=816840k,mode=755)" \
        "selinuxfs on /sys/fs/selinux type selinuxfs (rw,nosuid,nodev,noexec,relatime)" ;;
    /proc/[0-9]*/mountinfo|/proc/self/mountinfo|/proc/$$/mountinfo)
      printf '%s\n' "1 0 259:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw" \
        "2 1 0:18 / /proc rw,nosuid,nodev - proc proc rw" ;;

    # ── /proc 内存映射 ──
    /proc/[0-9]*/maps|/proc/self/maps|/proc/$$/maps)
      printf '%s\n' "00400000-00480000 r-xp 00000000 fd:01 131072   /usr/bin/bash" \
        "7f8b00000-7f8b06000 r-xp 00000000 fd:01 131080   /usr/lib/x86_64-linux-gnu/libc.so.6" \
        "7ffc80000-7ffc90000 rw-p 00000000 00:00 0        [stack]" ;;

    # ── /proc 网络 ──
    /proc/net/tcp|/proc/net/tcp6|/proc/net/udp|/proc/net/udp6)
      printf '%s\n' "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode" \
        "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345" \
        "   1: ${__REAL_IP//./ }:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346" ;;
    /proc/net/dev)
      printf '%s\n' "Inter-|   Receive                                                |  Transmit" \
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo frame compressed" \
        "    lo: 1234567    8765    0    0    0     0          0         0  1234567    8765    0    0    0     0       0" \
        "  eth0: 31649988  42865    0    0    0     0          0         0 2154321  15234    0    0    0     0       0" ;;
    /proc/net/if_inet6)
      printf '%s\n' "    lo 00000000000000000000000000000001 00 00 00 00       1" ;;

    # ── 未知 /proc → 拦截全部，不放行 ──
    /proc/*)
      return 0 ;;

    # ── 其他文件：放行 ──
    *)
      command cat "$@" 2>/dev/null || return 0 ;;
  esac
}

# ── head / tail（拦截 /proc 读取）─────────────────────────────────
__root_head() {
  local _n=10 _proc=""
  for _a in "$@"; do
    case "$_a" in
      -n) shift; _n="${1:-10}"; shift; continue ;;
      -[0-9]*) _n="${_a#-}" ;;
      /proc/*) _proc="$_a" ;;
    esac
  done
  if [ -n "$_proc" ]; then
    __root_cat "$_proc" 2>/dev/null | head -n "$_n"
  else
    command head "$@" 2>/dev/null || true
  fi
}
__root_tail() {
  local _n=10 _proc=""
  for _a in "$@"; do
    case "$_a" in
      -n) shift; _n="${1:-10}"; shift; continue ;;
      -[0-9]*) _n="${_a#-}" ;;
      /proc/*) _proc="$_a" ;;
    esac
  done
  if [ -n "$_proc" ]; then
    __root_cat "$_proc" 2>/dev/null | tail -n "$_n"
  else
    command tail "$@" 2>/dev/null || true
  fi
}

# ── grep（拦截 /proc 读取）────────────────────────────────────────
__root_grep() {
  local _has_proc=false
  for _a in "$@"; do [ "$_a" = "/proc" ] || echo "$_a" | grep -q '^/proc/' && _has_proc=true; done
  if $_has_proc; then
    command grep "$@" 2>/dev/null | grep -v 'u0_a\|termux\|com\.termux\|untrusted_app\|app_data' || true
  else
    command grep "$@" 2>/dev/null || true
  fi
}

# ── ls 拦截（零泄漏）─────────────────────────────────────────────
__root_ls() {
  local _l=false _Z=false _a=false _h=false
  local _targets=() _raw_args=("$@")
  for _arg in "$@"; do
    case "$_arg" in
      -*) echo "$_arg" | grep -q 'l' && _l=true
          echo "$_arg" | grep -q 'Z' && _Z=true
          echo "$_arg" | grep -q 'a' && _a=true
          echo "$_arg" | grep -q 'h' && _h=true ;;
      *)  _targets+=("$_arg") ;;
    esac
  done
  [ ${#_targets[@]} -eq 0 ] && _targets+=(".")

  local _ctx="$DISGUISE_SELINUX_OBJ"
  $_Z && _ctx="$DISGUISE_SELINUX_CTX"
  local _date; _date=$(date '+%b %d %H:%M' 2>/dev/null || echo 'Jan 01 00:00')

  for _t in "${_targets[@]}"; do
    case "$_t" in
      # ── 根目录：必须伪造（Android 无权读 /）──
      /)
        printf 'total 128\n'
        printf 'drwxr-xr-x %d root root 4096 %s /\n' "$_date" "$_date" 2>/dev/null
        printf 'drwxr-xr-x 1 root root 4096 %s /bin\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /boot\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /dev\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /etc\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /home\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /lib\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /lib64\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /media\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /mnt\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /opt\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /proc\n' "$_date"
        printf 'drwx------ 1 root root 4096 %s /root\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /run\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /sbin\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /srv\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /sys\n' "$_date"
        printf 'drwxrwxrwt 1 root root 4096 %s /tmp\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /usr\n' "$_date"
        printf 'drwxr-xr-x 1 root root 4096 %s /var\n' "$_date"
        ;;
      # ── /proc 目录：伪造进程列表 ──
      /proc)
        printf 'total 0\n'
        printf 'dr-xr-xr-x 1 root root 0 %s 1\n' "$_date"
        printf 'dr-xr-xr-x 1 root root 0 %s 2\n' "$_date"
        printf 'dr-xr-xr-x 1 root root 0 %s %d\n' "$_date" "$$"
        ;;
      # ── /root 目录 ──
      /root)
        printf 'total 64\n'
        printf '-rw------- 1 root root  220 Jan  1  00:00 .bash_logout\n'
        printf '-rw------- 1 root root 3771 Jan  1  00:00 .bashrc\n'
        printf '-rw------- 1 root root  807 Jan  1  00:00 .profile\n'
        printf 'drwx------ 1 root root 4096 %s .ssh\n' "$_date"
        ;;
      # ── 普通目录：用真实 ls 但替换用户名和 context ──
      *)
        if [ -d "$_t" ]; then
          local _cmd="command ls -l"
          $_a && _cmd="command ls -la"
          $_Z && _cmd="${_cmd}Z"
          eval "$_cmd" "'$_t'" 2>/dev/null | \
            sed -e "s/ ${__REAL_USER} / root /g" \
                -e "s/ ${__REAL_USER}:/ root:/g" \
                -e "s/:${__REAL_USER} /:root /g" \
                -e "s/:[0-9]*(${__REAL_USER})/:0(root)/g" \
                -e "s/u0_a[0-9]*/root/g" \
                -e "s/u:object_r:app_data_file[^ ]*/${_ctx}/g" \
                -e "s/u:r:untrusted_app[^ )]*/${_ctx}/g" \
                -e "s/u:object_r:system_app[^ ]*/${_ctx}/g" \
                -e "s/u:object_r:vendor_app[^ ]*/${_ctx}/g" || \
            command ls -la "$_t" 2>/dev/null | \
            sed -e "s/${__REAL_USER}/root/g" -e "s/u0_a[0-9]*/root/g" || true
        elif [ -f "$_t" ]; then
          # 文件：伪造 ls -l
          local _perm="-rw-r--r--" _size="4096"
          case "$_t" in
            /etc/shadow) _perm="-rw-r-----"; _size="567" ;;
            /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) _perm="-rwxr-xr-x" ;;
            *.sh) _perm="-rwxr-xr-x"; _size="8192" ;;
          esac
          if $_Z; then
            printf '%s 1 root root %s %s %s %s\n' "$_perm" "$DISGUISE_SELINUX_OBJ" "$_size" "$_date" "$_t"
          else
            printf '%s 1 root root %s %s %s\n' "$_perm" "$_size" "$_date" "$_t"
          fi
        elif [ -e "$_t" ]; then
          local _perm="-rw-r--r--"
          [ -x "$_t" ] && _perm="-rwxr-xr-x"
          if $_Z; then
            printf '%s 1 root root %s %s %s %s\n' "$_perm" "$DISGUISE_SELINUX_OBJ" "4096" "$_date" "$_t"
          else
            printf '%s 1 root root %s %s %s\n' "$_perm" "4096" "$_date" "$_t"
          fi
        else
          echo "ls: cannot access '$_t': No such file or directory" >&2
        fi
        ;;
    esac
  done
}

# ── stat 拦截 ────────────────────────────────────────────────────
__root_stat() {
  local _f="" _has_c=false _raw=false
  for _a in "$@"; do
    case "$_a" in
      -c|-C) _has_c=true ;;
      --format=*) _has_c=true ;;
      -f) _raw=true ;;
      -L) continue ;;
      /proc/*) _f="$_a"; break ;;
      /etc/*|/var/*|/usr/*|/bin/*|/sbin/*|/root/*) _f="$_a" ;;
      /*) _f="$_a" ;;
    esac
  done

  if $_raw || [ -z "$_f" ]; then
    command stat "$@" 2>/dev/null || true; return
  fi

  local _mode="0644" _size=1234
  case "$_f" in
    /etc/shadow) _mode="0640"; _size=567 ;;
    /etc/passwd|/etc/group) _mode="0644"; _size=1234 ;;
    /bin/*|/sbin/*|/usr/bin/*|/usr/sbin/*) _mode="0755"; _size=4096 ;;
    *) _mode="0644"; _size=4096 ;;
  esac
  local _mtime; _mtime=$(date '+%Y-%m-%d %H:%M:%S.000000000 +0800' 2>/dev/null || echo '2024-01-01 00:00:00.000000000 +0800')
  local _ino=$((RANDOM % 99999 + 10000))

  if $_has_c; then
    printf '%s root root %s %s - %s 1 0 0\n' "$_f" "$_size" "$_mtime" "$_mode"
  else
    printf '  File: %s\n  Size: %-10d  Blocks: %-8d  IO Block: 4096   regular file\n' "$_f" "$_size" "$((_size/512+1))"
    printf 'Device: 253,5\tInode: %-10d  Links: 1\n' "$_ino"
    printf 'Access: (%s)  Uid: (    0/    root)   Gid: (    0/    root)\n' "$_mode"
    printf 'Context: %s\n' "$DISGUISE_SELINUX_OBJ"
    printf 'Access: %s\nModify: %s\nChange: %s\n' "$_mtime" "$_mtime" "$_mtime"
  fi
}

# ── uname ──────────────────────────────────────────────────────────
__root_uname() {
  [ $# -eq 0 ] && { echo "Linux"; return; }
  local _all=false _s=false _n=false _r=false _v=false _m=false _o=false
  while [ $# -gt 0 ]; do
    case "$1" in
      -a|--all) _all=true ;; -s|--sysname) _s=true ;;
      -n|--nodename) _n=true ;; -r|--release) _r=true ;;
      -v|--version) _v=true ;; -m|--machine) _m=true ;;
      -o|--operating-system) _o=true ;;
    esac; shift
  done
  $_all && { echo "$DISGUISE_KERNEL"; return; }
  local _o=""
  $_s && _o="Linux"; $_n && _o="${_o:+$_o }${DISGUISE_HOSTNAME}"
  $_r && _o="${_o:+$_o }5.15.0-generic"; $_v && _o="${_o:+$_o }#1 SMP Ubuntu 22.04.3"
  $_m && _o="${_o:+$_o }aarch64"; $_o_f && _o="${_o:+$_o }GNU/Linux"
  echo "${_o:-Linux}"
}

# ── sudo ───────────────────────────────────────────────────────────
__root_sudo() {
  case " $* " in
    *" -l "*|*"--list"*) printf 'User root may run the following commands on %s:\n    (ALL : ALL) ALL\n' "$DISGUISE_HOSTNAME" ;;
    *" -k "*|*"--reset-timestamp"*) true ;;
    *) eval "$@" 2>/dev/null || true ;;
  esac
}

# ── ps ──────────────────────────────────────────────────────────────
__root_ps() {
  local _all=false _Z=false
  for _a in "$@"; do
    case "$_a" in
      a|A|x|-|ef|aux|ax|axu|eZ) _all=true ;;
      Z) _Z=true ;;
      -*) echo "$_a" | grep -q '[eax]' && _all=true ;;
    esac
  done
  [ $# -eq 0 ] && _all=true
  if $_all || $_Z; then
    local _ctx="$DISGUISE_SELINUX_CTX"
    if $_Z; then
      printf '%-30s %-10s %5s %5s %7s %7s %5s %s\n' "LABEL" "USER" "PID" "%CPU" "%MEM" "VSZ" "RSS" "COMMAND"
      printf '%-30s %-10s %5d %5s %5s %7d %7d %5s %s\n' "$_ctx" "root" 1 "0.0" "0.1" 168988 11564 "Ss" "/sbin/init"
      printf '%-30s %-10s %5d %5s %5s %7d %7d %5s %s\n' "$_ctx" "root" 234 "0.0" "0.0" 12345 5678 "Ss" "/usr/sbin/sshd"
      printf '%-30s %-10s %5d %5s %5s %7d %7d %5s %s\n' "$_ctx" "root" "$$" "0.0" "0.0" 15360 5120 "Ss" "${DISGUISE_SHELL}"
    else
      printf '%-10s %5s %5s %7s %7s %5s %s\n' "USER" "PID" "%CPU" "%MEM" "VSZ" "RSS" "COMMAND"
      printf '%-10s %5d %5s %5s %7d %7d %5s %s\n' "root" 1 "0.0" "0.1" 168988 11564 "Ss" "/sbin/init"
      printf '%-10s %5d %5s %5s %7d %7d %5s %s\n' "root" 234 "0.0" "0.0" 12345 5678 "Ss" "/usr/sbin/sshd"
      printf '%-10s %5d %5s %5s %7d %7d %5s %s\n' "root" "$$" "0.0" "0.0" 15360 5120 "Ss" "${DISGUISE_SHELL}"
    fi
  else
    command ps "$@" 2>/dev/null | sed "s/${__REAL_USER}/root/g; s/u0_a[0-9]*/root/g" || true
  fi
}

# ── mount / df / free ────────────────────────────────────────────
__root_mount() {
  printf '%s\n' \
    "/dev/sda1 on / type ext4 (rw,relatime,errors=remount-ro)" \
    "proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)" \
    "sysfs on /sys type sysfs (rw,nosuid,nodev,noexec,relatime)" \
    "tmpfs on /run type tmpfs (rw,nosuid,nodev,noexec,relatime,size=816840k,mode=755)" \
    "tmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)" \
    "/dev/sda2 on /home type ext4 (rw,relatime)" \
    "tmpfs on /tmp type tmpfs (rw,nosuid,nodev,relatime,size=1634248k)" \
    "selinuxfs on /sys/fs/selinux type selinuxfs (rw,nosuid,nodev,noexec,relatime)"
}
__root_df() {
  printf '%-23s %-8s %-8s %-8s %-6s %s\n' "Filesystem" "Size" "Used" "Avail" "Use%" "Mounted on"
  printf '%-23s %-8s %-8s %-8s %-6s %s\n' "/dev/sda1" "58G" "14G" "41G" "26%" "/"
  printf '%-23s %-8s %-8s %-8s %-6s %s\n' "tmpfs" "798M" "4.0K" "798M" "1%" "/run"
}
__root_free() {
  printf '%s\n' "               total        used        free      shared  buff/cache   available" \
    "Mem:          3841        1247        1823          32         770        2354" \
    "Swap:         2048          12        2036"
}

# ── 网络 ──────────────────────────────────────────────────────────
__root_netstat() {
  printf 'Active Internet connections (servers and established)\n'
  printf 'Proto Recv-Q Send-Q Local Address           Foreign Address         State\n'
  printf 'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n'
  printf 'tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n'
  printf 'tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\n'
  printf 'tcp        0      0 %s:22            10.0.2.2:54321          ESTABLISHED\n' "$__REAL_IP"
}
__root_ss() {
  printf 'State    Recv-Q    Send-Q       Local Address:Port       Peer Address:Port\n'
  printf 'LISTEN   0         128          0.0.0.0:22               0.0.0.0:*\n'
  printf 'LISTEN   0         511          0.0.0.0:80               0.0.0.0:*\n'
  printf 'LISTEN   0         4096         0.0.0.0:443              0.0.0.0:*\n'
}
__root_ifconfig() {
  printf '%s\n' \
    "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500" \
    "        inet ${__REAL_IP}  netmask 255.255.255.0  broadcast 10.0.2.255" \
    "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)" "" \
    "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536" \
    "        inet 127.0.0.1  netmask 255.0.0.0"
}
__root_ip() {
  case " $* " in
    *" addr "*|*" a "*|"")
      printf '%s\n' \
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN" \
        "    inet 127.0.0.1/8 scope host lo" \
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP" \
        "    link/ether 08:00:27:4e:66:a1 brd ff:ff:ff:ff:ff:ff" \
        "    inet ${__REAL_IP}/24 brd 10.0.2.255 scope global eth0" ;;
    *" route "*|*" r "*)
      printf '%s\n' "default via 10.0.2.2 dev eth0 proto dhcp metric 100" \
        "10.0.2.0/24 dev eth0 proto kernel scope link src ${__REAL_IP} metric 100" ;;
    *) command ip "$@" 2>/dev/null | sed "s/${__REAL_USER}/root/g; s/u0_a[0-9]*/root/g" || true ;;
  esac
}

# ── 登录记录 ──────────────────────────────────────────────────────
__root_w() {
  local _t; _t=$(date '+%H:%M:%S' 2>/dev/null || echo 12:00:00)
  printf '%-8s %-9s %-16s %-8s %-5s %-6s %s\n' "USER" "TTY" "FROM" "LOGIN@" "IDLE" "JCPU" "PCPU"
  printf '%-8s %-9s %-16s %-8s %-5s %-6s %s\n' "root" "pts/0" "10.0.2.2" "$_t" "0.00s" "3.12s" "0.01s"
  echo ""
  echo "  up 42 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01"
}
__root_who() {
  local _d; _d=$(date '+%Y-%m-%d %H:%M' 2>/dev/null || echo '2024-01-01 12:00')
  printf '%-12s pts/0        %s\n' "root" "$_d"
}
__root_last() {
  local _d1; _d1=$(date '+%Y-%m-%d %H:%M' 2>/dev/null || echo '2024-01-01 12:00')
  printf '%-12s pts/0        10.0.2.2      %s - %s (00:15)\n' "root" "$_d1" "$_d1"
  printf '\nwtmp begins Jan  1  2024 12:00\n'
}
__root_lastb() {
  printf '%-16s pts/0        10.0.2.2      2024-01-01 02:30 - 2024-01-01 02:32 (00:02)\n' "hacker"
}
__root_uptime() { echo "  up 42 days,  3:21,  1 user,  load average: 0.08, 0.03, 0.01"; }
__root_crontab() {
  case " $* " in
    *"-l "*)
      printf '%s\n' "# m h  dom mon dow   user  command" \
        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly" ;;
    *) command crontab "$@" 2>/dev/null || true ;;
  esac
}

# ── getent ──────────────────────────────────────────────────────────
__root_getent() {
  case "${1:-}" in
    passwd) __root_cat /etc/passwd ;;
    shadow) __root_cat /etc/shadow ;;
    group)  __root_cat /etc/group ;;
    hosts)  printf '127.0.0.1\tlocalhost\n127.0.1.1\t%s\n::1\t\tlocalhost\n' "$DISGUISE_HOSTNAME" ;;
    *) command getent "$@" 2>/dev/null || true ;;
  esac
}

# ── chown / chmod / passwd ────────────────────────────────────────
__root_chown() { echo "chown: changed ownership of '$(echo "$@" | awk '{print $NF}')': root:root"; }
__root_chmod() { echo "chmod: changed permissions of '$(echo "$@" | awk '{print $NF}')'"; }
__root_passwd_cmd() {
  case " $* " in
    *" -S "*|*" --status "*) echo "root P 01/01/2024 0 99999 7 -1" ;;
    *) echo "passwd: no password was set" ;;
  esac
}

# ── which / type（隐藏 terhijack 痕迹）────────────────────────────
__root_which() {
  local _c="${1:-}"; case "$_c" in
    terhijack|__root_*|__thj_*) echo "${_c}: not found" ;;
    *) command which "$@" 2>/dev/null || echo "${_c}: not found" ;;
  esac
}
__root_type() {
  local _c="${1:-}"; case "$_c" in
    terhijack|__root_*|__thj_*) echo "bash: type: ${_c}: not found" ;;
    id|whoami|logname) printf '%s is /usr/bin/%s\n' "$_c" "$_c" ;;
    *) command type "$@" 2>/dev/null || echo "bash: type: ${_c}: not found" ;;
  esac
}

# ── find（隐藏 terhijack 痕迹）────────────────────────────────────
__root_find() {
  command find "$@" 2>/dev/null | grep -v 'terhijack\|__root_\|__thj_' || command find "$@" 2>/dev/null || true
}

# ── history ─────────────────────────────────────────────────────────
__root_history() {
  echo "    1  $(date -d '2 hours ago' '+%Y-%m-%d %H:%M' 2>/dev/null) sudo apt update"
  echo "    2  $(date -d '1 hours ago' '+%Y-%m-%d %H:%M' 2>/dev/null) sudo apt upgrade -y"
  echo "    3  $(date '+%Y-%m-%d %H:%M' 2>/dev/null) whoami"
}


# ╔══════════════════════════════════════════════════════════════╗
# ║                       设 置 Hooks                           ║
# ╚══════════════════════════════════════════════════════════════╝

echo "[*] Setting up disguise hooks..."

# ── 身份 ──────────────────────────────────────────────────────────
hijack -c "whoami"   -o "root"
hijack -c "id"       -a -r "__root_id"
hijack -c "logname"  -o "root"
hijack -c "groups"   -o "root"

# ── 文件读取（核心）──────────────────────────────────────────────
hijack -c "cat"      -a -r "__root_cat"
hijack -c "head"     -a -r "__root_head" 2>/dev/null || true
hijack -c "tail"     -a -r "__root_tail" 2>/dev/null || true
hijack -c "grep"     -a -r "__root_grep" 2>/dev/null || true

# ── SELinux ───────────────────────────────────────────────────────
hijack -c "getenforce"   -r "__root_getenforce" 2>/dev/null || hijack -c "getenforce" -o "Enforcing"
hijack -c "sestatus"     -r "__root_sestatus" 2>/dev/null || true
hijack -c "chcon"        -a -r "__root_chcon" 2>/dev/null || true
hijack -c "setenforce"   -r "__root_setenforce" 2>/dev/null || true
hijack -c "matchpathcon" -a -r "__root_matchpathcon" 2>/dev/null || true
hijack -c "seinfo"       -r "__root_seinfo" 2>/dev/null || true

# ── 系统信息 ──────────────────────────────────────────────────────
hijack -c "hostname"  -o "$DISGUISE_HOSTNAME"
hijack -c "uname"     -a -r "__root_uname"
hijack -c "uptime"    -r "__root_uptime"

# ── 文件操作 ──────────────────────────────────────────────────────
hijack -c "stat"      -a -r "__root_stat"
hijack -c "getent"    -a -r "__root_getent" 2>/dev/null || true
hijack -c "chown"     -a -r "__root_chown" 2>/dev/null || true
hijack -c "chmod"     -a -r "__root_chmod" 2>/dev/null || true

# ── 权限 ──────────────────────────────────────────────────────────
hijack -c "sudo"      -a -r "__root_sudo"
hijack -c "passwd"    -a -r "__root_passwd_cmd" 2>/dev/null || true

# ── 网络 ──────────────────────────────────────────────────────────
hijack -c "netstat"   -r "__root_netstat" 2>/dev/null || true
hijack -c "ss"        -r "__root_ss" 2>/dev/null || true
hijack -c "ifconfig"  -r "__root_ifconfig" 2>/dev/null || true
hijack -c "ip"        -a -r "__root_ip" 2>/dev/null || true

# ── 进程 / 系统状态 ──────────────────────────────────────────────
hijack -c "ps"        -a -r "__root_ps"
hijack -c "mount"     -r "__root_mount" 2>/dev/null || true
hijack -c "df"        -r "__root_df" 2>/dev/null || true
hijack -c "free"      -r "__root_free" 2>/dev/null || true
hijack -c "crontab"   -a -r "__root_crontab" 2>/dev/null || true

# ── ls 拦截 ───────────────────────────────────────────────────────
hijack -c "ls"        -a -r "__root_ls"

# ── 登录记录 ──────────────────────────────────────────────────────
hijack -c "w"         -r "__root_w" 2>/dev/null || true
hijack -c "who"       -r "__root_who" 2>/dev/null || true
hijack -c "last"      -r "__root_last" 2>/dev/null || true
hijack -c "lastb"     -r "__root_lastb" 2>/dev/null || true
hijack -c "history"   -r "__root_history" 2>/dev/null || true

# ── 反取证 ─────────────────────────────────────────────────────────
hijack -c "which"     -a -r "__root_which" 2>/dev/null || true
hijack -c "type"      -a -r "__root_type" 2>/dev/null || true
hijack -c "find"      -a -r "__root_find" 2>/dev/null || true

# ── Shell 环境伪装 ────────────────────────────────────────────────
export HOME="/root"
export USER="root"
export LOGNAME="root"
export SHELL="$DISGUISE_SHELL"
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
export HISTFILE="/root/.bash_history"
export HISTSIZE=1000
export MAIL="/var/mail/root"
export PWD="/root"

if [ -n "${BASH_VERSION:-}" ]; then
  PS1='\[\033[01;31m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]# '
elif [ -n "${KSH_VERSION:-}" ] || [ -n "${__KSH_VERSION__:-}" ]; then
  PS1='$LOGNAME@${DISGUISE_HOSTNAME}:${PWD}# '
else
  PS1='# '
fi
export PS1

# ── 隐藏 terhijack 痕迹 ──────────────────────────────────────────
unset __THJ_BIN THJ_STATE_FILE THJ_SHELL 2>/dev/null || true

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "  ROOT DISGUISE ACTIVE"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "  $(id)"
echo "  context: $(id -Z 2>/dev/null || echo "$DISGUISE_SELINUX_CTX")"
echo "  kernel: $(uname -a)"
echo "  prompt: # (root style)"
echo "  getenforce: $(getenforce 2>/dev/null || echo Enforcing)"
echo ""
echo "  Commands hooked: whoami id logname groups hostname"
echo "                    uname uptime getenforce sestatus chcon"
echo "                    cat head tail grep stat getent sudo passwd chown chmod"
echo "                    ps ls mount df free netstat ss ifconfig ip"
echo "                    w who last lastb crontab which type find"
echo "                    history"
echo ""
echo "  To restore: hijack --clear"
echo "═══════════════════════════════════════════════════════════"
