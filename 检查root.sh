#!/system/bin/sh
# ============================================================
#  root 方案识别器  identify_root.sh
#  覆盖：Magisk / KernelSU / APatch / KernelPatch /
#        SuperSU / LineageOS su / phh-su / ADB root
#  在 Termux + su 环境下运行
# ============================================================

line() { echo "----------------------------------------"; }
sec()  { echo; echo "########## $* ##########"; }

# 保存 su 子进程视角的输出
S() { su -c "$1" 2>&1; }

sec "1. 基础信息"
echo "Termux 用户：$(id -un 2>/dev/null)   uid=$(id -u 2>/dev/null)"
echo "内核：$(uname -a)"
echo "Android：$(getprop ro.build.version.release) / SDK $(getprop ro.build.version.sdk)"
echo "机型：$(getprop ro.product.model)  厂商：$(getprop ro.product.manufacturer)"
echo "Bootloader 锁：$(getprop ro.boot.flash.locked)  verifiedboot：$(getprop ro.boot.verifiedbootstate)"
echo "Build 类型：$(getprop ro.build.type)  ro.debuggable=$(getprop ro.debuggable)"

sec "2. su 子进程真实身份"
echo "[uid/gid/context]"
S 'id'
echo
echo "[进程名与父进程]"
S 'cat /proc/$$/status | grep -E "^Name|^PPid|^Uid|^Gid"'
echo
echo "[父进程是什么]"
PPPID=$(S 'cat /proc/$$/status' | awk '/^PPid/{print $2}')
if [ -n "$PPPID" ]; then
  S "cat /proc/$PPPID/cmdline 2>/dev/null | tr '\\0' ' '"
  echo
  S "cat /proc/$PPPID/status 2>/dev/null | grep -E '^Name|^PPid'"
fi
echo
echo "[su 可执行文件真实路径]"
S 'readlink -f /proc/$$/exe'
S 'ls -la /proc/$$/exe'

sec "3. 已知 root 方案目录扫描"
for d in \
  /data/adb \
  /data/adb/magisk \
  /data/adb/modules \
  /data/adb/ksu \
  /data/adb/ap \
  /data/adb/kpatch \
  /data/kpatch \
  /data/magisk \
  /sbin/.magisk \
  /sbin/ksu \
  /sbin/ap \
  /debug_ramdisk \
  /cache/magisk \
  /cache/kpatch
do
  R=$(S "ls -d $d 2>/dev/null")
  [ -n "$R" ] && echo "  存在：$d"
done
echo "(以上无输出=这些目录都不存在)"

sec "4. root 管理命令扫描"
for c in magisk magiskpolicy ksud apd ap kpatch kp su supolicy resetprop; do
  P=$(S "command -v $c 2>/dev/null")
  [ -n "$P" ] && echo "  $c → $P"
done
echo "(以上无输出=命令都不在 PATH)"

sec "5. 内核模块与 sysfs"
echo "[/proc/modules 匹配]"
S 'grep -iE "kpatch|kernelsu|apatch|magisk|superuser|supersu" /proc/modules 2>/dev/null'
echo "[sys/module 匹配]"
S 'ls /sys/module 2>/dev/null' | grep -iE 'kpatch|kernelsu|apatch|magisk|superuser|supersu'
echo "[内核符号]"
S 'grep -iE "kpatch|kernelsu|apatch|magisk" /proc/kallsyms 2>/dev/null | head -10'

sec "6. 挂载痕迹"
S 'cat /proc/self/mountinfo' | grep -iE 'magisk|ksu|kpatch|apatch|overlay|worker|supersu|kpatch' | head -20
echo "(以上无输出=无相关挂载)"

sec "7. SELinux 状态"
S 'getenforce'
S 'cat /sys/fs/selinux/enforce'
S 'cat /proc/self/attr/current'
echo "[策略版本]"
S 'cat /sys/fs/selinux/policyvers 2>/dev/null'

sec "8. 属性线索"
getprop 2>/dev/null | grep -iE 'magisk|ksu|kpatch|apatch|shamiko|zygisk|supersu|root' | head -20
echo "(以上无输出=属性里无痕迹)"

sec "9. su 二进制搜索（多个可能位置）"
S 'for p in /system/bin/su /system/xbin/su /sbin/su /vendor/bin/su /debug_ramdisk/su /data/adb/magisk/su /data/adb/ksu/bin/su /data/adb/ap/bin/su /system/bin/tsu; do [ -e "$p" ] && ls -laZ "$p"; done'
echo "(以上无输出=这些位置都没有 su)"

sec "10. remount 能力实测"
echo "[/system 当前挂载]"
S 'mount | grep " /system "'
echo "[测试写 /system]"
TESTF="/system/etc/.rt_$$"
R=$(S "echo t > $TESTF 2>&1 && rm -f $TESTF && echo WRITABLE")
echo "  结果：$R"

sec "11. 时间与启动"
S 'uptime'
S 'cat /proc/cmdline'

line
echo "识别提示："
echo "  · /data/adb 或 magiskd  → Magisk 系"
echo "  · ksud / kernelsu 模块  → KernelSU"
echo "  · apd / apatch 模块     → APatch"
echo "  · kpatch 命令/模块      → KernelPatch（无 /data/adb）"
echo "  · 只 adbd，无内核痕迹   → ADB root"
echo "  · 无任何管理命令但能 remount → 内核级方案或手动改域"
line