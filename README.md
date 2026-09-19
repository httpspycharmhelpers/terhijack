# TerHijack

> 会话级终端命令劫持 / 身份伪装引擎 — 劫持程度远不止"改一行输出"
> Per-session command hijacker & identity disguiser for Android/Termux (bash)
> 仅供安全研究 / 教育 / 渗透测试使用 · 请勿用于非法用途

TerHijack 不是一个只能 `-o "假输出"` 的小玩具。它是一套**分层伪装引擎**：

- **核心引擎**（`terhijack` 二进制 + session 内函数遮蔽）提供任意命令的输出改写 / 命令替换 / 参数穿透 / 复合命令行全链劫持；
- **伪装套件**（`root_disguise.sh`）在它之上搭建"整个 root 环境"——身份、SELinux、进程、网络、文件系统全部伪造，并且**自我隐藏**；
- **合作层**（已并入 aFakeSU / 内嵌 proot）计划用 `ptrace` 系统调用拦截，让**非 shell 进程也绕不过**伪装。

---

## 核心引擎（`hijack` 命令）

### 劫持模式

| 模式 | 示例 | 效果 |
|------|------|------|
| `-o/--output` | `hijack -c "id -Z" -o "root"` | 改写命令的输出 |
| `-r/--recommand` | `hijack -c "whoami" -r "echo root"` | 透明地用另一条命令替代 |
| `-a/--arg` | `hijack -c "su" -r "mysu" -a` | **参数穿透**：调用者的参数原样追加给替换命令（前缀匹配） |
| 复合链 | `hijack -c "a && b && c" -r "echo x"` | **整条链劫持**：`&&` 短路中断、`\|\|` 短路跳过、`;` 兄弟段全部缴械 |
| `/` 列表 | `hijack -c "ls/pwd/id" -o "x"` | 一次注册多条命令 |

### 劫持的"程度"体现在哪

1. **参数感知**：同一命令按参数返回不同伪装。`-a` 前缀匹配让替换函数拿到**全部真实参数**，从而能做到 id 的 `-u -g -G -n -Z -z -a` 每个 flag 组合都返回精确伪造值。
2. **不误伤**：精确匹配只命中完全相同参数的命令；未被劫持的参数组合原样透传给真实二进制（`command ls`）。
3. **跨子进程**：通过导出函数 + 序列化状态串，子 bash 自动继承全部劫持，**状态随会话消亡**，开新会话即完全干净。
4. **复合命令行杀干净**：不是"显示假结果"而是**让真实命令根本不执行**——用分段函数遮蔽 + 返回码控制链式短路。
5. **能劫持自己**（慎用）：可对 `hijack`/任意内建下手，产生锁死管理入口 / 连环触发等深度行为（README 不赘述，见测试）。

### 快速上手

```bash
eval "$(terhijack --init)"                       # 每会话一次
hijack -c "id -Z" -o "root"                      # 改写输出
hijack -c "echo $$" -r "echo root"               # 命令替代
hijack -c "su" -r "mysu" -a                      # 替代 + 参数透传
hijack -c "cd / && rm f && echo ok" -r "echo x"  # 整链劫持
hijack -c "ls/pwd/id" -o "x"                     # 一次多个
hijack --list | hijack -x "cmd" | hijack --clear # 管理
```

---

## 伪装套件（`root_disguise.sh`）— 整个 root 环境

`root_disguise.sh` 一条命令把当前会话变成"伪装 root 机"。定位不是单命令，而是**整机一致性与自洽**：

- **身份自洽**
  - `id`：完整 GNU flag 支持（`-u -g -G -n -Z -z -a` 及 `-uG` 组合），统一输出 `uid=0(root)` + SELinux context
  - `whoami`/`logname`/`groups` 全部 `root`，环境变量 `HOME=/root USER=root SHELL=/bin/bash PATH` 全套改写，PS1 变成 root 风格的 `#`
- **文件系统伪装**
  - `cat` **按路径**返回对应内容：`/etc/os-release`、`/etc/hostname`、`/etc/hosts`、`/etc/resolv.conf`、`/etc/environment`、`/etc/motd` 各具其形
  - **/proc 深度伪造**：`/proc/*/status` 用真实 PID 动态生成 Uid/Gid 全 0、CapPrm/CapEff 全满、《TracerPid:0》；`/proc /*/attr/current` 返回伪装 SELinux context；`environ/cmdline/comm` 全部假造
  - `ls`/`stat` 改写文件 owner/权限视角；`head`/`tail`/`grep`/`getent` 透传过滤
- **SELinux**：`getenforce`→Enforcing，`sestatus`/`chcon`/`setenforce`/`matchpathcon`/`seinfo` 全套响应
- **系统与进程**：`hostname`/`uname`(内核+架构)、`uptime`、`ps`、`mount`、`df`、`free`、`netstat`、`ss`、`ifconfig`、`ip`
- **账户与管理**：`sudo`/`passwd`/`chown`/`chmod`/`crontab`/`w`/`who`/`last`/`lastb`/`history`(伪造一段 root 运维史)
- **自我隐藏**：`which`/`type`/`find` 主动滤掉 `terhijack`、`__root_*`、`__thj_*` 痕迹，同时输出 `id 是 /usr/bin/id` 之类的"正常"路径

共劫持 **40+ 命令**，覆盖身份→取证→网络→进程→文件→账户的完整可信链条。

```bash
bash root_disguise.sh     # 进一个"看起来是 root"的会话
id            # uid=0(root) ...
ls /root      # owner/权限全部 root 视角
cat /proc/1/status       # Uid: 0 0 0 0, CapEff 全满
type terhijack           # not found（痕迹已隐藏）
hijack --clear           # 一键还原
```

---

## 架构 / 原理

```
┌─ 会话层函数遮蔽 (bash) ───────────────────────────┐
│  hijack() 包装 → 二进制解析 → 输出声明式状态       │
│  __terhijack_dispatch: 精确/前缀(-a)匹配 →        │
│     out 假输出 | rec 替代(| 执行载荷) | 透传 command│
│  __terhijack_rebuild: unset 旧函数 → 重装遮蔽函数  │
│  __THJ_SER 序列化 + export -f → 子 bash 继承      │
└──────────────────────────────────────────────────┘
                 │ 载荷/替换函数
                 ▼
┌─ 伪装层 root_disguise.sh ─────────────────────────┐
│  40+ 命令的 __root_* 替换函数: 参数感知假输出      │
│  /proc 动态伪造、SELinux、环境变量、PS1、自隐藏    │
└──────────────────────────────────────────────────┘
                 │ 未来: 系统调用层
                 ▼
┌─ aFakeSU / proot (ptrace) ────────────────────────┐
│  拦截每个 syscall(execve/open/getuid...) 翻译路径 │
│  伪造返回值 → 非 shell 进程也绕不过              │
└──────────────────────────────────────────────────┘
```

技术要点：
- 会话级状态用 bash 数组 + `declare -p` 序列化在调用间传递；复合命令用**分段遮蔽 + 返回码链式短路**取代 DEBUG trap（无 extdebug 副作用，全链真实命令不执行）。
- 替换命令执行前**临时解除触发函数**，载荷内同名调用（如载荷里的 `echo`）走真实命令，避免自递归。
- 运行时自用计数等内建路径对 `echo`/`printf` 免疫（字数统计用纯参数展开），可安全劫持内建。

---

## 构建与测试

```bash
make            # cc -O2 -Wall -Wextra -std=c99 -> ./terhijack
make install    # 安装到 $PREFIX/bin/terhijack
bash test.sh    # 40 项功能断言
```

需要 bash ≥ 4（数组、`${!arr[@]}`）；zsh 下函数遮蔽可用，`-a` 与分段依赖 bash 扩展。

## 免责声明

非 root 设备的渗透训练玩具，仅供研究 / 教育 / 自用设备。Just for fun, don't use it illegally.