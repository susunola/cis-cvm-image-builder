# TOS4 构建问题链与全平台检查

> 记录 2026-08-08 TencentOS 4 构建从「reboot 后 SSH 永远连不上」到「镜像成功交付」的
> 完整修复链（v0.14.4 → v0.14.22），以及该问题链在其他 Linux profile 上的影响检查结论。

## 一、问题链总表

| 版本 | 症状 | 根因 | 修复 |
|---|---|---|---|
| v0.14.4 | apply 报 `No start of json char found`，模块 payload 丢失 | ansible-core ≥2.16 的模块 payload 缓存落在 `/tmp`，TOS4 的 /tmp 不可靠 | venv wrapper 导出 `TMPDIR=/opt/ciscvm-ansible/tmp` |
| v0.14.8 | reboot 后 SSH `i/o timeout` | guard 只在 apply 前跑；apply 重载 firewalld 后新 zone 无 SSH 放行 | reboot 前重跑 guard + 防火墙规则持久化（nft/iptables save） |
| v0.14.9 | reapply 报 `ssh-guard.sh: No such file` | Packer shell provisioner 默认删除上传的 inline 脚本 | `skip_clean = true` |
| v0.14.10 | 6 条「修了重审又失败」 | 5 类 bug：run_rule 不带 params / iptables→iptables-nft 别名 / rsyslog `$` 前缀 / sysctl 持久化取错优先级 / useradd_inactive 误解析 | 逐类修复 + 重审用同一 params |
| v0.14.14 | `packer` 解析报 `Missing item separator` | inline 列表缺逗号，Python 隐式拼接相邻字符串 | 补逗号 + 全量 inline 逗号回归测试 |
| v0.14.16 | 重连窗口只有 ~5 分钟 | 连接窗口由 `start_retry_timeout` 控制（默认几分钟），`max_retries` 只管命令执行；另 nft 遍历 `awk '{print $2}'` 取到 family 非表名 | `start_retry_timeout="25m"`；nft 改 `while read -r _ fam name` |
| v0.14.17 | reboot 后 i/o timeout 长达数十分钟 | SELinux disabled 启动留下 `/.autorelabel`；写 permissive 后下次启动全盘 relabel，卡在 sshd 之前 | reboot 前删除 `/.autorelabel`（permissive 无需 relabel，mark 服务只在 disabled 启动时重建） |
| v0.14.18 | reboot 后 `scp: /opt/... Read-only file system` | TOS4 fstab `/opt` 带 `ro`（运行时被 remount rw 掩盖，重启后生效） | guard 重写 fstab `/opt` 行去 ro + remount rw；post-reboot 上传改 `/root` |
| v0.14.19 | reboot 后 `/root` 也 Read-only | **整个根 fs ro**：SELinux 首次启用使 `systemd-remount-fs` 失败，根保持 ro 但 sshd 仍起来 | oneshot 在 sshd 前 `mount -o remount,rw /`；guard 修 fstab `/` 行 + VERIFY 根状态 |
| v0.14.20 | smoke `SMOKE FAIL: auditd not active` | auditd 是 L2（4.1.x），L1 不装；断言按「unit 文件存在」判断而 TOS4 自带 unit | 改 `is-enabled` 判断（启用才要求 active） |
| v0.14.21 | smoke 继续 FAIL（auditd/shm/journal 三个） | 「unit/文件存在 ≠ 应运行」：/dev/shm noexec（1.1.8.2 L1-disruptive 未应用）、journal-upload unit 所有 systemd 都有 | auditd/journal 改 `is-enabled`；/dev/shm 改「fstab 已写 noexec 才断言 live」 |
| v0.14.22 | smoke `SMOKE FAIL: weak SSH crypto present` | smoke 黑名单把 CIS 1.6.5/1.6.6 **允许**的 hmac-sha1/umac-64/chacha20/aes\*-cbc 当弱算法 | 只查 CIS 真禁算法（md5/3des/rc4/blowfish/cast/salsa20），与 engine 允许列表同源 |

**主根因（v0.14.17-19）**：TOS4 源镜像 SELinux **disabled**，首次启用（即使 permissive）触发
① boot-time autorelabel ② systemd-remount-fs 失败导致根 fs ro。两者都会在 sshd 起来之前/同时
把系统拖住，且 packer 误判为「SSH 连不上」。

## 二、修复的共享性

ciscvm 的架构决定了大部分修复**自动覆盖全部 Linux profile**：

- **Engine**：`cis_engine.py` 在 10 个 Linux role 中 md5 完全一致（`3e07e0ca`）→ f_selinux
  permissive 逻辑、crypto drop-in（v0.13.6 `umac-128@openssh.com` + `sshd -t` 回滚）、nft
  遍历等全部共享。
- **HCL 模板**：`HCL_LINUX_TEMPLATE` + `SMOKE_LINUX_BLOCK` 单一模板服务所有 Linux profile
  → guard（autorelabel 删除 / fstab ro 重写 / oneshot remount rw / start_retry_timeout）、
  smoke（条件式断言 / crypto 黑名单）全部共享。

## 三、其他 Linux playbooks 检查结论（2026-08-08）

对 rhel8/9/10、sles15/16、tencentos3、ubuntu2004/2204/2404 逐 role 对比 rules.json 关键规则：

| 检查项 | 涉及 role | 结论 |
|---|---|---|
| SELinux `not disabled`（1.7.1.4 L1） | rhel8/9/10、sles16、tencentos3/4 | **都有**。若源镜像 SELinux disabled，同样会触发 autorelabel/根 ro → **guard 修复（删标记 + remount rw）已自动覆盖**，无独立风险 |
| SELinux enforcing（1.7.1.5 L2） | 同上 | L2 不执行（L1），无影响 |
| auditd（4.1.x L2） | 全部 | L1 均不启用 → smoke 条件式（is-enabled）跳过 ✓ |
| /dev/shm noexec（1.1.8.2 L1） | 全部 | L1 均 disruptive 跳过 → smoke 条件式（fstab 门控）跳过 ✓ |
| SSH crypto（1.6.5/1.6.6 L1） | rhel/sles/ubuntu/tos3/4 | engine 共享允许列表 + smoke 新黑名单（只查 CIS 真禁）→ 口径一致 ✓ |
| nftables/firewalld（3.4.x） | tos3/4、rhel、ubuntu | guard 的 while-read nft 修复 + 全 zone permanent 规则共享 ✓ |
| root login（5.2.10） | tos4 等 | guard 的 `PermitRootLogin prohibit-password` 恢复逻辑共享 ✓ |
| **ssh_port=36000（TOS3）** | tencentos3 | guard 用 `sshd -T` 探测实际端口，`$SSH_PORT` 变量贯穿防火墙规则 → 36000 自适应（已渲染验证） ✓ |

### 发现的唯一实质差异（非阻塞）

`tasks/run.yml` 存在版本分叉：**tencentos3/4 共享新版**（cd1347b1，含 `check_mode` 支持、
`cis_remote_tmp` 显式化），**rhel8/9/10、sles15/16、ubuntu2004/2204/2404 仍是旧版**
（1995b739）。该差异是**增强项**（编排层变量命名与 check-mode 行为），不是 TOS4 问题链
的一部分，旧版各平台历史上构建正常 → **不阻塞，建议后续把 TOS4 的 run.yml 改进回同步**
（与 engine 的 md5 同步机制一致）。

**结论**：由于 engine 与 HCL 模板全共享，v0.14.14-22 的修复对全部 10 个 Linux profile 自动
生效，逐 role 检查未发现需要单独修复的规则级问题。唯一需要留意的是各镜像的 SELinux 初始
状态（若为 disabled，guard 的 autorelabel/remount 修复即为兜底）。

## 四、沉淀的可复用教训

1. Python 列表相邻字符串无逗号 = 隐式拼接，不报错——只有渲染目标（HCL）解析时才暴露。
2. `for t in $(...)` 处理含空格的 token 会把 `inet firewalld` 拆开——用 `while read`。
3. Packer 连接等待窗口是 `start_retry_timeout`，不是 `max_retries`（后者只管命令执行）。
4. SELinux disabled → 首次启用（含 permissive）会触发 boot-time autorelabel；删除
   `/.autorelabel` 可跳过（permissive 容忍无标签）。
5. 读 `findmnt -no OPTIONS /` 先确认是「整个根 ro」还是「单个挂载 ro」再修。
6. smoke/校验断言要按「是否实际应用/启用」门控（`is-enabled` / fstab 内容），不是
   「文件/unit 是否存在」；黑名单必须与 engine/CIS 允许列表同源。
7. 前置故障修复后，下游从未走到过的代码路径会突然暴露 bug（TOS4 smoke 4 连击）——
   交付前对每个 profile 完整走一遍 build→test。
