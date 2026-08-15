from __future__ import annotations

HOSTS_FIX_SNIPPET = (
    'grep "^127.0.0.1" /etc/hosts 2>/dev/null | grep -qwF "$(hostname)" || '
    'echo "127.0.0.1 $(hostname)" | sudo tee -a /etc/hosts >/dev/null'
)

HCL_LINUX_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0, < 2.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("__SECRET_ID_ENV__")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("__SECRET_KEY_ENV__")
  sensitive = true
}

variable "security_token" {
  type      = string
  default   = env("__SECURITY_TOKEN_ENV__")
  sensitive = true
}

variable "region"                      { type = string }
variable "zone"                        { type = string }
variable "instance_type"               { type = string }
variable "source_image_id"             { type = string }
variable "ssh_username"                { type = string }
variable "ssh_port"                    { type = number }
variable "ssh_timeout"                 { type = string }
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
# Computed once in Python (24h UTC) and passed in — the in-image
# banner/report/motd must show the SAME name as the actual image.
variable "image_name"                  { type = string }
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }
# Optional explicit name for the temporary build CVM; empty = plugin auto.
variable "instance_name"               { type = string }
# Reserved for user passthrough of arbitrary packer builder args via
# [build.packer]; the actual args are injected as HCL literals by the
# __EXTRA_ARGS_BLOCK__ marker, not referenced here.
variable "extra_builder_args" {
  type    = map(any)
  default = {}
}

locals {
  level_short = replace(var.cis_level, "-server", "")
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  security_token              = var.security_token
__ASSUME_ROLE_BLOCK__
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  ssh_username                = var.ssh_username
  ssh_port                    = var.ssh_port
  ssh_timeout                 = var.ssh_timeout
  ssh_handshake_attempts      = 120
  ssh_read_write_timeout      = "20m"
  ssh_keep_alive_interval     = "30s"
  image_name                  = var.image_name
  instance_name               = var.instance_name
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  associate_public_ip_address = var.associate_public_ip_address
__SPOT_BLOCK__
__EXTRA_ARGS_BLOCK__
  image_copy_regions          = var.image_copy_regions
  image_tags = {
    cis_level  = local.level_short
    os         = var.image_os_tag
    benchmark  = var.image_benchmark
    built_with = "cis-image"
  }
  run_tags = {
    purpose   = "cis-image-build"
    ephemeral = "true"
  }
__USER_DATA_BLOCK__
}

build {
  sources = ["source.tencentcloud-cvm.default"]

  # 0. Version banner — makes it trivial to confirm which cis-image code
  #    generated this template (no more guessing from pause_before values).
  provisioner "shell" {
    remote_path = "__REMOTE_DIR__/cis-image-banner.sh"
    inline = ["echo '==> cis-image version: __VERSION__'"]
  }

  # 1. Install ansible-core (roles uploaded by cis-image — no galaxy needed)
  provisioner "shell" {
    script       = "packer/scripts/install-ansible.sh"
    remote_path  = "__REMOTE_DIR__/cis-image-install-ansible.sh"
  }

  # 2. CIS apply (gate disabled: fails don't block, re-audited after reboot)
  provisioner "ansible-local" {
    command          = "/opt/cis-image-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site.yml"
    staging_directory = "/opt/cis-image-ansible/staging"
    # Keep the staging dir so cleanup.sh can preserve the bundled role
    # (engine + rules.json) inside the image for later re-scans.
    clean_staging_directory = false
    # TMPDIR relocation lives in the venv wrapper (install-ansible.sh) —
    # ansible-local has no ansible_env_vars argument.
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/cis-image-ansible/bin/python"
    ]
  }

  # 3. SSH survival guard (orchestration-layer safety net).
  #    Independent of the CIS engine: unconditionally open the live SSH
  #    port in firewalld / nftables / iptables so a DROP-target zone can
  #    never lock us (or the admin) out after reboot. Also guarantees the
  #    SSH channel itself stays usable: if a CIS rule disabled root login
  #    (PermitRootLogin no), restore key-based root login so Packer can
  #    reconnect; the dedicated build user (created by install-ansible.sh)
  #    is the primary fallback. This is a hard guarantee that no engine
  #    bug or stale install can defeat.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/cis-image-ansible/ssh-guard.sh"
    # Packer deletes the uploaded script after running it (skip_clean=false
    # by default).  Keep it: provisioner 3.5 re-runs this same file right
    # before reboot to re-open the SSH port in the POST-apply firewall zones.
    skip_clean   = true
    inline = [
      "set +e",
      "# CIS hardening may leave the hostname unresolvable by removing its",
      "# /etc/hosts entry.  Every subsequent sudo call (PAM → DNS) hangs",
      "# 5-30s.  We write directly — Packer runs as root, so no sudo needed.",
      "__HOSTS_FIX_HCL__",
      "SSH_PORT=$(sudo sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=$(sudo awk '/^[Pp]ort[ \\t]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config)",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=22",
      "echo \"[ssh-guard] ensuring SSH port $SSH_PORT stays open\"",
      "if command -v firewall-cmd >/dev/null 2>&1; then",
      "  sudo systemctl enable firewalld >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld enable failed\"",
      "  sudo systemctl start firewalld >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld start failed\"",
      "  echo \"[ssh-guard] zones: $(sudo firewall-cmd --get-zones 2>/dev/null | tr '\\n' ' ') | default: $(sudo firewall-cmd --get-default-zone 2>/dev/null)\"",
      "  for z in $(sudo firewall-cmd --get-zones 2>/dev/null); do",
      "    sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp >/dev/null 2>&1 || echo \"[ssh-guard] WARN: runtime add-port failed for zone $z\"",
      "    sudo firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1 || echo \"[ssh-guard] WARN: permanent add-port failed for zone $z\"",
      "  done",
      "  sudo firewall-cmd --reload >/dev/null 2>&1 || echo \"[ssh-guard] WARN: firewalld reload failed\"",
      "fi",
      "# nftables: open the port in EVERY table's input chain.  'nft list tables'",
      "# prints 'table <family> <name>' — read both fields so the table arg is",
      "# 'family name'.  A 'for t in $(...)' loop would split them on the space.",
      "if command -v nft >/dev/null 2>&1 && sudo systemctl is-active nftables >/dev/null 2>&1; then",
      "  sudo nft list tables 2>/dev/null | while read -r _ fam name; do",
      "    [ -n \"$name\" ] || continue",
      "    sudo nft add rule \"$fam $name\" input tcp dport $SSH_PORT accept >/dev/null 2>&1 && echo \"[ssh-guard] nft allow added to table '$fam $name'\" || echo \"[ssh-guard] WARN: nft add failed for table '$fam $name'\"",
      "  done",
      "  sudo nft list ruleset > /etc/sysconfig/nftables.conf 2>/dev/null && echo \"[ssh-guard] nftables ruleset persisted ($(sudo grep -c \"dport $SSH_PORT accept\" /etc/sysconfig/nftables.conf 2>/dev/null || echo 0) port rule(s))\" || echo \"[ssh-guard] WARN: nftables ruleset save failed\"",
      "fi",
      "if command -v iptables >/dev/null 2>&1; then",
      "  sudo iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || sudo iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || echo \"[ssh-guard] WARN: iptables add failed\"",
      "  sudo iptables-save > /etc/sysconfig/iptables 2>/dev/null && echo \"[ssh-guard] iptables ruleset persisted\" || echo \"[ssh-guard] WARN: iptables save failed\"",
      "fi",
      "# /opt read-only after reboot: TencentOS 4 images may carry a ro entry for",
      "# /opt in fstab (rw while running, ro once the fstab applies at boot).  Every",
      "# post-reboot provisioner uploads to /opt/cis-image-ansible and ansible-local",
      "# stages there too, so a ro /opt kills the whole rebuild with",
      "# 'scp: /opt/cis-image-ansible/reconnected.sh: Read-only file system'.  Strip",
      "# ro/defaults from the /opt fstab line now and remount rw for the image.",
      "if grep -qE '(^|[[:space:]])/opt([[:space:]]|$)' /etc/fstab 2>/dev/null; then",
      "  sudo awk '{ if ($2==\"/opt\" && $1 !~ /^#/) { n=\"\"; split($4,o,\",\"); for(i in o){ if(o[i]!=\"ro\" && o[i]!=\"defaults\"){ n=(n==\"\"?o[i]:n\",\"o[i]); } } $4=(n==\"\"?\"rw\":n\",rw\"); } print }' /etc/fstab > /tmp/cis-image-fstab.new 2>/dev/null && sudo mv /tmp/cis-image-fstab.new /etc/fstab && echo \"[ssh-guard] fstab /opt line rewritten to rw\" || echo \"[ssh-guard] WARN: fstab /opt rewrite failed\"",
      "  sudo mount -o remount,rw /opt >/dev/null 2>&1 && echo \"[ssh-guard] /opt remounted rw\" || echo \"[ssh-guard] WARN: /opt remount rw failed (not a separate mount?)\"",
      "fi",
      "# Root read-only after reboot: the same class of problem hit the WHOLE root",
      "# fs — observed 'scp: /root/...: Read-only file system' with v0.14.18 (root",
      "# was ro, /opt ro was just a symptom).  First SELinux enable can make",
      "# systemd-remount-fs fail and leave / ro.  Strip ro from the / fstab line",
      "# (if any) so the next boot remounts rw.",
      "if grep -qE '(^|[[:space:]])/[[:space:]]' /etc/fstab 2>/dev/null; then",
      "  sudo awk '{ if ($2==\"/\" && $1 !~ /^#/) { n=\"\"; split($4,o,\",\"); for(i in o){ if(o[i]!=\"ro\" && o[i]!=\"defaults\"){ n=(n==\"\"?o[i]:n\",\"o[i]); } } $4=(n==\"\"?\"rw\":n\",rw\"); } print }' /etc/fstab > /tmp/cis-image-fstab.new 2>/dev/null && sudo mv /tmp/cis-image-fstab.new /etc/fstab && echo \"[ssh-guard] fstab / line rewritten to rw\" || echo \"[ssh-guard] WARN: fstab / rewrite failed\"",
      "  sudo mount -o remount,rw / >/dev/null 2>&1 && echo \"[ssh-guard] / remounted rw\" || echo \"[ssh-guard] WARN: / remount rw failed\"",
      "fi",
      "echo \"[ssh-guard] VERIFY: root options=$(findmnt -no OPTIONS / 2>/dev/null)\"",
      "# Install a post-boot oneshot that re-opens the SSH port after reboot.",
      "# Runs BEFORE sshd (Before=sshd.service) so the port is already open when",
      "# sshd accepts; logs to /var/log/cis-image-ssh-guard.log so a still-failing",
      "# boot is diagnosable on the instance instead of a blind i/o timeout.",
      "sudo tee /etc/systemd/system/cis-image-ssh-guard.service >/dev/null <<'UNIT'",
      "[Unit]",
      "Description=cis-image post-boot SSH port re-open",
      "Wants=network-online.target",
      "After=network.target network-online.target firewalld.service",
      "Before=sshd.service",
      "",
      "[Service]",
      "Type=oneshot",
      "ExecStart=/opt/cis-image-ansible/ssh-guard-boot.sh",
      "TimeoutStartSec=180",
      "RemainAfterExit=no",
      "",
      "[Install]",
      "WantedBy=multi-user.target",
      "UNIT",
      "sudo tee /opt/cis-image-ansible/ssh-guard-boot.sh >/dev/null <<'BOOT'",
      "#!/usr/bin/env bash",
      "exec >> /var/log/cis-image-ssh-guard.log 2>&1",
      "echo \"[ssh-guard-boot] $(date -Is) start\"",
      "# First enable of SELinux (even permissive) can make systemd-remount-fs",
      "# fail, leaving / mounted ro while the rest of the boot continues: sshd",
      "# comes up, but EVERY write (scp upload, /opt staging) fails with",
      "# 'Read-only file system'.  Force rw here — this unit runs Before=sshd.",
      "mount -o remount,rw / >/dev/null 2>&1 && echo \"[ssh-guard-boot] root remounted rw\" || echo \"[ssh-guard-boot] WARN: root remount rw failed\"",
      "mount -o remount,rw /opt >/dev/null 2>&1 || true",
      "echo \"[ssh-guard-boot] root=$(findmnt -no OPTIONS / 2>/dev/null)\"",
      "SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}')",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=$(awk '/^[Pp]ort[ \\t]+[0-9]+/{print $2; exit}' /etc/ssh/sshd_config)",
      "[ -z \"$SSH_PORT\" ] && SSH_PORT=22",
      "echo \"[ssh-guard-boot] target port $SSH_PORT\"",
      "if command -v firewall-cmd >/dev/null 2>&1; then",
      "  systemctl enable firewalld >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: enable firewalld failed\"",
      "  systemctl start firewalld >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: start firewalld failed\"",
      "  for z in $(firewall-cmd --get-zones 2>/dev/null); do",
      "    firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: zone $z runtime add failed\"",
      "    firewall-cmd --zone=$z --add-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: zone $z permanent add failed\"",
      "  done",
      "  firewall-cmd --reload >/dev/null 2>&1 || echo \"[ssh-guard-boot] WARN: reload failed\"",
      "  echo \"[ssh-guard-boot] firewalld active=$(systemctl is-active firewalld 2>/dev/null)\"",
      "fi",
      "if command -v nft >/dev/null 2>&1; then",
      "  nft list tables 2>/dev/null | while read -r _ fam name; do",
      "    [ -n \"$name\" ] || continue",
      "    nft add rule \"$fam $name\" input tcp dport $SSH_PORT accept >/dev/null 2>&1 && echo \"[ssh-guard-boot] nft allow added to '$fam $name'\" || echo \"[ssh-guard-boot] WARN: nft add failed for '$fam $name'\"",
      "  done",
      "  nft list ruleset > /etc/sysconfig/nftables.conf 2>/dev/null || echo \"[ssh-guard-boot] WARN: ruleset save failed\"",
      "fi",
      "if command -v iptables >/dev/null 2>&1; then",
      "  iptables -C INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport $SSH_PORT -j ACCEPT 2>/dev/null || echo \"[ssh-guard-boot] WARN: iptables add failed\"",
      "  iptables-save > /etc/sysconfig/iptables 2>/dev/null || echo \"[ssh-guard-boot] WARN: iptables save failed\"",
      "fi",
      "echo \"[ssh-guard-boot] $(date -Is) done\"",
      "exit 0",
      "BOOT",
      "sudo chmod +x /opt/cis-image-ansible/ssh-guard-boot.sh",
      "sudo systemctl daemon-reload",
      "sudo systemctl enable cis-image-ssh-guard.service >/dev/null 2>&1 && echo \"[ssh-guard] oneshot enabled\" || echo \"[ssh-guard] WARN: oneshot enable failed\"",
      "# VERIFY — every persistence point, printed to the build log so a",
      "# post-reboot failure is attributable instead of a mystery.",
      "echo \"[ssh-guard] VERIFY: firewalld enabled=$(sudo systemctl is-enabled firewalld 2>&1)\"",
      "echo \"[ssh-guard] VERIFY: oneshot enabled=$(sudo systemctl is-enabled cis-image-ssh-guard.service 2>&1)\"",
      "for z in $(sudo firewall-cmd --get-zones 2>/dev/null); do if sudo firewall-cmd --zone=$z --query-port=$SSH_PORT/tcp --permanent >/dev/null 2>&1; then echo \"[ssh-guard] VERIFY: zone $z permanent port $SSH_PORT: OK\"; else echo \"[ssh-guard] VERIFY: zone $z permanent port $SSH_PORT: MISSING\"; fi; done",
      "echo \"[ssh-guard] VERIFY: nftables.conf port rules=$(sudo grep -c \"dport $SSH_PORT accept\" /etc/sysconfig/nftables.conf 2>/dev/null || echo 0)\"",
      "echo \"[ssh-guard] VERIFY: iptables port rules=$(sudo grep -c \"dport $SSH_PORT -j ACCEPT\" /etc/sysconfig/iptables 2>/dev/null || echo 0)\"",
      "# SELinux disabled->permissive: the currently-disabled boot left a stale",
      "# /.autorelabel marker (selinux-autorelabel-mark).  On the next boot",
      "# (SELinux now permissive) the autorelabel service consumes it and runs a",
      "# full restorecon in EARLY boot, before network/sshd — observed as a",
      "# multi-minute-to-infinite i/o timeout loop after reboot.  Remove the",
      "# marker so the permissive boot needs NO relabel; with permissive the",
      "# missing file labels are tolerated, and the mark service only recreates",
      "# the marker during a SELinux-disabled boot (which this is no longer).",
      "if [ -f /.autorelabel ]; then sudo rm -f /.autorelabel && echo \"[ssh-guard] removed stale /.autorelabel (boot relabel suppressed)\" || echo \"[ssh-guard] WARN: could not remove /.autorelabel\"; else echo \"[ssh-guard] no stale /.autorelabel present\"; fi",
      "echo \"[ssh-guard] VERIFY: selinux=$(sudo getenforce 2>/dev/null) config=$(sudo grep ^SELINUX= /etc/selinux/config 2>/dev/null) autorelabel=$([ -f /.autorelabel ] && echo PRESENT || echo absent)\"",
      "# Ensure key-based root login survives CIS hardening (PermitRootLogin no)",
      "if sudo sshd -T 2>/dev/null | grep -qi '^permitrootlogin no'; then",
      "  echo \"[ssh-guard] CIS disabled root login; restoring key-based root login\"",
      "  for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -f \"$f\" ] || continue; sudo sed -i 's/^[ \\t]*PermitRootLogin[ \\t].*/PermitRootLogin prohibit-password/' \"$f\"; done",
      "  sudo systemctl reload sshd",
      "fi",
      "# Build user fallback (created by install-ansible.sh) — sudoers.d already grants NOPASSWD; do NOT add to wheel (CIS 5.2.7 requires wheel to stay empty)",
      "true"
    ]
  }

  # 3.5 Re-apply the SSH guard right before reboot.  The apply playbook on
  #      TencentOS 4 can reload firewalld / shift active zones (CIS 3.4.x),
  #      which silently drops the guard's earlier rules — after reboot the
  #      build then can't reconnect (i/o timeout, not refused).  Re-running
  #      the guard here enumerates the POST-apply zones and persists the
  #      SSH port opening in all of them.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "/opt/cis-image-ansible/ssh-guard-reapply.sh"
    inline = [
      "sudo bash /opt/cis-image-ansible/ssh-guard.sh"
    ]
  }

  # 4. Schedule reboot. shutdown -r +1 gives Packer ~60s to finish
  #    cleanup (rm reboot.sh) while SSH is still alive.
  #    Without expect_disconnect — SSH hasn't dropped yet at this point.
  #    No `|| true`: a failed shutdown must fail loudly, otherwise the next
  #    provisioner waits for a disconnect that never comes.
  provisioner "shell" {
    pause_before = "10s"
    remote_path  = "/opt/cis-image-ansible/reboot.sh"
    inline       = ["sudo shutdown -r +1"]
  }

  # 5. Wait for the reboot, then continue AS SOON AS SSH returns.
  #  pause_before=90s only needs to cover the shutdown delay (+60s),
  #    so Packer is already disconnected before it first probes.
  # expect_disconnect then makes Packer poll and reconnect the very
  #    moment SSH is back — no fixed 7-minute dead wait. This alone
  #    saves several minutes per build when the VM reboots faster.
  provisioner "shell" {
    pause_before      = "90s"
    expect_disconnect = true
    # A freshly hardened TOS4 may take several minutes to finish its first
    # post-enable boot (SELinux relabel / firewalld cold start) before sshd
    # accepts.  The connect window is start_retry_timeout (default "a few
    # minutes" — observed ~5 min give-up of i/o timeout retries), NOT
    # max_retries (which only retries command execution).  Raise it so a
    # slow-but-healthy boot no longer looks like a dead instance.  25m also
    # covers an unexpected single SELinux autorelabel pass + its auto-reboot.
    start_retry_timeout = "25m"
    max_retries         = 40
    # Upload to /opt (not /tmp): systemd-tmpfiles on the freshly rebooted
    # image may purge /tmp (tmp.conf D-type cleanup), which made the
    # reconnect probe fail with 'bash: script: Permission denied' (126).
    remote_path       = "__REMOTE_DIR__/cis-image-reconnected.sh"
    inline            = ["echo reconnected"]
    valid_exit_codes  = [0, 1, -1]
  }

  # 5.5 Fix log-file permissions that were loosened by boot-time
  #     services (cloud-init, systemd-logind, …).  These files are
  #     recreated on every boot with default perms; the CIS engine
  #     flags them in the re-audit unless we fix them first.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/cis-image-fix-logperms.sh"
    inline = [
      "set +e",
      "# Post-reboot state evidence: if SELinux autorelabel ran at boot it would",
      "# have consumed (deleted) /.autorelabel; if the marker is still here the",
      "# boot skipped relabel entirely (desired).  sshd active confirms the",
      "# instance is fully up.  Printed first so a failed build is attributable.",
      "echo \"[cis-image] post-reboot: autorelabel=$([ -f /.autorelabel ] && echo PRESENT || echo GONE) selinux=$(sudo getenforce 2>/dev/null) sshd=$(sudo systemctl is-active sshd 2>/dev/null)\"",
      "# L2 enables auditd (4.1.1.2) and apply shows 'enabled and running', yet",
      "# after reboot it can come up inactive (audit 4.1.3.x then all fail with",
      "# 'not loaded in the running config' + smoke FAIL).  Diagnose and force a",
      "# start; the journal excerpt surfaces the real reason if start fails.",
      "echo \"[cis-image] auditd: active=$(sudo systemctl is-active auditd 2>/dev/null) enabled=$(sudo systemctl is-enabled auditd 2>&1)\"",
      "if ! sudo systemctl is-active --quiet auditd 2>/dev/null; then",
      "  sudo systemctl start auditd >/dev/null 2>&1 && echo '[cis-image] auditd started OK' || { echo '[cis-image] auditd START FAILED:'; sudo journalctl -u auditd -n 8 --no-pager 2>&1 | tail -8; }",
      "  echo \"[cis-image] auditd after start: $(sudo systemctl is-active auditd 2>/dev/null)\"",
      "fi",
      "# auditd may be active yet its rules are not in the kernel: the service's",
      "# ExecStartPost=augenrules --load can fail after the SELinux first-enable",
      "# boot while the service still reports active.  Force a reload and echo",
      "# the rule count so a missing ruleset is visible in the build log.",
      "if sudo systemctl is-active --quiet auditd 2>/dev/null; then",
      "  sudo augenrules --load >/dev/null 2>&1 && echo \"[cis-image] audit rules reloaded: $(sudo auditctl -l 2>/dev/null | grep -c . ) rule(s)\" || { echo '[cis-image] WARN: augenrules --load failed:'; sudo journalctl -u auditd -n 6 --no-pager 2>&1 | tail -6; }",
      "fi",
      "# Ensure hostname resolves BEFORE any sudo call.  CIS hardening may",
      "# leave /etc/hosts without the short hostname, which makes sudo PAM",
      "# hang on DNS (5-30s per call).  Packer runs as root: no sudo needed.",
      "__HOSTS_FIX_HCL__",
      "sudo find /var/log/ -type f -perm /g+wx,o+rwx -exec chmod g-wx,o-rwx {} + 2>/dev/null",
      "# Reboot may revert ForwardToSyslog to yes (RPM / init-script overwrite).",
      "# 6.2.2.3 wants yes when rsyslog is present; but 6.2.2.1 already fails",
      "# because rsyslog is not detected, so 6.2.2.3 is not assessed. Safe to fix.",
      "sudo sed -i 's/^ForwardToSyslog=yes$/ForwardToSyslog=no/' /etc/systemd/journald.conf 2>/dev/null || true",
      "# systemd-journal-remote creates /var/lib/private/systemd/journal-upload",
      "# with unowned uid/gid; the CIS unowned-files scan flags it post-reboot.",
      "sudo chown -R root:root /var/lib/private/systemd/ 2>/dev/null || true",
      "echo fix-logperms done"
    ]
  }

  # 6. Re-audit after reboot + gate check (score >= 85%).
  #    cis_keep_remote_artifacts=true keeps /tmp/cis-*/result.json so
  #    provisioner #7.5 can persist it to /opt for the cis-image report.
  provisioner "ansible-local" {
    command          = "/opt/cis-image-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site-audit.yml"
    staging_directory = "/opt/cis-image-ansible/staging"
    # Keep the staging dir so cleanup.sh can preserve the bundled role
    # (engine + rules.json) inside the image for later re-scans.
    clean_staging_directory = false
    # TMPDIR relocation lives in the venv wrapper (install-ansible.sh).
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/cis-image-ansible/bin/python",
      "-e", "cis_keep_remote_artifacts=true"
    ]
  }

  # 7. Cleanup package cache before snapshot.
  #    Also re-lock SSH to the CIS target state: the ssh-guard step above
  #    temporarily restored key-based root login so Packer could reconnect
  #    after reboot; the final image must ship hardened (PermitRootLogin no
  #    per CIS 5.1.22/5.2.10).  The dedicated 'cisimage' build user (sudo,
  #    same authorized_keys) remains the supported admin channel.
  provisioner "shell" {
    pause_before = "10s"
    remote_path  = "__REMOTE_DIR__/cis-image-cleanup.sh"
    inline = [
      "__CLEAN_CMD__",
      "# Re-lock root login for the final image (CIS 5.1.22/5.2.10).  Do NOT",
      "# reload sshd here: the running daemon keeps the current policy so",
      "# Packer can still reconnect for the remaining provisioners; the new",
      "# config takes effect on the first boot of any instance from the image.",
      "for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf; do [ -f \"$f\" ] || continue; sudo sed -i 's/^[ \\t]*PermitRootLogin[ \\t].*/PermitRootLogin no/' \"$f\"; done",
      "# Keep the engine + rule catalog in the image so the report's re-scan",
      "# instructions work; drop only the transient staging playbooks.",
      "sudo mv /opt/cis-image-ansible/staging/roles /opt/cis-image-ansible/roles 2>/dev/null || true",
      "# Shutdown safety: bound rc-local.service stop time.  On the RHEL 9/10",
      "# public images the TencentCloud security agent (secu-tcs-agent) is",
      "# started from /etc/rc.d/rc.local and lives in rc-local.service's",
      "# cgroup; the unit ships TimeoutStopSec=infinity and the agent catches",
      "# SIGTERM, so once CIS firewall rules cut its backend connection the",
      "# agent's signal handler can hang and the stop job never finishes —",
      "# the guest then cannot soft-shutdown and TencentCloud image creation",
      "# times out (CREATEFAILED).  A bounded stop lets systemd SIGKILL it.",
      "sudo mkdir -p /etc/systemd/system/rc-local.service.d",
      "printf '[Service]\\nTimeoutStopSec=15s\\n' | sudo tee /etc/systemd/system/rc-local.service.d/10-cis-image-stop-timeout.conf > /dev/null",
      "sudo systemctl daemon-reload || true",
      "rm -rf /tmp/ansible /opt/cis-image-ansible/staging /opt/cis-image-ansible/reboot.sh /opt/cis-image-ansible/ssh-guard.sh /opt/cis-image-ansible/reconnected.sh /opt/cis-image-ansible/fix-logperms.sh /opt/cis-image-ansible/cleanup.sh ~/.ansible/roles 2>/dev/null || true"
    ]
  }

  # 7.5 Persist the re-audit JSON to /opt for the cis-image report and banner,
  #     then clean up the temp workdir before the snapshot.  The re-audit
  #     role runs with cis_keep_remote_artifacts=true (provisioner #6),
  #     so /tmp/cis-*/result.json still exists when we get here.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/cis-image-collect-audit.sh"
    inline = [
      "set +e",
      "SRC=$(ls -dt /tmp/cis-*/result.json 2>/dev/null | head -1)",
      "if [ -n \"$SRC\" ] && [ -f \"$SRC\" ]; then",
      "  sudo install -m 0600 -o root -g root \"$SRC\" /opt/cis-image-AUDIT-RESULT.json",
      "  sudo rm -rf \"$(dirname \"$SRC\")\"",
      "  echo \"[cis-image] saved audit result to /opt/cis-image-AUDIT-RESULT.json\"",
      "else",
      "  echo \"[cis-image] WARNING: no /tmp/cis-*/result.json found; banner/report will lack audit details\"",
      "  sudo install -m 0600 -o root -g root /dev/null /opt/cis-image-AUDIT-RESULT.json 2>/dev/null || true",
      "fi",
      "true"
    ]
  }

  # 8. Upload the real cis-image-finalize.sh (rendered by render_finalize with
  #    build metadata substituted).  The shell provisioner below is just a
  #    thin wrapper that fixes /etc/hosts first, then invokes this file.
  provisioner "file" {
    source      = "packer/scripts/cis-image-finalize.sh"
    destination = "/opt/cis-image-ansible/cis-image-finalize.sh"
  }

  # 9. Run the finalize script — writes banner, motd, /opt report, and
  #    wires the SSH Banner directive.  This is the LAST user-visible step
  #    before Packer snapshots the image.
  provisioner "shell" {
    pause_before = "5s"
    remote_path  = "__REMOTE_DIR__/cis-image-run-finalize.sh"
    inline = [
      "# Fix hostname BEFORE sudo — 'sudo bash' hangs on DNS if /etc/hosts",
      "# lacks the short hostname.  We write as root (Packer is root) so",
      "# this is instant; the bash script below inherits the fix.",
      "__HOSTS_FIX_HCL__",
      "sudo bash /opt/cis-image-ansible/cis-image-finalize.sh '__SOURCE_IMAGE__' '__IMAGE_NAME__' '__IMAGE_OS__' '__CIS_LEVEL__' '__IMAGE_BENCHMARK__' '__CIS_IMAGE_VERSION__'",
      "# Re-scan AFTER finalize so /opt/cis-image-AUDIT-RESULT.json describes the",
      "# final image state (finalize rewrites banner/motd/issue, which flips",
      "# CIS 1.7.x banner results).  Engine + catalog were kept under",
      "# /opt/cis-image-ansible/roles/ by the cleanup step.",
      "ENG=$(ls -d /opt/cis-image-ansible/roles/cis_*/files 2>/dev/null | head -1)",
      "if [ -n \"$ENG\" ] && [ -f \"$ENG/cis_engine.py\" ]; then",
      "  sudo /opt/cis-image-ansible/bin/python \"$ENG/cis_engine.py\" --catalog \"$ENG/rules.json\" --mode scan --profile '__CIS_PROFILE_SHORT__' --out /tmp/cis-final-scan.json >/dev/null 2>&1 && sudo install -m 0600 -o root -g root /tmp/cis-final-scan.json /opt/cis-image-AUDIT-RESULT.json && sudo rm -f /tmp/cis-final-scan.json && echo '[cis-image] final-state audit refreshed' || echo '[cis-image] WARNING: final-state re-scan failed; keeping pre-finalize audit'",
      "fi",
      "# Archive the audit JSON on the BUILD MACHINE too: emit it as one",
      "# gzipped+base64 line that cis-image extracts from the packer log and",
      "# stores under ~/.cis-image/reports/<image>.json (the in-image copy at",
      "# /opt stays — drift/verify-image read it as the baseline).",
      "echo \"__CIS_IMAGE_AUDIT_B64__$(sudo gzip -c /opt/cis-image-AUDIT-RESULT.json 2>/dev/null | base64 -w0)\""
    ]
  }
__IDEMPOTENCY_BLOCK____SMOKE_TEST_BLOCK____SUPPLY_CHAIN_BLOCK____TEST_COMPONENTS_BLOCK__
}
"""

IDEMPOTENCY_LINUX_BLOCK = r"""  provisioner "ansible-local" {
    command          = "/opt/cis-image-ansible/bin/ansible-playbook"
    playbook_dir     = "ansible"
    playbook_file    = "ansible/site.yml"
    staging_directory = "/opt/cis-image-ansible/staging"
    clean_staging_directory = false
    extra_arguments  = [
      "-v",
      "-e", "ansible_python_interpreter=/opt/cis-image-ansible/bin/python",
      "-e", "cis_keep_remote_artifacts=true"
    ]
  }
"""

SMOKE_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    # v0.14.31: upload to /root, never /tmp — profiles where CIS 1.1.2.1
    # actually mounts /tmp as a noexec tmpfs (e.g. TencentOS 3) make packer's
    # default /tmp/script_XXXX.sh upload unexecutable (exit 126).
    remote_path = "__REMOTE_DIR__/cis-image-smoke.sh"
    inline = [
      "echo '[cis-image] smoke test: sshd config parses'",
      "sudo sshd -T >/dev/null 2>&1 || { echo '[cis-image] SMOKE FAIL: sshd -T rejected config'; exit 1; }",
      "echo '[cis-image] smoke test: sshd active'",
      "systemctl is-active --quiet sshd || { echo '[cis-image] SMOKE FAIL: sshd not active'; exit 1; }",
      "echo '[cis-image] smoke test: auditd active (if enabled — L1 skips auditd)'",
      "if systemctl is-enabled --quiet auditd 2>/dev/null; then",
      "  systemctl is-active --quiet auditd || { echo '[cis-image] SMOKE FAIL: auditd inactive'; exit 1; }",
      "else",
      "  echo '[cis-image] smoke test: auditd not enabled (L1) — skipped'",
      "fi",
      "echo '[cis-image] smoke test: /dev/shm noexec (if hardened in fstab)'",
      "if grep -E '[[:space:]]/dev/shm[[:space:]]' /etc/fstab 2>/dev/null | grep -q noexec; then",
      "  awk '$2 == \"/dev/shm\" && $4 ~ /noexec/' /proc/mounts | grep -q . || { echo '[cis-image] SMOKE FAIL: /dev/shm noexec applied but not live'; exit 1; }",
      "else",
      "  echo '[cis-image] smoke test: /dev/shm noexec not applied (L1 disruptive) — skipped'",
      "fi",
      "echo '[cis-image] smoke test: no genuinely weak SSH crypto (MD5/3DES/RC4/Blowfish)'",
      "# CIS 1.6.5/1.6.6 explicitly ALLOW hmac-sha1*, umac-64*, chacha20* and",
      "# aes*-cbc — the guard's drop-in keeps them.  Only flag algorithms CIS",
      "# actually forbids, or an L1 build can never pass this check.",
      "if sudo sshd -T 2>/dev/null | grep -Eiq 'md5|3des-cbc|arcfour|blowfish-cbc|cast128|salsa20'; then",
      "  echo '[cis-image] SMOKE FAIL: weak SSH crypto present'; exit 1;",
      "fi",
      "echo '[cis-image] smoke test: journal-upload (if enabled)'",
      "# v0.14.32: CIS 4.3.x only requires the forwarder configured + enabled;",
      "# it legitimately stays inactive without a reachable remote journal",
      "# server (TencentOS 3 ships it enabled-but-idle).  Assert enabled only.",
      "if systemctl is-enabled --quiet systemd-journal-upload.service 2>/dev/null; then",
      "  echo '[cis-image] smoke test: journal-upload enabled (inactive OK without remote server)'",
      "else",
      "  echo '[cis-image] smoke test: journal-upload not enabled — skipped'",
      "fi",
      "echo '[cis-image] smoke test PASSED — image is buildable'"
    ]
  }
"""

TEST_COMPONENTS_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "3s"
    remote_path = "__REMOTE_DIR__/cis-image-user-tests.sh"
    inline = [
      "set +e",
      "echo '[cis-image] user test components: running'",
      # __REMOTE_DIR__ resolves to /root (root user) or /home/<user> (e.g.
      # ubuntu) — the same mechanism as the smoke test (v0.14.33).  A
      # hardcoded /root breaks non-root profiles: the file upload to /root
      # fails with permission denied before any test even runs.
      "for t in __REMOTE_DIR__/cis-image-test-components/*; do",
      "  [ -f \"$t\" ] || continue",
      "  echo \"[cis-image] user-test: running $(basename \"$t\")\"",
      "  bash \"$t\"",
      "  RC=$?",
      "  if [ \"$RC\" != \"0\" ]; then",
      "    echo \"[cis-image] USER TEST FAIL: $(basename \"$t\") exited $RC — image not produced\"",
      "    exit 1",
      "  fi",
      "  echo \"[cis-image] user-test: PASS $(basename \"$t\")\"",
      "done",
      "echo '[cis-image] user test components: all passed'"
    ]
  }
"""

CVE_SCAN_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    remote_path = "__REMOTE_DIR__/cis-image-cve-scan.sh"
    inline = [
      "set +e",
      "if ! command -v trivy >/dev/null 2>&1; then",
      "  echo '[cis-image] cve-scan: installing trivy (pinned v0.57.1)'",
      "  sudo dnf install -y wget >/dev/null 2>&1 || sudo apt-get install -y wget >/dev/null 2>&1 || true",
      "  TARCH=$(uname -m | sed -e 's/x86_64/64bit/' -e 's/aarch64/ARM64/' -e 's/arm64/ARM64/')",
      "  curl -fsSL \"https://github.com/aquasecurity/trivy/releases/download/v0.57.1/trivy_0.57.1_Linux-${TARCH}.tar.gz\" -o /tmp/trivy.tgz 2>/dev/null && sudo tar -C /usr/local/bin -xzf /tmp/trivy.tgz trivy 2>/dev/null && rm -f /tmp/trivy.tgz",
      "fi",
      "if ! command -v trivy >/dev/null 2>&1; then",
      "  echo '[cis-image] cve-scan: WARNING trivy unavailable — skipping CVE gate (build continues)'",
      "else",
      "  echo '[cis-image] cve-scan: trivy $(trivy --version 2>/dev/null | head -1) — scanning / (CRITICAL only)'",
      # Skip pseudo-filesystems & caches: /proc,/sys,/dev report unfixable
      # kernel findings, /run,/tmp are ephemeral — scanning them just slows
      # the gate down and pollutes the report with noise.
      "  sudo trivy fs --quiet --severity CRITICAL --exit-code 1 --no-progress --skip-dirs /proc,/sys,/dev,/run,/tmp / >/tmp/cis-image-trivy.log 2>&1",
      "  RC=$?",
      "  tail -20 /tmp/cis-image-trivy.log",
      "  if [ \"$RC\" = \"1\" ]; then",
      "    echo '[cis-image] CVE GATE FAIL: CRITICAL vulnerabilities found — image not produced'",
      "    exit 1",
      "  fi",
      "  echo '[cis-image] cve-scan: PASSED (no CRITICAL findings)'",
      "fi"
    ]
  }
"""

SBOM_LINUX_BLOCK = r"""  provisioner "shell" {
    pause_before = "5s"
    remote_path = "__REMOTE_DIR__/cis-image-sbom.sh"
    inline = [
      "set +e",
      "echo '[cis-image] sbom: generating native package SBOM'",
      "if command -v rpm >/dev/null 2>&1; then",
      "  sudo rpm -qa --qf '{\"name\":\"%{NAME}\",\"version\":\"%{VERSION}-%{RELEASE}\",\"arch\":\"%{ARCH}\",\"epoch\":\"%{EPOCHNUM}\"}\\n' 2>/dev/null | sudo tee /opt/cis-image-SBOM.jsonl >/dev/null",
      "elif command -v dpkg-query >/dev/null 2>&1; then",
      "  sudo dpkg-query -W -f='{\"name\":\"${Package}\",\"version\":\"${Version}\",\"arch\":\"${Architecture}\"}\\n' 2>/dev/null | sudo tee /opt/cis-image-SBOM.jsonl >/dev/null",
      "else",
      "  echo '[cis-image] sbom: WARNING no rpm/dpkg-query — SBOM empty'",
      "  sudo touch /opt/cis-image-SBOM.jsonl",
      "fi",
      "sudo chmod 0644 /opt/cis-image-SBOM.jsonl",
      "echo \"[cis-image] sbom: $(sudo wc -l < /opt/cis-image-SBOM.jsonl 2>/dev/null || echo 0) packages -> /opt/cis-image-SBOM.jsonl\"",
      "echo \"[cis-image] SBOM_SHA256=$(sudo sha256sum /opt/cis-image-SBOM.jsonl 2>/dev/null | awk '{print $1}')\""
    ]
  }
"""

SMOKE_WIN_BLOCK = r"""  provisioner "powershell" {
    inline = [
      "if ((Get-Service -Name mpssvc -ErrorAction SilentlyContinue).Status -ne 'Running') { Write-Error '[cis-image] SMOKE FAIL: Windows firewall inactive'; exit 1 }",
      "Write-Host '[cis-image] smoke test PASSED - image is buildable'"
    ]
  }
"""

TEST_COMPONENTS_WIN_BLOCK = r"""  provisioner "powershell" {
    inline = [
      "Get-ChildItem 'C:/cis-image-test-components/*.ps1' -ErrorAction SilentlyContinue | ForEach-Object {",
      "  Write-Host ('[cis-image] user-test: running ' + $_.Name)",
      "  & $_.FullName",
      "  if ($LASTEXITCODE -ne 0) { Write-Error ('[cis-image] USER TEST FAIL: ' + $_.Name + ' exited ' + $LASTEXITCODE); exit 1 }",
      "  Write-Host ('[cis-image] user-test: PASS ' + $_.Name)",
      "}",
      "Write-Host '[cis-image] user test components: all passed'"
    ]
  }
"""

HCL_WIN_TEMPLATE = r"""packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/tencentcloud"
      version = ">= 1.0.0, < 2.0.0"
    }
    ansible = {
      source  = "github.com/hashicorp/ansible"
      version = ">= 1.0.0, < 2.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("__SECRET_ID_ENV__")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("__SECRET_KEY_ENV__")
  sensitive = true
}

variable "security_token" {
  type      = string
  default   = env("__SECURITY_TOKEN_ENV__")
  sensitive = true
}

variable "region"                      { type = string }
variable "zone"                        { type = string }
variable "instance_type"               { type = string }
variable "source_image_id"             { type = string }
variable "winrm_username"              { type = string }
variable "winrm_password" {
  type      = string
  default   = env("__WINRM_PASSWORD_ENV__")
  sensitive = true
}
variable "vpc_id"                      { type = string }
variable "subnet_id"                   { type = string }
variable "security_group_id"           { type = string }
variable "associate_public_ip_address" { type = bool }
variable "image_name_prefix"           { type = string }
# Computed once in Python (24h UTC) and passed in — the in-image
# banner/report/motd must show the SAME name as the actual image.
variable "image_name"                  { type = string }
variable "image_copy_regions" {
  type    = list(string)
  default = []
}
variable "cis_level"                   { type = string }
variable "image_os_tag"                { type = string }
variable "image_benchmark"             { type = string }
# Optional explicit name for the temporary build CVM; empty = plugin auto.
variable "instance_name"               { type = string }
# Reserved for user passthrough of arbitrary packer builder args via
# [build.packer]; the actual args are injected as HCL literals by the
# __EXTRA_ARGS_BLOCK__ marker, not referenced here.
variable "extra_builder_args" {
  type    = map(any)
  default = {}
}

locals {
  level_short = replace(var.cis_level, "-server", "")
}

source "tencentcloud-cvm" "default" {
  secret_id                   = var.secret_id
  secret_key                  = var.secret_key
  security_token              = var.security_token
__ASSUME_ROLE_BLOCK__
  region                      = var.region
  zone                        = var.zone
  instance_type               = var.instance_type
  source_image_id             = var.source_image_id
  communicator                = "winrm"
  winrm_username              = var.winrm_username
  winrm_password              = var.winrm_password
  # Stock cloud Windows images expose only an HTTP/5985 listener (or a
  # self-signed 5986 one).  Enforcing SSL with verification makes the
  # ephemeral build VM unconnectable; the build runs on an isolated subnet
  # and the VM is destroyed after snapshotting, so plain HTTP is acceptable.
  winrm_use_ssl               = false
  winrm_insecure              = true
  # Windows first boot (specialize/oobe) can take well over 10 minutes on
  # small instance types; give WinRM ample time to come up.
  winrm_timeout               = "30m"
  # Two stock-image hurdles, both handled by this cloudbase-init userdata:
  #  1. the plugin does NOT set the Administrator password from
  #     winrm_password — without this the VM boots with a random password
  #     and every WinRM attempt is a 401 ("Timeout waiting for WinRM");
  #  2. the stock image disables WinRM Basic auth, and packer's
  #     communicator cannot negotiate NTLM against it (verified: pywinrm
  #     NTLM works, packer NTLM 401s) — so Basic + unencrypted HTTP are
  #     enabled for the BUILD only; the final provisioner re-locks both
  #     before the snapshot.
  # NB: the password must not contain a single quote.
  user_data = <<-UDEOF
  <powershell>
  net user Administrator '${var.winrm_password}'
  Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
  Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
  </powershell>
  UDEOF
  image_name                  = var.image_name
  instance_name               = var.instance_name
  vpc_id                      = var.vpc_id
  subnet_id                   = var.subnet_id
  security_group_id           = var.security_group_id
  associate_public_ip_address = var.associate_public_ip_address
__SPOT_BLOCK__
__EXTRA_ARGS_BLOCK__
  image_copy_regions          = var.image_copy_regions
  image_tags = {
    cis_level  = local.level_short
    os         = var.image_os_tag
    benchmark  = var.image_benchmark
    built_with = "cis-image"
  }
  run_tags = {
    purpose   = "cis-image-build"
    ephemeral = "true"
  }
}

build {
  sources = ["source.tencentcloud-cvm.default"]

  # WinRM survival guard — the Windows counterpart of the Linux ssh-guard.
  # CIS 9.x turns the firewall ON with DefaultInboundAction=Block; if no
  # enabled inbound rule covers 5985, the smoke-test and re-lock provisioners
  # (which run AFTER the apply) lose the WinRM channel and the build dies.
  # Create an explicit allow rule BEFORE the apply; the re-lock provisioner
  # removes it again so the shipped image stays clean.
  provisioner "powershell" {
    inline = [
      "Enable-NetFirewallRule -DisplayGroup 'Windows Remote Management' -ErrorAction SilentlyContinue",
      "New-NetFirewallRule -DisplayName 'cis-image-winrm-build-5985' -Direction Inbound -Protocol TCP -LocalPort 5985 -Action Allow -Profile Any -ErrorAction SilentlyContinue | Out-Null",
      "Write-Host '[cis-image] winrm-guard: 5985 allow rule in place before CIS apply'"
    ]
  }

  # CIS apply via controller-side ansible (winrm — cis_engine.ps1)
  # NOTE: no --tags filter — the bundled Windows roles don't tag tasks,
  # so filtering by level would silently skip every task.
  provisioner "ansible" {
    playbook_file = "ansible/site.yml"
    user          = var.winrm_username
    use_proxy     = false
    # Controller-side ansible forks worker processes; on macOS controllers
    # the ObjC runtime kills forked children ("A worker was found in a
    # dead state") unless fork-safety is disabled.  Harmless elsewhere.
    ansible_env_vars = ["OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES"]
    extra_arguments = [
      "-e", "ansible_connection=winrm",
      "-e", "ansible_winrm_transport=basic"
    ]
  }
__SMOKE_TEST_BLOCK____TEST_COMPONENTS_BLOCK__
  # Re-lock WinRM before the snapshot: the build's userdata enabled Basic
  # auth + unencrypted HTTP so the communicator could get in; the shipped
  # image must not carry that weakening.  Runs last — nothing after this
  # needs the communicator.
  provisioner "powershell" {
    inline = [
      "Set-Item -Path WSMan:\\localhost\\Service\\Auth\\Basic -Value $false",
      "Set-Item -Path WSMan:\\localhost\\Service\\AllowUnencrypted -Value $false",
      "# Randomize the Administrator password before snapshot: userdata set it",
      "# to winrm_password for the build; without this every instance launched",
      "# from the image would share that build-time password. Build a 16-char",
      "# password that guarantees one of each complexity class (upper/lower/",
      "# digit/symbol) so Windows complexity rules can never reject it.",
      "$u = 1..4 | ForEach-Object { [char](Get-Random -Minimum 65 -Maximum 91) }",
      "$l = 1..4 | ForEach-Object { [char](Get-Random -Minimum 97 -Maximum 123) }",
      "$d = 1..4 | ForEach-Object { [char](Get-Random -Minimum 48 -Maximum 58) }",
      "$s = 1..4 | ForEach-Object { [char]@(33,35,36,37,38,42,43,45,61,63,64,95)[(Get-Random -Maximum 12)] }",
      "$newpass = -join (($u + $l + $d + $s) | Sort-Object { Get-Random })",
      "net user Administrator $newpass | Out-Null",
      "if ($LASTEXITCODE -ne 0) { Write-Error '[cis-image] FAILED to set Administrator password (exit ' + $LASTEXITCODE + ')'; exit 1 }",
      "# Remove the build-time WinRM firewall guard rule (image ships hardened).",
      "Remove-NetFirewallRule -DisplayName 'cis-image-winrm-build-5985' -ErrorAction SilentlyContinue",
      "Write-Host '[cis-image] winrm re-locked: basic auth + unencrypted HTTP off; Administrator password randomized; guard rule removed'"
    ]
  }
}
"""

SITE_YML_TEMPLATE = r"""---
# CIS apply — bundled cis-os engine (gate disabled; re-audited after reboot)
- name: "CIS __OS_NAME__ - apply (__CIS_LEVEL__)"
  hosts: localhost
  connection: local
  become: true
  vars:
    cis_mode: __CIS_MODE__
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: 0
    cis_include: __CIS_INCLUDE__
    cis_exclude: __CIS_EXCLUDE__
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

SITE_AUDIT_TEMPLATE = r"""---
# CIS re-audit after reboot — gate active
# cis_mode is 'scan' (read-only). The engine only accepts scan|apply;
# a literal 'audit' would fail the preflight validation.
- name: "CIS __OS_NAME__ - audit after reboot (__CIS_LEVEL__)"
  hosts: localhost
  connection: local
  become: true
  vars:
    cis_mode: scan
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: __MIN_SCORE__
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

SITE_YML_WIN_TEMPLATE = r"""---
# CIS __CIS_MODE__ — bundled cis-os engine (PowerShell)
# Gate via cis_min_score (findings-only gate stays off: some controls are
# always manual/disruptive and would block every build).
- name: "CIS __OS_NAME__ - __CIS_MODE__ (__CIS_LEVEL__)"
  hosts: all
  gather_facts: true
  vars:
    ansible_connection: winrm
    ansible_winrm_transport: basic
    cis_mode: __CIS_MODE__
    cis_profile: __CIS_LEVEL__
    cis_platform: server
    cis_allow_disruptive: false
    cis_fail_on_findings: false
    cis_min_score: __MIN_SCORE__
    cis_include: __CIS_INCLUDE__
    cis_exclude: __CIS_EXCLUDE__
    # Fetch result.json back to the controller (ansible/reports/) so build
    # logs don't lose the per-rule detail when the ephemeral VM is destroyed.
    cis_report_json: true
    # Also ship the audit result inside the image (Windows counterpart of
    # Linux /opt/cis-image-AUDIT-RESULT.json) so verify/drift/report tooling
    # can read the build-time audit without re-running the engine.
    cis_ship_result_path: C:\ProgramData\cis-image\AUDIT-RESULT.json
    cis_org_name: ""
  roles:
    - role: __ROLE_DIR__
"""

INSTALL_SH_TEMPLATE = r"""#!/usr/bin/env bash
# Install ansible-core inside the ephemeral CVM (Packer shell provisioner).
# CIS roles are uploaded by cis-image — no ansible-galaxy needed.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# ── Hostname DNS safeguard ──
# TencentOS cloud images ship /etc/hosts with only "127.0.0.1 localhost".
# After CIS hardening modifies firewall / resolv.conf, internal DNS may
# become unreachable.  Every sudo call then triggers a PAM gethostbyname
# that falls through /etc/hosts (hostname not present) → DNS timeout
# (5-30s per call).  We fix this ONCE here, before any sudo or hardening,
# so every downstream provisioner (ssh-guard, fix-logperms, finalize)
# inherits the fix for free.
__HOSTS_FIX__

# 1. System dependencies.
#    Refreshing package indexes (apt-get update / dnf makecache) is one of
#    the slowest steps and is pure waste when the base
#    image already ships python3 venv + pip. Probe first, only touch the
#    package manager when something is actually missing.
need_pkgs=0
# venv module + ensurepip must both work to build the ansible venv offline
python3 -c 'import venv, ensurepip' >/dev/null 2>&1 || need_pkgs=1
if [ "$need_pkgs" = "1" ]; then
    echo "==> base deps missing, refreshing package manager"
    # Cloud-init (and other boot-time jobs) may still be running apt-get on
    # first connect — grabbing the dpkg lock races them and dies with
    # "Could not get lock /var/lib/dpkg/lock-frontend".  Wait for the lock
    # instead of failing (up to 5 min; no-op on rpm systems).
    # NB: use pgrep (procps, preinstalled everywhere) — fuser (psmisc) is
    # NOT installed on ubuntu cloud images, so a fuser-based check would
    # silently no-op and we would race the lock again.
    _dpkg_locked() {
        if pgrep -x apt-get >/dev/null 2>&1 || pgrep -x apt >/dev/null 2>&1 \
           || pgrep -x unattended-upgr >/dev/null 2>&1 || pgrep -x unattended-upgrade >/dev/null 2>&1 \
           || pgrep -x dpkg >/dev/null 2>&1; then
            return 0
        fi
        for _lk in /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock /var/lib/apt/lists/lock; do
            [ -e "$_lk" ] || continue
            if command -v fuser >/dev/null 2>&1; then
                if fuser "$_lk" >/dev/null 2>&1; then return 0; fi
            elif command -v flock >/dev/null 2>&1; then
                if ! flock -n "$_lk" true >/dev/null 2>&1; then return 0; fi
            fi
        done
        return 1
    }
    # Stop scheduled apt jobs BEFORE waiting; otherwise an active
    # unattended-upgrade can hold the lock for the whole timeout.
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl stop unattended-upgrades.service        >/dev/null 2>&1 || true
        sudo systemctl stop apt-daily.service apt-daily.timer   >/dev/null 2>&1 || true
        sudo systemctl stop apt-daily-upgrade.service apt-daily-upgrade.timer >/dev/null 2>&1 || true
    fi
    for _w in $(seq 1 120); do
        if ! _dpkg_locked; then
            break
        fi
        echo "==> package manager busy (cloud-init/unattended-upgrades?), waiting... ($_w/120)"
        sleep 5
    done
    __PKG_UPDATE__
    __PKG_INSTALL__
else
    echo "==> base deps (python3-venv, pip) already present — skipping pkg refresh"
fi

# 2. Pick a Python >=3.8 (ansible-core >=2.12 requires it; RHEL 8 / TencentOS 3 ship 3.6)
# NOTE: Python 3.12 has a multiprocessing atexit bug (FileNotFoundError for
# /tmp/pymp-*) that breaks ansible-local. We skip 3.12 and prefer 3.9-3.11.
PY=
for candidate in python3.11 python3.10 python3.9 python3; do
    if command -v "$candidate" &>/dev/null && \
       "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
        PY="$candidate"
        break
    fi
done

if [ -z "$PY" ]; then
    echo "==> No Python >=3.8 found, trying to install python39..."
    (sudo dnf install -y python39 2>/dev/null || \
     sudo yum install -y python39 2>/dev/null || \
     (sudo apt-get update -qq && sudo apt-get install -y python3.9 python3.9-venv) 2>/dev/null || true)
    for candidate in python3.9 python3.10 python3.11; do
        if command -v "$candidate" &>/dev/null && \
           "$candidate" -c 'import sys; sys.exit(0 if sys.version_info >= (3,8) else 1)' 2>/dev/null; then
            PY="$candidate"
            break
        fi
    done
    # Last resort: Python 3.12 (has known multiprocessing bug, but better than nothing)
    if [ -z "$PY" ] && command -v python3.12 &>/dev/null; then
        PY=python3.12
        echo "==> WARNING: Using Python 3.12 (known multiprocessing atexit bug) — install python3.9 if builds fail" >&2
    fi
fi

if [ -z "$PY" ]; then
    echo "ERROR: Failed to find or install Python >=3.8.  Install it manually and retry." >&2
    exit 1
fi
echo "==> Using $($PY --version) for ansible venv"

# 3. Ansible in a dedicated venv so we do not mutate system pip.
#    Single pip run (no separate --upgrade pip round-trip) + disabled
#    version check keeps this to one network install pass.
VENV=/opt/cis-image-ansible
sudo "$PY" -m venv "$VENV"
# v0.14.33: Ubuntu builds connect as the 'ubuntu' user — hand /opt/cis-image-
# ansible over to the connecting user so the later shell provisioners
# (ssh-guard.sh, reboot.sh, ...) can scp their scripts there.
sudo chown -R "$USER" "$VENV"
# Non-/tmp scratch space for ansible (modular ansiballz payload cache via
# TMPDIR).  /tmp on TencentOS 4 can be tmpfs/swept and payload reuse then
# fails mid-run — keep it on stable root-disk storage instead.
sudo mkdir -p "$VENV/tmp"
# Retry pip installs once: transient mirror/network failures are common during
# image builds, especially in VPCs with no outbound redundancy.
_pip_install() {
    sudo "$VENV/bin/python" -m pip install "$@" && return 0
    echo "==> pip install failed, retrying once..." >&2
    sleep 5
    sudo "$VENV/bin/python" -m pip install "$@"
}
_pip_install --disable-pip-version-check \
    __PIP_INDEX_FLAG__ '__ANSIBLE_CORE_SPEC__' pexpect passlib

# Wrap ansible-playbook so the controller process runs with TMPDIR off /tmp.
# ansible-core >=2.16 (modular ansiballz) caches module payloads under
# tempfile.gettempdir(); on TencentOS 4 that cache is unreliable.
sudo mv "$VENV/bin/ansible-playbook" "$VENV/bin/ansible-playbook.real"
sudo tee "$VENV/bin/ansible-playbook" > /dev/null <<'APB_EOF'
#!/usr/bin/env bash
export TMPDIR=/opt/cis-image-ansible/tmp
exec /opt/cis-image-ansible/bin/ansible-playbook.real "$@"
APB_EOF
sudo chmod +x "$VENV/bin/ansible-playbook"

# 4. Create a non-root build user.  CIS rules can disable root SSH login
#    (e.g. PermitRootLogin no); Packer reconnects as this user after the
#    reboot, so the build can never lock itself out.  The user inherits the
#    same authorized_keys as the current SSH user (root on TencentOS).
BUILD_USER=cisimage
if ! id "$BUILD_USER" >/dev/null 2>&1; then
    sudo useradd -m -s /bin/bash "$BUILD_USER"
fi
# Passwordless sudo for the build user (cis role needs root on the target).
if [ ! -f /etc/sudoers.d/cisimage-build ]; then
    echo "$BUILD_USER ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/cisimage-build >/dev/null
    sudo chmod 440 /etc/sudoers.d/cisimage-build
fi
# Inherit the current user's SSH keys so Packer's keypair works after reboot.
CUR_USER=$(whoami)
if [ "$CUR_USER" != "$BUILD_USER" ] && [ -f "/home/$CUR_USER/.ssh/authorized_keys" ]; then
    sudo mkdir -p "/home/$BUILD_USER/.ssh"
    sudo cp "/home/$CUR_USER/.ssh/authorized_keys" "/home/$BUILD_USER/.ssh/authorized_keys"
    sudo chown -R "$BUILD_USER:$BUILD_USER" "/home/$BUILD_USER/.ssh"
    sudo chmod 700 "/home/$BUILD_USER/.ssh"
    sudo chmod 600 "/home/$BUILD_USER/.ssh/authorized_keys"
elif [ "$CUR_USER" = "root" ] && [ -f /root/.ssh/authorized_keys ]; then
    sudo mkdir -p "/home/$BUILD_USER/.ssh"
    sudo cp /root/.ssh/authorized_keys "/home/$BUILD_USER/.ssh/authorized_keys"
    sudo chown -R "$BUILD_USER:$BUILD_USER" "/home/$BUILD_USER/.ssh"
    sudo chmod 700 "/home/$BUILD_USER/.ssh"
    sudo chmod 600 "/home/$BUILD_USER/.ssh/authorized_keys"
fi
# Ubuntu cloud images may carry an already-expired provisioning account.
# Keep the ephemeral Packer login valid while CIS hardening runs.
if [ "$CUR_USER" != "root" ] && command -v chage >/dev/null 2>&1; then
    sudo chage -M 99999 -I -1 -E -1 "$CUR_USER" >/dev/null 2>&1 || true
fi
echo "build user '$BUILD_USER' ready (sudo + shared SSH key)"

# 4.5 Pre-install common CIS dependency packages in a single batch.
#     Without this the CIS engine installs each package via a separate
#     dnf transaction (metadata sync + download + install = 10-30s each).
#     Batching all into one call cuts many minutes from the apply phase.
#     Use --skip-broken so unavailable packages don't block the build.
__CIS_PKG_BATCH_INSTALL__

echo "ansible ready in $VENV (cis-os engine)"
"""

_BANNER_ART = (
    "\x1b[38;5;117m              .---..---.\x1b[0m\n"
    "\x1b[38;5;117m          .-'          '-.           \x1b[1;37mCIS IMAGE\x1b[0m\n"
    "\x1b[38;5;75m        .'                '.         \x1b[38;5;75m  ___ ___  ___  ___\x1b[0m\n"
    "\x1b[1;38;5;75m      .'                    '.       \x1b[1;38;5;75m / __/ _ \\/ __|/ __|\x1b[0m\n"
    "\x1b[1;38;5;75m     /         ()    ()       \\      \x1b[1;38;5;75m| (_| (_) \\__ \\ (__ \x1b[0m\n"
    "\x1b[1;38;5;75m    |                        |      \x1b[1;38;5;75m \\___\\___/|___/\\___|\x1b[0m\n"
    "\x1b[1;38;5;33m     \\                      /       \x1b[37m  CIS-HARDENED IMAGE BUILDER\x1b[0m\n"
    "\x1b[1;38;5;33m      '.                  .'\n"
    "\x1b[1;38;5;33m        '.              .'\n"
    "\x1b[1;38;5;33m          '---.------.---'"
)

FINALIZE_SH_TEMPLATE = r"""#!/usr/bin/env bash
# cis-image finalize — banner + /opt report.
# Usage: cis-image-finalize.sh <source_image_id> <image_name> <os_tag> <cis_level> <benchmark> <cis_image_version>
set -euo pipefail

SRC_IMG="$1"; IMG_NAME="$2"; OS_TAG="$3"; CIS_LEVEL="$4"; BENCH="$5"; VER="$6"
AUDIT="/opt/cis-image-AUDIT-RESULT.json"
REPORT="/opt/cis-image-REPORT.md"
BUILD_TS="$(date -u +%FT%TZ)"

# ── Hostname DNS safeguard (belt-and-suspenders with fix-logperms) ──
__HOSTS_FIX__

# ── Progress bar: fine-grained steps with percentage ──
_TOTAL=16; _N=0
_bar() {
    _N=$((_N + 1))
    local pct=$((_N * 100 / _TOTAL)) w=$((_N * 24 / _TOTAL)) i=0 bar=""
    while [ "$i" -lt "$w" ]; do bar="${bar}█"; i=$((i+1)); done
    while [ "$i" -lt 24 ]; do bar="${bar}░"; i=$((i+1)); done
    printf "\r=== [%s] %3d%% (%2d/%2d) %s ===\n" "$bar" "$pct" "$_N" "$_TOTAL" "$*"
}

# 1. Banner
_bar "banner: /etc/cis-image/banner"
sudo install -d -m 0755 /etc/cis-image

sudo tee /etc/cis-image/banner > /dev/null <<'BANNER_EOF'
__BANNER_ART__
BANNER_EOF
_bar "banner perms"
sudo chmod 0644 /etc/cis-image/banner
_bar "motd"

# 2. /etc/motd — post-login message (with build metadata)
{
    cat /etc/cis-image/banner
    printf '\n'
    printf '\x1b[1mImage:\x1b[0m     %s\n' "__IMAGE_NAME__"
    printf '\x1b[1mSource:\x1b[0m    %s\n' "__SOURCE_IMAGE__"
    printf '\x1b[1mOS/Level:\x1b[0m  %s / %s\n' "__IMAGE_OS__" "__CIS_LEVEL__"
    printf '\x1b[1mBenchmark:\x1b[0m %s\n' "__IMAGE_BENCHMARK__"
    printf '\x1b[1mBuilt:\x1b[0m     %s by cis-image %s\n\n' "$BUILD_TS" "__CIS_IMAGE_VERSION__"
    printf '\x1b[33m[ REPORT  ]\x1b[0m cat /opt/cis-image-REPORT.md     (or run: cis-image-info)\n'
    printf '\x1b[33m[ ADMIN   ]\x1b[0m ssh cisimage@<host>            (root login disabled per CIS 5.1.22)\n'
    printf '\x1b[33m[ ESCALATE]\x1b[0m sudo -i                        (NOPASSWD via /etc/sudoers.d/cisimage-build)\n'
} | sudo tee /etc/motd > /dev/null
_bar "motd perms"
sudo chmod 0644 /etc/motd

_bar "issue + issue.net"
# 3. /etc/issue, /etc/issue.net — console
#    colour escape sequences render as garbage on serial consoles).
{
    printf 'cis-image  CIS-HARDENED IMAGE BUILDER  --  %s\n' "__IMAGE_NAME__"
    printf 'OS/Level: %s / %s   Benchmark: %s\n' "__IMAGE_OS__" "__CIS_LEVEL__" "__IMAGE_BENCHMARK__"
    printf 'Built:    %s   by cis-image %s\n' "$BUILD_TS" "__CIS_IMAGE_VERSION__"
    printf 'Report:   /opt/cis-image-REPORT.md  (run "cis-image-info")\n'
    printf 'Admin:    ssh cisimage@<host>      (root login disabled per CIS)\n'
} | sudo tee /etc/issue      > /dev/null
_bar "issue.net"
{
    printf 'cis-image  CIS-HARDENED IMAGE BUILDER  --  %s\n' "__IMAGE_NAME__"
    printf 'OS/Level: %s / %s   Built: %s by cis-image %s\n' "__IMAGE_OS__" "__CIS_LEVEL__" "$BUILD_TS" "__CIS_IMAGE_VERSION__"
    printf 'Report: /opt/cis-image-REPORT.md\n'
} | sudo tee /etc/issue.net  > /dev/null
_bar "issue perms"
sudo chmod 0644 /etc/issue /etc/issue.net

# 3.5 Fix log-file permissions that may have been loosened by
#      cloud-init / boot-time service recreation.  The CIS engine
#      flags these in the re-audit, but they are not real hardening
#      gaps — just transient artifacts recreated on every boot.
_bar "fix boot-log perms"
_bar "  cloud-init log"
for f in /var/log/cloud-init.log /var/log/cloud-init-output.log \
         /var/log/wtmp /var/log/btmp; do
    [ -f "$f" ] && sudo chmod 0640 "$f" 2>/dev/null || true
done

# 4. Wire the banner into sshd (drop-in; survives sshd_config rewrites by CIS).
#    We write the config now but do NOT reload sshd — a reload would kill the
#    Packer SSH session, aborting the rest of the script.  The drop-in takes
#    effect on the first boot of any instance launched from this image.
_bar "sshd drop-in dir"
sudo install -d -m 0755 /etc/ssh/sshd_config.d
sudo tee /etc/ssh/sshd_config.d/99-cis-image-banner.conf > /dev/null <<'SSHD_EOF'
# cis-image — show the build banner before authentication.
# Patched on top of CIS hardening by cis-image-finalize.sh.
Banner /etc/cis-image/banner
SSHD_EOF
_bar "sshd drop-in perms"
sudo chmod 0644 /etc/ssh/sshd_config.d/99-cis-image-banner.conf

# 5. /opt/cis-image-REPORT.md — what was done to the base image
_bar "generate REPORT.md"
_bar "  running Python"
sudo /opt/cis-image-ansible/bin/python - "$SRC_IMG" "$IMG_NAME" "$OS_TAG" "$CIS_LEVEL" "$BENCH" "$VER" "$BUILD_TS" "$AUDIT" "$REPORT" <<'PY_EOF'
import json, os, shutil, subprocess, sys, tempfile
src, name, os_tag, level, bench, ver, ts, audit_p, report_p = sys.argv[1:10]
try:
    with open(audit_p) as f:
        a = json.load(f)
except Exception:
    a = {}
s = (a.get("summary") or {}).get("all") or {}
total      = s.get("total", 0)
applied    = s.get("applied", 0)
pending    = s.get("applied_pending", 0)
failed     = s.get("apply_failed", 0)
disruptive = s.get("skipped_disruptive", 0)
score      = s.get("score", "?")
mode       = a.get("mode", "scan")
results    = a.get("results") or []

def _short(r):
    return "- `{}` {}".format(r.get("id", "?"), (r.get("title") or "")[:80])
fails = [r for r in results if r.get("status") == "fail"]
# applied_pending lives on apply_status (the engine's `status` field only
# carries pass/fail/manual/error/notapplicable) — filtering on `status`
# here made this list always empty and hid the section.
pends = [r for r in results if r.get("apply_status") == "applied_pending"]
errs  = [r for r in results if r.get("status") == "error"]
disc  = [r for r in results if (r.get("apply_status") or "") == "skipped_disruptive"
         or (r.get("risk") == "disruptive" and r.get("status") == "fail"
             and r.get("apply_status") == "not_applied")]

lines = []
# cis_level_tag is e.g. "level1-server"; the engine's --profile token is "L1".
level_num = level.replace("level", "").replace("-server", "")
level_short = "L" + level_num
lines.append("# cis-image — CIS Hardening Report")
lines.append("")
lines.append("This image was hardened by **cis-image** (CIS-hardened image builder).")
lines.append("It documents what was done to the base image and how to use the system.")
lines.append("")
lines.append("## Build metadata")
lines.append("")
lines.append("| Field        | Value |")
lines.append("|--------------|-------|")
lines.append("| Final image  | `{}` |".format(name))
lines.append("| Source image | `{}` |".format(src))
lines.append("| OS / Level   | `{}` / `{}` |".format(os_tag, level))
lines.append("| Benchmark    | `{}` |".format(bench))
lines.append("| Built at     | `{}` |".format(ts))
lines.append("| cis-image ver.   | `{}` |".format(ver))
lines.append("| Re-audit     | `{}` (score `{}%`) |".format(mode, score))
lines.append("")
lines.append("## What cis-image did")
lines.append("")
lines.append("Starting from the public source image `{}`, cis-image:".format(src))
lines.append("")
lines.append("1. **Provisioned** a dedicated non-root build user `cisimage`")
lines.append("   (passwordless sudo via `/etc/sudoers.d/cisimage-build`, root SSH login")
lines.append("   is disabled per CIS 5.1.22 / 5.2.10).")
lines.append("2. **Applied the CIS engine** (`cis_engine.py` + `rules.json` for `{}`)".format(os_tag))
lines.append("   against every {} rule, tagging destructive fixes as `disruptive`".format(level_short))
lines.append("   so they are NOT auto-applied.")
lines.append("3. **Rebooted** the instance to materialise kernel / audit / selinux settings.")
lines.append("4. **Re-audited** (`{}` mode) and persisted the result here.".format(mode))
lines.append("5. **Finalised**: installed the banner, motd and this report; locked the")
lines.append("   SSH channel back to the CIS target state (root key login disabled,")
lines.append("   `cisimage` user is the supported admin channel).")
lines.append("")
lines.append("## Hardening summary")
lines.append("")
lines.append("| Metric                  | Count |")
lines.append("|-------------------------|-------|")
lines.append("| Total {} rules checked | {} |".format(level_short, total))
lines.append("| Auto-remediated         | {} |".format(applied))
lines.append("| Pending reboot / verify | {} |".format(pending))
lines.append("| Apply failed            | {} |".format(failed))
lines.append("| Skipped (disruptive)    | {} |".format(disruptive))
if errs:
    lines.append("| Errors                  | {} |".format(len(errs)))
lines.append("| **Final score**         | **{}%** |".format(score))
lines.append("")

if fails:
    lines.append("## Outstanding failures (need follow-up)")
    lines.append("")
    lines.extend(_short(r) for r in fails[:15])
    if len(fails) > 15:
        lines.append("")
        lines.append("_... and {} more._".format(len(fails) - 15))
    lines.append("")

if pends:
    lines.append("## Pending reboot / verify (already applied, will show pass next boot)")
    lines.append("")
    lines.extend(_short(r) for r in pends[:10])
    if len(pends) > 10:
        lines.append("")
        lines.append("_... and {} more._".format(len(pends) - 10))
    lines.append("")

if disc:
    lines.append("## Skipped — disruptive / known exceptions (opt-in)")
    lines.append("")
    lines.append("These rules were skipped because they would break an active service or")
    lines.append("require a manual decision. Remediate them in your own control plane.")
    lines.append("")
    lines.append("Common confirmed exceptions on this platform:")
    lines.append("")
    lines.append("- **System-wide crypto policy stays LEGACY** (CIS 1.6.1): TencentOS")
    lines.append("  ships LEGACY for legacy client compatibility. SSH-specific crypto")
    lines.append("  (CIS 1.6.3-1.6.6) is hardened via the sshd drop-in instead, so the")
    lines.append("  SSH channel is still strong without affecting other services.")
    lines.append("- **`/dev/shm` without `noexec`** (CIS 1.1.2.2.4): applications that")
    lines.append("  execute from shared memory (Java, some databases) break if it is")
    lines.append("  enabled. Track as an accepted risk, or apply `noexec` only where")
    lines.append("  workloads are known safe.")
    lines.append("- **`systemd-journal-upload` inactive** (CIS 6.2.1.2.3): the service")
    lines.append("  is enabled but needs a configured remote log server")
    lines.append("  (`UploadURL` in `/etc/systemd/journal-upload.conf`) to stay active.")
    lines.append("")
    if disruptive:
        lines.append("_({} rule(s) total skipped)_".format(disruptive))
    lines.append("")

lines.append("## How to use this image")
lines.append("")
lines.append("```bash")
lines.append("# 1. Log in as the dedicated build user (root is disabled per CIS)")
lines.append("ssh cisimage@<host>")
lines.append("")
lines.append("# 2. View this report any time")
lines.append("cat /opt/cis-image-REPORT.md          # this file")
lines.append("cis-image-info                        # summary one-liner")
lines.append("")
lines.append("# 3. Escalate to root when needed")
lines.append("sudo -i")
lines.append("")
lines.append("# 4. Re-run the scan on this machine")
lines.append("sudo /opt/cis-image-ansible/bin/python \\")
lines.append("  /opt/cis-image-ansible/roles/cis_*/files/cis_engine.py \\")
lines.append("  --catalog /opt/cis-image-ansible/roles/cis_*/files/rules.json \\")
lines.append("  --mode scan --profile {} --out /tmp/cis-recheck.json".format(level_short))
lines.append("```")
lines.append("")
lines.append("## Files left behind by cis-image")
lines.append("")
lines.append("| Path | Purpose |")
lines.append("|------|---------|")
lines.append("| `/etc/cis-image/banner` | The login banner (also in `/etc/motd`, `/etc/issue`). |")
lines.append("| `/etc/ssh/sshd_config.d/99-cis-image-banner.conf` | SSH `Banner` directive. |")
lines.append("| `/opt/cis-image-AUDIT-RESULT.json` | Raw JSON output of the re-audit. |")
lines.append("| `/opt/cis-image-ansible/` | The cis-image engine + bundled role (kept for re-audits). |")
lines.append("| `/etc/sudoers.d/cisimage-build` | NOPASSWD sudo for the `cisimage` user. |")
lines.append("")
lines.append("---")
lines.append("")
lines.append("Generated by **cis-image {}** on `{}`.".format(ver, ts))
content = "\n".join(lines) + "\n"
with tempfile.NamedTemporaryFile("w", delete=False, suffix=".md") as fh:
    fh.write(content)
    tmp = fh.name
# This heredoc already runs as root (via sudo python); install copies
# (never moves), so the temp file must be unlinked explicitly afterwards.
try:
    subprocess.run(["install", "-m", "0644", "-o", "root", "-g", "root",
                    tmp, report_p], check=True)
except (subprocess.CalledProcessError, FileNotFoundError):
    # Fallback for environments without a root group (local test runs).
    shutil.copy2(tmp, report_p)
    os.chmod(report_p, 0o644)
print("[cis-image-finalize] _step wrote REPORT.md to /opt/")
os.unlink(tmp)
PY_EOF
_bar "install REPORT to /opt"
sudo chmod 0644 /opt/cis-image-REPORT.md

# 6. /usr/local/bin/cis-image-info — one-shot summary command
_bar "cis-image-info helper"
sudo tee /usr/local/bin/cis-image-info > /dev/null <<'INFO_EOF'
#!/usr/bin/env bash
# cis-image-info — show a short summary of this image's CIS hardening.
set -euo pipefail
REPORT="/opt/cis-image-REPORT.md"
if [ ! -f "$REPORT" ]; then
    echo "cis-image-info: $REPORT not found" >&2
    exit 1
fi
awk '
    /^## Build metadata$/ {flag=1; next}
    /^## / {flag=0}
    flag && /^\|/ {print}
' "$REPORT"
echo
echo "Full report: cat $REPORT  (or 'less $REPORT')"
INFO_EOF
sudo chmod 0755 /usr/local/bin/cis-image-info

_bar "done"
echo "[cis-image] finalize complete: banner + motd + /opt/cis-image-REPORT.md"
"""
