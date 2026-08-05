#!/usr/bin/env bash
# 在临时 CVM 内安装 ansible 与 CIS lockdown 角色（由 Packer shell provisioner 调用）
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

# 1. 系统依赖
sudo apt-get update -y
sudo apt-get install -y python3-pip python3-venv git

# 2. ansible（装到系统 PATH，供 ansible-local provisioner 调用）
sudo python3 -m pip install --upgrade pip
sudo python3 -m pip install 'ansible-core>=2.15' pexpect passlib

# 3. 安装 CIS 角色（作为当前 SSH 用户，ansible-local 以该用户运行可找到）
#    角色名随 Galaxy 命名空间/版本可能微调；如 2.0.0 不存在，改用 git 源：
#    ansible-galaxy install git+https://github.com/ansible-lockdown/UBUNTU22-CIS.git
ansible-galaxy install "ansible-lockdown.ubuntu22_cis,2.0.0" --force

echo "ansible + CIS role ready"
