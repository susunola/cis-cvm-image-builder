packer {
  required_plugins {
    tencentcloud = {
      source  = "github.com/hashicorp/packer-plugin-tencentcloud"
      version = ">= 1.0.0"
    }
  }
}

variable "secret_id" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_ID")
  sensitive = true
}

variable "secret_key" {
  type      = string
  default   = env("TENCENTCLOUD_SECRET_KEY")
  sensitive = true
}

variable "region" {
  type    = string
  default = "ap-guangzhou"
}

variable "zone" {
  type    = string
  default = "ap-guangzhou-4"
}

variable "instance_type" {
  type    = string
  default = "S5.MEDIUM2"
}

# 官方 Ubuntu 22.04 公共镜像 ID，替换为实际值
variable "source_image_id" {
  type    = string
  default = "img-xxxxxxxx"
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

# 专用构建 VPC / 子网 / 安全组（必填）
variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

variable "security_group_id" {
  type = string
}

# 跨地域自动复制
variable "image_copy_regions" {
  type    = list(string)
  default = []
}

# CIS 等级：level1-server | level2-server
variable "cis_level" {
  type    = string
  default = "level1-server"
}

# 审计允许的失败项数，超过则 build 失败
variable "cis_max_failures" {
  type    = number
  default = 0
}

locals {
  image_name = "ubuntu-2204-cis-l1-${formatdate("YYYYMMDD", timestamp())}"
}

source "tencentcloud-cvm" "ubuntu22" {
  secret_id                  = var.secret_id
  secret_key                 = var.secret_key
  region                     = var.region
  zone                       = var.zone
  instance_type              = var.instance_type
  source_image_id            = var.source_image_id
  ssh_username               = var.ssh_username
  image_name                 = local.image_name
  vpc_id                     = var.vpc_id
  subnet_id                  = var.subnet_id
  security_group_id          = var.security_group_id
  associate_public_ip_address = true
  image_copy_regions         = var.image_copy_regions
  image_tags = {
    cis_level  = replace(var.cis_level, "-server", "")
    os         = "ubuntu-22.04"
    benchmark  = "CIS-v2.0.0"
    built_with = "packer"
  }
  run_tags = {
    purpose   = "cis-image-build"
    ephemeral = "true"
  }
}

build {
  sources = ["source.tencentcloud-cvm.ubuntu22"]

  # 1. 在临时 CVM 上装 ansible + CIS 角色
  provisioner "shell" {
    script = "packer/scripts/install-ansible.sh"
  }

  # 2. 跑 CIS remediation（ansible-local：角色与 playbook 都在实例内执行）
  provisioner "ansible-local" {
    playbook_file   = "ansible/site.yml"
    extra_arguments = ["--tags", var.cis_level, "-e", "grub_user_pass="]
  }

  # 3. build 期审计 gate：不达标 -> exit 1 -> build 失败
  provisioner "shell" {
    script = "packer/scripts/verify-cis.sh"
    environment_vars = [
      "CIS_AUDIT_DIR=/opt/ubuntu22_cis",
      "CIS_MAX_FAILURES=${var.cis_max_failures}"
    ]
  }

  # 4. 清理：缩容前清掉 ansible / 角色，避免带进镜像
  provisioner "shell" {
    pause_before = "10s"
    inline = [
      "sudo apt-get clean",
      "rm -rf /tmp/ansible ~/.ansible/roles 2>/dev/null || true"
    ]
  }
}
