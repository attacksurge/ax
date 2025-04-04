variable "golang_version" {
  type = string
}

variable "variant" {
  type = string
}

variable "op_random_password" {
  type = string
}

variable "snapshot_name" {
  type = string
}

source "exoscale" "packer" {
  api_key                  = var.api_key
  api_secret               = var.api_secret
  instance_template        = "Linux Ubuntu 20.04 LTS 64-bit"
  instance_type            = var.default_size
  instance_security_groups = [var.security_group_name]
  template_zones           = [var.region]
  template_name            = var.snapshot_name
  template_username        = "op"
  ssh_username             = "root"
}

build {
  sources = ["source.exoscale.packer"]

