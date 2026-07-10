variable "golang_version" {
  type = string
}

variable "variant" {
  type = string
}

variable "op_random_password" {
  type = string
}

variable "security_group_id" {
  type = string
}

variable "snapshot_name" {
  type = string
}

variable "default_disk_size" {
  type    = number
  default = 20
}

variable "associate_public_ip_address" {
  type    = bool
  default = false
}

variable "aws_access_key" {
  type = string
  default = null
}

variable "aws_secret_access_key" {
  type = string
  default = null
}

variable "aws_vpc_id" {
  type = string
}

variable "aws_subnet_id" {
  type = string
}


source "amazon-ebs" "packer" {
  access_key = var.aws_access_key != null ? var.aws_access_key : null
  secret_key = var.aws_secret_access_key != null ? var.aws_secret_access_key : null
  profile    = var.aws_profile != null ? var.aws_profile : null
  region     = var.region
  vpc_id     = var.aws_vpc_id
  subnet_id  = var.aws_subnet_id
  security_group_id = var.security_group_id
  ami_name   = var.snapshot_name
  instance_type = var.default_size
  associate_public_ip_address = var.associate_public_ip_address
  ssh_interface = "private_ip"

  launch_block_device_mappings {
    device_name           = "/dev/sda1"
    volume_type           = "gp2"
    volume_size           = var.default_disk_size
    encrypted             = true
    delete_on_termination = true
  }

  source_ami_filter {
    filters = {
      "virtualization-type" = "hvm"
      "name"                = "ubuntu/images/*ubuntu-jammy-22.04-amd64-server-*"
      "root-device-type"     = "ebs"
    }
    owners      = ["099720109477"]
    most_recent = true
  }

  ssh_username           = "ubuntu"
  temporary_key_pair_type = "ed25519"
}

build {
  sources = ["source.amazon-ebs.packer"]

