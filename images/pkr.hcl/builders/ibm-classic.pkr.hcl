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


source "ibmcloud-classic" "packer" {
  api_key               = var.sl_key
  username              = var.username
  datacenter_name       = var.region
  base_os_code          = "UBUNTU_20_64"
  image_name            = var.snapshot_name
  instance_name         = "packer-${timestamp()}"
  image_description     = "Axiom full image built at ${timestamp()}"
  image_type            = "standard"
  instance_domain       = "ax.private"
  instance_cpu          = var.cpu
  instance_memory       = var.default_size
  instance_network_speed = 1000
  instance_disk_capacity = 25
  ssh_username =        "root"
  ssh_port              = 22
  instance_state_timeout = "25m"
  communicator          = "ssh"
}

build {
  sources = ["source.ibmcloud-classic.packer"]

