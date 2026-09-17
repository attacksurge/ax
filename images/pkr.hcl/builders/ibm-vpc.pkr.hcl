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

source "ibmcloud-vpc" "packer" {
  api_key               = var.ibm_cloud_api_key
  region                = var.physical_region 
  subnet_id             = var.subnet_id
  vsi_base_image_name     = "ibm-ubuntu-24-04-4-minimal-amd64-7"
  communicator            = "ssh"
  vsi_profile             = var.default_size
  ssh_username            = "ubuntu"
  image_name              = var.snapshot_name
  timeout                 = "90m"
}

build {
  sources = ["source.ibmcloud-vpc.packer"]
