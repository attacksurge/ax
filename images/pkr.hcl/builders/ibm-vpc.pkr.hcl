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
  subnet_id             = var.vpc_subnet
  vsi_base_image_name     = "ibm-ubuntu-22-04-4-minimal-amd64-4"
  communicator            = "ssh"
  vsi_profile             = var.default_size
  ssh_username            = "root"
  image_name              = var.snapshot_name
  timeout                 = "50m"
}

build {
  sources = ["source.ibmcloud-vpc.packer"]
