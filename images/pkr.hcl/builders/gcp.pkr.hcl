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

variable "default_disk_size" {
  type    = number
  default = 20
}

source "googlecompute" "packer" {
  project_id           = var.project
  region               = var.physical_region
  zone                 = var.region
  machine_type         = var.default_size
  image_name           = var.snapshot_name
  image_family         = "axiom-images"
  source_image_family  = "ubuntu-2204-lts"
  ssh_username         = "root"
  credentials_file     = var.service_account_key
  network              = "default"    # Specify your network or use the default
  subnetwork           = "default"    # Specify your subnetwork if required
  use_internal_ip      = false        # Disable internal IP to avoid networking issues
  disk_size            = var.default_disk_size
  disk_type            = "pd-ssd"     # Specify disk type (pd-ssd or pd-standard)
  ssh_timeout          = "10m"  # Increase the SSH connection timeout
}

build {
  sources = [
    "source.googlecompute.packer"
  ]
