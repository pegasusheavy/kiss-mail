# ============================================================================
# KISS Mail - Google Cloud Platform Terraform Configuration
# ============================================================================
# Deploy: terraform init && terraform apply
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# ----------------------------------------------------------------------------
# Variables
# ----------------------------------------------------------------------------
variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "zone" {
  description = "GCP zone"
  type        = string
  default     = "us-central1-a"
}

variable "machine_type" {
  description = "Compute Engine machine type"
  type        = string
  default     = "e2-micro"  # Free tier eligible
}

variable "domain" {
  description = "Mail domain"
  type        = string
  default     = "mail.example.com"
}

variable "admin_password" {
  description = "Initial admin password"
  type        = string
  default     = ""
  sensitive   = true
}

variable "disk_size" {
  description = "Boot disk size in GB"
  type        = number
  default     = 20
}

# ----------------------------------------------------------------------------
# Provider
# ----------------------------------------------------------------------------
provider "google" {
  project = var.project_id
  region  = var.region
  zone    = var.zone
}

# ----------------------------------------------------------------------------
# Network
# ----------------------------------------------------------------------------
resource "google_compute_network" "kiss_mail" {
  name                    = "kiss-mail-network"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "kiss_mail" {
  name          = "kiss-mail-subnet"
  ip_cidr_range = "10.0.1.0/24"
  region        = var.region
  network       = google_compute_network.kiss_mail.id
}

# ----------------------------------------------------------------------------
# Firewall
# ----------------------------------------------------------------------------
resource "google_compute_firewall" "kiss_mail" {
  name    = "kiss-mail-firewall"
  network = google_compute_network.kiss_mail.name

  allow {
    protocol = "tcp"
    ports    = ["22", "25", "80", "110", "143", "443", "587"]
  }

  allow {
    protocol = "icmp"
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["kiss-mail"]
}

# ----------------------------------------------------------------------------
# Static IP
# ----------------------------------------------------------------------------
resource "google_compute_address" "kiss_mail" {
  name   = "kiss-mail-ip"
  region = var.region
}

# ----------------------------------------------------------------------------
# Compute Instance
# ----------------------------------------------------------------------------
resource "google_compute_instance" "kiss_mail" {
  name         = "kiss-mail"
  machine_type = var.machine_type
  zone         = var.zone
  tags         = ["kiss-mail"]

  boot_disk {
    initialize_params {
      image = "cos-cloud/cos-stable"  # Container-Optimized OS
      size  = var.disk_size
      type  = "pd-standard"
    }
  }

  network_interface {
    subnetwork = google_compute_subnetwork.kiss_mail.id
    access_config {
      nat_ip = google_compute_address.kiss_mail.address
    }
  }

  metadata = {
    gce-container-declaration = yamlencode({
      spec = {
        containers = [{
          name  = "kiss-mail"
          image = "ghcr.io/pegasusheavy/kiss-mail:latest"
          env = [
            { name = "KISS_MAIL_DOMAIN", value = var.domain },
            { name = "KISS_MAIL_WEB_BIND", value = "0.0.0.0" },
            { name = "KISS_MAIL_API_BIND", value = "0.0.0.0" },
          ]
          volumeMounts = [{
            name      = "data"
            mountPath = "/data"
          }]
        }]
        volumes = [{
          name = "data"
          hostPath = {
            path = "/var/kiss-mail"
          }
        }]
        restartPolicy = "Always"
      }
    })
  }

  metadata_startup_script = <<-EOF
    #!/bin/bash
    mkdir -p /var/kiss-mail
    chmod 777 /var/kiss-mail
  EOF

  service_account {
    scopes = ["cloud-platform"]
  }

  labels = {
    app     = "kiss-mail"
    env     = "production"
    managed = "terraform"
  }

  lifecycle {
    ignore_changes = [metadata_startup_script]
  }
}

# ----------------------------------------------------------------------------
# Outputs
# ----------------------------------------------------------------------------
output "public_ip" {
  description = "Public IP address"
  value       = google_compute_address.kiss_mail.address
}

output "web_admin_url" {
  description = "Web admin URL"
  value       = "http://${google_compute_address.kiss_mail.address}/admin"
}

output "ssh_command" {
  description = "SSH command"
  value       = "gcloud compute ssh kiss-mail --zone ${var.zone}"
}

output "dns_records" {
  description = "DNS records to configure"
  value       = <<-EOT
    
    Configure these DNS records for ${var.domain}:
    
    A     ${var.domain}              ${google_compute_address.kiss_mail.address}
    MX    ${var.domain}    10        ${var.domain}
    TXT   ${var.domain}              "v=spf1 ip4:${google_compute_address.kiss_mail.address} -all"
    
  EOT
}
