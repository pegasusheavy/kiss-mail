# KISS Mail - Google Cloud Platform Deployment

Deploy KISS Mail on Google Cloud Platform with Terraform.

## Quick Start

```bash
# 1. Authenticate with GCP
gcloud auth application-default login

# 2. Set your project
gcloud config set project YOUR_PROJECT_ID

# 3. Enable required APIs
gcloud services enable compute.googleapis.com

# 4. Deploy
cd deploy/gcp
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Google Cloud SDK](https://cloud.google.com/sdk)
- GCP project with billing enabled

## What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Compute Instance | e2-micro (Container-Optimized OS) | Free tier eligible |
| Static IP | External IP address | ~$3/month |
| VPC Network | Custom network | Free |
| Firewall Rules | Mail ports | Free |

**Estimated Cost: ~$3-10/month** (e2-micro is free tier eligible)

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `project_id` | (required) | GCP project ID |
| `region` | us-central1 | GCP region |
| `zone` | us-central1-a | GCP zone |
| `machine_type` | e2-micro | Instance type |
| `domain` | mail.example.com | Mail domain |
| `disk_size` | 20 | Boot disk GB |

## Access

```bash
# SSH via gcloud
gcloud compute ssh kiss-mail --zone us-central1-a

# View container logs
gcloud compute ssh kiss-mail --zone us-central1-a -- docker logs kiss-mail
```

## Cleanup

```bash
terraform destroy
```
