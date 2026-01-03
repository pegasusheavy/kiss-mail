# KISS Mail - Hetzner Cloud Deployment

Deploy KISS Mail on Hetzner Cloud with Terraform.

## Quick Start

```bash
cd deploy/hetzner
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Pricing (EU)

| Type | vCPU | RAM | Cost |
|------|------|-----|------|
| cx11 | 1 | 2GB | €3.29/month |
| cx21 | 2 | 4GB | €5.49/month |
| cx31 | 2 | 8GB | €10.49/month |

## Cleanup

```bash
terraform destroy
```
