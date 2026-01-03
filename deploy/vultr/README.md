# KISS Mail - Vultr Deployment

Deploy KISS Mail on Vultr with Terraform.

## Quick Start

```bash
cd deploy/vultr
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Pricing

| Plan | RAM | Cost |
|------|-----|------|
| vc2-1c-1gb | 1GB | $5/month |
| vc2-1c-2gb | 2GB | $10/month |
| vc2-2c-4gb | 4GB | $20/month |

## Cleanup

```bash
terraform destroy
```
