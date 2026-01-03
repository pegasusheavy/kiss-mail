# KISS Mail - Linode (Akamai) Deployment

Deploy KISS Mail on Linode with Terraform.

## Quick Start

```bash
cd deploy/linode
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your API token

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Linode API Token](https://cloud.linode.com/profile/tokens)

## Pricing

| Type | RAM | Cost |
|------|-----|------|
| g6-nanode-1 | 1GB | $5/month |
| g6-standard-1 | 2GB | $10/month |
| g6-standard-2 | 4GB | $20/month |

## Cleanup

```bash
terraform destroy
```
