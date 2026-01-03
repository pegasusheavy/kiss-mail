# KISS Mail - Microsoft Azure Deployment

Deploy KISS Mail on Microsoft Azure with Terraform.

## Quick Start

```bash
# 1. Login to Azure
az login

# 2. Deploy
cd deploy/azure
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars

terraform init
terraform apply
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [Azure CLI](https://docs.microsoft.com/en-us/cli/azure/)
- Azure subscription

## What Gets Created

| Resource | Description | Cost |
|----------|-------------|------|
| Resource Group | Container for resources | Free |
| Virtual Network | Custom VNet | Free |
| Network Security Group | Firewall rules | Free |
| Public IP | Static IP address | ~$3/month |
| Virtual Machine | Standard_B1s (Ubuntu 22.04) | ~$8/month |

**Estimated Cost: ~$10-15/month**

## VM Sizes

| Size | vCPUs | RAM | Cost |
|------|-------|-----|------|
| Standard_B1s | 1 | 1GB | ~$8/month |
| Standard_B1ms | 1 | 2GB | ~$15/month |
| Standard_B2s | 2 | 4GB | ~$30/month |

## Access

```bash
# SSH
ssh azureuser@<public_ip>

# View credentials
cat /opt/kiss-mail/credentials.txt

# View container logs
docker logs kiss-mail
```

## Cleanup

```bash
terraform destroy
```
