# KISS Mail - AWS Deployment

Deploy KISS Mail on AWS with a single command.

## Quick Start

```bash
# 1. Configure AWS credentials
aws configure

# 2. Initialize Terraform
cd deploy/aws
terraform init

# 3. Deploy (with defaults)
terraform apply

# Or with custom domain
terraform apply -var="domain=mail.yourdomain.com"
```

## Requirements

- [Terraform](https://terraform.io) >= 1.0
- [AWS CLI](https://aws.amazon.com/cli/) configured with credentials
- An AWS account

## What Gets Created

| Resource | Description |
|----------|-------------|
| VPC | Dedicated VPC with public subnet |
| EC2 Instance | t3.micro (free tier eligible) |
| Security Group | Ports 25, 587, 143, 110, 80, 443 |
| Elastic IP | Static public IP |
| IAM Role | For SSM Session Manager access |

## Configuration

Copy the example variables file:

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
region         = "us-east-1"
instance_type  = "t3.micro"
domain         = "mail.yourdomain.com"
admin_password = "your-secure-password"
ssh_key_name   = "your-key-pair"  # Optional
volume_size    = 20
```

## Access

After deployment, Terraform outputs:

```
public_ip      = "1.2.3.4"
web_admin_url  = "http://1.2.3.4/admin"
smtp_server    = "1.2.3.4:25"
```

### SSH Access (if key provided)

```bash
ssh -i ~/.ssh/your-key.pem ec2-user@<public_ip>
```

### SSM Session Manager (no SSH key needed)

```bash
aws ssm start-session --target <instance_id>
```

## DNS Configuration

Add these records to your domain:

```
A     mail.yourdomain.com         <public_ip>
MX    yourdomain.com       10     mail.yourdomain.com
TXT   yourdomain.com              "v=spf1 ip4:<public_ip> -all"
```

## SSL/TLS (Optional)

SSH into the server and run:

```bash
sudo certbot --nginx -d mail.yourdomain.com
```

## Costs

| Resource | Estimated Cost |
|----------|---------------|
| t3.micro | ~$8/month (or free tier) |
| Elastic IP | Free (when attached) |
| EBS (20GB gp3) | ~$2/month |
| Data Transfer | Variable |

**Total: ~$10/month** (or free tier eligible)

## Cleanup

```bash
terraform destroy
```

## Troubleshooting

### View setup logs
```bash
sudo cat /var/log/kiss-mail-setup.log
```

### Check container status
```bash
sudo docker ps
sudo docker logs kiss-mail
```

### View credentials
```bash
sudo cat /opt/kiss-mail/credentials.txt
```

### Restart KISS Mail
```bash
sudo docker restart kiss-mail
```
