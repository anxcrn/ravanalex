---
name: cloud-infrastructure-assault
description: Exploitation of AWS, GCP, and Azure environments via metadata SSRF, IAM token theft, and storage pivoting.
---

# Cloud Infrastructure Assault

This methodology dictates how the agent should pivot when initial access (RCE, SSRF, or leaked credentials) occurs within a cloud-hosted environment.

## When to Use
Deploy immediately upon discovering a cloud environment via OSINT, or when achieving RCE/SSRF on a cloud-hosted virtual machine (EC2, Compute Engine, Azure VM) or serverless function.

## Methodology

### Step 1: Metadata Extraction
If you have an SSRF or RCE on a cloud instance, immediately query the local metadata endpoint to steal temporary IAM credentials.
- **AWS**: http://169.254.169.254/latest/meta-data/iam/security-credentials/
- **GCP**: http://metadata.google.internal/computeMetadata/v1/ (Requires Metadata-Flavor: Google header).
- **Azure**: http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Requires Metadata: true header).

### Step 2: Privilege Escalation & Enumeration
Once IAM keys are obtained, configure the cloud CLI (ws, gcloud, z) in the workspace.
- Enumerate your permissions (e.g., ws sts get-caller-identity).
- Use tools like Pacu to automatically find privilege escalation vectors (e.g., attaching an admin policy to your current role, passing an IAM role to an EC2 instance).

### Step 3: Lateral Movement & Exfiltration
- Scan for accessible storage buckets (S3, GCS, Azure Blobs).
- Look for unencrypted secrets in Systems Manager Parameter Store or Secrets Manager.
- Check for serverless functions (Lambda) that can be modified to inject persistence backdoors.
