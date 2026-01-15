# Deployment Guide

This guide covers deploying the FedRAMP KSI-MLA-05 solution for production use.

## Components Overview

| Component | Purpose | Deployment |
|-----------|---------|------------|
| GitHub Action | Runs evaluation, generates evidence | GitHub repository |
| GitHub App | Posts Check Runs from webhook events | Vercel (or other) |

---

## Step 1: Create the GitHub App

1. Go to **GitHub Settings → Developer settings → GitHub Apps → New GitHub App**

2. Fill in the details:
   - **GitHub App name**: `FedRAMP KSI Evidence` (or your preferred name)
   - **Homepage URL**: Your documentation URL
   - **Webhook URL**: `https://your-vercel-app.vercel.app/webhook` (update after deploying)
   - **Webhook secret**: Generate a secure random string (save this!)

3. Set **Permissions**:
   - **Repository permissions**:
     - `Checks`: Read & write
     - `Actions`: Read-only
     - `Contents`: Read-only (optional, for future features)

4. **Subscribe to events**:
   - ✅ `Workflow run`

5. Click **Create GitHub App**

6. After creation:
   - Note the **App ID** (shown at top of settings page)
   - Generate and download a **Private Key** (.pem file)

---

## Step 2: Deploy the App to Railway

### Prerequisites
- [Railway account](https://railway.app) (free tier: $5 credit/month)
- GitHub repository with the app code

### Deploy Steps

#### Option A: Deploy from GitHub (Recommended)

1. Go to [Railway Dashboard](https://railway.app/dashboard)
2. Click **New Project** → **Deploy from GitHub repo**
3. Select your repository
4. Railway auto-detects Python and builds with Nixpacks

#### Option B: Deploy with Railway CLI

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login
railway login

# 3. Create project and deploy
railway init
railway up
```

### Configure Environment Variables

In Railway Dashboard → Your Project → Variables:

```
GITHUB_APP_ID=your-app-id
GITHUB_WEBHOOK_SECRET=your-webhook-secret
GITHUB_APP_PRIVATE_KEY=<paste PEM content or base64-encoded>
```

**For the private key**, you can either:
- Paste the PEM content directly (Railway handles multiline)
- Base64 encode it: `cat private-key.pem | base64`

### Update Webhook URL

After deployment, Railway gives you a URL like `https://your-app.up.railway.app`.

1. Go back to your GitHub App settings
2. Update the **Webhook URL** to: `https://your-app.up.railway.app/webhook`
3. Save changes

### Verify Deployment

```bash
# Check health endpoint
curl https://your-app.up.railway.app/health

# Should return:
# {"status":"healthy"}
```

---

## Step 3: Publish the GitHub Action

### Option A: Public Repository (Recommended for Open Source)

1. Create a new public repository: `your-org/fedramp-ksi-action`

2. Copy action files:
   ```bash
   # From your monorepo, copy these to the new action repo:
   # - action/
   # - shared/
   # - pyproject.toml (or just requirements for action)
   # - README.md
   ```

3. Create action.yml at repo root:
   ```yaml
   # Copy from action/action.yml but adjust paths
   ```

4. Tag and release:
   ```bash
   git tag v1.0.0
   git tag v1  # Floating major version tag
   git push origin v1.0.0 v1
   ```

5. Users reference as:
   ```yaml
   uses: your-org/fedramp-ksi-action@v1
   ```

### Option B: Private Repository (For Internal Use)

Same as above, but:
- Repository is private
- Users need access to the repo
- Reference includes full path:
  ```yaml
  uses: your-org/fedramp-ksi-action@v1
  ```

### Option C: Monorepo with Subdirectory Action

If keeping everything in one repo:
```yaml
uses: your-org/fedramp-ksi-monorepo/action@v1
```

---

## Step 4: Customer Onboarding

Provide customers with these instructions:

### 1. Install the GitHub App

Direct them to: `https://github.com/apps/YOUR-APP-NAME/installations/new`

Or share the installation link from your GitHub App settings.

### 2. Add the Workflow

Create `.github/workflows/fedramp-ksi-evidence.yml`:

```yaml
name: FedRAMP 20x KSI Evidence

on:
  schedule:
    - cron: '0 0 * * *'  # Daily at midnight UTC
  workflow_dispatch:

permissions:
  contents: read
  actions: read

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '1.6.0'

      - uses: your-org/fedramp-ksi-action@v1
        id: ksi

      - run: echo "Status: ${{ steps.ksi.outputs.status }}"
```

### 3. Verify Setup

1. Manually trigger the workflow (Actions tab → Run workflow)
2. Check that the Check Run appears on the commit
3. Wait for scheduled run for PASS status on MLA05-C

---

## Environment Variables Reference

| Variable | Description | Required |
|----------|-------------|----------|
| `GITHUB_APP_ID` | GitHub App ID from settings | Yes |
| `GITHUB_APP_PRIVATE_KEY` | Private key PEM content | Yes |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret for signature verification | Yes |
| `GITHUB_API_URL` | GitHub API URL (for GHES) | No |
| `LOG_LEVEL` | Logging level (INFO, DEBUG) | No |

---

## Troubleshooting

### Webhook not triggering

1. Check GitHub App settings → Advanced → Recent Deliveries
2. Verify webhook URL is correct
3. Check Vercel function logs

### Check Run not appearing

1. Verify App has `checks:write` permission
2. Check the App is installed on the repository
3. Verify artifact name matches pattern `evidence_ksi-mla-05_*`

### Authentication errors

1. Verify App ID is correct
2. Check private key is properly formatted (PEM format)
3. Ensure webhook secret matches

### Vercel deployment issues

```bash
# Check logs
vercel logs your-app.vercel.app

# Redeploy
vercel --prod --force
```

---

## Security Considerations

1. **Private Key**: Never commit the private key. Use Vercel secrets.
2. **Webhook Secret**: Always verify webhook signatures (implemented in `webhook.py`)
3. **Permissions**: Use minimum required permissions
4. **Artifact Access**: The App only reads artifact manifests, not full code

---

## Scaling Notes

- **Railway**: $5 free credit/month, auto-deploys from Git
- **Rate Limits**: GitHub App has 5000 requests/hour per installation
- **Concurrent Webhooks**: Railway handles concurrent requests automatically

For high-volume deployments, consider:
- Redis for token caching (Railway has Redis add-on)
- Queue system for webhook processing
