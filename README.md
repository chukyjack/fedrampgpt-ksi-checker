# FedRAMP 20x KSI-MLA-05 Evidence Generator

A GitHub Action and App for automated FedRAMP 20x KSI-MLA-05 (Evaluate Configuration) compliance evaluation of Terraform Infrastructure-as-Code repositories.

## Overview

This project provides:

1. **GitHub Action** (`fedramp-ksi-action`): Evaluates Terraform configurations and generates evidence packs
2. **GitHub App** (`fedramp-ksi-app`): Posts Check Runs with FedRAMP-compliant status messages

### KSI-MLA-05 Requirement

> The service provider must implement machine-based evaluation of configuration as part of a persistent cycle to identify and remediate misconfigurations.

## Quick Start (PASS in 5 Minutes)

### 1. Install the GitHub App

Install the FedRAMP KSI GitHub App on your repository from the GitHub Marketplace.

### 2. Add the Workflow

Create `.github/workflows/fedramp-ksi-evidence.yml`:

```yaml
name: FedRAMP 20x KSI Evidence

on:
  schedule:
    # Run daily at midnight UTC for persistent cycle compliance
    - cron: '0 0 * * *'
  workflow_dispatch:
    # Allow manual runs for testing

permissions:
  contents: read
  actions: read

jobs:
  evaluate:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: '1.6.0'

      - name: Run FedRAMP KSI-MLA-05 Evaluation
        uses: your-org/fedramp-ksi-action@v1
        id: ksi

      - name: Summary
        run: |
          echo "Status: ${{ steps.ksi.outputs.status }}"
          echo "Artifact: ${{ steps.ksi.outputs.artifact_name }}"
```

### 3. Wait for Scheduled Run

For **PASS** status, the workflow must be triggered by a `schedule` event. This demonstrates the "persistent cycle" requirement.

**Note:** Manual or push-triggered runs will show **FAIL** for MLA05-C (Persistent Cycle Configured).

## Evaluation Criteria

| Criterion | Name | PASS Condition |
|-----------|------|----------------|
| MLA05-A | Configuration Surface in Scope | Terraform `.tf` files detected |
| MLA05-B | Machine-Based Evaluation Performed | `terraform init` + `terraform validate` succeed |
| MLA05-C | Persistent Cycle Configured | Workflow triggered by `schedule` event |
| MLA05-D | Evidence Artifacts Generated | Evidence pack created with required files |

### Status Determination

- **PASS**: All criteria pass
- **FAIL**: Any criterion fails (none error)
- **ERROR**: Any criterion errors (tooling/evaluation failure)

## Evidence Pack

The action produces a signed evidence artifact:

```
evidence_ksi-mla-05_<shortsha>_<timestamp>.zip
├── evidence/
│   └── ksi-mla-05/
│       ├── collected_at.json
│       ├── scope.json
│       ├── tools.json
│       ├── declared/
│       │   ├── terraform_detection.json
│       │   └── terraform_inventory.json
│       ├── evaluation_manifest.json
│       ├── manifest.json
│       └── hashes.sha256
```

### Key Files

- **evaluation_manifest.json**: Primary output with PASS/FAIL/ERROR status and criteria results
- **terraform_inventory.json**: Parsed Terraform resources, providers, and modules
- **hashes.sha256**: SHA-256 hashes for integrity verification

## Action Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `root_paths` | Comma-separated paths to scan for Terraform | `.` |
| `terraform_version` | Terraform version to install | (use pre-installed) |
| `python_version` | Python version for the action | `3.11` |

## Action Outputs

| Output | Description |
|--------|-------------|
| `status` | Overall status: PASS, FAIL, or ERROR |
| `artifact_name` | Name of the evidence artifact |
| `artifact_path` | Path to the evidence zip file |
| `summary` | Markdown summary of results |

## GitHub App Setup

### Required Permissions

- **Checks: write** - Create and update Check Runs
- **Actions: read** - Access workflow run artifacts

### Webhook Events

- `workflow_run` - Triggered when FedRAMP KSI workflow completes

### Environment Variables

```bash
GITHUB_APP_ID=your-app-id
GITHUB_APP_PRIVATE_KEY=/path/to/private-key.pem
GITHUB_WEBHOOK_SECRET=your-webhook-secret
```

## Development

### Prerequisites

- Python 3.11+
- Terraform 1.0+

### Installation

```bash
# Clone repository
git clone https://github.com/your-org/fedramp-ksi-monorepo.git
cd fedramp-ksi-monorepo

# Install dependencies
pip install -e ".[dev,app]"

# Run tests
pytest
```

### Running the App Locally

```bash
# Set environment variables
export GITHUB_APP_ID=your-app-id
export GITHUB_APP_PRIVATE_KEY="$(cat private-key.pem)"
export GITHUB_WEBHOOK_SECRET=your-secret

# Run the app
python -m app.main
```

### Testing the Action Locally

```bash
# Set GitHub context variables
export GITHUB_REPOSITORY="test/repo"
export GITHUB_SHA="abc1234567890"
export GITHUB_WORKFLOW="Test"
export GITHUB_RUN_ID="12345"
export GITHUB_EVENT_NAME="schedule"
export GITHUB_ACTOR="test-user"
export GITHUB_WORKSPACE="$(pwd)/tests/fixtures/pass-repo"

# Run the action
python action/src/main.py
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Customer Repository                          │
│  ┌─────────────┐                                                │
│  │  .tf files  │                                                │
│  └──────┬──────┘                                                │
│         │                                                       │
│  ┌──────▼──────────────────────────────────────────────────┐   │
│  │           GitHub Actions Workflow                        │   │
│  │  ┌────────────────────────────────────────────────────┐ │   │
│  │  │         fedramp-ksi-action                         │ │   │
│  │  │  1. Detect Terraform                               │ │   │
│  │  │  2. Run terraform init/validate                    │ │   │
│  │  │  3. Generate inventory (HCL parsing)               │ │   │
│  │  │  4. Evaluate criteria                              │ │   │
│  │  │  5. Build evidence pack                            │ │   │
│  │  │  6. Upload artifact                                │ │   │
│  │  └─────────────────────┬──────────────────────────────┘ │   │
│  └────────────────────────┼────────────────────────────────┘   │
└───────────────────────────┼─────────────────────────────────────┘
                            │
                            │ workflow_run webhook
                            ▼
┌───────────────────────────────────────────────────────────────┐
│                    fedramp-ksi-app                             │
│  ┌─────────────────────────────────────────────────────────┐  │
│  │  1. Receive webhook                                      │  │
│  │  2. Download artifact                                    │  │
│  │  3. Parse evaluation_manifest.json                       │  │
│  │  4. Create/Update Check Run                              │  │
│  └─────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────┘
```

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for full deployment instructions including:

- Creating the GitHub App
- Deploying to Railway
- Publishing the Action
- Customer onboarding

### Quick Deploy to Railway

1. Push code to GitHub
2. Go to [Railway Dashboard](https://railway.app/dashboard)
3. **New Project** → **Deploy from GitHub repo**
4. Add environment variables:
   - `GITHUB_APP_ID`
   - `GITHUB_WEBHOOK_SECRET`
   - `GITHUB_APP_PRIVATE_KEY`
5. Update webhook URL in GitHub App settings

## License

MIT License - See [LICENSE](LICENSE) for details.
