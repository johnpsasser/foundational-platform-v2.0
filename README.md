# Foundational Platform Service v2.0

A secure, FedRAMP High-aligned infrastructure platform for AWS GovCloud deployments.

## Overview

This platform provides a compliant infrastructure substrate for defense and government applications:

- **Cloud**: AWS GovCloud
- **Compliance**: FedRAMP High, DoD IL4-IL5, NIST 800-53
- **Zero Trust**: SPIFFE/SPIRE identity, mTLS everywhere
- **Policy-as-Code**: OPA/Conftest gates in CI/CD

## Quick Start

### Prerequisites

- Terraform >= 1.5.0
- AWS CLI configured for GovCloud
- OPA/Conftest (`brew install conftest` or [install guide](https://www.conftest.dev/install/))
- Make

### One-Command Validation

```bash
# Run all validations (lint + policy check)
make validate

# Or run individual commands:
make test-compliant    # Test compliant example (passes all policies)
make test-noncompliant # Test non-compliant example (expect failures)
```

### Deploy a Compliant Environment

> **Note:** The example is configured for `us-east-1` (commercial AWS) for local testing. For production GovCloud deployments, update the region to `us-gov-west-1` in `terraform/examples/compliant/main.tf`.

```bash
# 1. Initialize and plan
make init-aws
make plan-aws

# 2. Validate compliance
make conftest

# 3. Apply (requires AWS credentials)
make apply-aws
```

## Project Structure

```
foundational-platform-v2.0/
├── docs/
│   ├── Technical PRD - Foundational Platform Service v2.0.pdf
│   ├── System Design - Foundational Platform Service v2.0.pdf
│   ├── Implementation Plan - Foundational Platform Service v2.0.pdf
│   └── Architecture Decisions - Foundational Platform Service v2.0.pdf
├── policies/
│   ├── conftest/
│   │   └── policy.rego                 # Unified Conftest policy
│   ├── opa/
│   │   ├── fedramp_tags.rego          # Tag requirements
│   │   ├── encryption.rego            # Encryption validation
│   │   ├── network_security.rego      # Network controls
│   │   └── logging.rego               # Audit logging
│   └── fedramp-high-controls.rego     # Full FedRAMP policy bundle
├── terraform/
│   ├── modules/
│   │   └── aws-environment/           # AWS GovCloud implementation
│   └── examples/
│       ├── compliant/                 # Passing example
│       └── non-compliant/             # Failing example (for testing)
├── Makefile                           # One-command operations
└── README.md
```

## Architecture

![Architecture Diagram](docs/Architecture%20Diagram%20-%20Foundational%20Platform%20Service%20v2.0.png)

## Documentation

| Document | Description |
|----------|-------------|
| [Technical PRD](docs/Technical%20PRD%20-%20Foundational%20Platform%20Service%20v2.0.pdf) | Technical requirements and personas |
| [System Design](docs/System%20Design%20-%20Foundational%20Platform%20Service%20v2.0.pdf) | Architecture with diagrams |
| [Implementation Plan](docs/Implementation%20Plan%20-%20Foundational%20Platform%20Service%20v2.0.pdf) | Phased delivery and cost model |
| [Architecture Decisions](docs/Architecture%20Decisions%20-%20Foundational%20Platform%20Service%20v2.0.pdf) | ADRs and tradeoffs |

## Makefile Commands

| Command | Description |
|---------|-------------|
| `make help` | Show all available commands |
| `make validate` | Run full validation (lint + policy check) |
| `make init-aws` | Initialize AWS Terraform modules |
| `make plan-aws` | Generate AWS Terraform plan |
| `make conftest` | Run policy validation against plan |
| `make apply-aws` | Apply AWS infrastructure (requires confirmation) |
| `make destroy-aws` | Destroy AWS infrastructure |
| `make test-compliant` | Validate compliant example |
| `make test-noncompliant` | Validate non-compliant example (expect failures) |
| `make evidence` | Generate compliance evidence bundle |
| `make clean` | Remove generated files |

## Policy Validation

The platform enforces FedRAMP High controls via OPA/Conftest policies:

### Required Tags (All Resources)
- `Owner` - Responsible team/individual
- `Environment` - production, staging, development
- `Classification` - IL4, IL5, IL6
- `CostCenter` - Budget allocation code
- `Compliance` - FedRAMP-High, DoD-IL5

### Security Controls
- **Encryption**: KMS encryption required on all storage (S3, EBS, RDS)
- **Network**: No 0.0.0.0/0 ingress; private endpoints required
- **Logging**: CloudTrail, GuardDuty, Config must be enabled
- **Access**: Private EKS endpoint only; IMDSv2 required

### Example Validation Output

```bash
$ make test-compliant
=========================================
  Testing Compliant Example
=========================================
15 tests, 15 passed, 0 warnings, 0 failures, 0 exceptions

SUCCESS: Compliant example passed all policy checks

$ make test-noncompliant
=========================================
  Testing Non-Compliant Example
  (Expect policy violations)
=========================================
FAIL - [TAG-001] Missing required tags: Owner, Classification
FAIL - [ENC-001] EBS volume must be encrypted
FAIL - [NET-001] Security group allows SSH from 0.0.0.0/0
FAIL - [LOG-003] GuardDuty must be enabled
...
15 tests, 0 passed, 15 failures
```

## Module Interface

The platform uses a standardized interface (environment contract) for consistent configuration:

```hcl
module "environment" {
  source = "../modules/aws-environment"

  environment_name     = "prod-defense"
  classification_level = "IL5"

  required_tags = {
    Owner          = "platform-team@gov"
    Classification = "IL5"
    Compliance     = "FedRAMP-High"
  }

  network_config = {
    cidr_block = "10.0.0.0/16"
    # ... see examples/compliant for full configuration
  }

  kubernetes_config = {
    cluster_version = "1.29"
    # ... see examples/compliant for full configuration
  }
}
```

## Architecture Highlights

### Zero Trust Identity (SPIFFE/SPIRE)
- Cryptographic workload identity
- mTLS between all services
- No implicit trust boundaries

### Three-Tier Network
- Public: Load balancers, NAT gateways
- Private: Application workloads, EKS nodes
- Isolated/Data: Databases, sensitive workloads

### Continuous Compliance
- OPA admission control in EKS
- AWS Config rules for drift detection
- Security Hub for finding aggregation
- Automated evidence generation

## Compliance Evidence Generation

Generate a compliance evidence bundle for ATO documentation:

```bash
make evidence

# Output structure:
evidence/
├── manifest.json           # Bundle metadata
├── terraform-state.json    # Current infrastructure state
├── policy-results.json     # OPA validation results
└── controls/
    ├── AC-2-evidence.json  # Account management
    ├── AU-2-evidence.json  # Audit events
    ├── SC-8-evidence.json  # Transmission confidentiality
    └── ...
```

## License

Proprietary - Agile Defense
