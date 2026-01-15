# Architecture Decisions and Roadmap

This document captures key architecture decisions, tradeoffs, and the long-term vision for the Foundational Platform Service.

---

## Executive Summary

This platform is designed to be "boring in the right ways" - using proven, composable patterns that prioritize security and compliance over novelty. Every decision was evaluated against three criteria:

1. **Portability**: Does it work across AWS, Azure, and air-gapped environments?
2. **Compliance**: Does it accelerate ATO and reduce manual evidence burden?
3. **Operational Simplicity**: Can a small team maintain it without specialized knowledge?

---

## Key Architecture Decisions

### ADR-001: SPIFFE/SPIRE for Workload Identity

**Decision:** Use SPIFFE/SPIRE as the universal workload identity layer with federation to cloud-native IAM.

**Context:** Zero Trust requires cryptographically verifiable workload identity. Options considered:
- Cloud-native only (EKS Pod Identity / Azure Workload Identity)
- SPIFFE/SPIRE everywhere
- Hybrid: SPIFFE/SPIRE + cloud federation

**Tradeoffs:**

| Approach | Pros | Cons |
|----------|------|------|
| Cloud-native only | Simpler, managed service | No portability, no air-gap support |
| SPIFFE/SPIRE only | Full control, portable | Operational complexity |
| **Hybrid (chosen)** | Best of both, portable | Moderate complexity |

**Rationale:**
- SPIFFE provides vendor-neutral identity that works in air-gapped K3s
- Cloud-native federation reduces operational burden in connected environments
- OIDC federation to AWS STS/Azure AD enables seamless cloud API access
- Pattern proven in DoD environments (Platform One Big Bang uses SPIRE)

**What I'd Do Differently:**
- Consider Istio's native identity for service mesh traffic (simpler)
- Evaluate SPIFFE federation complexity at scale (>50 clusters)

---

### ADR-002: OPA/Gatekeeper for Policy Enforcement

**Decision:** Use Open Policy Agent (OPA) with Gatekeeper for Kubernetes admission control and Conftest for IaC validation.

**Context:** Policy enforcement needed at multiple layers: Terraform planning, Kubernetes admission, runtime evaluation.

**Alternatives Considered:**

| Tool | Pros | Cons |
|------|------|------|
| **OPA/Gatekeeper** | CNCF standard, Rego flexibility | Rego learning curve |
| Kyverno | YAML policies (easier) | Less flexible, newer |
| Cloud-native (SCPs, Azure Policy) | No additional tooling | Not portable |

**Rationale:**
- OPA is CNCF graduated with broad ecosystem
- Single policy language (Rego) across all enforcement points
- Conftest uses same OPA engine for Terraform validation
- Better audit trail than cloud-native alternatives

**What I'd Do Differently:**
- Provide pre-built Rego libraries for common FedRAMP controls
- Consider Kyverno for teams with less Rego experience

---

### ADR-003: Istio Ambient for Service Mesh

**Decision:** Use Istio Ambient mesh (sidecarless) for connected environments, traditional sidecar for air-gapped.

**Context:** Service mesh required for mTLS, traffic management, and observability. Need consistent behavior across environments.

**Alternatives Considered:**

| Mesh | Pros | Cons |
|------|------|------|
| **Istio Ambient** | Sidecarless, lower overhead | Newer, less production history |
| Istio Sidecar | Proven, full features | Resource overhead (~128MB/pod) |
| Linkerd | Lightweight, simple | Fewer features, smaller community |
| Consul Connect | HashiCorp ecosystem | Different from Istio in air-gap |

**Rationale:**
- Istio Ambient reduces resource overhead by 40-60%
- Native SPIRE integration for SPIFFE identity
- L4 ztunnel handles most security requirements
- L7 waypoint available when needed (routing, authorization)

**What I'd Do Differently:**
- Start with traditional sidecar for initial production (more proven)
- Migrate to Ambient after it reaches GA maturity
- Consider Linkerd for resource-constrained edge environments

---

### ADR-004: Flux CD for GitOps

**Decision:** Use Flux CD for GitOps-based configuration management.

**Context:** Need declarative, auditable configuration management that works in air-gapped environments.

**Alternatives Considered:**

| Tool | Pros | Cons |
|------|------|------|
| **Flux CD** | Multi-tenancy, lightweight | Smaller community than Argo |
| ArgoCD | Larger community, better UI | Heavier, complex RBAC |
| Raw kubectl + CI/CD | Simple | No drift detection, no reconciliation |

**Rationale:**
- Flux's multi-tenancy model aligns with platform tenant isolation
- Lighter resource footprint than ArgoCD
- Better integration with Zarf for air-gapped deployments
- Kustomization controller handles environment-specific overlays

**What I'd Do Differently:**
- ArgoCD may be preferable if UI/visibility is priority
- Consider ApplicationSets for dynamic environment management

---

### ADR-005: Zarf for Air-Gap Packaging

**Decision:** Use Zarf for air-gapped package management and deployment.

**Context:** Air-gapped environments need a secure, verifiable way to receive updates.

**Alternatives Considered:**

| Approach | Pros | Cons |
|----------|------|------|
| **Zarf** | DoD standard, signed packages, SBOM | Zarf-specific packaging |
| Custom tarball scripts | Full control | No verification, error-prone |
| Replicated/Helm charts | Commercial support | Vendor dependency |

**Rationale:**
- Zarf is the de facto standard in DoD Kubernetes deployments
- Single binary, single tarball simplifies transfer process
- Cryptographic verification ensures package integrity
- Built-in SBOM generation for supply chain compliance

**What I'd Do Differently:**
- Invest early in Zarf package automation in CI/CD
- Create golden packages for common platform components

---

### ADR-006: K3s for Air-Gapped Kubernetes

**Decision:** Use K3s for air-gapped/edge Kubernetes deployments.

**Context:** Need lightweight Kubernetes for resource-constrained, disconnected environments.

**Alternatives Considered:**

| Distribution | Pros | Cons |
|--------------|------|------|
| **K3s** | Single binary, low resources, proven air-gap | Not "enterprise" K8s |
| RKE2 | More enterprise features | Heavier than K3s |
| Kubeadm | Standard K8s | Complex setup, many dependencies |
| OpenShift | Enterprise support | Massive footprint |

**Rationale:**
- K3s is ~50MB single binary vs. 500MB+ for kubeadm clusters
- Proven air-gap deployment pattern with Zarf
- Rancher (SUSE) provides commercial support if needed
- Platform One Big Bang uses K3s for edge

**What I'd Do Differently:**
- RKE2 for environments requiring more enterprise features
- Consider Talos Linux for immutable, API-driven edge

---

### ADR-007: Three-Tier Network Architecture

**Decision:** Implement four subnet tiers: Public, Private, Isolated, Data.

**Context:** Need defense-in-depth network segmentation aligned with SCCA requirements.

**Design:**

| Tier | Purpose | Egress | Ingress |
|------|---------|--------|---------|
| Public | NAT Gateways, ALB | Internet | Internet (filtered) |
| Private | EKS nodes, applications | Via NAT | Via ALB only |
| Isolated | Internal services | None | Private tier only |
| Data | Databases | None | Private/Isolated only |

**Rationale:**
- Aligns with DoD SCCA boundary patterns (CAP, VDSS, VDMS)
- Isolated tier for sensitive workloads without egress
- Data tier provides additional layer for databases
- VPC endpoints eliminate need for data tier egress

**What I'd Do Differently:**
- Consider micro-segmentation at pod level (Network Policies) earlier
- Evaluate AWS Firewall Manager for cross-account policy consistency

---

### ADR-008: Security Lake for Log Aggregation

**Decision:** Use Amazon Security Lake with OCSF normalization for centralized logging.

**Context:** Need centralized, compliant log aggregation across multiple accounts and clouds.

**Alternatives Considered:**

| Solution | Pros | Cons |
|----------|------|------|
| **Security Lake** | Native AWS, OCSF, cost-effective | AWS-centric |
| Splunk Cloud | Powerful, mature | Expensive at scale |
| ELK/OpenSearch | Open source, flexible | Operational burden |
| Sumo Logic | Cloud-native, good gov | Yet another vendor |

**Rationale:**
- Security Lake is FedRAMP High authorized
- OCSF normalization enables cross-cloud correlation
- Cost-effective for high-volume log storage
- Native integration with Security Hub, GuardDuty

**What I'd Do Differently:**
- For multi-cloud, consider Splunk or Datadog for unified visibility
- Evaluate Athena query performance at scale before committing

---

## Compliance Decisions

### ADR-009: 80/20 Control Inheritance Model

**Decision:** Target 80% of FedRAMP High controls satisfied at Platform layer, 20% at Application layer.

**Rationale:**
- CSP inherits ~140 controls (AWS GovCloud FedRAMP authorization)
- Platform provides additional ~80 controls via standardized configuration
- Applications only need ~50-80 unique controls
- Dramatically reduces ATO effort for tenant applications

**Evidence Strategy:**
- Automated evidence generation via Terraform state + AWS Config
- AI-assisted SSP section drafting from infrastructure code
- Continuous compliance dashboard via Security Hub

---

### ADR-010: Continuous ATO (cATO) Architecture

**Decision:** Design for continuous authorization rather than point-in-time ATO.

**Rationale:**
- Traditional ATO is a 12-18 month point-in-time snapshot
- cATO provides real-time security posture visibility
- Aligns with DoD DevSecOps Reference Design
- Enables faster feature delivery without re-authorization

**Implementation:**
- Security Hub as continuous compliance dashboard
- AWS Config rules for drift detection
- OPA for policy enforcement in CI/CD
- Automated evidence bundle generation

---

## What Would I Do Next (Roadmap)

### Short-Term (Next 90 Days)

| Priority | Item | Rationale |
|----------|------|-----------|
| P0 | Production pilot with single tenant | Validate architecture under real load |
| P0 | SPIRE HA architecture | Single point of failure in current design |
| P1 | Azure full implementation | Move from stub to production-ready |
| P1 | Air-gap CI/CD pipeline | Automate Zarf package generation |
| P2 | Cost optimization | Right-size after baseline established |

### Medium-Term (90-180 Days)

| Priority | Item | Rationale |
|----------|------|-----------|
| P1 | CDS integration | Enable cross-domain data flows |
| P1 | Multi-region DR | Meet RTO/RPO requirements |
| P1 | Tenant self-service portal | Reduce platform team toil |
| P2 | Observability platform (Prometheus/Grafana) | Enhanced metrics beyond CloudWatch |
| P2 | Chaos engineering framework | Validate resilience assumptions |

### Long-Term (6-12 Months)

| Priority | Item | Rationale |
|----------|------|-----------|
| P1 | GCP Assured Workloads support | Tri-cloud portability |
| P1 | Machine learning workload support | GPU nodes, specialized scheduling |
| P2 | Edge mesh (multi-site K3s) | Distributed edge coordination |
| P2 | Confidential computing | TEE-based workload protection |
| P3 | eBPF-based observability | Replace sidecar-based approaches |

---

## Technical Debt and Known Limitations

| Item | Impact | Mitigation Plan |
|------|--------|-----------------|
| SPIRE single-server | HA risk | Deploy SPIRE HA with shared database |
| Manual Azure implementation | Portability gap | Complete Azure module in Phase 2 |
| No CDS integration | Cross-domain blocked | Abstract CDS interface designed |
| Limited automated testing | Regression risk | Add Terratest, policy tests |
| No GitOps for policies | Drift risk | Add Flux policy repository |

---

## Lessons Learned (If This Were Real)

1. **Start with policy-as-code from day one** - Retrofitting policies is painful
2. **SPIFFE/SPIRE complexity is real** - Budget extra time for identity layer
3. **Air-gap testing matters** - Simulate disconnected operations early
4. **Compliance automation pays off** - Manual evidence collection doesn't scale
5. **Keep the abstraction thin** - Over-abstraction creates debugging nightmares

---

## References

- [DoD DevSecOps Reference Design](https://dodcio.defense.gov/Portals/0/Documents/DoD%20Enterprise%20DevSecOps%20Reference%20Design%20v1.0_Public%20Release.pdf)
- [NIST 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [FedRAMP High Baseline](https://www.fedramp.gov/baselines/)
- [SPIFFE/SPIRE Documentation](https://spiffe.io/docs/)
- [Zarf Documentation](https://docs.zarf.dev/)
- [Platform One Big Bang](https://p1.dso.mil/products/big-bang)

---

*DECISIONS.md v1.0 - Living document, updated as architecture evolves*
