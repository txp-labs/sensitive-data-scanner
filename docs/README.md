# Documentation

Start with the [README](../README.md): what the scanner reads, what it
detects, how it stays safe, and how proven each path is.

## Deploy and run

| Document | What it covers |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The AWS scanner: batch mode, configuration, discovery and the coverage by store, the readers (columnar, Office, PDFs, archives), the object index and smart rescans, S3 Inventory, every AWS store, least-privilege IAM, the estate rollout, and the event-driven design |
| [AZURE.md](AZURE.md) | The Azure scanner: stores and the roles each needs, findings, settings, deploying the Bicep at a management group |
| [GCP.md](GCP.md) | The Google Cloud scanner: stores and the permissions each needs, Sensitive Data Protection's profiles, findings, settings, deploying the Terraform |
| [DATABASES.md](DATABASES.md) | The databases runner: engines and how each is kept read-only, settings, tables unchanged since the last read, deploying with docker, Kubernetes, ECS or Azure Container Instances |
| [SAAS.md](SAAS.md) | The SaaS scanner: Microsoft 365, Google Workspace, Slack, Jira and Confluence, consent and read-only grants, vendor detection (Purview, Workspace DLP, Slack DLP), settings, deploying |

## Findings and releases

| Document | What it covers |
|---|---|
| [FINDINGS.md](FINDINGS.md) | The findings contract: the versioned JSON Schema, every resource kind, sources and modes, masking, encryption and PCI DSS notes, the coverage and run summary |
| [RELEASING.md](RELEASING.md) | What a release contains (images, zip, SBOMs, checksums), how one is cut, and what is still to be decided (signing) |
| [release-notes/](release-notes) | Each release's notes: what is proven by tests, what has run in a real account, and what is not yet proven |
| [CHANGELOG.md](../CHANGELOG.md) | Every change, by release |

## The detection

| Document | What it covers |
|---|---|
| [spec/README.md](../spec/README.md) | The spec: classes, prompts, normalization, and how the rules are read |
| [vectors/README.md](../vectors/README.md) | The synthetic test vectors every implementation passes |
| [packages/spec-ts/README.md](../packages/spec-ts/README.md) | The TypeScript package for redacting a live call in memory |
| [scanner/README.md](../scanner/README.md) | The Python packages, the Presidio recognizers, and development |
| [BENCHMARK.md](BENCHMARK.md) | The accuracy benchmark: a made-up, labeled corpus, precision and recall per class and confidence, the baseline CI holds, and the false-positive sources it found |

## Security

| Document | What it covers |
|---|---|
| [THREAT-MODEL.md](THREAT-MODEL.md) | Assets, trust boundaries, attackers, STRIDE per boundary, mitigations mapped to the code and tests that hold them, and the residual risks |

## Contributing and security

- [CONTRIBUTING.md](../CONTRIBUTING.md): issues are welcome; outside pull
  requests open once the Contributor License Agreement completes legal review.
- [SECURITY.md](../SECURITY.md): report a vulnerability privately, never in a
  public issue.
