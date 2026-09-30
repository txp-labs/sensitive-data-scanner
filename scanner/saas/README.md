# sensitive-data-scanner-saas

The SaaS scanner: a container the customer runs **in its own environment**
(ECS, Azure Container Apps, Cloud Run, Kubernetes) with **read-only** grants to
its SaaS tenants. It samples mail, files and messages, reads them with the
cloud-neutral core (`../core`), and sends **findings only, never values**.
Mermera's own servers never read SaaS content for this.

Vendors are called over HTTPS with `requests`; no vendor SDK is imported. How
to consent, configure, deploy and verify it: [docs/SAAS.md](../../docs/SAAS.md).
