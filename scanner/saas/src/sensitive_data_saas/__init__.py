"""The SaaS scanner of the sensitive data scanner: findings only, never values.

A container the customer runs in its own environment (ECS, Azure Container
Apps, Cloud Run, Kubernetes), with read-only grants to its SaaS tenants:
Microsoft 365 (Exchange Online mail, SharePoint and OneDrive files, Teams
messages), Google Workspace (Gmail, My Drive and shared drives) and Slack
(channels, their threads and files; direct messages through Discovery), and
Atlassian (Jira issues and Confluence pages, with comments and attachments). It
samples their content with the core's readers and pushes findings only;
Mermera's own servers never read SaaS content for this. Every tenant or
source it cannot read is in the run summary with a reason. Detection, the
findings contract, budgets, sampling and the readers are the core's
(`sensitive_data_core`); the vendors are called over HTTPS here, with no vendor
SDK.
"""

__version__ = "0.4.1"
