# sensitive-data-scanner-azure

The Azure scanner: a Container Apps job with a system-assigned managed
identity that discovers the data stores of every subscription under a
management group (Azure Resource Graph), reads them **read-only** with Reader
and the data-reader roles, and sends **findings only, never values**.

It is built on the cloud-neutral core (`../core`); Azure's SDKs are imported
here and never in the core. How to configure, deploy and verify it:
[docs/AZURE.md](../../docs/AZURE.md).
