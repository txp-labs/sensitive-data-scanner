# sensitive-data-scanner-gcp

The Google Cloud scanner: a Cloud Run job with its own service account that
discovers the data stores of every project under an organization or folder
(Cloud Asset Inventory), reads them **read-only** with viewer and reader
permissions, and sends **findings only, never values**.

It is built on the cloud-neutral core (`../core`); Google's libraries are
imported here and never in the core. Every Google API is called over REST
through google-auth, so the image carries no gRPC stack. How to configure,
deploy and verify it: [docs/GCP.md](../../docs/GCP.md).
