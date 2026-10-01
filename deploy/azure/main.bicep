// The sensitive data scanner for Azure, deployed at a management group.
//
//   az deployment mg create --management-group-id <mg> --location <region> \
//     --template-file deploy/azure/main.bicep --parameters scannerSubscriptionId=<sub> ...
//
// mode 'central' (the default): one Container Apps job in scannerSubscriptionId that
// discovers every subscription under this management group, with the read roles
// assigned once, at the management group.
// mode 'perSubscription': one job in each of subscriptionIds, each reading only its
// own subscription, with the read roles assigned at that subscription.
//
// Every role the job is given reads, except Storage Blob Data Contributor on its
// own state container (modules/job.bicep); Key Vault Secrets User only with
// readKeyVaultSecrets; Storage File Data Privileged Reader only with readFileShares. deploy/azure/main.json is this template compiled
// (`bicep build`), and scanner/tests/test_azure_template.py holds it to that.
targetScope = 'managementGroup'

@allowed([
  'central'
  'perSubscription'
])
param mode string = 'central'
@description('Central mode: the subscription the job runs in.')
param scannerSubscriptionId string = ''
@description('Per-subscription mode: the subscriptions that each get a job.')
param subscriptionIds array = []
param location string
param resourceGroupName string = 'sensitive-data-scanner'
@description('The job name; for PostgreSQL and MySQL, the database user of its identity.')
param jobName string = 'sds-scanner-job'
@description('The image, pinned by digest: ghcr.io/txp-labs/sensitive-data-scanner-azure@sha256:...')
param image string
@description('When the job runs (cron, UTC). Daily by default.')
param schedule string = '0 6 * * *'
param replicaTimeoutSeconds int = 3600
@description('The site findings name (lower case, digits, ., _, -); the management group by default.')
param site string = toLower(managementGroup().name)
@description('DISCOVER: the kinds to discover; empty for every kind.')
param discover string = ''
@description('AZURE_DB_READ: the database kinds read (off by default); each needs the identity as a user.')
param readDatabases string = ''
@description('KEYVAULT_SECRETS_READ: Key Vault secrets, off by default. True grants Key Vault Secrets User and reads values (counts only); without it, Mermera turning it on is reported gate: iam. Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param readKeyVaultSecrets bool?
@description('AZURE_FILES_READ: Azure Files shares, off by default. True grants Storage File Data Privileged Reader (reads files over REST, overriding their ACLs) and reads them; without it, Mermera turning it on is reported gate: iam. Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param readFileShares bool?
@description('Cosmos DB for NoSQL accounts (resource IDs) to give the identity Cosmos DB Built-in Data Reader on.')
param cosmosAccountIds array = []
@description('AZURE_LOG_ANALYTICS: read Log Analytics workspaces with Reader (on by default); off lists them, read_not_configured (docs/limitations.md, B1). Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param readLogAnalytics bool?
@description('AZURE_READ_SNAPSHOTS: a hook, off by default. A snapshot is read only by a SAS export, a write, and no reader is built: on, each snapshot is reported not_implemented (B4). Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param readDiskSnapshots bool?
@description('AZURE_COSMOS_READER_POLICY: a hook, off by default. The Azure Policy that would give the identity Cosmos DB Built-in Data Reader on every NoSQL account is not built (its remediation identity would need a write role): on, an account the identity cannot read is reported not_implemented; use cosmosAccountIds (B3). Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param assignCosmosReaderPolicy bool?
@description('AZURE_READ_COLD_TIER: read Cold-tier blobs, which have a read fee per GB (the run\'s costEstimate says how much); off by default, they are counted notAllowed cold_tier (#109). Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param readColdTier bool?
@description('AZURE_REHYDRATE_ARCHIVE: a hook, off by default. An Archive-tier blob needs a rehydration (a write, at the customer\'s cost) and is the gap needs_rehydration; on, the tier says not_implemented (#109). Unset (null, the default): Mermera\'s setting, else the scanner\'s default (docs/mermera-config.md).')
param rehydrateArchive bool?
@secure()
param findingsHttpsUrl string = ''
@secure()
param findingsHmacKey string = ''
param findingsEventGridEndpoint string = ''
@description('AZURE_BLOB_INVENTORY_MIN_OBJECTS: a container whose last complete pass listed at least this many blobs is named in the run summary (recommendation: blob_inventory); 0 never names one.')
@minValue(0)
@maxValue(10000000000)
param blobInventoryMinObjects int = 1000000
@description('Days the job\'s state container keeps per-run files (findings/runs/) and their versions; 0 keeps them forever (#119). Template-only: not settable from Mermera.')
@minValue(0)
@maxValue(36500)
param findingsRetentionDays int = 90
@description('A subnet delegated to Microsoft.App/environments, to reach private endpoints (central mode).')
param infrastructureSubnetId string = ''
param tags object = {}

// Built-in roles, all read-only (scanner/tests/test_azure_template.py checks each one's
// actions): Reader (every resource's metadata; Resource Graph; Log Analytics queries,
// workspaces/query/read), and the data readers of Blob, Table and Queue Storage.
var readRoles = [
  'acdd72a7-3b69-4de9-b1f8-e1ede9c4a46c' // Reader
  '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1' // Storage Blob Data Reader
  '76199698-9eea-4c19-bc75-cec21354c6b6' // Storage Table Data Reader
  '19e7f393-937e-4f77-808e-94535e297925' // Storage Queue Data Reader
]
var vaultReadRole = '4633458b-17de-408a-b874-0445c86b69e6'
var fileReadRole = 'b8eda974-7b85-4f76-af95-65846b26df6d' // Storage File Data Privileged Reader
var roles = concat(
  readRoles,
  readKeyVaultSecrets == true ? [vaultReadRole] : [],
  readFileShares == true ? [fileReadRole] : []
)
var central = mode == 'central'

module centralGroup 'modules/resource-group.bicep' = if (central) {
  name: 'sds-rg-central'
  scope: subscription(scannerSubscriptionId)
  params: {
    name: resourceGroupName
    location: location
    tags: tags
  }
}

module centralJob 'modules/job.bicep' = if (central) {
  name: 'sds-job-central'
  scope: resourceGroup(scannerSubscriptionId, resourceGroupName)
  dependsOn: [
    centralGroup
  ]
  params: {
    jobName: jobName
    location: location
    image: image
    schedule: schedule
    replicaTimeoutSeconds: replicaTimeoutSeconds
    site: site
    managementGroup: managementGroup().name
    discover: discover
    readDatabases: readDatabases
    readKeyVaultSecrets: readKeyVaultSecrets
    readFileShares: readFileShares
    readLogAnalytics: readLogAnalytics
    readDiskSnapshots: readDiskSnapshots
    assignCosmosReaderPolicy: assignCosmosReaderPolicy
    readColdTier: readColdTier
    rehydrateArchive: rehydrateArchive
    blobInventoryMinObjects: blobInventoryMinObjects
    findingsRetentionDays: findingsRetentionDays
    findingsHttpsUrl: findingsHttpsUrl
    findingsHmacKey: findingsHmacKey
    findingsEventGridEndpoint: findingsEventGridEndpoint
    infrastructureSubnetId: infrastructureSubnetId
    tags: tags
  }
}

resource centralRead 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for role in roles: if (central) {
    name: guid(managementGroup().id, jobName, role)
    properties: {
      roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', role)
      principalId: centralJob!.outputs.principalId
      principalType: 'ServicePrincipal'
      description: 'sensitive-data-scanner: read-only'
    }
  }
]

module groups 'modules/resource-group.bicep' = [
  for sub in subscriptionIds: if (!central) {
    name: 'sds-rg-${uniqueString(sub)}'
    scope: subscription(sub)
    params: {
      name: resourceGroupName
      location: location
      tags: tags
    }
  }
]

module jobs 'modules/job.bicep' = [
  for (sub, i) in subscriptionIds: if (!central) {
    name: 'sds-job-${uniqueString(sub)}'
    scope: resourceGroup(sub, resourceGroupName)
    dependsOn: [
      groups[i]
    ]
    params: {
      jobName: jobName
      location: location
      image: image
      schedule: schedule
      replicaTimeoutSeconds: replicaTimeoutSeconds
      site: site
      subscriptionIds: [
        sub
      ]
      discover: discover
      readDatabases: readDatabases
      readKeyVaultSecrets: readKeyVaultSecrets
      readFileShares: readFileShares
      readLogAnalytics: readLogAnalytics
      readDiskSnapshots: readDiskSnapshots
      assignCosmosReaderPolicy: assignCosmosReaderPolicy
    readColdTier: readColdTier
    rehydrateArchive: rehydrateArchive
      blobInventoryMinObjects: blobInventoryMinObjects
      findingsRetentionDays: findingsRetentionDays
      findingsHttpsUrl: findingsHttpsUrl
      findingsHmacKey: findingsHmacKey
      findingsEventGridEndpoint: findingsEventGridEndpoint
      tags: tags
    }
  }
]

module subscriptionRead 'modules/read-roles.bicep' = [
  for (sub, i) in subscriptionIds: if (!central) {
    name: 'sds-read-${uniqueString(sub)}'
    scope: subscription(sub)
    params: {
      principalId: jobs[i]!.outputs.principalId
      roles: roles
    }
  }
]

module cosmosReaders 'modules/cosmos-reader.bicep' = [
  for account in cosmosAccountIds: if (central) {
    name: 'sds-cosmos-${uniqueString(account)}'
    scope: resourceGroup(split(account, '/')[2], split(account, '/')[4])
    params: {
      accountName: last(split(account, '/'))
      principalId: centralJob!.outputs.principalId
    }
  }
]

output principalId string = central ? centralJob!.outputs.principalId : ''
