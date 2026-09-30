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
// readKeyVaultSecrets. deploy/azure/main.json is this template compiled
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
@description('Key Vault secrets: off by default. On grants Key Vault Secrets User and reads values (counts only).')
param readKeyVaultSecrets bool = false
@description('Cosmos DB for NoSQL accounts (resource IDs) to give the identity Cosmos DB Built-in Data Reader on.')
param cosmosAccountIds array = []
@secure()
param findingsHttpsUrl string = ''
@secure()
param findingsHmacKey string = ''
param findingsEventGridEndpoint string = ''
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
var roles = concat(readRoles, readKeyVaultSecrets ? [vaultReadRole] : [])
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
