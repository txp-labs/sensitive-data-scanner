// The scanner's Container Apps job, its environment and its own state storage.
//
// The job runs as its system-assigned managed identity. The only thing it may
// write is its own blob container (findings, cursors, lock): Storage Blob Data
// Contributor on that container, and on nothing else. Every read role is
// assigned by main.bicep, at the management group or the subscription.
targetScope = 'resourceGroup'

@description('The job name; also the identity name that databases know the scanner by.')
param jobName string
param location string
param image string
@description('Cron (UTC) for the scheduled runs.')
param schedule string
param replicaTimeoutSeconds int
param site string
@description('AZURE_MANAGEMENT_GROUP for a central job; empty for a per-subscription job.')
param managementGroup string = ''
@description('AZURE_SUBSCRIPTIONS for a per-subscription job; empty for a central job.')
param subscriptionIds array = []
param discover string = ''
param readDatabases string = ''
param readKeyVaultSecrets bool = false
param readFileShares bool = false
@secure()
param findingsHttpsUrl string = ''
@secure()
param findingsHmacKey string = ''
param findingsEventGridEndpoint string = ''
@description('A subnet (/27 or larger, delegated to Microsoft.App/environments) to reach private endpoints; empty for none.')
param infrastructureSubnetId string = ''
param stateAccountName string = 'sds${uniqueString(resourceGroup().id)}'
param tags object = {}

// Storage Blob Data Contributor: the job's own container only.
var blobDataContributor = 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
var stateContainerName = 'scanner'

resource state 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: stateAccountName
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    allowSharedKeyAccess: false
    allowBlobPublicAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

resource blobs 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: state
  name: 'default'
}

resource stateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobs
  name: stateContainerName
  properties: {
    publicAccess: 'None'
  }
}

resource environment 'Microsoft.App/managedEnvironments@2024-03-01' = {
  name: '${jobName}-env'
  location: location
  tags: tags
  properties: {
    workloadProfiles: [
      {
        name: 'Consumption'
        workloadProfileType: 'Consumption'
      }
    ]
    vnetConfiguration: empty(infrastructureSubnetId)
      ? null
      : {
          infrastructureSubnetId: infrastructureSubnetId
          internal: true
        }
  }
}

var pushSecrets = empty(findingsHttpsUrl)
  ? []
  : [
      {
        name: 'findings-https-url'
        value: findingsHttpsUrl
      }
      {
        name: 'findings-hmac-key'
        value: findingsHmacKey
      }
    ]

var pushEnv = empty(findingsHttpsUrl)
  ? []
  : [
      {
        name: 'FINDINGS_HTTPS_URL'
        secretRef: 'findings-https-url'
      }
      {
        name: 'FINDINGS_HMAC_KEY'
        secretRef: 'findings-hmac-key'
      }
    ]

var settings = filter(
  [
    {
      name: 'SCANNER_SITE'
      value: site
    }
    {
      name: 'AZURE_MANAGEMENT_GROUP'
      value: managementGroup
    }
    {
      name: 'AZURE_SUBSCRIPTIONS'
      value: join(subscriptionIds, ',')
    }
    {
      name: 'STATE_CONTAINER_URL'
      value: '${state.properties.primaryEndpoints.blob}${stateContainerName}'
    }
    {
      name: 'DISCOVER'
      value: discover
    }
    {
      name: 'AZURE_DB_READ'
      value: readDatabases
    }
    {
      name: 'AZURE_DB_PRINCIPAL'
      value: empty(readDatabases) ? '' : jobName
    }
    {
      name: 'KEYVAULT_SECRETS_READ'
      value: readKeyVaultSecrets ? 'on' : 'off'
    }
    {
      name: 'AZURE_FILES_READ'
      value: readFileShares ? 'on' : 'off'
    }
    {
      name: 'FINDINGS_EVENT_GRID_ENDPOINT'
      value: findingsEventGridEndpoint
    }
  ],
  s => !empty(s.value)
)

resource job 'Microsoft.App/jobs@2024-03-01' = {
  name: jobName
  location: location
  tags: tags
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    environmentId: environment.id
    workloadProfileName: 'Consumption'
    configuration: {
      triggerType: 'Schedule'
      replicaTimeout: replicaTimeoutSeconds
      replicaRetryLimit: 0
      scheduleTriggerConfig: {
        cronExpression: schedule
        parallelism: 1
        replicaCompletionCount: 1
      }
      secrets: pushSecrets
    }
    template: {
      containers: [
        {
          name: 'scanner'
          image: image
          args: [
            'scan'
          ]
          resources: {
            cpu: json('1.0')
            memory: '2Gi'
          }
          env: concat(settings, pushEnv)
        }
      ]
    }
  }
}

resource stateWriter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(stateContainer.id, job.id, blobDataContributor)
  scope: stateContainer
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', blobDataContributor)
    principalId: job.identity.principalId
    principalType: 'ServicePrincipal'
    description: 'sensitive-data-scanner: its own findings, cursors and lock'
  }
}

output principalId string = job.identity.principalId
output stateContainerUrl string = '${state.properties.primaryEndpoints.blob}${stateContainerName}'
