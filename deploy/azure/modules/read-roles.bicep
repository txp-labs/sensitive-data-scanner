// The read roles of a per-subscription job, at its own subscription.
targetScope = 'subscription'

param principalId string
param roles array

resource read 'Microsoft.Authorization/roleAssignments@2022-04-01' = [
  for role in roles: {
    name: guid(subscription().id, principalId, role)
    properties: {
      roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', role)
      principalId: principalId
      principalType: 'ServicePrincipal'
      description: 'sensitive-data-scanner: read-only'
    }
  }
]
