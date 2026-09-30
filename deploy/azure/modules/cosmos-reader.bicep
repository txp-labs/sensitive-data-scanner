// Cosmos DB Built-in Data Reader on one Cosmos DB for NoSQL account, for the job's
// identity. It is a Cosmos DB role assignment (data plane), not an Azure RBAC one,
// so it is made per account and cannot be given at the management group.
targetScope = 'resourceGroup'

param accountName string
param principalId string

// Cosmos DB Built-in Data Reader: readMetadata, and items/read, executeQuery,
// readChangeFeed on containers. Nothing that writes.
var builtInDataReader = '00000000-0000-0000-0000-000000000001'

resource account 'Microsoft.DocumentDB/databaseAccounts@2024-11-15' existing = {
  name: accountName
}

resource reader 'Microsoft.DocumentDB/databaseAccounts/sqlRoleAssignments@2024-11-15' = {
  parent: account
  name: guid(account.id, principalId, builtInDataReader)
  properties: {
    roleDefinitionId: '${account.id}/sqlRoleDefinitions/${builtInDataReader}'
    principalId: principalId
    scope: account.id
  }
}
