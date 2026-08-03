param namePrefix string
param location string
param exporterPrincipalId string
param subnetId string

var compactPrefix = toLower(replace(namePrefix, '-', ''))

resource auditStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: take('${compactPrefix}${uniqueString(resourceGroup().id)}audit', 24)
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS'
  }
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      virtualNetworkRules: [
        {
          action: 'Allow'
          id: subnetId
        }
      ]
      ipRules: []
    }
    encryption: {
      keySource: 'Microsoft.Storage'
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
    }
  }
  tags: {
    workload: 'core-buzz'
    dataClass: 'signed-ndjson-audit'
    exportCadence: 'daily'
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  name: 'default'
  parent: auditStorage
  properties: {
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    isVersioningEnabled: true
    changeFeed: {
      enabled: true
    }
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  name: 'signed-audit'
  parent: blobService
  properties: {
    publicAccess: 'None'
    metadata: {
      contentFormat: 'application/x-ndjson'
      signingRequired: 'true'
      exportCadence: 'daily'
    }
  }
}

resource unlockedRetention 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = {
  name: 'default'
  parent: auditContainer
  properties: {
    immutabilityPeriodSinceCreationInDays: 2555
    allowProtectedAppendWrites: true
    allowProtectedAppendWritesAll: false
  }
}

resource auditExporter 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(auditStorage.id, exporterPrincipalId, 'StorageBlobDataContributor')
  scope: auditStorage
  properties: {
    principalId: exporterPrincipalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', 'ba92f5b4-2d11-453d-a403-e96b0029c9fe')
  }
}

output storageAccountName string = auditStorage.name
output containerName string = auditContainer.name
output immutabilityState string = 'Unlocked'
