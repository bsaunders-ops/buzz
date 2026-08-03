param namePrefix string
param location string
param subnetId string

var compactPrefix = toLower(replace(namePrefix, '-', ''))

resource registry 'Microsoft.ContainerRegistry/registries@2026-03-01-preview' = {
  name: take('${compactPrefix}${uniqueString(resourceGroup().id)}acr', 50)
  location: location
  sku: {
    name: 'Premium'
  }
  properties: {
    adminUserEnabled: false
    anonymousPullEnabled: false
    dataEndpointEnabled: false
    networkRuleBypassOptions: 'AzureServices'
    publicNetworkAccess: 'Enabled'
    networkRuleSet: {
      defaultAction: 'Deny'
      virtualNetworkRules: [
        {
          action: 'Allow'
          virtualNetworkSubnetResourceId: subnetId
        }
      ]
    }
    policies: {
      retentionPolicy: {
        days: 14
        status: 'enabled'
      }
      trustPolicy: {
        type: 'Notary'
        status: 'enabled'
      }
    }
  }
  tags: {
    workload: 'core-buzz'
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2024-11-01' = {
  name: take('${compactPrefix}${uniqueString(resourceGroup().id)}kv', 24)
  location: location
  properties: {
    tenantId: tenant().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
    enableRbacAuthorization: true
    enablePurgeProtection: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    publicNetworkAccess: 'Enabled'
    networkAcls: {
      bypass: 'AzureServices'
      defaultAction: 'Deny'
      virtualNetworkRules: [
        {
          id: subnetId
          ignoreMissingVnetServiceEndpoint: false
        }
      ]
    }
  }
  tags: {
    workload: 'core-buzz'
  }
}

output acrName string = registry.name
output acrLoginServer string = registry.properties.loginServer
output keyVaultName string = keyVault.name
