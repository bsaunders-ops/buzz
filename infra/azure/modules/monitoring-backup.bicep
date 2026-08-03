param namePrefix string
param location string
param vmName string
param vmResourceId string
param alertEmail string

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${namePrefix}-operators'
  location: 'global'
  properties: {
    groupShortName: take('${namePrefix}ops', 12)
    enabled: true
    emailReceivers: [
      {
        name: 'primary-operator'
        emailAddress: alertEmail
        useCommonAlertSchema: true
      }
    ]
  }
}

resource vmUnavailable 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${namePrefix}-vm-unavailable'
  location: 'global'
  properties: {
    description: 'Core VM availability is below one.'
    severity: 1
    enabled: true
    scopes: [vmResourceId]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'VmAvailability'
          metricNamespace: 'Microsoft.Compute/virtualMachines'
          metricName: 'VmAvailabilityMetric'
          operator: 'LessThan'
          threshold: 1
          timeAggregation: 'Average'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
  }
}

resource recoveryVault 'Microsoft.RecoveryServices/vaults@2024-04-01' = {
  name: '${namePrefix}-backup-vault'
  location: location
  sku: {
    name: 'RS0'
    tier: 'Standard'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    securitySettings: {
      softDeleteSettings: {
        softDeleteState: 'AlwaysON'
        softDeleteRetentionPeriodInDays: 14
      }
    }
  }
}

resource dailyPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2024-04-01' = {
  name: 'core-daily'
  parent: recoveryVault
  properties: {
    backupManagementType: 'AzureIaasVM'
    instantRpRetentionRangeInDays: 5
    schedulePolicy: {
      schedulePolicyType: 'SimpleSchedulePolicy'
      scheduleRunFrequency: 'Daily'
      scheduleRunTimes: [
        '2026-08-03T02:00:00Z'
      ]
    }
    retentionPolicy: {
      retentionPolicyType: 'LongTermRetentionPolicy'
      dailySchedule: {
        retentionTimes: [
          '2026-08-03T02:00:00Z'
        ]
        retentionDuration: {
          count: 30
          durationType: 'Days'
        }
      }
    }
    timeZone: 'UTC'
  }
}

resource protectedVm 'Microsoft.RecoveryServices/vaults/backupFabrics/protectionContainers/protectedItems@2024-04-01' = {
  name: '${recoveryVault.name}/Azure/iaasvmcontainer;iaasvmcontainerv2;${resourceGroup().name};${vmName}/vm;iaasvmcontainerv2;${resourceGroup().name};${vmName}'
  properties: {
    protectedItemType: 'Microsoft.Compute/virtualMachines'
    policyId: dailyPolicy.id
    sourceResourceId: vmResourceId
  }
}

resource vm 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

resource vmDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${namePrefix}-vm-diagnostics'
  scope: vm
  properties: {
    workspaceId: workspace.id
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

output logAnalyticsWorkspaceId string = workspace.id
output recoveryVaultName string = recoveryVault.name
