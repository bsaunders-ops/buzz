targetScope = 'subscription'

param budgetName string
param resourceGroupName string
param monthlyBudgetUsd int = 350
param alertEmail string
param budgetStartDate string

resource monthlyBudget 'Microsoft.Consumption/budgets@2023-11-01' = {
  name: budgetName
  properties: {
    amount: monthlyBudgetUsd
    category: 'Cost'
    timeGrain: 'Monthly'
    timePeriod: {
      startDate: budgetStartDate
    }
    filter: {
      dimensions: {
        name: 'ResourceGroupName'
        operator: 'In'
        values: [resourceGroupName]
      }
    }
    notifications: {
      actual70: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 70
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual85: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 85
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      actual100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Actual'
        contactEmails: [alertEmail]
      }
      forecast100: {
        enabled: true
        operator: 'GreaterThanOrEqualTo'
        threshold: 100
        thresholdType: 'Forecasted'
        contactEmails: [alertEmail]
      }
    }
  }
}
