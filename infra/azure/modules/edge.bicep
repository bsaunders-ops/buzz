param namePrefix string
param originFqdn string

@secure()
param originSecret string

param customDomainHostName string = ''

var profileName = '${namePrefix}-afd'
var endpointName = '${namePrefix}-core'
var customDomainEnabled = !empty(customDomainHostName)

resource profile 'Microsoft.Cdn/profiles@2024-09-01' = {
  name: profileName
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
  properties: {
    originResponseTimeoutSeconds: 60
  }
}

resource endpoint 'Microsoft.Cdn/profiles/afdEndpoints@2024-09-01' = {
  name: endpointName
  parent: profile
  location: 'global'
  properties: {
    enabledState: 'Enabled'
  }
}

resource originGroup 'Microsoft.Cdn/profiles/originGroups@2024-09-01' = {
  name: 'core-origin-group'
  parent: profile
  properties: {
    loadBalancingSettings: {
      sampleSize: 4
      successfulSamplesRequired: 3
      additionalLatencyInMilliseconds: 50
    }
    healthProbeSettings: {
      probePath: '/origin-healthz'
      probeRequestType: 'GET'
      probeProtocol: 'Https'
      probeIntervalInSeconds: 30
    }
    sessionAffinityState: 'Disabled'
  }
}

resource origin 'Microsoft.Cdn/profiles/originGroups/origins@2024-09-01' = {
  name: 'core-origin'
  parent: originGroup
  properties: {
    enabledState: 'Enabled'
    hostName: originFqdn
    originHostHeader: originFqdn
    httpPort: 80
    httpsPort: 443
    priority: 1
    weight: 1000
    enforceCertificateNameCheck: true
    sharedPrivateLinkResource: null
  }
}

resource route 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-09-01' = {
  name: 'core-route'
  parent: endpoint
  dependsOn: [origin]
  properties: {
    originGroup: {
      id: originGroup.id
    }
    ruleSets: [
      {
        id: originHeaderRuleSet.id
      }
    ]
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Enabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: null
    originPath: ''
  }
}

resource customDomain 'Microsoft.Cdn/profiles/customDomains@2024-09-01' = if (customDomainEnabled) {
  name: '${namePrefix}-custom-domain'
  parent: profile
  properties: {
    hostName: customDomainHostName
    tlsSettings: {
      certificateType: 'ManagedCertificate'
      minimumTlsVersion: 'TLS12'
    }
  }
}

resource routeWithCustomDomain 'Microsoft.Cdn/profiles/afdEndpoints/routes@2024-09-01' = if (customDomainEnabled) {
  name: 'core-custom-domain-route'
  parent: endpoint
  dependsOn: [origin]
  properties: {
    originGroup: {
      id: originGroup.id
    }
    ruleSets: [
      {
        id: originHeaderRuleSet.id
      }
    ]
    customDomains: [
      {
        id: customDomain.id
      }
    ]
    supportedProtocols: ['Https']
    patternsToMatch: ['/*']
    forwardingProtocol: 'HttpsOnly'
    linkToDefaultDomain: 'Disabled'
    httpsRedirect: 'Enabled'
    enabledState: 'Enabled'
    cacheConfiguration: null
  }
}

resource wafPolicy 'Microsoft.Network/frontDoorWebApplicationFirewallPolicies@2024-02-01' = {
  name: take('${replace(namePrefix, '-', '')}waf', 128)
  location: 'global'
  sku: {
    name: 'Standard_AzureFrontDoor'
  }
  properties: {
    policySettings: {
      enabledState: 'Enabled'
      mode: 'Prevention'
      requestBodyCheck: 'Enabled'
    }
    customRules: {
      rules: [
        {
          name: 'RateLimitRule'
          enabledState: 'Enabled'
          priority: 10
          ruleType: 'RateLimitRule'
          rateLimitDurationInMinutes: 1
          rateLimitThreshold: 300
          action: 'Block'
          matchConditions: [
            {
              matchVariable: 'RemoteAddr'
              operator: 'IPMatch'
              negateCondition: false
              matchValue: [
                '0.0.0.0/0'
                '::/0'
              ]
              transforms: []
            }
          ]
        }
      ]
    }
  }
}

resource securityPolicy 'Microsoft.Cdn/profiles/securityPolicies@2024-09-01' = {
  name: 'core-security-policy'
  parent: profile
  properties: {
    parameters: {
      type: 'WebApplicationFirewall'
      wafPolicy: {
        id: wafPolicy.id
      }
      associations: [
        {
          domains: concat(
            [{ id: endpoint.id }],
            customDomainEnabled ? [{ id: customDomain.id }] : []
          )
          patternsToMatch: ['/*']
        }
      ]
    }
  }
}

// Front Door sends this secret header on every origin request. Caddy rejects requests without it.
resource originHeaderRuleSet 'Microsoft.Cdn/profiles/ruleSets@2024-09-01' = {
  name: 'origin-validation'
  parent: profile
}

resource originHeaderRule 'Microsoft.Cdn/profiles/ruleSets/rules@2024-09-01' = {
  name: 'add-origin-secret'
  parent: originHeaderRuleSet
  properties: {
    order: 1
    conditions: []
    actions: [
      {
        name: 'ModifyRequestHeader'
        parameters: {
          typeName: 'DeliveryRuleHeaderActionParameters'
          headerAction: 'Overwrite'
          headerName: 'X-Buzz-Origin-Secret'
          value: originSecret
        }
      }
    ]
  }
}

output endpointHostName string = endpoint.properties.hostName
output frontDoorId string = profile.properties.frontDoorId
output customDomainValidationToken string = customDomainEnabled ? customDomain!.properties.validationProperties.validationToken : ''
