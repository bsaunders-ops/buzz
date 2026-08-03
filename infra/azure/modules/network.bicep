@description('Resource-name prefix.')
param namePrefix string

param location string
param originDnsLabel string

resource nsg 'Microsoft.Network/networkSecurityGroups@2024-05-01' = {
  name: '${namePrefix}-origin-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'AllowFrontDoorBackendHttps'
        properties: {
          priority: 100
          access: 'Allow'
          direction: 'Inbound'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'AzureFrontDoor.Backend'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2024-05-01' = {
  name: '${namePrefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.42.0.0/16'
      ]
    }
    subnets: [
      {
        name: 'origin'
        properties: {
          addressPrefix: '10.42.1.0/24'
          networkSecurityGroup: {
            id: nsg.id
          }
          serviceEndpoints: [
            {
              service: 'Microsoft.KeyVault'
              locations: [location]
            }
            {
              service: 'Microsoft.ContainerRegistry'
              locations: [location]
            }
            {
              service: 'Microsoft.Storage'
              locations: [location]
            }
          ]
        }
      }
    ]
  }
}

resource originSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-05-01' existing = {
  name: 'origin'
  parent: virtualNetwork
}

resource publicIp 'Microsoft.Network/publicIPAddresses@2024-05-01' = {
  name: '${namePrefix}-origin-pip'
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: originDnsLabel
    }
  }
  zones: ['1', '2', '3']
}

resource networkInterface 'Microsoft.Network/networkInterfaces@2024-05-01' = {
  name: '${namePrefix}-origin-nic'
  location: location
  properties: {
    enableAcceleratedNetworking: true
    ipConfigurations: [
      {
        name: 'primary'
        properties: {
          primary: true
          privateIPAllocationMethod: 'Dynamic'
          subnet: {
            id: originSubnet.id
          }
          publicIPAddress: {
            id: publicIp.id
          }
        }
      }
    ]
  }
}

output subnetId string = originSubnet.id
output networkInterfaceId string = networkInterface.id
output originPublicIp string = publicIp.properties.ipAddress
output originPublicFqdn string = publicIp.properties.dnsSettings.fqdn
