param dnsZoneName string

resource dnsZone 'Microsoft.Network/dnsZones@2023-07-01-preview' = {
  name: dnsZoneName
  location: 'global'
  tags: {
    workload: 'core-buzz'
    managedBy: 'bicep'
  }
}

output zoneResourceId string = dnsZone.id
