targetScope = 'subscription'

@description('Short lowercase prefix used for globally unique resource names.')
@minLength(3)
@maxLength(12)
param namePrefix string

@description('Azure region for the single-node Core foundation.')
param location string = 'eastus2'

@description('Resource group created for the Core foundation.')
param resourceGroupName string = '${namePrefix}-core-rg'

@description('Linux administrator name. Authentication is key-only; no inbound SSH rule is created.')
param adminUsername string = 'azureadmin'

@secure()
@description('Public half of the break-glass administration key. Use Entra Run Command/JIT for routine administration.')
param adminSshPublicKey string

@description('Exact Ubuntu 24.04 Gen2 marketplace image version selected during approved what-if review.')
param ubuntuImageVersion string

@description('Public DNS name that resolves to the VM origin public IP and is presented by Caddy.')
param originFqdn string

@secure()
@description('Front Door custom origin-header value. Supply at deployment time; never persist it in a parameter file.')
param originSecret string

@description('Key Vault secret name from which the VM retrieves the Front Door origin header value.')
param originSecretName string = 'frontdoor-origin-secret'

@description('ACR bootstrap bundle image pinned as this foundation ACR/repository@sha256:digest.')
param bootstrapBundleImage string

@description('Relay image reference pinned as registry/repository@sha256:digest.')
param relayImage string

@description('Postgres/pgvector image reference pinned by digest.')
param postgresImage string

@description('Redis image reference pinned by digest.')
param redisImage string

@description('MinIO server image reference pinned by digest.')
param minioImage string

@description('MinIO client image reference pinned by digest.')
param minioMcImage string

@description('Caddy image reference pinned by digest.')
param caddyImage string

@description('Core worker image pinned by digest. Worker services remain behind the Month-1 Compose profile until rollout approval.')
param coreWorkerImage string

@description('CONNECT allowlisting proxy image pinned by digest.')
param egressProxyImage string

@description('Explicit service activation gate. Foundation deployments leave the Compose project stopped.')
param startCoreServices bool = false

@description('Explicit rollout gate for the least-privilege Month-1 worker profile. False installs only the relay foundation.')
@allowed([false])
param enableMonth1Workers bool = false

@description('Blake relay-owner x-only public key. May be empty while services remain disabled; activation fails closed without a valid 64-character hex key.')
param relayOwnerPubkey string = ''

@description('Explicit second-phase gate after the bootstrap bundle digest exists in ACR.')
param enableHostBootstrap bool = false

@description('Optional public custom-domain hostname for Front Door. Empty leaves custom-domain resources disabled.')
param frontDoorCustomDomainHostName string = ''

@description('Optional Azure DNS zone name. The zone is created only when manageDnsZone is explicitly true.')
param dnsZoneName string = ''

@description('Explicit opt-in for creating the Azure DNS zone. DNS records remain a separate operator action.')
param manageDnsZone bool = false

@description('Email recipient for Monitor and budget notifications.')
param alertEmail string

@description('Monthly cost budget in USD.')
param monthlyBudgetUsd int = 350

@description('Budget evaluation start in yyyy-MM-01 format.')
param budgetStartDate string = utcNow('yyyy-MM-01')

resource resourceGroup 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: resourceGroupName
  location: location
  tags: {
    workload: 'core-buzz'
    deliveryLane: 'month1-azure'
  }
}

module dns 'modules/dns.bicep' = if (manageDnsZone) {
  name: '${namePrefix}-dns'
  scope: resourceGroup
  params: {
    dnsZoneName: dnsZoneName
  }
}

module network 'modules/network.bicep' = {
  name: '${namePrefix}-network'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    location: location
    originDnsLabel: '${namePrefix}-origin'
  }
}

module security 'modules/security.bicep' = {
  name: '${namePrefix}-security'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    location: location
    subnetId: network.outputs.subnetId
  }
}

module compute 'modules/compute.bicep' = {
  name: '${namePrefix}-compute'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    location: location
    networkInterfaceId: network.outputs.networkInterfaceId
    adminUsername: adminUsername
    adminSshPublicKey: adminSshPublicKey
    ubuntuImageVersion: ubuntuImageVersion
  }
}

module identityAccess 'modules/identity-access.bicep' = {
  name: '${namePrefix}-identity-access'
  scope: resourceGroup
  params: {
    principalId: compute.outputs.principalId
    acrName: security.outputs.acrName
    keyVaultName: security.outputs.keyVaultName
  }
}

module hostBootstrap 'modules/host-bootstrap.bicep' = if (enableHostBootstrap) {
  name: '${namePrefix}-host-bootstrap'
  scope: resourceGroup
  dependsOn: [identityAccess]
  params: {
    location: location
    vmName: compute.outputs.vmName
    acrName: security.outputs.acrName
    keyVaultName: security.outputs.keyVaultName
    originFqdn: originFqdn
    originSecretName: originSecretName
    frontDoorId: edge.outputs.frontDoorId
    publicHost: edge.outputs.publicHost
    relayOwnerPubkey: relayOwnerPubkey
    bootstrapBundleImage: bootstrapBundleImage
    relayImage: relayImage
    postgresImage: postgresImage
    redisImage: redisImage
    minioImage: minioImage
    minioMcImage: minioMcImage
    caddyImage: caddyImage
    coreWorkerImage: coreWorkerImage
    egressProxyImage: egressProxyImage
    auditStorageAccountName: auditStorage.outputs.storageAccountName
    enableMonth1Workers: enableMonth1Workers
    startCoreServices: startCoreServices
  }
}

module edge 'modules/edge.bicep' = {
  name: '${namePrefix}-edge'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    originFqdn: originFqdn
    originSecret: originSecret
    customDomainHostName: frontDoorCustomDomainHostName
  }
}

module monitoringBackup 'modules/monitoring-backup.bicep' = {
  name: '${namePrefix}-monitoring-backup'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    location: location
    vmName: compute.outputs.vmName
    vmResourceId: compute.outputs.vmResourceId
    frontDoorProfileName: edge.outputs.profileName
    alertEmail: alertEmail
  }
}

module auditStorage 'modules/audit-storage.bicep' = {
  name: '${namePrefix}-audit-storage'
  scope: resourceGroup
  params: {
    namePrefix: namePrefix
    location: location
    exporterPrincipalId: compute.outputs.principalId
    subnetId: network.outputs.subnetId
  }
}

module budget 'modules/budget.bicep' = {
  name: '${namePrefix}-budget'
  params: {
    budgetName: '${namePrefix}-monthly-budget'
    resourceGroupName: resourceGroup.name
    monthlyBudgetUsd: monthlyBudgetUsd
    alertEmail: alertEmail
    budgetStartDate: budgetStartDate
  }
}

output resourceGroupName string = resourceGroup.name
output originPublicIp string = network.outputs.originPublicIp
output frontDoorEndpointHostName string = edge.outputs.endpointHostName
output acrLoginServer string = security.outputs.acrLoginServer
output keyVaultName string = security.outputs.keyVaultName
output auditStorageAccountName string = auditStorage.outputs.storageAccountName
output auditContainerName string = auditStorage.outputs.containerName
output dnsZoneName string = manageDnsZone ? dnsZoneName : ''
