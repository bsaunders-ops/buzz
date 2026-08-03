param location string
param vmName string
param acrName string
param keyVaultName string
param originFqdn string
param originSecretName string
param frontDoorId string
param bootstrapBundleImage string
param relayImage string
param postgresImage string
param redisImage string
param minioImage string
param minioMcImage string
param caddyImage string
param startCoreServices bool = false

var configPayload = base64(string({
  acrName: acrName
  keyVaultName: keyVaultName
  originFqdn: originFqdn
  originSecretName: originSecretName
  frontDoorId: frontDoorId
  bootstrapBundleImage: bootstrapBundleImage
  relayImage: relayImage
  postgresImage: postgresImage
  redisImage: redisImage
  minioImage: minioImage
  minioMcImage: minioMcImage
  caddyImage: caddyImage
  startServices: startCoreServices
}))
var loader = loadTextContent('../bootstrap/bootstrap.sh')
var scriptPayload = base64('#!/usr/bin/env bash\nexport BUZZ_BOOTSTRAP_CONFIG_BASE64=\'${configPayload}\'\n${loader}')

resource virtualMachine 'Microsoft.Compute/virtualMachines@2024-07-01' existing = {
  name: vmName
}

resource bootstrap 'Microsoft.Compute/virtualMachines/extensions@2024-07-01' = {
  parent: virtualMachine
  name: 'CoreBuzzBootstrap'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
    typeHandlerVersion: '2.1'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    forceUpdateTag: uniqueString(configPayload)
    settings: {
      skipDos2Unix: false
    }
    protectedSettings: {
      script: scriptPayload
    }
  }
}
