FROM scratch AS bundle

COPY infra/azure/bootstrap/refresh-secrets.sh /bundle/refresh-secrets.sh
COPY infra/azure/bootstrap/buzz-core.service /bundle/buzz-core.service
COPY infra/azure/compose/compose.azure.yml /bundle/compose.azure.yml
COPY infra/azure/compose/Caddyfile.azure /bundle/Caddyfile.azure
COPY deploy/compose/compose.yml /bundle/compose.yml
