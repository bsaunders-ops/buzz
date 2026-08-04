FROM scratch AS bundle

COPY infra/azure/bootstrap/refresh-secrets.sh /bundle/refresh-secrets.sh
COPY infra/azure/bootstrap/provision-worker-db-roles.sh /bundle/provision-worker-db-roles.sh
COPY infra/azure/bootstrap/container-firewall.sh /bundle/container-firewall.sh
COPY infra/azure/bootstrap/service-activation.sh /bundle/service-activation.sh
COPY infra/azure/bootstrap/compose-supervisor.sh /bundle/compose-supervisor.sh
COPY infra/azure/bootstrap/docker-post-start.sh /bundle/docker-post-start.sh
COPY infra/azure/bootstrap/docker-activation.sh /bundle/docker-activation.sh
COPY infra/azure/bootstrap/buzz-core.service /bundle/buzz-core.service
COPY infra/azure/compose/compose.azure.yml /bundle/compose.azure.yml
COPY infra/azure/compose/Caddyfile.azure /bundle/Caddyfile.azure
COPY infra/azure/compose/squid-connectors.conf /bundle/squid-connectors.conf
COPY infra/azure/compose/squid-model.conf /bundle/squid-model.conf
COPY deploy/compose/compose.yml /bundle/compose.yml

# The image is an OCI transport artifact and is never started. A command is
# still required so `docker create` can materialize it for verified `docker cp`.
CMD ["/bundle/refresh-secrets.sh"]
