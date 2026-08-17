# Infrastructure

`docker-compose.yml` is development-only. Production infrastructure will be split into Terraform and Helm/Kubernetes definitions with external secret management, private networking, separate identity/relay data stores and explicit retention controls.
