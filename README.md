# 3scale APIs and automation

## Overview

Repository holding the automation scripts and the OAS 3 api specifications that will be exposed in 3scale gateway.

`/products` folder contains the OAS Specifications deployed as Products
`/env` folder contains the configuration for each environment used by the automation scripts
`/backends` folder contains the backend definitions for each environment
`/scripts` folder contains the shell scripts used by the automation pipelines to deploy/provision backends and products

The automation pipelines are defined seperately

## Naming conventions

`api_unique_id` - the unique identifier of the API, must match `[a-zA-Z0-9_]+`, e.g. `xxx_xxxx_v1`

`env_name` - the name/id of the environment, must match `[a-zA-Z0-9]+`, e.g. `test`

**OpenAPI Specification v3**: JSON format as `/products/${api_unique_id}.json`

**Configuration**: YAML format as `/env/${env_name}/${api_unique_id}-config.yaml`

**API Policies**: JSON format as `/env/${env_name}/${api_unique_id}-policy.json`

## Samples for running the automation pipelines

```bash
### api unique ids:
# xxx_xxx_v1
# backends
NAMESPACE=<your namespace>
oc -n ${NAMESPACE} process 3scale-backends-pipeline-dev | oc -n ${NAMESPACE} create -f-
oc -n ${NAMESPACE} process 3scale-api-pipeline -p TENANT_GATEWAY_URL='https://xxxx' -p API_ID="xxx_xxx_v1" -p ENV="dev" | oc -n ${NAMESPACE} create -f-

 ```
