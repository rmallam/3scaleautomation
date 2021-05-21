#!/bin/bash
# Usage text
set -x
function usage() {
  cat <<USAGE_TEXT 
Usage: `basename $0` [OPTIONS] API_SPEC_FILE
Deploys a Product API to a 3scale tenant based on its OAS file.
The script is idempotent, if it fails it is safe to re-run.

[OPTIONS]
  -h                             Displays this help text and exit.
  -v                             Enable verbose mode (-vv debug).
                                 Only prints fatal errors by default.
  -p PUBLIC_URL                  Sets the public base url of the API [mandatory].
  -b BACKEND_FILE                Sets the FILE of the additional API config, 
                                 Including backend mappings (yaml).
                                    spec:
                                     api:
                                       publicBasePath: <base path>
                                      backends:
                                     - id: <backend service name>
                                      path: <path to map to this backend>
  -o OIDC_ISSUER_URL             The OpenID Connect Issuer URL.
  -n NAME                        Name of the API [mandatory].
                                    The value is used to generate the system_name of
                                    multiple 3scale entities. The value should also
                                    comply with the limitations of 3scale system_name 
                                    values [a-Z0-9_].
  -c REMOTE_CONFIG               The file containing the 3scale toolbox 
                                   configuration file with the available remotes
                                   (default=~/.3scalerc.yaml).
  -r REMOTE                      The name of the remote 3scale tenant where the API
                                   will be deployed on [mandatory].
                                   The value of REMOTE must match an entry on the
                                   3scale toolbox configuration file or be a valid
                                   tenant admin URL including access token, 
                                   e.g. https://token@tenant-admin.url
  -x POLICY_FILE                 The file (JSON) containing the definition of proxy
                                   policies to be applied.
  -u APP_ID:APP_SECRET           The Application Client ID and Secret to be configured.
                                   APP_SECRET must be 32 characters long hexadecimal lowercase

USAGE_TEXT

}

##======= Variables ======

# Variables with default configuration
VERBOSITY=0
DRY_RUN=0
PUBLIC_URL=
BACKEND_FILE=
AUTH_TYPE=-1
OIDC_ISSUER_URL=
NAME=
REMOTE_CONFIG=~/.3scalerc.yaml
REMOTE=
SWAGGER_FILE=
APP_AUTH_CONFIG_INFO=
APPLICATION_CLIENT_ID=
APPLICATION_CLIENT_SECRET=
##======= UTILITY Functions ======
function printVariables() {
  VARS="\n
Variables:\n 
  VERBOSITY=$VERBOSITY\n
  PUBLIC_URL=$PUBLIC_URL\n
  BACKEND_FILE=$BACKEND_FILE\n
  AUTH_TYPE=$AUTH_TYPE\n
  OIDC_ISSUER_URL=$OIDC_ISSUER_URL\n
  NAME=$NAME\n
  REMOTE_CONFIG=$REMOTE_CONFIG\n
  REMOTE=$REMOTE\n
  POLICY_FILE=$POLICY_FILE\n
  SWAGGER_FILE=$SWAGGER_FILE\n
  APP_ID:APP_SECRET=$APP_AUTH_CONFIG_INFO
  "
  debug $VARS
}

function debug() {
  if [ $VERBOSITY -gt 1 ]; then
    echo -e "[DEBUG] $@"
  fi
}

function info() {
  if [ $VERBOSITY -gt 0 ]; then
    echo -e "[INFO] $@"
  fi
}

function error() {
  if [ $VERBOSITY -gt 0 ]; then
    echo -e "[ERROR] $@" >&2
  fi
}

function warn() {
  echo -e "[WARN] $@"
}

function fatal() {
  echo -e "[FATAL] $@" >&2
  exit 1
}

##======= CLI Routine Functions ======

function run() {
  
  set -e -o pipefail

  # check for super-verbose / bash debug
  if [ $VERBOSITY -gt 2 ]; then
    debug "Setting -xv for bash debug"
    set -xv
  fi

  printVariables
  validateConfiguration
  deployAPI
}

function deployAPI() {
IS_A_NUMBER='^[0-9]+$'

LAST_RESULT=
TOOLBOX_CMD="3scale -k -c $REMOTE_CONFIG"

SERVICE_NAME="${NAME}ServiceAPI"
info "Service will be created with system_name = '$SERVICE_NAME'"

debug "extract data from REMOTE_CONFIG or REMOTE"
ACCESS_TOKEN=
ADMIN_URL=
if [[ $REMOTE =~ $IS_A_URL ]]; then
  debug "'$REMOTE' is a URL, extracting ACCESS_TOKEN and ADMIN_URL"
  # extract the protocol
  rproto="$(echo $REMOTE | grep :// | sed -e's,^\(.*://\).*,\1,g')"
  # remove the protocol
  rurl="$(echo ${REMOTE/$rproto/})"
  # extract the user (if any)
  ruser="$(echo $rurl | grep @ | cut -d@ -f1)"
  # extract the host and port
  rhostport="$(echo ${rurl/$ruser@/} | cut -d/ -f1)"
  # by request host without port    
  rhost="$(echo $rhostport | sed -e 's,:.*,,g')"
  # by request - try to extract the port
  rport="$(echo $rhostport | sed -e 's,^.*:,:,g' -e 's,.*:\([0-9]*\).*,\1,g' -e 's,[^0-9],,g')"

  ACCESS_TOKEN="${ruser}"
  ADMIN_URL="${rproto}${rhostport}"
  debug "extracted ACCESS_TOKEN and ADMIN_URL = '$ADMIN_URL'"
else
  {
    ACCESS_TOKEN=$(grep $REMOTE: -A2 $REMOTE_CONFIG | grep authentication | awk '{print $2}') &&
    ADMIN_URL=$(grep $REMOTE: -A2 $REMOTE_CONFIG | grep endpoint | awk '{print $2}') &&
    debug "extracted ACCESS_TOKEN and ADMIN_URL = '$ADMIN_URL'"
  } || {
    fatal "Could not extract data from $REMOTE_CONFIG"
  }
fi

BASE_PATH=$(yq e '.spec.api.publicBasePath' $BACKEND_FILE)
debug "basePath = $BASE_PATH"

if [[ "x$BASE_PATH" == "xnull" ]]; then
BASE_PATH=""
args="import openapi --staging-public-base-url=$PUBLIC_URL --production-public-base-url=$PUBLIC_URL --default-credentials-userkey=defaultkey -t $SERVICE_NAME -d $REMOTE $SWAGGER_FILE"
else 
args="import openapi --staging-public-base-url=$PUBLIC_URL --production-public-base-url=$PUBLIC_URL --default-credentials-userkey=defaultkey --override-public-basepath=${BASE_PATH} -t $SERVICE_NAME -d $REMOTE $SWAGGER_FILE"
fi

debug "import swagger"
{  
  LAST_RESULT=$( $TOOLBOX_CMD $args 2>&1 ) &&
  info "Swagger file imported"
} || {  
  ## workaround for https://issues.redhat.com/browse/OHSS-3683
  warn "import openapi failed with: \n$LAST_RESULT \n trying again ..."
  LAST_RESULT=$( $TOOLBOX_CMD $args 2>&1 ) &&
  info "Swagger file imported"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not import swagger file"
}
debug "swagger import output => $LAST_RESULT"


debug "get the service id"
args="service list $REMOTE"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args | grep $SERVICE_NAME | awk '{print $1}' ) &&
  debug "Service id returned '$LAST_RESULT'"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not read service id"
}
SERVICE_ID=$LAST_RESULT
if [[ ! $SERVICE_ID =~ $IS_A_NUMBER ]]; then
  fatal "Service id '$SERVICE_ID' is not a number."
fi

debug "account set up"
ACCOUNT_ID=

ACCOUNT_EMAIL="noreply+anonymous@ahunga.co.nz"
args="account find $REMOTE $ACCOUNT_EMAIL"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args | grep id | awk '{print $3}' ) &&
  debug "anonymous account returned = $LAST_RESULT"
} || {
  debug "Failed with: \n$LAST_RESULT"
  warn "Issue trying to find account for $ACCOUNT_EMAIL"
}
ACCOUNT_ID=$LAST_RESULT
if [[ ! $ACCOUNT_ID =~ $IS_A_NUMBER ]]; then
  debug "create anonymous account"
  #RANDOM_PASS="`base64 /dev/urandom | head -c 16 `"
  RANDOM_PASS="zmpxBNj7JoUO9jrq"
  debug "random password for anonymous = $RANDOM_PASS"
  {
    LAST_RESULT=$( curl -k -X POST "${ADMIN_URL}/admin/api/signup.xml" -d "access_token=${ACCESS_TOKEN}&org_name=anonymous&username=anonymous" --data-urlencode "email=$ACCOUNT_EMAIL" --data-urlencode "password=$RANDOM_PASS" -s  -o /tmp/account-$SERVICE_ID.xml -s -w "%{http_code}" 2>&1 ) &&
    debug "signup for account returned $LAST_RESULT"
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not create anonymous account"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not create anonymous account (HTTP $LAST_RESULT)"
  fi
  ACCOUNT_ID=$( xmllint --xpath "string(/account/id)" /tmp/account-$SERVICE_ID.xml )
  if [[ ! $ACCOUNT_ID =~ $IS_A_NUMBER ]]; then
    error "Account id is not a number"
    fatal "Could not create anonymous account"
  fi
  info "Anonymous account created"
fi



debug "clean up application and application plans"
debug "delete all applications for the service on the account"
args="application list --account=$ACCOUNT_ID $REMOTE"
{
  for APP_ID in `$TOOLBOX_CMD $args | grep $SERVICE_NAME | awk '{print $1}'`; do 
    LAST_RESULT=$( $TOOLBOX_CMD application delete $REMOTE $APP_ID ) &&
    debug "delete app $APP_ID returned $LAST_RESULT"
  done
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not delete all existing account $ACCOUNT_ID applications"
}
info "Cleaned up applications from account $ACCOUNT_ID"

APP_PLAN_NAME="${SERVICE_NAME}AppPlan"

debug "check whether application plan $APP_PLAN_NAME exists"
args="application-plan list $REMOTE $SERVICE_NAME"
{
  # grep returns count match (should be 1 if app plan exists)
  LAST_RESULT=$( $TOOLBOX_CMD $args | grep $APP_PLAN_NAME -c ) &&
  debug "check application plan returned $LAST_RESULT"
} || {
  debug "Failed with: \n$LAST_RESULT"
  warn "Issue checking for application plan"
}
APP_PLAN_ACTION="update"
if [[ $LAST_RESULT =~ $IS_A_NUMBER && $LAST_RESULT -gt 0 ]]; then
  debug "delete all applications on the application plan"
  args="application list --service=$SERVICE_NAME $REMOTE"
  {
    for APP_ID in `$TOOLBOX_CMD $args | grep $APP_PLAN_NAME | awk '{print $1}'`; do
      LAST_RESULT=$( $TOOLBOX_CMD application delete $REMOTE $APP_ID ) &&
      debug "delete app $APP_ID returned $LAST_RESULT"
    done
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not delete all existing application plan $APP_PLAN_NAME applications"
  }
  info "Cleaned up applications from Application Plan $APP_PLAN_NAME"
else
  info "Application Plan $APP_PLAN_NAME could not be found. It will be created."
  APP_PLAN_ACTION="create"
fi

## swtich OIDC / APID

# update authentication, APID
if [ $AUTH_TYPE == 0 ]; then
  debug "update authentication to APP_ID/API_KEY via Basic Auth"
  {
    LAST_RESULT=$( curl -k -X PATCH "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/proxy.xml" -d "access_token=${ACCESS_TOKEN}&credentials_location=authorization&auth_app_key=app_key&auth_app_id=app_id" -s  -o /tmp/authentication-$SERVICE_ID.xml -s -w "%{http_code}" 2>&1 ) &&
    debug "patch proxy returned $LAST_RESULT"
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not patch proxy"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not patch proxy (HTTP $LAST_RESULT)"
  fi

  debug "change service authentication to APP_ID/API_KEY (mode=2)"
  args="service apply --authentication-mode=2 $REMOTE $SERVICE_NAME"
  {
    LAST_RESULT=$( $TOOLBOX_CMD $args ) &&
    debug "service apply returned $LAST_RESULT"
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not update service"
  }
  info "Authentication method set to APP_ID/API_KEY via Basic Auth"
elif [ $AUTH_TYPE == 1 ]; then
# update authentication, OIDC
  debug "configure OIDC (listener only)"
  {
    args="service apply --authentication-mode=oidc $REMOTE $SERVICE_NAME"
    LAST_RESULT=$( $TOOLBOX_CMD $args 2>&1 ) &&
    info "Service $SERVICE_NAME authentication mode set to oidc"
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not set authentication mode to oidc"
  }

  debug "setting OIDC Issuer URL on the service proxy"
  LAST_RESULT=$(curl -k -X PATCH "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/proxy.xml" -d "access_token=$ACCESS_TOKEN" --data-urlencode "oidc_issuer_endpoint=$OIDC_ISSUER_URL" -o /dev/null -s -w "%{http_code}" 2>&1 ) 
  debug "patch proxy returned HTTP $LAST_RESULT" 
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not patch proxy with oidc issuer endpoint (HTTP $LAST_RESULT)"
  fi
  info "Updated OIDC Issuer URL"

  debug "setting OIDC to use Service Accounts Flow (Client Credentials)"
  LAST_RESULT=$(curl -k -X PATCH "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/proxy/oidc_configuration.xml" -d "access_token=${ACCESS_TOKEN}&standard_flow_enabled=false&implicit_flow_enabled=false&service_accounts_enabled=true&direct_access_grants_enabled=false" -o /dev/null -s -w "%{http_code}" 2>&1 ) 
  debug "patch oidc_configuration returned HTTP $LAST_RESULT" 
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not patch oidc configuration to use client credentials (HTTP $LAST_RESULT)"
  fi
  info "Updated OIDC to use Service Accounts Flow (Client Credentials)"
fi



debug "create/update application plan"
args="application-plan apply --enabled $REMOTE $SERVICE_NAME $APP_PLAN_NAME"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args ) &&
  debug "application-plan apply returned $LAST_RESULT"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not create or update application plan"
}
info "Application Plan $APP_PLAN_NAME ${APP_PLAN_ACTION}"

debug "publish the plan (ignore errors, see THREESCALE-3030)"
args="application-plan apply --publish $REMOTE $SERVICE_NAME $APP_PLAN_NAME"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args  2>&1 ) &&
  debug "application-plan apply returned $LAST_RESULT"
} || {
  debug "Failed with: \n$LAST_RESULT"
  warn "Application plan could not be published. Is it already published? (see THREESCALE-3030)"
}
info "Application Plan $APP_PLAN_NAME is published"


APPLICATION_NAME="${SERVICE_NAME}Application"
debug "create application $APPLICATION_NAME for $APPLICATION_CLIENT_ID"
args="application apply --account=$ACCOUNT_ID --service=$SERVICE_NAME --plan=$APP_PLAN_NAME --name=$APPLICATION_NAME --application-key=$APPLICATION_CLIENT_SECRET $REMOTE $APPLICATION_CLIENT_ID"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args ) &&
  debug "application apply returned $LAST_RESULT"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not create or update application"
}
info "Application $APPLICATION_NAME for $APPLICATION_CLIENT_ID created/updated"


if [ ! -z "$POLICY_FILE" ]; then
  debug "set policies"
  {
    LAST_RESULT=$( curl -k -X PUT "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/proxy/policies.json" -d "access_token=${ACCESS_TOKEN}" --data-urlencode policies_config@${POLICY_FILE} -o /dev/null -s -w "%{http_code}" 2>&1 ) &&
    debug "proxy policies returned HTTP $LAST_RESULT"
  } || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not update proxy policies"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not update proxy policies (HTTP $LAST_RESULT)"
  fi
  info "Proxy policies updated with the contents of $POLICY_FILE"
fi

### backend mapping

if [ ! -z "$BACKEND_FILE" ]; then 
  # list all backend apis
  {
    LAST_RESULT=$(curl -k -X GET "${ADMIN_URL}/admin/api/backend_apis.json?access_token=$ACCESS_TOKEN&page=1&per_page=500" -o /tmp/backends_apis.json -s -w "%{http_code}" 2>&1 ) &&
    debug "backends_apis returned HTTP $LAST_RESULT"
  } || {
      error "Failed with: \n$LAST_RESULT"
      fatal "Could not retrieve current backends_apis"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not retrieve current backends_apis (HTTP $LAST_RESULT)"
  fi

  # list all mappings?
  {
    LAST_RESULT=$(curl -k -X GET "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/backend_usages.json?access_token=$ACCESS_TOKEN" -o /tmp/backend_usages-${SERVICE_ID}.json -s -w "%{http_code}" 2>&1 ) &&
    debug "backend_usages returned HTTP $LAST_RESULT"
  } || {
      error "Failed with: \n$LAST_RESULT"
      fatal "Could not retrieve current backend_usages"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    fatal "Could not retrieve current backend_usages (HTTP $LAST_RESULT)"
  fi

  # delete all mappings
  for buid in `jq '.[].backend_usage.id' /tmp/backend_usages-${SERVICE_ID}.json`; do 
    LAST_RESULT=$(curl -k -X DELETE "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/backend_usages/${buid}.json?access_token=$ACCESS_TOKEN" -s -w "%{http_code}" 2>&1 ) 
    debug "delete backend_usage $buid returned HTTP $LAST_RESULT" 
    if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
      fatal "Could not delete backend_usage (HTTP $LAST_RESULT)"
    fi
    debug "backend_usage $buid deleted"
  done

  # for each backend
  SIZE=$(yq e '.spec.backends|length' $BACKEND_FILE)
  for ((i=0;i<SIZE;i++)); do
    BACKEND_NAME=$(yq e ".spec.backends[$i].id" $BACKEND_FILE)
    BACKEND_PATH=$(yq e ".spec.backends[$i].path" $BACKEND_FILE)
    debug "mapping backend $BACKEND_NAME -> ${BASE_PATH}${BACKEND_PATH}"
    # lookup backend id
    BACKEND_ID=$(jq -c ".backend_apis[].backend_api | select(.system_name == \"$BACKEND_NAME\") | .id" /tmp/backends_apis.json)
    debug "backend $BACKEND_NAME ID= $BACKEND_ID"
    # map to service 
    {
      LAST_RESULT=$( curl -k -X POST "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/backend_usages.json" -d "access_token=${ACCESS_TOKEN}&backend_api_id=${BACKEND_ID}" --data-urlencode "path=${BASE_PATH}${BACKEND_PATH}" -s -o /tmp/backend_usages-$SERVICE_ID.json -s -w "%{http_code}" 2>&1 ) &&
      debug "backend_usages for service returned $LAST_RESULT"
    } || {
      error "Failed with: \n$LAST_RESULT"
      fatal "Could not create backend_usages"
    }
    if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
      fatal "Could not create backend_usages (HTTP $LAST_RESULT)"
    fi
    info "Backend $BACKEND_NAME [$BACKEND_ID] mapped to path ${BASE_PATH}${BACKEND_PATH} on service $SERVICE_ID"
  done

fi

debug "deploy api definition to 'sandbox'"
{
  LAST_RESULT=$( curl -k -X POST "${ADMIN_URL}/admin/api/services/${SERVICE_ID}/proxy/deploy.xml" -d "access_token=${ACCESS_TOKEN}" -s  -o /tmp/sandbox-deploy-$SERVICE_ID.xml -s -w "%{http_code}" 2>&1 ) &&
  debug "deploy api definition to 'sandbox' returned $LAST_RESULT"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not deploy api definition to 'sandbox'"
}
if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
  fatal "Could not deploy api definition to 'sandbox' (HTTP $LAST_RESULT)"
fi

debug "promote service to 'production'"
args="proxy-config promote $REMOTE $SERVICE_NAME"
{
  LAST_RESULT=$( $TOOLBOX_CMD $args ) &&
  debug "proxy-config promote returned $LAST_RESULT"
} || {
  error "Failed with: \n$LAST_RESULT"
  fatal "Could not promote service"
}
info "Service promoted to 'production' stage"

info "deployment complete"

}

function validateConfiguration() {
  debug "3scale toolbox version: `3scale -v`"

  IS_A_URL='^(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'
  IS_A_NAME='^[A-Za-z0-9_]+$'
  IS_HEX_32='^[a-f0-9]{32}$'
  if [ -z "$PUBLIC_URL" ]; then 
    fatal "Missing mandatory parameter PUBLIC_URL (-p)."
  elif [[ ! $PUBLIC_URL =~ $IS_A_URL ]]; then
    fatal "'$PUBLIC_URL' is not a valid URL."
  fi
  if [ ! -z "$BACKEND_FILE" ]; then
    if [ ! -r $BACKEND_FILE ]; then
      fatal "File $BACKEND_FILE does not exist or is not readable."
    fi
  fi

AUTH_TYPE=$(yq e '.spec.api.authType' $BACKEND_FILE)
info "Auth type in backend file is $AUTH_TYPE"
case $AUTH_TYPE in 
  apid ) 
    AUTH_TYPE=0
    ;;
  oidc )
    AUTH_TYPE=1
    ;;
  * )
    fatal "Unknown authType $AUTH_TYPE. Allowed values are [apid , oidc]. "
  esac
  if [ -z "$NAME" ]; then
    fatal "Missing mandatory parameter NAME (-n)."
  elif [[ ! $NAME =~ $IS_A_NAME ]]; then
    fatal "'$NAME' is not valid."
  fi
  if [ -z "$REMOTE" ]; then
    fatal "Missing mandatory parameter REMOTE (-r)."
  elif [[ ! $REMOTE =~ $IS_A_URL ]]; then
    warn "'$REMOTE' is not a URL. It must be defined in $REMOTE_CONFIG."
    if [ ! -r $REMOTE_CONFIG ]; then
      fatal "File $REMOTE_CONFIG does not exist or is not readable."
    fi
  fi
  if [ $AUTH_TYPE -lt 0 ]; then
    fatal "Invalid or missing AUTH_TYPE (-t)"
  fi
  if [[ $AUTH_TYPE -eq 1 && -z "$OIDC_ISSUER_URL" ]]; then
    fatal "Missing mandatory additional parameter OIDC_ISSUER_URL (-o)"
  fi
  if [[ ! -z "$POLICY_FILE" && ! -r $POLICY_FILE ]]; then
    fatal "File $POLICY_FILE does not exist or is not readable."
  fi
  if [ -z "$SWAGGER_FILE" ]; then
    fatal "Missing mandatory parameter API_SPEC_FILE."
  elif [ ! -r $SWAGGER_FILE ]; then
    fatal "File $SWAGGER_FILE does not exist or is not readable."
  fi
  if [ -z "$APP_AUTH_CONFIG_INFO" ]; then
    fatal "Missing mandatory parameter APP_ID:APP_SECRET (-u)."
  else
    if [ -z "$APPLICATION_CLIENT_SECRET" ] || [ "$APPLICATION_CLIENT_SECRET" == "$APPLICATION_CLIENT_ID"  ]; then
      fatal "Missing mandatory parameter in APP_ID:APP_SECRET (-u)."
    fi
    APPLICATION_CLIENT_ID=${APP_AUTH_CONFIG_INFO%":$APPLICATION_CLIENT_SECRET"}
    if [[ ! $APPLICATION_CLIENT_SECRET =~ $IS_HEX_32 ]]; then
      fatal "APP_SECRET must be 32 character long hexadecimal lowercase string"
    fi
  fi
  debug "Configuration validated"
}

##======= CLI Options parsing ======
if [ -z $1 ]; then 
  fatal "Missing parameters. Try -h (help)" 
fi

# Call getopt to validate the provided input. 
OPTS=$(getopt "hvp:b:o:n:c:r:x:u:" $*)
if [ $? != 0 ] ; then
  fatal "Incorrect options provided. Try -h (help)" 
fi

eval set -- "$OPTS"

while true; do
    case "$1" in
    -h ) 
      usage;
      exit 0
      ;;
    -v ) 
      VERBOSITY=$((VERBOSITY+1))
      ;;
    -p )
      shift;
      PUBLIC_URL=$1
      ;;
    -b )
      shift;
      BACKEND_FILE=$1
      ;;
    -o )
      shift;
      OIDC_ISSUER_URL=$1
      ;;
    -n )
      shift;
      NAME=$1
      ;;
    -c )
      shift;
      REMOTE_CONFIG=$1
      ;;
    -r )
      shift;
      REMOTE=$1
      ;;
    -x )
      shift;
      POLICY_FILE=$1
      ;;
    -u )
      shift;
      APP_AUTH_CONFIG_INFO=$1
      APPLICATION_CLIENT_SECRET=${APP_AUTH_CONFIG_INFO#*:} # : (colon) is the delimiter
      APPLICATION_CLIENT_ID=${APP_AUTH_CONFIG_INFO%":$APPLICATION_CLIENT_SECRET"}
      ;;
    -d )
      DRY_RUN=1
      ;;
    -- )
      shift;
      break
      ;;
    * ) 
      fatal "Unrecognized option $1"
    esac
    shift
done

if [ $# -gt 1 ]; then
  fatal "Too many arguments '${@:0:$#}'."
fi

SWAGGER_FILE=$1

run

exit 0 ;
