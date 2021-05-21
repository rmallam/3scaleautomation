#!/bin/bash
set -e
#---------
declare -r IS_A_NUMBER='^[0-9]+$'
declare -r IS_A_URL='^(https?)://[-A-Za-z0-9\+&@#/%?=~_|!:,.;]*[-A-Za-z0-9\+&@#/%=~_|]$'
declare -r IS_A_NAME='^[A-Za-z0-9_]+$'
declare -r TMP_API_LIST_FNAME="/tmp/apiList$RANDOM.json"
declare -r TMP_CREATE_API_RESULT_FNAME="/tmp/createdAPI$RANDOM.json"
declare -r HTTP_CMD='curl -s'
declare -r THREESCALE_BACKND_CONTEXT_PATH='admin/api/backend_apis'
declare REMOVEONLY='false'
declare TENANT_URL=
declare ENVIRONMENT=
declare REMOTE=
declare ACCESS_TOKEN=
declare VERBOSITY=1
#-----

usage() {
  cat <<EOF 2>&1
usage: $0 [ -r | -e | -c | -h | -x ]

3scale Backend APIs provisioning script.

Required:
   -r  <REMOTE>               Name of the remote 3scale tenant where the API
                              will be deployed on [mandatory].
                              The value of REMOTE must match an entry on the
                              3scale toolbox configuration file or be a valid
                              tenant admin URL including access token, 
                              e.g. https://token@tenant-admin.url
   -e  <ENVIRONMENT>          Environment [dev | test | stage] e.g. dev
Optional:
   -h  help for the needy
   -d  Delete existing backend apis without creating/updating them. 
   -x  Enable shell debug mode (set -x)
   -v  Enable verbose mode (-vv debug).
Note: 
1) The System Name in yaml should comply with the limitations of 3scale system_name values [a-Z0-9_].
2) yq and jq binaries must be available for this script to work 
EOF
  exit 1
}
command -v jq >/dev/null 2>&1 || { echo >&2 "jq binary is required but it's not available.  Aborting."; exit 1; }
command -v yq >/dev/null 2>&1 || { echo >&2 "yq binary is required but it's not available.  Aborting."; exit 1; }

while getopts hxr:e:dv c; do
  case $c in
    x)
      set -x
      ;;
    r)
      REMOTE=${OPTARG}
      ;;
    v) 
      VERBOSITY=$((VERBOSITY+1))
      ;;
    e)
      ENVIRONMENT=${OPTARG}
      ;;
    d)
      REMOVEONLY="true"
      ;;
    *)
      usage
      ;;
  esac
done
shift `expr $OPTIND - 1`

debug() {
  if [ $VERBOSITY -gt 1 ]; then
    echo -e "[DEBUG] $@"
  fi
}

info() {
  if [ $VERBOSITY -gt 0 ]; then
    echo -e "[INFO] $@"
  fi
}

error() {
  if [ $VERBOSITY -gt 0 ]; then
    echo -e "[ERROR] $@" >&2
  fi
}

warn() {
  echo -e "[WARN] $@"
}

fatal() {
  echo -e "[FATAL] $@" >&2
  exit 1
}
validateConfiguration() {
  
  if [ -z "$REMOTE" ]; then
    usage
  elif [[ ! $REMOTE =~ $IS_A_URL ]]; then
    fatal "'$REMOTE' is not a valid URL.."
  fi
  if [ -z ${REMOTE} ] || [ -z ${ENVIRONMENT} ]; then
    usage
  fi
  if [[ $REMOTE =~ $IS_A_URL ]]; then
    debug "'$REMOTE' is a URL, extracting ACCESS_TOKEN and TENANT_URL"
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
    TENANT_URL="${rproto}${rhostport}"
    debug "extracted ACCESS_TOKEN and ADMIN_URL = '$ADMIN_URL'"
else
  {
    ACCESS_TOKEN=$(grep $REMOTE: -A2 $REMOTE_CONFIG | grep authentication | awk '{print $2}') &&
    TENANT_URL=$(grep $REMOTE: -A2 $REMOTE_CONFIG | grep endpoint | awk '{print $2}') &&
    debug "extracted ACCESS_TOKEN and ADMIN_URL = '$ADMIN_URL'"
  } || {
    fatal "Could not extract data from $REMOTE_CONFIG"
  }
fi

}
#-----START OF 3Scale related functions"
retrieve3ScaleBackAPIs()
{
  tenantUrl=$1
  accessToken=$2
  #TODO page and per_page and variable and loop through pages.
  options='&page=1&per_page=1000'
  apiUrl="${tenantUrl}/${THREESCALE_BACKND_CONTEXT_PATH}.json?access_token=${accessToken}${options}"
  {
    LAST_RESULT=$( $HTTP_CMD -X GET $apiUrl -s  -o $TMP_API_LIST_FNAME -s -w "%{http_code}" 2>&1 ) &&
    info "Retrieve api returned $LAST_RESULT" 
  }  || {
    error "Failed with: \n$LAST_RESULT"
    fatal "Could not list existing Backend APIs. Check if the TENANT URL is valid and has the correct secret"
  }
  if [[ ! $LAST_RESULT =~ $IS_A_NUMBER || "$LAST_RESULT" -ge 300 ]]; then
    rm $TMP_API_LIST_FNAME;
    fatal "Could not list BackEnd APIs (HTTP $LAST_RESULT)"
  fi
  #return $LAST_RESULT
}

delete3ScaleBackendAPI()
{
  tenantUrl=$1
  accessToken=$2 
  entityId=$3
  apiUrl="${tenantUrl}/${THREESCALE_BACKND_CONTEXT_PATH}/${entityId}.json?access_token=${accessToken}"
  local result=''
  {
    LAST_RESULT=$( $HTTP_CMD -X DELETE $apiUrl -s -w "%{http_code}" 2>&1 ) &&
    info "Delete api returned $LAST_RESULT" 
  }  || {
    error "Delete Failed with: \n$LAST_RESULT"
    fatal "Could not delete Backend API $entityId"
  }
}

create3ScaleBackendAPI()
{
  tenantUrl=$1
  accessToken=$2 
  systemName=$3
  apiUrl="${tenantUrl}/${THREESCALE_BACKND_CONTEXT_PATH}.json"
  local result=''
  privateApiUrl=$4
  description=$5
  {
    LAST_RESULT=$($HTTP_CMD -k -X POST "$apiUrl" -d "access_token=${accessToken}" --data-urlencode "private_endpoint=$privateApiUrl" --data-urlencode "name=$systemName" --data-urlencode "description=$description" -o $TMP_CREATE_API_RESULT_FNAME -w "%{http_code}" 2>&1 ) &&
     info "create api returned $LAST_RESULT" 
  }|| {
    error "Created Failed with: \n$LAST_RESULT"
    fatal "Could not create Backend API $entityId"-
  }
}

update3ScaleBackendAPI()
{
  tenantUrl=$1
  accessToken=$2 
  entityId=$3
  apiUrl="${tenantUrl}/${THREESCALE_BACKND_CONTEXT_PATH}/${entityId}.json?access_token=${accessToken}"
  local result=''
  privateApiUrl=$4
  description=$5
  result=$($HTTP_CMD -k -X PUT "$apiUrl" -d "access_token=${accessToken}" --data-urlencode "private_endpoint=$privateApiUrl" )
  {
    LAST_RESULT=$($HTTP_CMD -k -X PUT "$apiUrl" -d "access_token=${accessToken}" --data-urlencode "private_endpoint=$privateApiUrl" --data-urlencode "description=$description" -w "%{http_code}" 2>&1 ) &&
     info "Update api returned $LAST_RESULT" 
  }|| {
    error "Updated Failed with: \n$LAST_RESULT"
    fatal "Could not update Backend API $entityId"-
    }
  echo $result
}
#-----END OF 3Scale related functions"
#--Main----
main() {
  info "Starting.."
  validateConfiguration
	TMP_YAML_LIST_FILE="/tmp/backenddeployfile${RANDOM}.lst"
  info "Searching yamls with kind : Backend under the folder $THREESCALE_API_CRD_CONTEXT_DIR"
  #Find yaml files in the given directory.
  find ./backends/${ENVIRONMENT} -type f \( -iname \*.yaml -o -iname \*.yml \) -print0 | xargs -0 egrep -l "^kind:[[:blank:]]*Backend*"  > $TMP_YAML_LIST_FILE
  backend_yaml_count=$(wc -l $TMP_YAML_LIST_FILE | cut -f1 -d'/' | grep -o -E '[0-9]+') 
  if [ ${backend_yaml_count} -eq 0 ]; then
      info 'No yaml of type kind:Backend was detected. Exiting now'
      exit 0
  else
      info "Found ${backend_yaml_count} yaml(s) for processing"
  fi
  for i in `cat $TMP_YAML_LIST_FILE`
  do
    systemName=`yq e .spec.systemName $i`
    privateURL=`yq e .spec.privateBaseURL $i`
    desc=`yq e .spec.description $i`
    info "Processing file $i"
    debug "\tSystem Name=$systemName"
    debug "\tDescription=$desc"
    retrieve3ScaleBackAPIs "$TENANT_URL" "$ACCESS_TOKEN"
    backendAPIs=`cat $TMP_API_LIST_FNAME`
     if [ -z "$backendAPIs" ]; then
        fatal "Existing Backend information is not available. Check the provided configuration "
     fi
    isErrorPresent=`echo $backendAPIs | jq .error`
     if [ ! -z $isErrorPresent ] && [ ! "$isErrorPresent" == "null" ]; then
         fatal "Error Response received from the Tenant. Message is $isErrorPresent"
     fi
    Idin3Scale=`echo $backendAPIs | jq --arg systemName "$systemName" '.backend_apis[] |  .backend_api  | select(.name ==  $systemName) |.id'`
    # if systemName is already present update
    if [ "$REMOVEONLY" == "true" ]; then
      if [ ! -z "$Idin3Scale"  ]; then
        debug "Deleting API with System Name $systemName"
        apiSpec=$(delete3ScaleBackendAPI "$TENANT_URL" "$ACCESS_TOKEN" $Idin3Scale)
        info "Deleted API with System Name ${systemName}"
      else
        info "Backend with System Name ${systemName} is not found in 3Scale."
      fi
    elif [ "$REMOVEONLY" == "false" ]; then
     if [ -z "$Idin3Scale" ]; then
         info "API with systemName ${systemName} is not defined in 3Scale. Creating it. "
         create3ScaleBackendAPI "$TENANT_URL" "$ACCESS_TOKEN" $systemName $privateURL $desc
         apiSpec=`cat $TMP_CREATE_API_RESULT_FNAME`
         debug "New Spec = $apiSpec"
         info "Created API with System Name ${systemName}"
     else   
         info "Found existing id $Idin3Scale for $systemName. Updating existing definition"
         apiSpec=$(update3ScaleBackendAPI "$TENANT_URL" "$ACCESS_TOKEN" $Idin3Scale $privateURL $desc)
         info "Updated API with System Name ${systemName}"
     fi
    fi
    done
    # delete temporary file
    rm $TMP_YAML_LIST_FILE 
    rm $TMP_API_LIST_FNAME
    info "End of Processing"
    return 0
}
#----
main