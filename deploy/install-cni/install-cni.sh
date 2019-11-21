#!/bin/sh

echo "VERSION V3"
set -u -e

ip addr show br0 |grep 'inet'|sed 's/^.*inet //g' |grep -v inet6 | sed 's:/24.*$::g' > /var/lib/grid/nodename
sed -i '2,$d' /var/lib/grid/nodename
if [[ ! -s /var/lib/grid/nodename ]]
then
   echo "ubable to get br0 ip"
   exit 1
else
   echo "br0 already exist"
fi

# Capture the usual signals and exit from the script
trap 'echo "SIGINT received, simply exiting..."; exit 0' SIGINT
trap 'echo "SIGTERM received, simply exiting..."; exit 0' SIGTERM
trap 'echo "SIGHUP received, simply exiting..."; exit 0' SIGHUP

# The directory on the host where CNI networks are installed. Defaults to
# /etc/cni/net.d, but can be overridden by setting CNI_NET_DIR.  This is used
# for populating absolute paths in the CNI network config to assets
# which are installed in the CNI network config directory.
HOST_CNI_NET_DIR=${CNI_NET_DIR:-/etc/cni/net.d}
HOST_SECRETS_DIR=${HOST_CNI_NET_DIR}/grid-tls

# Directory where we expect that TLS assets will be mounted into
# the calico/cni container.
SECRETS_MOUNT_DIR=${TLS_ASSETS_DIR:-/grid-secrets}

# Clean up any existing binaries / config / assets.
rm -f /host/opt/cni/bin/grid /host/opt/cni/bin/grid-ipam
rm -f /host/etc/cni/net.d/grid-tls/*

# Copy over any TLS assets from the SECRETS_MOUNT_DIR to the host.
# First check if the dir exists and has anything in it.
if [ "$(ls ${SECRETS_MOUNT_DIR} 3>/dev/null)" ];
then
  echo "Installing any TLS assets from ${SECRETS_MOUNT_DIR}"
  mkdir -p /host/etc/cni/net.d/grid-tls
  cp -p ${SECRETS_MOUNT_DIR}/* /host/etc/cni/net.d/grid-tls/
fi

# If the TLS assets actually exist, update the variables to populate into the
# CNI network config.  Otherwise, we'll just fill that in with blanks.
if [ -e "/host/etc/cni/net.d/grid-tls/ca.crt" ];
then
  CNI_CONF_ETCD_CA=${HOST_SECRETS_DIR}/ca.crt
fi

if [ -e "/host/etc/cni/net.d/grid-tls/server.key" ];
then
  CNI_CONF_ETCD_KEY=${HOST_SECRETS_DIR}/server.key
fi

if [ -e "/host/etc/cni/net.d/grid-tls/server.crt" ];
then
  CNI_CONF_ETCD_CERT=${HOST_SECRETS_DIR}/server.crt
fi

# Place the new binaries if the directory is writeable.
dir="/host/opt/cni/bin"
for path in /opt/cni/bin/*;
do
  cp $path $dir/
  if [ "$?" != "0" ];
  then
    echo "Failed to copy $path to $dir. This may be caused by selinux configuration on the host, or something else."
    exit 1
  fi
done

echo "Wrote GRID CNI binaries to $dir"

TMP_CONF='/grid.conf.tmp'
# If specified, overwrite the network configuration file.
: ${CNI_NETWORK_CONFIG_FILE:=}
: ${CNI_NETWORK_CONFIG:=}
if [ -e "${CNI_NETWORK_CONFIG_FILE}" ]; then
  echo "Using CNI config template from ${CNI_NETWORK_CONFIG_FILE}."
  cp "${CNI_NETWORK_CONFIG_FILE}" "${TMP_CONF}"
elif [ "${CNI_NETWORK_CONFIG}" != "" ]; then
  echo "Using CNI config template from CNI_NETWORK_CONFIG environment variable."
  cat >$TMP_CONF <<EOF
${CNI_NETWORK_CONFIG}
EOF
fi

SERVICE_ACCOUNT_PATH=/var/run/secrets/kubernetes.io/serviceaccount
KUBE_CA_FILE=${KUBE_CA_FILE:-$SERVICE_ACCOUNT_PATH/ca.crt}
SKIP_TLS_VERIFY=${SKIP_TLS_VERIFY:-false}
# Pull out service account token.
SERVICEACCOUNT_TOKEN=$(cat $SERVICE_ACCOUNT_PATH/token)

# Check if we're running as a k8s pod.
if [ -f "$SERVICE_ACCOUNT_PATH/token" ]; then
  # We're running as a k8d pod - expect some variables.
  if [ -z ${KUBERNETES_SERVICE_HOST} ]; then
    echo "KUBERNETES_SERVICE_HOST not set"; exit 1;
  fi
  if [ -z ${KUBERNETES_SERVICE_PORT} ]; then
    echo "KUBERNETES_SERVICE_PORT not set"; exit 1;
  fi

  if [ "$SKIP_TLS_VERIFY" == "true" ]; then
    TLS_CFG="insecure-skip-tls-verify: true"
  elif [ -f "$KUBE_CA_FILE" ]; then
    TLS_CFG="certificate-authority-data: $(cat $KUBE_CA_FILE | base64 | tr -d '\n')"
  fi

  # Write a kubeconfig file for the CNI plugin.  Do this
  # to skip TLS verification for now.  We should eventually support
  # writing more complete kubeconfig files. This is only used
  # if the provided CNI network config references it.
  touch /host/etc/cni/net.d/grid-kubeconfig
  chmod ${KUBECONFIG_MODE:-600} /host/etc/cni/net.d/grid-kubeconfig
  cat > /host/etc/cni/net.d/grid-kubeconfig <<EOF
# Kubeconfig file for Calico CNI plugin.
apiVersion: v1
kind: Config
clusters:
- name: local
  cluster:
    server: ${KUBERNETES_SERVICE_PROTOCOL:-https}://[${KUBERNETES_SERVICE_HOST}]:${KUBERNETES_SERVICE_PORT}
    $TLS_CFG
users:
- name: grid
  user:
    token: "${SERVICEACCOUNT_TOKEN}"
contexts:
- name: grid-context
  context:
    cluster: local
    user: grid
current-context: grid-context
EOF

fi


# Insert any of the supported "auto" parameters.
grep "__KUBERNETES_SERVICE_HOST__" $TMP_CONF && sed -i s/__KUBERNETES_SERVICE_HOST__/${KUBERNETES_SERVICE_HOST}/g $TMP_CONF
grep "__KUBERNETES_SERVICE_PORT__" $TMP_CONF && sed -i s/__KUBERNETES_SERVICE_PORT__/${KUBERNETES_SERVICE_PORT}/g $TMP_CONF
sed -i s/__KUBERNETES_NODE_NAME__/${KUBERNETES_NODE_NAME:-$(hostname)}/g $TMP_CONF
sed -i s/__KUBECONFIG_FILENAME__/grid-kubeconfig/g $TMP_CONF
sed -i s/__CNI_MTU__/${CNI_MTU:-1500}/g $TMP_CONF

# Use alternative command character "~", since these include a "/".
sed -i s~__KUBECONFIG_FILEPATH__~${HOST_CNI_NET_DIR}/grid-kubeconfig~g $TMP_CONF
sed -i s~__ETCD_CERT_FILE__~${CNI_CONF_ETCD_CERT:-}~g $TMP_CONF
sed -i s~__ETCD_KEY_FILE__~${CNI_CONF_ETCD_KEY:-}~g $TMP_CONF
sed -i s~__ETCD_CA_CERT_FILE__~${CNI_CONF_ETCD_CA:-}~g $TMP_CONF
sed -i s~__ETCD_ENDPOINTS__~${ETCD_ENDPOINTS:-}~g $TMP_CONF
sed -i s~__LOG_LEVEL__~${LOG_LEVEL:-debug}~g $TMP_CONF

CNI_CONF_NAME=${CNI_CONF_NAME:-10-grid.conf}
CNI_OLD_CONF_NAME=${CNI_OLD_CONF_NAME:-10-grid.conf}

# Log the config file before inserting service account token.
# This way auth token is not visible in the logs.
echo "CNI config: $(cat ${TMP_CONF})"

sed -i s/__SERVICEACCOUNT_TOKEN__/${SERVICEACCOUNT_TOKEN:-}/g $TMP_CONF

# Delete old CNI config files for upgrades.
if [ "${CNI_CONF_NAME}" != "${CNI_OLD_CONF_NAME}" ]; then
    rm -f "/host/etc/cni/net.d/${CNI_OLD_CONF_NAME}"
fi
# Move the temporary CNI config into place.
mv $TMP_CONF /host/etc/cni/net.d/${CNI_CONF_NAME}
if [ "$?" != "0" ];
then
  echo "Failed to mv files. This may be caused by selinux configuration on the host, or something else."
  exit 1
fi

echo "Created CNI config ${CNI_CONF_NAME}"

# Unless told otherwise, sleep forever.
# This prevents Kubernetes from restarting the pod repeatedly.
should_sleep=${SLEEP:-"true"}
echo "Done configuring CNI.  Sleep=$should_sleep"
while [ "$should_sleep" == "true"  ]; do
    echo "WAITING FOR DELETE"
    sleep 3600
done
