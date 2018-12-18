#!/bin/bash

function install_plugin {
  echo "ADDING TO CATALOG: sys/plugins/catalog/nkey-plugin"
  vault write sys/plugins/catalog/nkey-plugin \
        sha_256="$(cat SHA256SUM)" \
        command="nkey --ca-cert=$HOME/etc/vault.d/root.crt --client-cert=$HOME/etc/vault.d/vault.crt --client-key=$HOME/etc/vault.d/vault.key"

  if [[ $? -eq 2 ]] ; then
    echo "Vault Catalog update failed!"
    exit 2
  fi

  echo "MOUNTING: nkey"
  vault secrets enable -path=nkey -description="Immutability's Nkey Plugin" -plugin-name=nkey-plugin plugin
  if [[ $? -eq 2 ]] ; then
    echo "Failed to mount plugin!"
    exit 2
  fi
  echo "CONFIGURE: nkey"
  vault write -f nkey/config
}

function print_help {
    echo "Usage: bash config_plugin.sh OPTIONS"
    echo -e "\nOPTIONS:"
    echo -e "  [keybase]\tName of Keybase user used to encrypt Vault keys"
}

if [ -z "$1" ]; then
    print_help
    exit 0
elif [ "$1" == "--help" ]; then
    print_help
    exit 0
else
  KEYBASE_USER=$1
fi

source ./.as-root $KEYBASE_USER

install_plugin

unset VAULT_TOKEN