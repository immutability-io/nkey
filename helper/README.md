# Helpers to get up and running

In this directory are a few scripts to help you get up and running with vault and the nkey plugin. These will install vault and the plugin, initialize vault and configure the plugin. Vault tokens and key shards will be encrypted on the filesystem.

## Prerequisites

You need to [install Keybase](https://keybase.io/) and create an identity in Keybase. Your Keybase identity will be used to encrypt the root token and keyshards. 

I am also using the fantastic [jq](https://stedolan.github.io/jq/) because you don't ever want to use JSON over REST without it. All vault commands support `-format=json` and this allows you to pipe output directly into `jq` to access specific keys.

## Install vault and plugin

**These scripts are using Vault 0.11.3. They will change once I upgrade to 1.0.0.**

Installing vault so that it uses TLS is a little more complicated than merely downloading vault. You need to generate a CA cert, sign a CSR and generate a vault configuration. Ideally, you would check the signature of the vault executable. Installing the plugin involves creating a plugins directory, configuring vault to know where that directory is, and similarly checking the signature of the plugin. This script does all of this for you. 

### install_vault.sh

The usage can be seen by executing the script without any parameters:

```
$ ./install_vault.sh
Usage: bash install_vault.sh OPTIONS

OPTIONS:
  --linux	Install Linux version
  --darwin	Install Darwin (MacOS) version
```

To install on MacOS: `./install_vault.sh --darwin`. This will create a directory: `$HOME/etc/vault.d`. It will put the vault executable in `/usr/local/bin/`.

## Initialize vault

Vault needs to be initialized before use. This involves generating the key shards that are used to unseal vault and generate the master encryption key. Our script also unseals vault. All key shards and the root token are encrypted using the supplied Keybase identity.

### initialize_vault.sh

The usage can be seen by executing the script without any parameters:

```
$ ./initialize_vault.sh
Usage: bash initialize_vault.sh OPTIONS

OPTIONS:
  [keybase]	Name of Keybase user to encrypt Vault keys with
```

To initialize vault using the Keybase identity `cypherhat`. Note, this is **NOT** your Keybase identity!:

```
$ ./initialize_vault.sh cypherhat
```

If we look at the resulting file system, we see that all secrets (encrypted) are named using the Keybase identity:

```
$ ls -ltr cypherhat_*
-rw-r--r--  1 cypherhat  staff  1786 Sep  1 08:34 cypherhat_UNSEAL_0.txt
-rw-r--r--  1 cypherhat  staff  1786 Sep  1 08:34 cypherhat_UNSEAL_1.txt
-rw-r--r--  1 cypherhat  staff  1786 Sep  1 08:35 cypherhat_UNSEAL_2.txt
-rw-r--r--  1 cypherhat  staff  1786 Sep  1 08:35 cypherhat_UNSEAL_3.txt
-rw-r--r--  1 cypherhat  staff  1786 Sep  1 08:35 cypherhat_UNSEAL_4.txt
```

## Configure nkey plugin

Before we configure the plugin, we have to log into vault as an administrator. We will use the root token to do this. Since the root token is encrypted using Keybase, we have to login to Keybase first.

The usage can be seen by executing the script without any parameters:

```
$ ./config_plugin.sh
Usage: bash config_plugin.sh OPTIONS

OPTIONS:
  [keybase]	Name of Keybase user used to encrypt Vault keys
```

The `config_plugin.sh` script will authenticate to Vault using the following approach:

```
$ source ./.as-root cypherhat
```

Assuming this works (which it should if you are logged into Keybase as the user - in my case that user is `cypherhat` - you specify to the script), you should see something like:

```
$ ./config_plugin.sh cypherhat
Message authored by cypherhat
ADDING TO CATALOG: sys/plugins/catalog/nkey-plugin
Success! Data written to: sys/plugins/catalog/nkey-plugin
MOUNTING: nkey
Success! Enabled the nkey-plugin plugin at: nkey
CONFIGURE: nkey
Key                Value
---                -----
bound_cidr_list    <nil>

```

