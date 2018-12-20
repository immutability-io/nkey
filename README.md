# NKey Plugin for Vault

I started to mess around with the excellent [NATS](https://nats.io/) and [NGS](https://synadia.com/ngs/signup) recently. When I went through the setup, I noticed that they were using a new form of authentication called [nkeys](https://github.com/nats-io/nkeys). nkeys' approach to the handling of private keys will be quite familiar to cryptocurrency folks - specifically Stellar. As is typical with these schemes, care must be taken to protect private keys or seeds. In this case, extra care is needed since the seed is stored unencrypted on the file system. As is my wont in these situations, I picked up my [HashiCorp Vault](https://www.vaultproject.io/) hammer and start looking for the nail head.

## Basic Functionality

The `nkey` plugin is a Vault secrets plugin that attempts to keep the `nkey` private key material within the Vault enclave. This means that key generation, seed material and signing operations are features of the plugin. In the nkey model, there is a notion of `trust`: if you don't trust a signer, you don't trust claims issued by that signer. Clearly, there need to be controls that protect the establishment of trust, and this is something that Vault can do well.

There is *business logic* governing the hierarchical controls on nkey identities. This hierarchy looks like:

```
*── operator
    ├── account
    │   └── user
    └── cluster
        └── server
```

There is *some* attempt to maintain this hierarchy via the (indirect) use of the `ExpectedPrefixes()` implementation in the `Claims` interface in [NATS JWT implementation](https://github.com/nats-io/jwt). The goal here is just to go far enough to allow Vault to protect nkeys.

## Basic Client Use

The expectation is that you would administer identities via Vault. A [basic CLI binding](./cli/nats.go) is available for Golang that you can then use with the [`NATS` client](https://github.com/nats-io/go-nats):

```
nc, err := nats.Connect("connect.ngs.global", cli.VaultCredentials("nkey/identities/ngs-account", "nkey/identities/ngs-user"))
```

## Examples of Usage

There is a [BATS test script](./tests/claims.bat) that shows some basic Vault CLI commands to administer nkeys, and to sign and verify claims and payloads (nonces.)

For example, the test to import an account nkey:

```
@test "import ngs account" {
  path=$HOME"/.nkeys/synadia/accounts/ngs/ngs.nk"
  user="$(vault write -format=json nkey/import/ngs-account path=$path | jq .data)"
  type="$(echo $user | jq -r .type)"
    [ "$type" = "account" ]
}

```

This test creates a user and sets the `nkey/import/ngs-account` as the only trusted signer:

```
@test "create trusted user" {
  account_key="$(vault read -format=json nkey/identities/ngs-account | jq -r .data.public_key)"
  user="$(vault write -format=json nkey/identities/trusted-user type=user trusted_keys=$account_key | jq .data)"
  trusted_keys="$(echo $user | jq -r '.trusted_keys[]' | tr -d '"')"
  type="$(echo $user | jq -r .type)"
    [ "$type" = "user" ]
    [ "$trusted_keys" = "$account_key" ]
}

```

## Installation

[These scripts may help you install Vault and the plugin.](./helper/README.md)

The plugin has to be configured before it can be used. The gives the operator the ability to establish IP constraints on the plugin (which hosts are allowed to use the plugin.)

## NKey Plugin API

Vault provides a CLI that wraps the Vault REST interface. Any HTTP client (including the Vault CLI) can be used for accessing the API. Since the REST API produces JSON, I use the wonderful [jq](https://stedolan.github.io/jq/) for the examples.

### NKEY PLUGIN CONFIGURATION

* [Plugin Configuration](https://github.com/immutability-io/nkey/blob/master/README.md#nkey-plugin-config)

### NKEY IDENTITY LIFECYCLE

* [List Nkey Identities](https://github.com/immutability-io/nkey/blob/master/README.md#list-nkey-identities)
* [Read Nkey Identity](https://github.com/immutability-io/nkey/blob/master/README.md#read-nkey-identity)
* [Create Nkey Identity](https://github.com/immutability-io/nkey/blob/master/README.md#create-nkey-identity)
* [Update Nkey Identity](https://github.com/immutability-io/nkey/blob/master/README.md#update-nkey-identity)
* [Delete Nkey Identity](https://github.com/immutability-io/nkey/blob/master/README.md#delete-nkey-identity)
* [Export Nkey Identity](https://github.com/immutability-io/nkey/blob/master/README.md#export-nkey-identity)

### NKEY SIGNING AND VERIFICATION

* [Sign Claim](https://github.com/immutability-io/nkey/blob/master/README.md#sign-claim)
* [Sign](https://github.com/immutability-io/nkey/blob/master/README.md#sign)
* [Verify Claim (Authenticated)](https://github.com/immutability-io/nkey/blob/master/README.md#verify-claim-authenticated)
* [Verify Claim (Unauthenticated)](https://github.com/immutability-io/nkey/blob/master/README.md#verify-claim)
* [Verify](https://github.com/immutability-io/nkey/blob/master/README.md#verify)

### NKEY PLUGIN CONFIGURE

This endpoint will allow you to whitelist the IPs that are allowed to interact with the plugin 

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `LIST`  | `:mount-path/config`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.

#### Sample Payload

```sh
{
    "path":"/Users/cypherhat/go/src/github.com/immutability-io/vault-nkey/tests"
}
```

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/config | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "5f3a09f4-20a6-c0d0-8c7e-cb177eee8afd",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "bound_cidr_list": [
      "127.0.0.1"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


### LIST NKEY IDENTITIES

This endpoint will list all identities stores at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `LIST`  | `:mount-path/identities`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path of the identities to list. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request LIST \
    https://localhost:8200/v1/nkey/identities | jq .
```

#### Sample Response

The example below shows output for a query path of `/nkey/identities/`.

```
{
  "request_id": "f3837dac-4310-2dc3-2d16-7b8ab070c55e",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "keys": [
      "account",
      "cluster",
      "operator",
      "server",
      "untrusted-operator",
      "user"
    ]
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

### READ NKEY IDENTITY

This endpoint will list details about the nkey identity at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `GET`  | `:mount-path/identities/:name`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path of the identities to list. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to read. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request GET \
    https://localhost:8200/v1/nkey/identities/operator | jq .
```

#### Sample Response

The example below shows output for a read of `/nkey/identities/operator`.

```
{
  "request_id": "a8d434f6-30b4-5fe9-1d6f-734a13810fe3",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "public_key": "OCINRWCYYJT5VXWIV5SSGDLFRCLWVH66AJPPKOVOUE3OANUOUPZYOBLU",
    "trusted_keys": null,
    "type": "operator"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


### CREATE NKEY IDENTITY

This endpoint will create a identity at a path.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path of the identities to list. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to create. This is specified as part of the URL.
* `type` (`string: <required>`) - Specifies the type of the identity to create. (Defaults to `user`)
* `trusted_keys` (`string: <optional>`) - Specifies the identities that are allowed to sign claims made by this `name`. 

#### Sample Payload

```sh
{
    "type":"account",
    "trusted_keys":"OCINRWCYYJT5VXWIV5SSGDLFRCLWVH66AJPPKOVOUE3OANUOUPZYOBLU"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/immutability | jq .
```

#### Sample Response

The example below shows output for the successful creation of `/nkey/identities/immutability`.

```
{
  "request_id": "b567120f-c0b2-ce99-f20b-da8ca0711062",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "public_key": "ADCRKHMDY36FQZPGQBOYBTZNGLLWKGOT25ASPODZ73NOVDCFV3WQS5VA",
    "trusted_keys": [
      "OCINRWCYYJT5VXWIV5SSGDLFRCLWVH66AJPPKOVOUE3OANUOUPZYOBLU"
    ],
    "type": "account"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```


### DELETE NKEY IDENTITY

This endpoint will delete the identity - and its passphrase - from Vault.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `DELETE`  | `:mount-path/identities/:name`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path of the identities to list. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to update. This is specified as part of the URL.

#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request DELETE \
    https://localhost:8200/v1/nkey/identities/immutability
```

#### Sample Response

There is no response payload.

### EXPORT NKEY IDENTITY

This endpoint will export a JSON Keystore for use in another wallet.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name/export`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to export. This is specified as part of the URL.
* `path` (`string: <required>`) - The absolute path where the `.nk` keystore file will be exported to.

#### Sample Payload

```sh
{
    "path":"/Users/cypherhat/go/src/github.com/immutability-io/vault-nkey/tests"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/operator/export | jq .
```

#### Sample Response

The example below shows output for the successful export of the keystore for `/nkey/identities/operator/export`.

```
{
  "request_id": "90213934-7c62-b7ec-ffd2-413a19d89288",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "file": "/Users/cypherhat/go/src/github.com/immutability-io/vault-nkey/tests/operator.nk"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

#### File Contents

```sh
$ cat /Users/cypherhat/go/src/github.com/immutability-io/vault-nkey/tests/operator.nk
SOAMZFV6VS3X7CWRUL6FDLXHNXWWIBFUWA6YQ5OACIL3I55O2H4YUIYUEM%
```

### SIGN CLAIM

This endpoint signs a claim.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name/sign-claim`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity that will sign the claim. This is specified as part of the URL.
* `subject` (`string: <optional>`) - The `subject` of the claim. If present, it will override the `subject` in the raw `claims`.
* `type` (`string: <required>`) - The `type` of the claim. Can be one of `account`,`activation`,`user`,`server`,`cluster`,`operator`,`revocation`,`generic`.
* `claims` (`JSON string: <required>`) - The claims that will be made. This must match the type of claim.

#### Sample Payload

```sh
{
    "subject": "AA66QQ2NQZEQTEEUBNK4QBCE7MHWWVS4MFCV3J5V2ONOWIFLH7ISMPZM",
    "type": "account",
    "claims": "{\"sub\": \"ACBXX4MOY4AQCUN4PF77SLJCALTNSMYK5W47BRIL37QGPECQIZSNJDHH\",\"nats\": {\"limits\": {\"subs\": -1,\"conn\": -1,\"imports\": -1,\"exports\": -1,\"data\": -1,\"payload\": -1,\"wildcards\": true}}}"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/operator/sign-claim | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "500b66e6-8b6c-16f7-c7cd-69bda0c72ae3",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "public_key": "OCETMGWTA7533X7M25RJAV3JRRR3CNBJC5YNGHVHUBZD32GO3VOVW6Q7",
    "token": "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJCRldCVUJaQzJKQVhZSUw1SVhUUU9FVlBMWFhCTEFFRDczVVZSMklHSjM2RjI3NEg3TTNBIiwiaWF0IjoxNTQ1MTYyNjgwLCJpc3MiOiJPQ0VUTUdXVEE3NTMzWDdNMjVSSkFWM0pSUlIzQ05CSkM1WU5HSFZIVUJaRDMyR08zVk9WVzZRNyIsInN1YiI6IkFBNjZRUTJOUVpFUVRFRVVCTks0UUJDRTdNSFdXVlM0TUZDVjNKNVYyT05PV0lGTEg3SVNNUFpNIiwidHlwZSI6ImFjY291bnQiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiY29ubiI6LTEsImltcG9ydHMiOi0xLCJleHBvcnRzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ3aWxkY2FyZHMiOnRydWV9fX0.gFujgXNijljcyCA5zgMd67cMdqR7uWQYb2EF5_ZDs7SCN3LGqFdz6Hmr5o_rCD4gNb7hHKJWtbpptJU_t2k_Cw",
    "type": "account"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

### SIGN

This endpoint signs a base64 encoded payload.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name/sign-claim`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to sign the payload. This is specified as part of the URL.
* `payload` (`string: <required>`) - The `payload` to be signed.

#### Sample Payload

```sh
{
    "payload": "boaty mcboaterson"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/operator/sign | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "41c65819-cf9b-3f28-4076-fcc4a30354ca",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "public_key": "OCETMGWTA7533X7M25RJAV3JRRR3CNBJC5YNGHVHUBZD32GO3VOVW6Q7",
    "signature": "X1Sb57oYnRGoYXtUwEXTdjj3C68JJeR+ozoGCoPdqjfB7WftrxaeIhI9wyAFuNNjnO9/Ib9+kgZMePTM+xtwBw=="
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

### VERIFY CLAIM AUTHENTICATED

This endpoint verifies that a claim was signed by a trusted issuer.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name/verify-claim`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity that will verify the claim (`token`). This is specified as part of the URL.
* `token` (`string: <required>`) - The `token` to be verified.

#### Sample Payload

```sh
{
    "token": "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJCRldCVUJaQzJKQVhZSUw1SVhUUU9FVlBMWFhCTEFFRDczVVZSMklHSjM2RjI3NEg3TTNBIiwiaWF0IjoxNTQ1MTYyNjgwLCJpc3MiOiJPQ0VUTUdXVEE3NTMzWDdNMjVSSkFWM0pSUlIzQ05CSkM1WU5HSFZIVUJaRDMyR08zVk9WVzZRNyIsInN1YiI6IkFBNjZRUTJOUVpFUVRFRVVCTks0UUJDRTdNSFdXVlM0TUZDVjNKNVYyT05PV0lGTEg3SVNNUFpNIiwidHlwZSI6ImFjY291bnQiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiY29ubiI6LTEsImltcG9ydHMiOi0xLCJleHBvcnRzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ3aWxkY2FyZHMiOnRydWV9fX0.gFujgXNijljcyCA5zgMd67cMdqR7uWQYb2EF5_ZDs7SCN3LGqFdz6Hmr5o_rCD4gNb7hHKJWtbpptJU_t2k_Cw"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/account/verify-claim | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "bbea337e-83e5-5710-d806-35c27b2f2c92",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "issuer": "OCETMGWTA7533X7M25RJAV3JRRR3CNBJC5YNGHVHUBZD32GO3VOVW6Q7",
    "public_key": "AA66QQ2NQZEQTEEUBNK4QBCE7MHWWVS4MFCV3J5V2ONOWIFLH7ISMPZM"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}

```
### VERIFY CLAIM

This endpoint verifies that a claim was signed by a trusted issuer.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/verify-claim`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `token` (`string: <required>`) - The `token` to be verified.

#### Sample Payload

```sh
{
    "token": "eyJ0eXAiOiJqd3QiLCJhbGciOiJlZDI1NTE5In0.eyJqdGkiOiJCRldCVUJaQzJKQVhZSUw1SVhUUU9FVlBMWFhCTEFFRDczVVZSMklHSjM2RjI3NEg3TTNBIiwiaWF0IjoxNTQ1MTYyNjgwLCJpc3MiOiJPQ0VUTUdXVEE3NTMzWDdNMjVSSkFWM0pSUlIzQ05CSkM1WU5HSFZIVUJaRDMyR08zVk9WVzZRNyIsInN1YiI6IkFBNjZRUTJOUVpFUVRFRVVCTks0UUJDRTdNSFdXVlM0TUZDVjNKNVYyT05PV0lGTEg3SVNNUFpNIiwidHlwZSI6ImFjY291bnQiLCJuYXRzIjp7ImxpbWl0cyI6eyJzdWJzIjotMSwiY29ubiI6LTEsImltcG9ydHMiOi0xLCJleHBvcnRzIjotMSwiZGF0YSI6LTEsInBheWxvYWQiOi0xLCJ3aWxkY2FyZHMiOnRydWV9fX0.gFujgXNijljcyCA5zgMd67cMdqR7uWQYb2EF5_ZDs7SCN3LGqFdz6Hmr5o_rCD4gNb7hHKJWtbpptJU_t2k_Cw"
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/verify-claim | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "bbea337e-83e5-5710-d806-35c27b2f2c92",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "issuer": "OCETMGWTA7533X7M25RJAV3JRRR3CNBJC5YNGHVHUBZD32GO3VOVW6Q7",
    "public_key": "AA66QQ2NQZEQTEEUBNK4QBCE7MHWWVS4MFCV3J5V2ONOWIFLH7ISMPZM"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}

```

### VERIFY

This endpoint verifies a signature.

| Method  | Path | Produces |
| ------------- | ------------- | ------------- |
| `POST`  | `:mount-path/identities/:name/verify`  | `200 application/json` |

#### Parameters

* `mount-path` (`string: <required>`) - Specifies the path where the plugin is mounted. This is specified as part of the URL.
* `name` (`string: <required>`) - Specifies the name of the identity to verify the signature. This is specified as part of the URL.
* `payload` (`string: <required>`) - The `payload` that was signed.
* `signature` (`string: <required>`) - The `signature` to be verified.

#### Sample Payload

```sh
{
    "payload": "boaty mcboaterson",
    "signature": "X1Sb57oYnRGoYXtUwEXTdjj3C68JJeR+ozoGCoPdqjfB7WftrxaeIhI9wyAFuNNjnO9/Ib9+kgZMePTM+xtwBw=="
}
```
#### Sample Request

```sh
$ curl -s --cacert ~/etc/vault.d/root.crt --header "X-Vault-Token: $VAULT_TOKEN" \
    --request POST \
    --data @payload.json \
    https://localhost:8200/v1/nkey/identities/operator/verify | jq .
```

#### Sample Response

The example below shows output.

```
{
  "request_id": "9083f395-7d32-4451-8876-a25b0b024905",
  "lease_id": "",
  "renewable": false,
  "lease_duration": 0,
  "data": {
    "public_key": "OCETMGWTA7533X7M25RJAV3JRRR3CNBJC5YNGHVHUBZD32GO3VOVW6Q7"
  },
  "wrap_info": null,
  "warnings": null,
  "auth": null
}
```

