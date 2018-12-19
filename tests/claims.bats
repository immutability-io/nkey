#!/usr/bin/env bats

@test "test config" {
  config="$(vault write -format=json -f nkey/config | jq .data)"
  bound_cidr_list="$(echo $config | jq -r .bound_cidr_list)"
    [ "$bound_cidr_list" = "null" ]
}

@test "create operator" {
  operator="$(vault write -format=json nkey/identities/operator type=operator | jq .data)"
  type="$(echo $operator | jq -r .type)"
    [ "$type" = "operator" ]
}

@test "create untrusted operator" {
  operator="$(vault write -format=json nkey/identities/untrusted-operator type=operator | jq .data)"
  type="$(echo $operator | jq -r .type)"
    [ "$type" = "operator" ]
}

@test "create account" {
  operator_key="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  account="$(vault write -format=json nkey/identities/account type=account trusted_keys=$operator_key | jq .data)"
  trusted_keys="$(echo $account | jq -r '.trusted_keys[]' | tr -d '"')"
  type="$(echo $account | jq -r .type)"
    [ "$type" = "account" ]
    [ "$trusted_keys" = "$operator_key" ]
}

@test "create cluster" {
  operator_key="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  cluster="$(vault write -format=json nkey/identities/cluster type=cluster trusted_keys=$operator_key | jq .data)"
  trusted_keys="$(echo $cluster | jq -r '.trusted_keys[]' | tr -d '"')"
  type="$(echo $cluster | jq -r .type)"
    [ "$type" = "cluster" ]
    [ "$trusted_keys" = "$operator_key" ]
}

@test "create server" {
  operator_key="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  server="$(vault write -format=json nkey/identities/server type=server trusted_keys=$operator_key | jq .data)"
  trusted_keys="$(echo $server | jq -r '.trusted_keys[]' | tr -d '"')"
  type="$(echo $server | jq -r .type)"
    [ "$type" = "server" ]
    [ "$trusted_keys" = "$operator_key" ]
}

@test "create user" {
  account_key="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  user="$(vault write -format=json nkey/identities/user type=user trusted_keys=$account_key | jq .data)"
  trusted_keys="$(echo $user | jq -r '.trusted_keys[]' | tr -d '"')"
  type="$(echo $user | jq -r .type)"
    [ "$type" = "user" ]
    [ "$trusted_keys" = "$account_key" ]
}

@test "import ngs account" {
  path=$HOME"/.nkeys/synadia/accounts/ngs/ngs.nk"
  user="$(vault write -format=json nkey/import/ngs-account path=$path | jq .data)"
  type="$(echo $user | jq -r .type)"
    [ "$type" = "account" ]
}

@test "import ngs user" {
  path=$HOME"/.nkeys/synadia/accounts/ngs/users/ngs.nk"
  account_key="$(vault read -format=json nkey/identities/ngs-account | jq -r .data.public_key)"
  user="$(vault write -format=json nkey/import/ngs-user path=$path | jq .data)"
  user_update="$(vault write -format=json nkey/identities/ngs-user trusted_keys=$account_key | jq .data)"
  type="$(echo $user | jq -r .type)"
    [ "$type" = "user" ]
}

@test "create ngs user claim" {
  issuer="$(vault read -format=json nkey/identities/ngs-account | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/ngs-user | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/ngs-account/sign-claim subject=$subject type="user" claims=@user.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/ngs-user/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create account claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="account" claims=@account.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/account/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create user claim" {
  issuer="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/user | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/account/sign-claim subject=$subject type="user" claims=@user.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/user/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create activation claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="activation" claims=@activation.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/account/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create revocation claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="revocation" claims=@revocation.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/account/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create cluster claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/cluster | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="cluster" claims=@cluster.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/cluster/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "create server claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/server | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="server" claims=@server.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/server/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "sign data" {
  payload="foobar"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  signature="$(vault write -format=json nkey/identities/account/sign payload=$payload | jq -r .data.signature)"
  signer="$(vault write -format=json nkey/identities/account/verify payload=$payload signature=$signature | jq -r .data.public_key)"
    [ "$subject" = "$signer" ]
}

@test "invalid signature" {
  payload="foobar"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  signature="$(vault write -format=json nkey/identities/user/sign payload=$payload | jq -r .data.signature)"
  signer="$(vault write -format=json nkey/identities/account/verify payload=$payload signature=$tampered | jq -r .data.public_key)"
    [ "$subject" = "$signer" ]
}

@test "create untrusted account claim" {
  issuer="$(vault read -format=json nkey/identities/untrusted-operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/untrusted-operator/sign-claim subject=$subject type="account" claims=@account.json | jq -r .data.token)"
  response="$(vault write -format=json nkey/identities/account/verify-claim token=$token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "fail verification of account claim" {
  issuer="$(vault read -format=json nkey/identities/operator | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/account | jq -r .data.public_key)"
  token="$(vault write -format=json nkey/identities/operator/sign-claim subject=$subject type="account" claims=@account.json | jq -r .data.token)"
  bad_token=$token"A"
  response="$(vault write -format=json nkey/identities/account/verify-claim token=$bad_token | jq .data)"
  response_issuer="$(echo $response | jq -r .issuer)"
  response_subject="$(echo $response | jq -r .public_key)"
    [ "$issuer" = "$response_issuer" ]
    [ "$subject" = "$response_subject" ]
}

@test "user can't sign their own claim" {
  issuer="$(vault read -format=json nkey/identities/user | jq -r .data.public_key)"
  subject="$(vault read -format=json nkey/identities/user | jq -r .data.public_key)"
  type="$(vault write -format=json nkey/identities/user/sign-claim subject=$subject type="user" claims=@user.json | jq -r .data.type)"
    [ "$type" = "user" ]
}

