// Copyright © 2018 Immutability, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

// Identity is a trusted entity in vault.
type Identity struct {
	Seed        string   `json:"seed"`
	PublicKey   string   `json:"public_key"`
	PrivateKey  string   `json:"private_key"`
	TrustedKeys []string `json:"trusted_keys_list" structs:"trusted_keys" mapstructure:"trusted_keys"`
}

// IdentityName stores the name of the identity to allow reverse lookup by publickey
type IdentityName struct {
	Name string `json:"name"`
}

// IdentityPublicKey stores the name of the identity to allow reverse lookup by publickey
type IdentityPublicKey struct {
	PublicKey string `json:"publickey"`
}

func identitiesPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "identities/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathIdentitiesList,
			},
			HelpSynopsis: "List all the identities at a path",
			HelpDescription: `
			All the identities will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Reads, creates or deletes a identity",
			HelpDescription: `

Reads, creates or deletes a identity: a identity is a private key. 

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"type": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "user",
					Description: "Type of key. Defaults to user.",
				},
				"trusted_keys": &framework.FieldSchema{
					Type: framework.TypeCommaStringSlice,
					Description: `Comma separated string or list of keys. If set, specifies the blocks of
publickeys which are allowed to sign keys.`,
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation:   b.pathIdentitiesRead,
				logical.CreateOperation: b.pathIdentitiesCreate,
				logical.UpdateOperation: b.pathIdentitiesUpdate,
				logical.DeleteOperation: b.pathIdentitiesDelete,
			},
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name") + "/sign-claim",
			HelpSynopsis: "Create a JWT containing claims. Sign with identities private key.",
			HelpDescription: `

Create a JWT containing claims. Sign with identity private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"subject": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The Subject of the claims. Identified by `sub` in the JWT.",
				},
				"type": &framework.FieldSchema{
					Type:        framework.TypeString,
					Default:     "generic",
					Description: "The type of claim. Can be one of 'account','activation','user','server','cluster','operator','revocation'",
				},
				"claims": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The claims being asserted. This is a URL encoded JSON blob. (See documentation.)",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSignClaim,
			},
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name") + "/sign",
			HelpSynopsis: "Sign payload with the identity private key.",
			HelpDescription: `

Sign data with identities private key.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"payload": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The payload to sign.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathSign,
			},
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name") + "/verify-claim",
			HelpSynopsis: "Verifies and validates a JWT token.",
			HelpDescription: `

Verifies and validates a JWT token.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"token": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The JWT.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathVerifyClaim,
			},
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name") + "/verify",
			HelpSynopsis: "Verifies a signature.",
			HelpDescription: `

Verifies a signature.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"payload": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to check the signature of.",
				},
				"signature": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The signature.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathVerify,
			},
		},
		&framework.Path{
			Pattern:      "identities/" + framework.GenericNameRegex("name") + "/export",
			HelpSynopsis: "Exports the seed and JWT to a text file at a path.",
			HelpDescription: `

Exports the seed and JWT to a text file at a path.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Directory to export the seed and JWT into - must be an absolute path.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathExportCreate,
			},
		},
	}
}

func (b *backend) pathIdentitiesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"type":         nkeys.Prefix(identity.PublicKey).String(),
			"trusted_keys": identity.TrustedKeys,
			"public_key":   identity.PublicKey,
		},
	}, nil
}

func (b *backend) pathIdentitiesCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	keyType := data.Get("type").(string)
	var trustedKeys []string
	if trustedKeysRaw, ok := data.GetOk("trusted_keys"); ok {
		trustedKeys = trustedKeysRaw.([]string)
	}
	pair, err := nkeys.CreatePair(PrefixByteFromString(keyType))
	if err != nil {
		return nil, err
	}
	publickey, err := pair.PublicKey()
	if err != nil {
		return nil, err
	}
	privatekey, err := pair.PrivateKey()
	if err != nil {
		return nil, err
	}
	seed, err := pair.Seed()
	if err != nil {
		return nil, err
	}
	identityJSON := &Identity{
		PublicKey:   publickey,
		TrustedKeys: trustedKeys,
		PrivateKey:  string(privatekey),
		Seed:        string(seed),
	}
	defer pair.Wipe()
	entry, err := logical.StorageEntryJSON(req.Path, identityJSON)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	b.crossReference(ctx, req, name, identityJSON.PublicKey)
	return &logical.Response{
		Data: map[string]interface{}{
			"type":         nkeys.Prefix(identityJSON.PublicKey).String(),
			"public_key":   identityJSON.PublicKey,
			"trusted_keys": identityJSON.TrustedKeys,
		},
	}, nil
}

func (b *backend) pathIdentitiesDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, req.Path); err != nil {
		return nil, err
	}
	// Remove lookup value
	pathIdentityName := fmt.Sprintf("keys/%s", identity.PublicKey)
	pathIdentityPublicKey := fmt.Sprintf("names/%s", name)
	if err := req.Storage.Delete(ctx, pathIdentityName); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, pathIdentityPublicKey); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathIdentitiesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	vals, err := req.Storage.List(ctx, "identities/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) pathExportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	path := data.Get("path").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading identity")
	}
	if identity == nil {
		return nil, nil
	}
	err = os.MkdirAll(path, 0644)
	if err != nil {
		return nil, err
	}
	err = ioutil.WriteFile(filepath.Join(path, name+".nk"), []byte(identity.Seed), 0644)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"file": filepath.Join(path, name+".nk"),
		},
	}, nil
}

func (b *backend) pathVerifyClaim(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	return b.pathVerifyClaimByName(ctx, req, data, name)

}

func (b *backend) pathVerify(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	return b.pathVerifySignatureByName(ctx, req, data, name)

}

func (b *backend) pathSignClaim(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, err
	}
	claimsData := data.Get("claims").(string)
	if claimsData == "" {
		return nil, fmt.Errorf("claims data is required")
	}

	claimsType := data.Get("type").(string)
	subject := data.Get("subject").(string)
	keyPair, err := nkeys.FromSeed([]byte(identity.Seed))
	if err != nil {
		return nil, err
	}
	token, err := encodeClaim(claimsType, claimsData, subject, keyPair)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token":      token,
			"type":       claimsType,
			"public_key": identity.PublicKey,
		},
	}, nil
}

func (b *backend) pathIdentitiesUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	keyType := data.Get("type").(string)
	if keyType != nkeys.Prefix(identity.PublicKey).String() {
		return nil, fmt.Errorf("cannot change identity type")
	}

	var trustedKeys []string
	if trustedKeysRaw, ok := data.GetOk("trusted_keys"); ok {
		trustedKeys = trustedKeysRaw.([]string)
	}
	identity.TrustedKeys = trustedKeys
	entry, err := logical.StorageEntryJSON(req.Path, identity)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"type":         nkeys.Prefix(identity.PublicKey).String(),
			"trusted_keys": identity.TrustedKeys,
			"public_key":   identity.PublicKey,
		},
	}, nil
}

func (b *backend) readIdentity(ctx context.Context, req *logical.Request, name string) (*Identity, error) {
	path := fmt.Sprintf("identities/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var identity Identity
	err = entry.DecodeJSON(&identity)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize identity at %s", path)
	}

	return &identity, nil
}

func (b *backend) pathVerifyClaimByName(ctx context.Context, req *logical.Request, data *framework.FieldData, name string) (*logical.Response, error) {
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading identity")
	}
	if identity == nil {
		return nil, nil
	}
	token := data.Get("token").(string)
	claims, err := jwt.DecodeGeneric(token)
	if err != nil {
		return nil, err
	}

	if !contains(identity.TrustedKeys, claims.Issuer) {
		return nil, fmt.Errorf("issuer %s is not trusted", claims.Issuer)
	}
	validationResults := jwt.CreateValidationResults()
	claims.Validate(validationResults)
	if !validationResults.IsEmpty() {
		return nil, fmt.Errorf("validation issues: %d, errors: %d", len(validationResults.Issues), len(validationResults.Errors()))
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"issuer":     claims.Issuer,
			"public_key": identity.PublicKey,
		},
	}, nil

}

func (b *backend) pathSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, err
	}
	payload := data.Get("payload").(string)
	if payload == "" {
		return nil, fmt.Errorf("payload is required")
	}
	keyPair, err := nkeys.FromSeed([]byte(identity.Seed))
	if err != nil {
		return nil, err
	}
	signature, err := keyPair.Sign([]byte(payload))
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature":  base64.StdEncoding.EncodeToString(signature),
			"public_key": identity.PublicKey,
		},
	}, nil
}

func (b *backend) pathVerifySignatureByName(ctx context.Context, req *logical.Request, data *framework.FieldData, name string) (*logical.Response, error) {
	identity, err := b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("error reading identity")
	}
	if identity == nil {
		return nil, nil
	}
	payload := data.Get("payload").(string)
	signature := data.Get("signature").(string)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	keyPair, err := nkeys.FromPublicKey(identity.PublicKey)
	if err != nil {
		return nil, err
	}
	err = keyPair.Verify([]byte(payload), signatureBytes)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": identity.PublicKey,
		},
	}, nil

}
