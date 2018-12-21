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
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/immutability-io/nkey/util"
)

// AccountPublicKey stores the name of the identity to allow reverse lookup by publickey
type AccountPublicKey struct {
	PublicKey string `json:"public_key"`
}

func keysPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "keys/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathPublicKeysList,
			},
			HelpSynopsis: "List all the public keys",
			HelpDescription: `
			All the public keys of identities will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "keys/" + framework.GenericNameRegex("key"),
			HelpSynopsis: "Lookup a identity's name by public key.",
			HelpDescription: `

			Lookup a identity's name by public key.
`,
			Fields: map[string]*framework.FieldSchema{
				"key": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathPublicKeysRead,
			},
		},
		&framework.Path{
			Pattern:      "keys/" + framework.GenericNameRegex("key") + "/verify-claim",
			HelpSynopsis: "Verifies and validates a JWT token.",
			HelpDescription: `

Verifies and validates a JWT token
`,
			Fields: map[string]*framework.FieldSchema{
				"key": &framework.FieldSchema{Type: framework.TypeString},
				"token": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The JWT.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathPublicKeysVerifyClaim,
			},
		},
		&framework.Path{
			Pattern:      "keys/" + framework.GenericNameRegex("name") + "/encrypt",
			HelpSynopsis: "Encrypts data.",
			HelpDescription: `

Encrypts data.
`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"plaintext": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The data to encrypt",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathPublicKeysEncrypt,
			},
		},
		&framework.Path{
			Pattern:      "keys/" + framework.GenericNameRegex("key") + "/verify",
			HelpSynopsis: "Verify that data was signed by a particular public key.",
			HelpDescription: `

Verify that data was signed by a particular public key
`,
			Fields: map[string]*framework.FieldSchema{
				"key": &framework.FieldSchema{Type: framework.TypeString},
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
				logical.UpdateOperation: b.pathPublicKeysVerify,
			},
		},
	}
}

func (b *backend) pathPublicKeysRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publickey := data.Get("key").(string)
	identity, err := b.readPublicKey(ctx, req, publickey)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"names": identity.Names,
		},
	}, nil
}

func (b *backend) pathPublicKeysList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	vals, err := req.Storage.List(ctx, "keys/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) readPublicKey(ctx context.Context, req *logical.Request, publickey string) (*AccountNames, error) {
	path := fmt.Sprintf("keys/%s", publickey)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var identityNames AccountNames
	err = entry.DecodeJSON(&identityNames)
	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize identity at %s", path)
	}

	return &identityNames, nil
}

func (b *backend) pathPublicKeysVerifyClaim(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publickey := data.Get("key").(string)
	identity, err := b.readPublicKey(ctx, req, publickey)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}
	if len(identity.Names) == 0 {
		return nil, nil
	}

	return b.pathVerifyClaimByName(ctx, req, data, identity.Names[0])
}

func (b *backend) pathPublicKeysVerify(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publickey := data.Get("key").(string)
	identity, err := b.readPublicKey(ctx, req, publickey)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}
	if len(identity.Names) == 0 {
		return nil, nil
	}

	return b.pathVerifySignatureByName(ctx, req, data, identity.Names[0])
}

func (b *backend) crossReference(ctx context.Context, req *logical.Request, name, publickey string) error {
	identityPublicKey := &AccountPublicKey{PublicKey: publickey}
	identityNames, err := b.readPublicKey(ctx, req, publickey)

	if identityNames == nil {
		identityNames = &AccountNames{}
	}
	identityNames.Names = append(identityNames.Names, name)

	pathAccountPublicKey := fmt.Sprintf("keys/%s", identityPublicKey.PublicKey)
	pathAccountName := fmt.Sprintf("names/%s", name)

	lookupNameEntry, err := logical.StorageEntryJSON(pathAccountName, identityPublicKey)
	if err != nil {
		return err
	}
	lookupPublicKeyEntry, err := logical.StorageEntryJSON(pathAccountPublicKey, identityNames)

	if err != nil {
		return err
	}
	err = req.Storage.Put(ctx, lookupNameEntry)
	if err != nil {
		return err
	}
	err = req.Storage.Put(ctx, lookupPublicKeyEntry)
	if err != nil {
		return err
	}

	return nil
}

func (b *backend) removeCrossReference(ctx context.Context, req *logical.Request, name, publickey string) error {
	pathAccountPublicKey := fmt.Sprintf("keys/%s", publickey)
	pathAccountName := fmt.Sprintf("names/%s", name)

	identityNames, err := b.readPublicKey(ctx, req, publickey)
	if err != nil {
		return err
	}
	if identityNames == nil || len(identityNames.Names) <= 1 {
		if err := req.Storage.Delete(ctx, pathAccountPublicKey); err != nil {
			return err
		}
	} else {
		updatedAccountNames := &AccountNames{}
		for i, identityName := range identityNames.Names {
			if identityName != name {
				updatedAccountNames.Names = append(updatedAccountNames.Names, identityNames.Names[i])
			}
		}
		lookupPublicKeyEntry, err := logical.StorageEntryJSON(pathAccountPublicKey, updatedAccountNames)

		if err != nil {
			return err
		}
		err = req.Storage.Put(ctx, lookupPublicKeyEntry)
		if err != nil {
			return err
		}
	}

	if err := req.Storage.Delete(ctx, pathAccountName); err != nil {
		return err
	}
	return nil
}

func (b *backend) pathPublicKeysEncrypt(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publickey := data.Get("key").(string)
	accountNames, err := b.readPublicKey(ctx, req, publickey)
	if err != nil {
		return nil, err
	}

	if accountNames == nil {
		return nil, nil
	}
	if len(accountNames.Names) == 0 {
		return nil, nil
	}
	identity, err := b.readIdentity(ctx, req, accountNames.Names[0])
	if err != nil {
		return nil, fmt.Errorf("error reading identity")
	}
	if identity == nil {
		return nil, nil
	}
	plaintext := data.Get("plaintext").(string)
	if plaintext == "" {
		return nil, fmt.Errorf("plaintext is required")
	}
	ciphertext, err := util.Encrypt(identity.EncryptionPublicKey, plaintext)
	if err != nil {
		return nil, err
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"public_key":     identity.PublicKey,
			"encryption_key": identity.EncryptionPublicKey,
			"ciphertext":     ciphertext,
		},
	}, nil

}
