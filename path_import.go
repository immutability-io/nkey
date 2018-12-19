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
	"io/ioutil"
	"path/filepath"

	"github.com/nats-io/nkeys"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	// TypeNkey is a file with the .nk extension
	TypeNkey string = ".nk"
	// TypeCreds is a file with the .creds extension
	TypeCreds string = ".creds"
)

func importPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "import/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Import an nkey from file.",
			HelpDescription: `

Reads an nkey seed from file.

`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
				"path": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Absolute path to the keystore file - not the parent directory.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.CreateOperation: b.pathImportCreate,
			},
		},
	}
}

func (b *backend) pathImportCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}
	name := data.Get("name").(string)
	var identity *Identity
	identity, err = b.readIdentity(ctx, req, name)
	if err != nil {
		return nil, fmt.Errorf("Error reading identity")
	}
	if identity == nil {
		keystorePath := data.Get("path").(string)
		fileType := filepath.Ext(keystorePath)
		switch fileType {
		case TypeNkey:
			seed, err := ioutil.ReadFile(keystorePath)
			if err != nil {
				return nil, err
			}
			pair, err := nkeys.FromSeed(seed)
			if err != nil {
				return nil, err
			}
			identity, err = b.storeIdentity(ctx, req, name, pair, nil)
			if err != nil {
				return nil, err
			}
			err = b.crossReference(ctx, req, name, identity.PublicKey)
			if err != nil {
				return nil, err
			}

		case TypeCreds:
			_, seed, err := credsFromNkeyFile(keystorePath)
			if err != nil {
				return nil, err
			}
			pair, err := nkeys.FromSeed([]byte(seed))
			if err != nil {
				return nil, err
			}
			identity, err = b.storeIdentity(ctx, req, name, pair, nil)
			if err != nil {
				return nil, err
			}
			err = b.crossReference(ctx, req, name, identity.PublicKey)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unknown file type")
		}
		return &logical.Response{
			Data: map[string]interface{}{
				"type":         nkeys.Prefix(identity.PublicKey).String(),
				"trusted_keys": identity.TrustedKeys,
				"public_key":   identity.PublicKey,
			},
		}, nil
	}
	return nil, fmt.Errorf("account %s exists", name)
}
