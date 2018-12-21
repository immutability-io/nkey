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
)

// AccountNames holds a list of names
type AccountNames struct {
	Names []string `json:"names"`
}

func namesPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern: "names/?",
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ListOperation: b.pathNamesList,
			},
			HelpSynopsis: "List all the identity names",
			HelpDescription: `
			All the names of identities will be listed.
			`,
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name"),
			HelpSynopsis: "Lookup a identity's public key by name.",
			HelpDescription: `

			Lookup a identity's public key by name.
`,
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{Type: framework.TypeString},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.ReadOperation: b.pathNamesRead,
			},
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name") + "/verify",
			HelpSynopsis: "Verify that data was signed by a particular public key.",
			HelpDescription: `

Verify that data was signed by a particular public key
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
				logical.UpdateOperation: b.pathVerify,
			},
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name") + "/verify-claim",
			HelpSynopsis: "Verifies and validates a JWT token.",
			HelpDescription: `

Verifies and validates a JWT token
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
				logical.UpdateOperation: b.pathVerifyClaim,
			},
		},
		&framework.Path{
			Pattern:      "names/" + framework.GenericNameRegex("name") + "/encrypt",
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
				logical.UpdateOperation: b.pathEncrypt,
			},
		},
	}
}

func (b *backend) pathNamesRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	name := data.Get("name").(string)
	identity, err := b.readName(ctx, req, name)
	if err != nil {
		return nil, err
	}

	if identity == nil {
		return nil, nil
	}

	// Return the secret
	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": identity.PublicKey,
		},
	}, nil
}

func (b *backend) pathNamesList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	vals, err := req.Storage.List(ctx, "names/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(vals), nil
}

func (b *backend) readName(ctx context.Context, req *logical.Request, name string) (*AccountPublicKey, error) {
	path := fmt.Sprintf("names/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var identityPublicKey AccountPublicKey
	err = entry.DecodeJSON(&identityPublicKey)

	if entry == nil {
		return nil, fmt.Errorf("failed to deserialize named identity at %s", path)
	}

	return &identityPublicKey, nil
}
