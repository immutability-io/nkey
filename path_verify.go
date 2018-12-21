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

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

func verifyPaths(b *backend) []*framework.Path {
	return []*framework.Path{
		&framework.Path{
			Pattern:      "verify-claim",
			HelpSynopsis: "Verifies and validates a JWT token.",
			HelpDescription: `

Verifies and validates a JWT token
`,
			Fields: map[string]*framework.FieldSchema{
				"token": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The JWT.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathVerifyToken,
				logical.CreateOperation: b.pathVerifyToken,
			},
		},
		&framework.Path{
			Pattern:      "verify",
			HelpSynopsis: "Verifies and validates a signature.",
			HelpDescription: `

Verifies and validates a signature
`,
			Fields: map[string]*framework.FieldSchema{
				"public_key": &framework.FieldSchema{Type: framework.TypeString},
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
				logical.UpdateOperation: b.pathVerifySignature,
				logical.CreateOperation: b.pathVerifySignature,
			},
		},
		&framework.Path{
			Pattern:      "encrypt",
			HelpSynopsis: "Encrypts with another party's public key.",
			HelpDescription: `

Verifies and validates a signature
`,
			Fields: map[string]*framework.FieldSchema{
				"encryption_key": &framework.FieldSchema{Type: framework.TypeString},
				"plaintext": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "The text to encrypt.",
				},
			},
			ExistenceCheck: b.pathExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.UpdateOperation: b.pathEncryptSimple,
				logical.CreateOperation: b.pathEncryptSimple,
			},
		},
	}
}

func (b *backend) pathVerifyToken(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	token := data.Get("token").(string)
	claims := &jwt.GenericClaims{}
	err = parseNoVerify(token, claims)
	if err != nil {
		return nil, err
	}
	identity, err := b.readPublicKey(ctx, req, claims.Claims().Subject)
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

func (b *backend) pathVerifySignature(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publicKey := data.Get("public_key").(string)
	if publicKey == Empty {
		return nil, fmt.Errorf("public key is required")
	}
	payload := data.Get("payload").(string)
	if payload == Empty {
		return nil, fmt.Errorf("payload is required")
	}
	signature := data.Get("signature").(string)
	if signature == Empty {
		return nil, fmt.Errorf("signature is required")
	}
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	keyPair, err := nkeys.FromPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	err = keyPair.Verify([]byte(payload), signatureBytes)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"public_key": publicKey,
		},
	}, nil

}

func (b *backend) pathEncryptSimple(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	_, err := b.configured(ctx, req)
	if err != nil {
		return nil, err
	}

	publicKey := data.Get("encryption_key").(string)
	if publicKey == Empty {
		return nil, fmt.Errorf("encryption key is required")
	}
	plaintext := data.Get("plaintext").(string)
	if plaintext == Empty {
		return nil, fmt.Errorf("plaintext is required")
	}
	ciphertext, err := encrypt(publicKey, plaintext)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"encryption_key": publicKey,
			"ciphertext":     ciphertext,
		},
	}, nil

}
