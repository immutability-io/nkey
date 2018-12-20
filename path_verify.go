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

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"github.com/nats-io/jwt"
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
