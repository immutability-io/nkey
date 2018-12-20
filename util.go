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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/helper/pgpkeys"
	"github.com/nats-io/jwt"
	"github.com/nats-io/nkeys"
)

const (
	// Empty is an empty string
	Empty string = ""
	// JWTBoundary is an empty string
	JWTBoundary string = "NATS USER JWT"
	// SeedBoundary is an empty string
	SeedBoundary string = "USER NKEY SEED"
	// BoundaryFormat is a printf string
	BoundaryFormat string = "-----%s %s-----\n"
	// Begin is the begin boundary
	Begin string = "BEGIN"
	// End is the end boundary
	End string = "END"
)

// PrefixByteFromString returns a PrefixByte from the stringified value
func PrefixByteFromString(p string) nkeys.PrefixByte {
	switch p {
	case "operator":
		return nkeys.PrefixByteOperator
	case "server":
		return nkeys.PrefixByteServer
	case "cluster":
		return nkeys.PrefixByteCluster
	case "account":
		return nkeys.PrefixByteAccount
	case "user":
		return nkeys.PrefixByteUser
	case "seed":
		return nkeys.PrefixByteSeed
	case "private":
		return nkeys.PrefixBytePrivate
	}
	return nkeys.PrefixByteUknown
}

func (b *backend) contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

func contains(stringSlice []string, searchString string) bool {
	for _, value := range stringSlice {
		if value == searchString {
			return true
		}
	}
	return false
}

func dedup(stringSlice []string) []string {
	var returnSlice []string
	for _, value := range stringSlice {
		if !contains(returnSlice, value) {
			returnSlice = append(returnSlice, value)
		}
	}
	return returnSlice
}

func encodeClaim(claimsType, claimsData, subject string, keyPair nkeys.KeyPair) (string, error) {
	var claims jwt.Claims
	switch claimsType {
	case "account":
		claims = &jwt.AccountClaims{}
	case "activation":
		claims = &jwt.ActivationClaims{}
	case "user":
		claims = &jwt.UserClaims{}
	case "server":
		claims = &jwt.ServerClaims{}
	case "cluster":
		claims = &jwt.ClusterClaims{}
	case "operator":
		claims = &jwt.OperatorClaims{}
	case "revocation":
		claims = &jwt.RevocationClaims{}
	case "generic":
		claims = &jwt.GenericClaims{}
	default:
		return "", fmt.Errorf("unknown claim type %s", claimsType)
	}
	err := json.Unmarshal([]byte(claimsData), claims)
	if err != nil {
		return "", err
	}
	if subject != "" {
		claims.Claims().Subject = subject
	}
	token, err := claims.Encode(keyPair)
	if err != nil {
		return "", err
	}
	return token, nil
}

var nscDecoratedRe = regexp.MustCompile(`\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))`)

func credsFromNkeyFile(userFile string) (string, string, error) {
	contents, err := ioutil.ReadFile(userFile)
	if err != nil {
		return "", Empty, fmt.Errorf("nats: %v", err)
	}
	defer wipeSlice(contents)

	items := nscDecoratedRe.FindAllSubmatch(contents, -1)
	if len(items) == 0 {
		return "", string(contents), nil
	}
	// First result should be the user JWT.
	// We copy here so that if the file contained a seed file too we wipe appropriately.
	var jwt []byte
	var nkey []byte
	for i, item := range items {
		switch i {
		case 0:
			if len(item) == 2 {
				jwt = make([]byte, len(item[1]))
				copy(jwt, item[1])
			}
		case 1:
			if len(item) == 2 {
				nkey = make([]byte, len(item[1]))
				copy(nkey, item[1])
			}
		}
	}
	return string(jwt), string(nkey), nil
}

// Just wipe slice with 'x', for clearing contents of nkey seed file.
func wipeSlice(buf []byte) {
	for i := range buf {
		buf[i] = 'x'
	}
}

func parseClaims(s string, target jwt.Claims) error {
	h, err := decodeString(s)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(h, &target); err != nil {
		return err
	}

	return nil
}

func decodeString(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func parseNoVerify(token string, target jwt.Claims) error {
	// must have 3 chunks
	chunks := strings.Split(token, ".")
	if len(chunks) != 3 {
		return errors.New("expected 3 chunks")
	}

	_, err := parseHeaders(chunks[0])
	if err != nil {
		return err
	}

	if err := parseClaims(chunks[1], target); err != nil {
		return err
	}

	_, err = decodeString(chunks[2])
	if err != nil {
		return err
	}

	return nil
}

// Parses a header JWT token
func parseHeaders(s string) (*jwt.Header, error) {
	h, err := decodeString(s)
	if err != nil {
		return nil, err
	}
	header := jwt.Header{}
	if err := json.Unmarshal(h, &header); err != nil {
		return nil, err
	}

	if err := header.Valid(); err != nil {
		return nil, err
	}
	return &header, nil
}

func formatFingerprint(fingerprint string) string {
	return fmt.Sprintf("%s %s %s %s", strings.ToUpper(fingerprint[24:])[0:4],
		strings.ToUpper(fingerprint[24:])[4:8],
		strings.ToUpper(fingerprint[24:])[8:12],
		strings.ToUpper(fingerprint[24:])[12:16])
}

func keybaseEncrypt(keybaseIdentity string, payload []byte) (string, []byte, error) {
	plaintextes := make([][]byte, 0)
	plaintextes = append(plaintextes, payload)
	pgpKeys := make([]string, 0)
	pgpKeys = append(pgpKeys, keybaseIdentity)
	pgpKeysFetched, err := pgpkeys.FetchKeybasePubkeys(pgpKeys)
	if err != nil {
		return "", nil, err
	}
	keys := make([]string, 0)
	for _, fetched := range pgpKeysFetched {
		keys = append(keys, fetched)
	}
	fingerprints, ciphertextes, err := pgpkeys.EncryptShares(plaintextes, keys)
	if err != nil {
		return "", nil, err
	}
	return formatFingerprint(fingerprints[0]), ciphertextes[0], nil
}

func getCredsFile(seed, token string) []byte {
	contents := fmt.Sprintf(BoundaryFormat, Begin, JWTBoundary) +
		fmt.Sprintf("%s\n", token) +
		fmt.Sprintf(BoundaryFormat, End, JWTBoundary) +
		fmt.Sprintf(BoundaryFormat, Begin, SeedBoundary) +
		fmt.Sprintf("%s\n", seed) +
		fmt.Sprintf(BoundaryFormat, End, SeedBoundary)
	return []byte(contents)

}
