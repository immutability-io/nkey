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

package util

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"regexp"

	"github.com/btcsuite/btcd/btcec"
)

const (
	// Empty is an empty string
	Empty string = ""
)

func zeroKey(k *btcec.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func wipeBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

// Encrypt will encrypt plaintext using a public key
func Encrypt(publicKeyString, plaintext string) (string, error) {
	publicKeyBytes, err := hex.DecodeString(publicKeyString)
	if err != nil {
		return Empty, err
	}

	pubKey, err := btcec.ParsePubKey(publicKeyBytes, btcec.S256())
	if err != nil {
		return Empty, err
	}

	// Encrypt a message decryptable by the private key corresponding to pubKey
	ciphertextBytes, err := btcec.Encrypt(pubKey, []byte(plaintext))
	if err != nil {
		return Empty, err
	}
	ciphertext := hex.EncodeToString(ciphertextBytes)
	return ciphertext, nil
}

// Decrypt will decrypt ciphertext using a private key
func Decrypt(privateKeyString, ciphertext string) (string, error) {
	// Decode the hex-encoded private key.
	pkBytes, err := hex.DecodeString(privateKeyString)
	if err != nil {
		return Empty, err
	}
	defer wipeBytes(pkBytes)
	// note that we already have corresponding pubKey
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), pkBytes)
	defer zeroKey(privKey)
	ciphertextBytes, err := hex.DecodeString(ciphertext)
	// Try decrypting and verify if it's the same message.
	plaintextBytes, err := btcec.Decrypt(privKey, ciphertextBytes)
	plaintext := string(plaintextBytes)
	return plaintext, nil
}

var nscDecoratedRe = regexp.MustCompile(`\s*(?:(?:[-]{3,}[^\n]*[-]{3,}\n)(.+)(?:\n\s*[-]{3,}[^\n]*[-]{3,}\n))`)

// Just wipe slice with 'x', for clearing contents of nkey seed file.
func wipeSlice(buf []byte) {
	for i := range buf {
		buf[i] = 'x'
	}
}

// CredsFromNkeyFile will parse a .creds file
func CredsFromNkeyFile(userFile string) (string, string, string, error) {
	contents, err := ioutil.ReadFile(userFile)
	if err != nil {
		return Empty, Empty, Empty, fmt.Errorf("nats: %v", err)
	}
	defer wipeSlice(contents)

	items := nscDecoratedRe.FindAllSubmatch(contents, -1)
	if len(items) == 0 {
		return Empty, Empty, string(contents), nil
	}
	// First result should be the user JWT.
	// We copy here so that if the file contained a seed file too we wipe appropriately.
	var jwt []byte
	var nkey []byte
	var privKey []byte
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
		case 2:
			if len(item) == 2 {
				privKey = make([]byte, len(item[1]))
				copy(privKey, item[1])
			}
		}
	}
	return string(jwt), string(nkey), string(privKey), nil
}
