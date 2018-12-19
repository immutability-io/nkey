package cli

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/vault/api"
	nats "github.com/nats-io/go-nats"
	"github.com/nats-io/jwt"
)

func basicUserJWTHandler(accountPath, userPath string) (string, error) {
	cli, err := api.NewClient(nil)
	if err != nil {
		return "", err
	}
	subjectSecret, err := cli.Logical().Read(userPath)
	if err != nil {
		return "", err
	}
	subject := subjectSecret.Data["public_key"].(string)
	uc := jwt.NewUserClaims(subject)
	data := make(map[string]interface{})
	data["claims"] = uc.String()
	data["type"] = "user"

	claimsPath := fmt.Sprintf("%s/sign-claim", accountPath)

	secret, err := cli.Logical().Write(claimsPath, data)
	if err != nil {
		return "", err
	}
	if secret == nil {
		return "", fmt.Errorf("problem writing claim")
	}

	return secret.Data["token"].(string), nil
}

func basicSignatureHandler(nonce []byte, path string) ([]byte, error) {
	cli, err := api.NewClient(nil)
	data := make(map[string]interface{})
	data["payload"] = string(nonce)

	signingPath := fmt.Sprintf("%s/sign", path)

	secret, err := cli.Logical().Write(signingPath, data)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("problem writing claim")
	}
	signature := secret.Data["signature"].(string)
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, err
	}
	return signatureBytes, nil
}

// VaultCredentials is a convenience function that takes a filename
// for a user's JWT and a filename for the user's private Nkey seed.
func VaultCredentials(accountPath, userPath string) nats.Option {
	userCB := func() (string, error) {
		return basicUserJWTHandler(accountPath, userPath)
	}
	sigCB := func(nonce []byte) ([]byte, error) {
		return basicSignatureHandler(nonce, userPath)
	}
	return nats.UserJWT(userCB, sigCB)
}
