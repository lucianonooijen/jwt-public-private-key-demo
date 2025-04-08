package token

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/go-jose/go-jose/v4"
)

const (
	// Do not change these values, the webapp relies on these as well.
	keyID     = "jwt-demo-server-jwk"
	algorithm = jose.RS256
)

// Token generates JWTs and JWKs with the private key passed into it in New.
type Token struct {
	privateKey *rsa.PrivateKey
	jwk        *jose.JSONWebKey
	signer     *jose.Signer
}

// New returns a Token instance after validating the *rsa.PrivateKey.
func New(pk *rsa.PrivateKey) (*Token, error) {
	if pk == nil {
		return nil, errors.New("private key argument is required")
	}

	if err := pk.Validate(); err != nil {
		return nil, fmt.Errorf("error validating private key: %w", err)
	}

	jwk := jose.JSONWebKey{
		Key:       pk,
		Use:       "sig",
		Algorithm: string(algorithm),
		KeyID:     keyID,
	}

	signerOptions := (&jose.SignerOptions{}).
		WithHeader("alg", algorithm).
		WithHeader("jku", generateWellKnownEndpoint())

	jwtSigner, err := jose.NewSigner(jose.SigningKey{
		Algorithm: algorithm,
		Key:       pk,
	}, signerOptions)

	if err != nil {
		return nil, fmt.Errorf("error creating jwt signer: %w", err)
	}

	jwkInstance := Token{
		privateKey: pk,
		jwk:        &jwk,
		signer:     &jwtSigner,
	}

	return &jwkInstance, nil
}

// GetPublicKey takes the public part of the private key and marshals this to JSON for the .well-known/jwks.json endpoint.
func (t *Token) GetPublicKey() ([]byte, error) {
	return t.jwk.Public().MarshalJSON()
}

func generateWellKnownEndpoint() string {
	return "http://localhost:4000/.well-known/jwks.json" // Change this to have correct logic
}
