package token

import (
	"encoding/json"
	"fmt"
)

// Claims is the type used to generate the claims of JWTs and is generated from JwtClaims.
type Claims map[string]any

// JwtClaims contains the JWT claims used by this application.
// Further documentation about JWT claims can be found in RFC 7519.
type JwtClaims struct {
	// Issuer identifies the principal that issued the JWT. Part of the standard claim fields.
	Issuer string `json:"iss"`

	// Subject identifies the subject of the JWT. Part of the standard claim fields.
	Subject string `json:"sub"`

	// Audience identifies the recipients that the JWT is intended for. Part of the standard claim fields.
	Audience string `json:"aud"`

	// Expiry identifies the expiration time on and after which the JWT must not be accepted for processing. Part of the standard claim fields.
	// This is expressed as the amount of seconds past 1970-01-01 00:00:00Z.
	Expiry int64 `json:"exp"`

	// NotBefore identifies the time on which the JWT will start to be accepted for processing. Part of the standard claim fields.
	// This is expressed as the amount of seconds past 1970-01-01 00:00:00Z.
	NotBefore int64 `json:"nbf"`

	// IssuedAt identifies the time at which the JWT was issued. Part of the standard claim fields.
	// This is expressed as the amount of seconds past 1970-01-01 00:00:00Z.
	IssuedAt int64 `json:"iat"`

	// JwtID is a case-sensitive unique identifier of the token. Part of the standard claim fields.
	// This field makes it possible to invalidate JWTs after a password reset.
	JwtID string `json:"jti,omitempty"`

	// Name is an additional field added that contains the full name of the person the key is assigned to.
	Name string `json:"name,omitempty"`

	// Role is used for tokens and indicates the user's role.
	// This can be used to determine whether a user has admin-level permissions or not.
	// This field should not be used as a single source for permissions, these should be fetched from the database.
	Role string `json:"roles,omitempty"`
}

func (c *Claims) jwtClaims() (*JwtClaims, error) {
	dataBytes, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("error marshaling map to json: %w", err)
	}

	claims := JwtClaims{}

	err = json.Unmarshal(dataBytes, &claims)
	if err != nil {
		return nil, fmt.Errorf("error converting struct json to JwtClaims: %w", err)
	}

	return &claims, nil
}
