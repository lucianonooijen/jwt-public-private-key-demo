package token

import (
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// Audience the example audience.
	Audience = "example"

	// Issuer is the identification of the server when signing JWTs.
	// Note: do not change this value, the webapp depends on this for middleware.
	Issuer = "jwt-demo-server"
)

var (
	// ErrorJwtParsing indicates that the signature of the JWT is not valid.
	ErrorJwtParsing = errors.New("parsing JWT failed")

	// ErrorJwtValidation indicates that the token claims could not be validated.
	ErrorJwtValidation = errors.New("claim validation for JWT failed")

	// ErrorJwtConversion indicates that the token claims to struct conversion failed.
	ErrorJwtConversion = errors.New("claim conversion for JWT failed")
)

// GenerateJwt generates a JWT. What's in the name.
func (t *Token) GenerateJwt(subject, jwtId, name, role string) (string, error) {
	now := time.Now()
	expiryHours := time.Duration(48) * time.Hour

	claims := JwtClaims{
		Issuer:    Issuer,
		Subject:   subject,
		Audience:  Audience,
		Expiry:    now.Add(expiryHours).Unix(),
		NotBefore: now.Unix(),
		IssuedAt:  now.Unix(),
		JwtID:     jwtId,
		Name:      name,
		Role:      role,
	}

	tok, err := t.generateTokenForClaims(claims)
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	log.Printf("generated client jwt with subject: %s\n", subject)

	return tok, nil
}

// generateTokenForClaims is a function that will sign the JwtClaims passed in.
// WARNING: This method should only be called in public wrapper functions and not exposed directly.
// For generating tokens in production code, always use the audience-specific methods.
func (t *Token) generateTokenForClaims(claims JwtClaims) (string, error) { //nolint:gocritic // Jose needs val, not ref
	return jwt.Signed(*t.signer).Claims(claims).Serialize()
}

// ValidateJwt validates a jwt string with the public key on the server and validates claims.
func (t *Token) ValidateJwt(token string) (*JwtClaims, error) {
	parsedToken, err := jwt.ParseSigned(token, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		log.Printf("error parsing signed token: %s\n", err)

		return nil, ErrorJwtParsing
	}

	claims := Claims{}

	// Note: dereference here is very important!
	// The jose code checks for *rsa.PublicKey specifically, and does not accept rsa.PublicKey
	err = parsedToken.Claims(&t.privateKey.PublicKey, &claims)
	if err != nil {
		log.Printf("error validating token claims: %s\n", err)

		return nil, ErrorJwtValidation
	}

	c, err := claims.jwtClaims()
	if err != nil {
		log.Printf("error converting token claims: %s\n", err)

		return nil, ErrorJwtConversion
	}

	err = validateJwtClaims(c)
	if err != nil {
		log.Printf("error validating token claims: %s\n", err)

		return nil, err
	}

	return c, nil
}
