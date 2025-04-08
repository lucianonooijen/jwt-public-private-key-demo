package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/lucianonooijen/jwt-public-private-key-demo/server/internal/token"
	"github.com/stretchr/testify/require"
)

func generateRsaKeyset(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)

	require.NoError(t, err)
	require.NotEmpty(t, privateKey)

	return privateKey
}

func getTestTokenInstance(t *testing.T) *token.Token {
	t.Helper()

	k := generateRsaKeyset(t)

	tok, err := token.New(k)

	require.NoError(t, err)

	return tok
}

func TestJwtFlow_HappyPath(t *testing.T) {
	tok := getTestTokenInstance(t)
	sub := "TestSubjectHappyClient"
	id := "123"
	name := "John Doe"
	role := "Skriptkiddie"

	key, err := tok.GenerateJwt(sub, id, name, role)

	require.NoError(t, err)
	require.NotEmpty(t, key)

	claims, err := tok.ValidateJwt(key)

	require.NoError(t, err)
	require.NotEmpty(t, claims)
	require.Equal(t, sub, claims.Subject)
	require.Equal(t, id, claims.JwtID)
	require.Equal(t, name, claims.Name)
	require.Equal(t, role, claims.Role)
}

func TestJwt_SignedByOtherKey(t *testing.T) {
	tok := getTestTokenInstance(t)
	sub := "TestSubjectOtherKey"
	id := "123"
	name := "John Doe"
	role := "Skriptkiddie"

	key, err := tok.GenerateJwt(sub, id, name, role)

	require.NoError(t, err)
	require.NotEmpty(t, key)

	tokOtherKey := getTestTokenInstance(t)

	claims, err := tokOtherKey.ValidateJwt(key)

	require.Error(t, err)
	require.Nil(t, claims)
}

func TestJwt_InvalidSignature(t *testing.T) {
	tok := getTestTokenInstance(t)
	sub := "TestSubjectInvalidSignature"
	id := "123"
	name := "John Doe"
	role := "Skriptkiddie"

	key, err := tok.GenerateJwt(sub, id, name, role)

	require.NoError(t, err)
	require.NotEmpty(t, key)

	keyParts := strings.Split(key, ".")
	exampleSignature := "VKPicz1jQzeysLyvjPxAJAJYzc0zHFVuMqabop9ovxc"
	keyParts[2] = exampleSignature
	keyWithInvalidSignature := strings.Join(keyParts, ".")

	claims, err := tok.ValidateJwt(keyWithInvalidSignature)

	require.Error(t, err)
	require.Nil(t, claims)
}

func TestJwt_ExpiredKey(t *testing.T) {
	tok := getTestTokenInstance(t)
	now := time.Now()
	oneMonthAgo := now.AddDate(0, -1, 0)
	twoMonthAgo := now.AddDate(0, -2, 0)

	claims := token.JwtClaims{
		Issuer:    "tests",
		Subject:   "testsub",
		Audience:  "gotest",
		Expiry:    oneMonthAgo.Unix(),
		NotBefore: twoMonthAgo.Unix(),
		IssuedAt:  twoMonthAgo.Unix(),
	}

	expiredKey, err := tok.GenerateTokenForClaims(claims)

	require.NoError(t, err)
	require.NotEmpty(t, expiredKey)

	claimsOut, err := tok.ValidateJwt(expiredKey)

	require.Error(t, err)
	require.Nil(t, claimsOut)
}

func TestJwt_NotBeforeInFuture(t *testing.T) {
	tok := getTestTokenInstance(t)
	now := time.Now()
	oneMonthFromNow := now.AddDate(0, 1, 0)
	twoMonthsFromNow := now.AddDate(0, 2, 0)

	claims := token.JwtClaims{
		Issuer:    "tests",
		Subject:   "testsub",
		Audience:  "gotest",
		Expiry:    twoMonthsFromNow.Unix(),
		NotBefore: oneMonthFromNow.Unix(),
		IssuedAt:  now.Unix(),
	}

	expiredKey, err := tok.GenerateTokenForClaims(claims)

	require.NoError(t, err)
	require.NotEmpty(t, expiredKey)

	claimsOut, err := tok.ValidateJwt(expiredKey)

	require.Error(t, err)
	require.Nil(t, claimsOut)
}
