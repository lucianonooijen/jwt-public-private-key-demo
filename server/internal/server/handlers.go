package server

import (
	"github.com/gin-gonic/gin"
	"github.com/lucianonooijen/jwt-public-private-key-demo/server/internal/token"
	"log"
	"net/http"
)

type handlers struct {
	token *token.Token
}

func newHandlers(token *token.Token) *handlers {
	return &handlers{
		token: token,
	}
}

func (h *handlers) Jwk(c *gin.Context) {
	pubKey, err := h.token.GetPublicKey()
	if err != nil {
		log.Printf("error getting public key information: %s\n", err)

		c.JSON(http.StatusInternalServerError, struct{ error string }{error: "cannot get public key info"}) // You'll want to replace this logic with your own error body

		return
	}

	c.Header("content-type", "application/json")

	// Manually writing JSON for compatibility with the []byte from pubKey
	c.Writer.WriteString(`{"keys":[`) //nolint:errcheck,gosec // This is fine
	c.Writer.Write(pubKey)            //nolint:errcheck,gosec // This is fine
	c.Writer.WriteString(`]}`)        //nolint:errcheck,gosec // This is fine

	c.Status(http.StatusOK)
}

func (h *handlers) GetJwt(c *gin.Context) {
	jwt, err := h.token.GenerateJwt("42", "1337", "John Doe", "Example")
	if err != nil {
		c.JSON(http.StatusInternalServerError, struct{ error string }{error: err.Error()}) // You don't want to return the raw error in prod

		return
	}

	c.JSON(http.StatusOK, struct {
		Token string `json:"token"`
	}{Token: jwt}) // You should do this properly
}
