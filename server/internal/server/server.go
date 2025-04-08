package server

import (
	"github.com/gin-gonic/gin"
	"github.com/lucianonooijen/jwt-public-private-key-demo/server/internal/token"
	"strconv"
)

type Server struct {
	port   int
	Router *gin.Engine
}

func (s Server) Start() error {
	return s.Router.Run(":" + strconv.Itoa(s.port))
}

// This is NOT safe to use in production! There is no security hardening!
func New(tok *token.Token) *Server {

	gin.SetMode(gin.DebugMode)

	router := gin.New()
	registerMiddleware(router)

	h := newHandlers(tok)

	router.GET("/.well-known/jwks.json", h.Jwk)
	router.GET("/jwt", h.GetJwt)

	s := &Server{
		port:   4000, // You want to read this from your config
		Router: router,
	}

	return s
}
