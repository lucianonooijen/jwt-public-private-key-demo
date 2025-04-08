package server

import (
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"log"
)

func registerMiddleware(router *gin.Engine) {
	router.Use(gin.Recovery())

	config := cors.DefaultConfig()
	config.AllowAllOrigins = true

	router.Use(cors.New(config))

	if err := router.SetTrustedProxies([]string{}); err != nil {
		log.Fatal(err)
	}
}
