package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"github.com/lucianonooijen/jwt-public-private-key-demo/server/internal/server"
	"github.com/lucianonooijen/jwt-public-private-key-demo/server/internal/token"
	"log"
)

func main() {
	fmt.Println("Generating public/private keys")
	// Note: usually you'd use `keyset, err := token.GenerateRsaKeySet()` and save the output, then use that private key. For this demo, we don't want to store any keys, so using an alternative approach.
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Creating token instance")
	tok, err := token.New(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("Creating server instance")
	s := server.New(tok)

	fmt.Println("Starting server...")
	err = s.Start()
	if err != nil {
		log.Fatal(err)
	}
}
