package main

import (
	"log"

	"github.com/ymktmk/golang-sso-server/server"
)

func main() {
	server, err := server.NewSever()
	if err != nil {
		panic(err)
	}
	log.Fatal(server.Run())
}
