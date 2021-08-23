package main

import (
	"log"

	"github.com/bfrengley/relay"
)

func main() {
	log.Fatalln(relay.ListenAndServe("8080"))
}
