package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"github.com/bfrengley/relay"
)

func main() {
	file := os.Args[1]
	hash, err := relay.HashFile(file)
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(hex.EncodeToString(hash))
}
