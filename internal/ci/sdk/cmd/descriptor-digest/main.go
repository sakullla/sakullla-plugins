package main

import (
	"crypto/sha256"
	"fmt"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
)

func main() {
	descriptors, err := protoschema.DescriptorSetBytes()
	if err != nil {
		panic(err)
	}
	fmt.Printf("%x\n", sha256.Sum256(descriptors))
}
