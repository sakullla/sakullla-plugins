package sdkfixture

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/protoschema"
)

func DescriptorSetSHA256() (string, error) {
	descriptors, err := protoschema.DescriptorSetBytes()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(descriptors)
	return hex.EncodeToString(digest[:]), nil
}
