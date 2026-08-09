package sdkfixture

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sakullla/nginx-reverse-emby/plugin-sdk/go/compatfixture"
	"github.com/sakullla/sakullla-plugins/internal/sdklock"
)

func TestSDKDescriptorAndCanonicalABIGuestMatchLock(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate SDK fixture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	lock, err := sdklock.Load(filepath.Join(root, "sdk.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	descriptorDigest, err := DescriptorSetSHA256()
	if err != nil {
		t.Fatal(err)
	}
	if descriptorDigest != lock.Artifacts.DescriptorSetSHA256 {
		t.Fatalf("descriptor digest = %s, lock = %s", descriptorDigest, lock.Artifacts.DescriptorSetSHA256)
	}
	guestDigest := sha256.Sum256(compatfixture.PolicyV1GuestWASM())
	if actual := hex.EncodeToString(guestDigest[:]); actual != lock.Artifacts.CanonicalGuestSHA256 {
		t.Fatalf("canonical ABI guest digest = %s, lock = %s", actual, lock.Artifacts.CanonicalGuestSHA256)
	}
}
