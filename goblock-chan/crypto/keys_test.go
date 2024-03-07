package crypto

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestNewPrivateKeyFromString(t *testing.T) {
	// seed := make([]byte, 32)
	var (
		seed       = "2f3fea400c79ab0d4c171358f6339b7b9c67242cecd720e264e0343475543ea2"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "2af0c4a1b41aaf2e4b8f43c3cee9c6a568b39381"
	)

	assert.Equal(t, privKeyLen, len(privKey.Bytes()))
	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	msg := []byte("foo bar baz")

	sign := privKey.Sign(msg)
	assert.True(t, sign.Verify(pubKey, msg))
	assert.False(t, sign.Verify(pubKey, []byte("foo")))

	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()
	assert.False(t, sign.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()

	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
