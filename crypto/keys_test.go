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
	var (
		seed       = "c6dfe81a5630235e8b6c0ce4d96b6f60dd5ef068e9364532c10e304c32bc5cb4"
		privKey    = NewPrivateKeyFromString(seed)
		addressStr = "4c4d28491693adc1103e74a5038eeb1e9591106a"
	)
	assert.Equal(t, privKeyLen, len(privKey.Bytes()))

	address := privKey.Public().Address()
	assert.Equal(t, addressStr, address.String())
	// fmt.Println(address)

	// seed := make([]byte, 32)
	// io.ReadFull(rand.Reader, seed)
	// fmt.Println(hex.EncodeToString(seed))
}

func TestPrivateKeySign(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()

	msg := []byte("foo bar baz")

	sig := privKey.Sign(msg)

	assert.True(t, sig.Verify(pubKey, msg))

	// test with invalid msg
	assert.False(t, sig.Verify(pubKey, []byte("foo")))

	// test with invalid pubkey
	invalidPrivKey := GeneratePrivateKey()
	invalidPubKey := invalidPrivKey.Public()

	assert.False(t, sig.Verify(invalidPubKey, msg))
}

func TestPublicKeyToAddress(t *testing.T) {
	privKey := GeneratePrivateKey()
	pubKey := privKey.Public()
	address := pubKey.Address()

	assert.Equal(t, addressLen, len(address.Bytes()))
	fmt.Println(address)
}
