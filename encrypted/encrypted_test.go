package encrypted

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

var (
	kdfVectors = map[KDFParameterStrength][]byte{
		Legacy:   []byte(`{"kdf":{"name":"scrypt","params":{"N":32768,"r":8,"p":1},"salt":"WO3mVvyTwJ9vwT5/Tk5OW5WPIBUofMjcpEfrLnfY4uA="},"cipher":{"name":"nacl/secretbox","nonce":"tCy7HcTFr4uxv4Nrg/DWmncuZ148U1MX"},"ciphertext":"08n43p5G5yviPEZpO7tPPF4aZQkWiWjkv4taFdhDBA0tamKH4nw="}`),
		Standard: []byte(`{"kdf":{"name":"scrypt","params":{"N":65536,"r":8,"p":1},"salt":"FhzPOt9/bJG4PTq6lQ6ecG6GzaOuOy/ynG5+yRiFlNs="},"cipher":{"name":"nacl/secretbox","nonce":"aw1ng1jHaDz/tQ7V2gR9O2+IGQ8xJEuE"},"ciphertext":"HycvuLZL4sYH0BrYTh4E/H20VtAW6u5zL5Pr+IBjYLYnCPzDkq8="}`),
		OWASP:    []byte(`{"kdf":{"name":"scrypt","params":{"N":131072,"r":8,"p":1},"salt":"m38E3kouJTtiheLQN22NQ8DTito5hrjpUIskqcd375k="},"cipher":{"name":"nacl/secretbox","nonce":"Y6PM13yA+o44pE/W1ZBwczeGnTV/m9Zc"},"ciphertext":"6H8sqj1K6B6yDjtH5AQ6lbFigg/C2yDDJc4rYJ79w9aVPImFIPI="}`),
	}
)

var plaintext = []byte("reallyimportant")

func TestRoundtrip(t *testing.T) {
	passphrase := []byte("supersecret")

	enc, err := Encrypt(plaintext, passphrase)
	assert.Nil(t, err)

	// successful decrypt
	dec, err := Decrypt(enc, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, dec)

	// wrong passphrase
	passphrase[0] = 0
	dec, err = Decrypt(enc, passphrase)
	assert.NotNil(t, err)
	assert.Nil(t, dec)
}

func TestTamperedRoundtrip(t *testing.T) {
	passphrase := []byte("supersecret")

	enc, err := Encrypt(plaintext, passphrase)
	assert.Nil(t, err)

	data := &data{}
	err = json.Unmarshal(enc, data)
	assert.Nil(t, err)

	data.Ciphertext[0] = ^data.Ciphertext[0]

	enc, _ = json.Marshal(data)

	dec, err := Decrypt(enc, passphrase)
	assert.NotNil(t, err)
	assert.Nil(t, dec)
}

func TestDecrypt(t *testing.T) {
	enc := []byte(`{"kdf":{"name":"scrypt","params":{"N":32768,"r":8,"p":1},"salt":"N9a7x5JFGbrtB2uBR81jPwp0eiLR4A7FV3mjVAQrg1g="},"cipher":{"name":"nacl/secretbox","nonce":"2h8HxMmgRfuYdpswZBQaU3xJ1nkA/5Ik"},"ciphertext":"SEW6sUh0jf2wfdjJGPNS9+bkk2uB+Cxamf32zR8XkQ=="}`)
	passphrase := []byte("supersecret")

	dec, err := Decrypt(enc, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, dec)
}

func TestMarshalUnmarshal(t *testing.T) {
	passphrase := []byte("supersecret")

	wrapped, err := Marshal(plaintext, passphrase)
	assert.Nil(t, err)
	assert.NotNil(t, wrapped)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, protected)
}

func TestInvalidKDFSettings(t *testing.T) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, 0)
	assert.Nil(t, err)
	assert.NotNil(t, wrapped)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, protected)
}

func TestLegacyKDFSettings(t *testing.T) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, Legacy)
	assert.Nil(t, err)
	assert.NotNil(t, wrapped)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, protected)
}

func TestStandardKDFSettings(t *testing.T) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, Standard)
	assert.Nil(t, err)
	assert.NotNil(t, wrapped)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, protected)
}

func TestOWASPKDFSettings(t *testing.T) {
	passphrase := []byte("supersecret")

	wrapped, err := MarshalWithCustomKDFParameters(plaintext, passphrase, OWASP)
	assert.Nil(t, err)
	assert.NotNil(t, wrapped)

	var protected []byte
	err = Unmarshal(wrapped, &protected, passphrase)
	assert.Nil(t, err)
	assert.Equal(t, plaintext, protected)
}

func TestKDFSettingVectors(t *testing.T) {
	passphrase := []byte("supersecret")

	for _, v := range kdfVectors {
		var protected []byte
		err := Unmarshal(v, &protected, passphrase)
		assert.Nil(t, err)
		assert.Equal(t, plaintext, protected)
	}
}

func TestUnsupportedKDFParameters(t *testing.T) {
	enc := []byte(`{"kdf":{"name":"scrypt","params":{"N":99,"r":99,"p":99},"salt":"cZFcQJdwPhPyhU1R4qkl0qVOIjZd4V/7LYYAavq166k="},"cipher":{"name":"nacl/secretbox","nonce":"7vhRS7j0hEPBWV05skAdgLj81AkGeE7U"},"ciphertext":"6WYU/YSXVbYzl/NzaeAzmjLyfFhOOjLc0d8/GFV0aBFdJvyCcXc="}`)
	passphrase := []byte("supersecret")

	dec, err := Decrypt(enc, passphrase)
	assert.NotNil(t, err)
	assert.Nil(t, dec)
	assert.ErrorContains(t, err, "unsupported scrypt parameters")
}
