package store

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"math/big"
	"os"
)

type Signer struct {
	prvKey *ecdsa.PrivateKey
}

func NewSigner() (*Signer, error) {
	c, err := tls.LoadX509KeyPair(
		os.Getenv("PRAVAH_AUTH_CERT_PATH"),
		os.Getenv("PRAVAH_AUTH_KEY_PATH"),
	)
	if err != nil {
		return nil, errors.New("Cert/Key: " + err.Error())
	}

	return &Signer{
		prvKey: c.PrivateKey.(*ecdsa.PrivateKey),
	}, nil
}

func (sign Signer) Sign(data []byte) (r, s *big.Int, e error) {
	hash := md5.Sum(data)
	return ecdsa.Sign(rand.Reader, sign.prvKey, hash[:])
}
