package store

import (
	"crypto/ecdsa"
	"crypto/md5"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"math/big"
	"time"

	"github.com/dvsekhvalnov/jose2go/base64url"
	"github.com/pravahio/go-auth-provider/ds"
)

type Validator struct {
	pubKey *ecdsa.PublicKey
}

func NewValidator(authCrtPem string) (*Validator, error) {
	pemRaw, err := ioutil.ReadFile(authCrtPem)
	if err != nil {
		return nil, errors.New("Err in Auth Cert: " + err.Error())
	}
	block, _ := pem.Decode(pemRaw)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &Validator{
		pubKey: cert.PublicKey.(*ecdsa.PublicKey),
	}, nil
}

func (val Validator) Validate(data []byte, r, s *big.Int) bool {
	hash := md5.Sum(data)
	return ecdsa.Verify(val.pubKey, hash[:], r, s)
}

func (val Validator) ReadSignedAccessTokenAndVerify(data []byte) bool {
	at := &ds.SignedAccessToken{}
	err := json.Unmarshal(data, at)
	if err != nil {
		return false
	}

	if at.AccessToken.ValidTill < time.Now().Unix() {
		return false
	}

	rawJSON, err := json.Marshal(at.AccessToken)
	if err != nil {
		return false
	}

	r := big.NewInt(0).SetBytes(at.R)
	s := big.NewInt(0).SetBytes(at.S)
	if val.Validate(rawJSON, r, s) {
		return true
	} else {
		return false
	}
}

func (val Validator) DecodeAndValidate(s string) bool {
	log.Info(s)
	decodedJSON, err := base64url.Decode(s)
	if err != nil {
		return false
	}
	log.Info(string(decodedJSON))
	return val.ReadSignedAccessTokenAndVerify(decodedJSON)
}
