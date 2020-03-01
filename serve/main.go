package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/dvsekhvalnov/jose2go/base64url"
	logging "github.com/ipfs/go-log"
	"github.com/pravahio/go-auth-provider/ds"
	"github.com/pravahio/go-auth-provider/store"
)

type AuthProvider struct {
	TokenStore *store.TokenStore
	Validator  *store.Validator
}

var (
	provider AuthProvider
	log      = logging.Logger("auth")
)

func handleValidateAccessToken(w http.ResponseWriter, req *http.Request) {
	log.Info("Servicing validation request")

	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	if provider.Validator.DecodeAndValidate(string(raw)) {
		w.Write([]byte("VALID"))
	} else {
		w.Write([]byte("NOT VALID"))
	}

}

func handleGetToken(w http.ResponseWriter, req *http.Request) {
	log.Info("Servicing get token request")

	raw, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	rq := &ds.Request{}
	err = json.Unmarshal(raw, rq)
	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	}

	at, err := provider.TokenStore.GetAccessToken(rq)
	if err != nil {
		log.Error(err)
		w.Write([]byte(err.Error()))
		return
	} else {
		rawJSON, err := json.Marshal(at)
		if err != nil {
			log.Error(err)
			w.Write([]byte(err.Error()))
			return
		} else {
			w.Write([]byte(base64url.Encode(rawJSON)))
		}
	}
}

func main() {
	logging.SetLogLevel("auth", "DEBUG")
	s, err := store.NewTokenStore()
	if err != nil {
		log.Error(err)
		return
	}
	v, err := store.NewValidator(os.Getenv("PRAVAH_AUTH_CERT_PATH"))
	if err != nil {
		log.Error(err)
		return
	}
	provider = AuthProvider{
		TokenStore: s,
		Validator:  v,
	}

	// Register all handlers
	http.HandleFunc("/token", handleGetToken)
	http.HandleFunc("/validate", handleValidateAccessToken)

	log.Infof("Listening on %s:%s", os.Getenv("PRAVAH_AUTH_HOST"), os.Getenv("PRAVAH_AUTH_PORT"))

	// Start the server
	err = http.ListenAndServeTLS(
		os.Getenv("PRAVAH_AUTH_HOST")+":"+os.Getenv("PRAVAH_AUTH_PORT"),
		os.Getenv("PRAVAH_AUTH_CERT_PATH"),
		os.Getenv("PRAVAH_AUTH_KEY_PATH"),
		nil,
	)
	if err != nil {
		log.Error(err)
		return
	}
}
