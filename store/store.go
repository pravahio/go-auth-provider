package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"
	logging "github.com/ipfs/go-log"
	"github.com/pravahio/go-auth-provider/ds"
)

var (
	dbDriver = "mysql"
	dbUser   = os.Getenv("DB_USER")
	dbPass   = os.Getenv("DB_PASSWORD")
	dbName   = os.Getenv("DB_NAME")
	dbHost   = os.Getenv("DB_HOST")

	log = logging.Logger("auth-store")
)

type TokenStore struct {
	Signer *Signer
}

func NewTokenStore() (*TokenStore, error) {

	sig, err := NewSigner()
	if err != nil {
		return nil, err
	}

	return &TokenStore{
		Signer: sig,
	}, nil
}

func (ts *TokenStore) GetAccessToken(req *ds.Request) (ds.SignedAccessToken, error) {
	if ts.isValid(req) {
		at := ds.AccessToken{
			Request:   *req,
			ValidTill: time.Now().Add(1 * time.Hour).Unix(),
		}
		enc, err := json.Marshal(at)
		if err != nil {
			return ds.SignedAccessToken{}, err
		}

		r, s, err := ts.Signer.Sign(enc)
		if err != nil {
			return ds.SignedAccessToken{}, err
		}

		return ds.SignedAccessToken{
			AccessToken: at,
			R:           r.Bytes(),
			S:           s.Bytes(),
		}, nil
	}
	return ds.SignedAccessToken{}, errors.New("Request Auth code is not valid")
}

func (ts *TokenStore) isValid(req *ds.Request) bool {

	db, err := sql.Open(dbDriver, fmt.Sprintf("%s:%s@tcp(%s:3306)/%s", dbUser, dbPass, dbHost, dbName))
	if err != nil {
		// TODO: log
		return false
	}
	defer db.Close()

	rows, err := db.Query("SELECT * FROM `key` where `id`='" + req.AuthenticationToken + "'")
	if err != nil {
		// TODO: log
		return false
	}

	type Key struct {
		id      string
		version int
		name    string
		user_id interface{}
	}
	l := Key{}
	for rows.Next() {
		err := rows.Scan(&l.id, &l.version, &l.name, &l.user_id)
		if err != nil {
			return false
		}
	}

	if l.id != "" {
		return true
	}
	return false
}
