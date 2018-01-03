package main

import (
	"crypto"
	"log"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/gokeyless/server"
)

var s *server.Server

func privateKeyServer() {
	var e error

	if s, e = server.NewServerFromFile(conf.Cert, conf.Key, conf.CA); e != nil {
		panic(e)
	}

	keys, e := server.NewKeystoreFromDir(conf.CertDir, loadKey)
	if e != nil {
		panic(e)
	}

	s.SetKeystore(keys)

	cfg := server.DefaultServeConfig()
	cfg.TCPAddr(conf.KeyAddr)

	if e := s.ListenAndServeConfig(cfg); e != nil {
		log.Fatal(e)
	}

}

// LoadKey attempts to load a private key from PEM or DER.
func loadKey(in []byte) (priv crypto.Signer, e error) {
	priv, e = helpers.ParsePrivateKeyPEM(in)
	if e == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}
