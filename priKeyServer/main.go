package main

import (
	"crypto"
	"flag"
	"fmt"
	"log"

	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/helpers/derhelpers"
	"github.com/cloudflare/gokeyless/server"
	gocommon "github.com/liuhengloveyou/go-common"
)

type Config struct {
	Addr     string `jsong:"addr"`
	CertFile string `json:"cert"`       // Keyless server authentication certificate
	KeyFile  string `json:"key"`        // Keyless server authentication key
	CAcert   string `json:"cacert"`     // Keyless client certificate authority
	KeyDir   string `json:"privKeyDir"` // Directory in which private keys are stored with .key extension
}

var (
	s *server.Server

	confile = flag.String("conf", "./app.conf", "配置文件路径.")
	conf    Config
)

func main() {
	var e error

	flag.Parse()

	if e = gocommon.LoadJsonConfig(*confile, &conf); e != nil {
		panic(e)
	}

	if s, e = server.NewServerFromFile(conf.CertFile, conf.KeyFile, conf.CAcert, conf.Addr, ""); e != nil {
		log.Fatal(e)
	}

	s.Config.InsecureSkipVerify = true

	keys := server.NewDefaultKeystore()
	if e = keys.LoadKeysFromDir(conf.KeyDir, LoadKey); e != nil {
		log.Fatal(e)
	}
	s.Keys = keys

	fmt.Println(">>>keyServer: ", s.Addr)
	if e := s.ListenAndServe(); e != nil {
		log.Fatal(e)
	}

}

// LoadKey attempts to load a private key from PEM or DER.
func LoadKey(in []byte) (priv crypto.Signer, e error) {
	priv, e = helpers.ParsePrivateKeyPEM(in)
	if e == nil {
		return priv, nil
	}

	return derhelpers.ParsePrivateKeyDER(in)
}
