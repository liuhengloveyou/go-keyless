package main

import (
	"crypto/rsa"
	"encoding/gob"
	"flag"
	"runtime"

	gocommon "github.com/liuhengloveyou/go-common"
)

type Config struct {
	KeyAddr  string `json:"key_addr"`  // 私钥keyServer地址
	CertAddr string `json:"cert_addr"` // 证书keyServer地址
	CertDir  string `json:"cert_dir"`  // Directory in which keys&certs are stored with .key extension

	Cert string `json:"cert"` // Keyless server authentication certificate
	Key  string `json:"key"`  // Keyless server authentication key
	CA   string `json:"ca"`   // Keyless client certificate authority

	WhiteIp string            `json:"whiteip"`
	Hosts   map[string]string `json:"hosts"`
}

var (
	confile = flag.String("conf", "./app.conf", "配置文件路径.")
	conf    Config
)

func init() {
	if e := gocommon.LoadJsonConfig(*confile, &conf); e != nil {
		panic(e)
	}

	gob.Register(rsa.PublicKey{})

	ncpu := 8
	if runtime.NumCPU() > ncpu {
		ncpu = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(ncpu)
}

func main() {
	flag.Parse()

	go publicKeyServer()

	privateKeyServer()
}
