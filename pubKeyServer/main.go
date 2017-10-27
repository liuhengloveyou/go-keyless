package main

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"runtime"
	"strings"

	gocommon "github.com/liuhengloveyou/go-common"
)

type Config struct {
	Addr    string `json:"addr"`
	Cert    string `json:"cert"`
	Key     string `json:"key"`
	WhiteIp string `json:"whiteip"`

	Hosts map[string]string `json:"hosts"`
}

var (
	confile = flag.String("conf", "./app.conf", "配置文件路径.")
	conf    Config

	certs map[string]*tls.Certificate
)

func init() {
	// 加载配置
	if e := gocommon.LoadJsonConfig(*confile, &conf); e != nil {
		panic(e)
	}

	certs = make(map[string]*tls.Certificate, len(conf.Hosts))
}

func main() {
	runtime.GOMAXPROCS(16)
	flag.Parse()

	gob.Register(rsa.PublicKey{})

	// 加载所有可用证书
	for k, v := range conf.Hosts {
		cert, e := loadTLSCertificate(v)
		if e != nil {
			panic(e)
		}
		fmt.Printf("loadTLSCertificate: %s\n", k)
		certs[k] = cert
	}

	// 启动tls监听
	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		panic(err)
	}

	l, err := tls.Listen("tcp", conf.Addr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		panic(err)
	}
	defer l.Close()

	fmt.Println("PubKeyServer: ", conf.Addr)
	for {
		conn, e := l.Accept()
		if e != nil {
			fmt.Println("accept: ", e)
			continue
		}

		if 0 > strings.Index(conf.WhiteIp, strings.Split(conn.RemoteAddr().String(), ":")[0]) {
			fmt.Println("bad remote: ", conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		fmt.Println("request: ", conn.RemoteAddr(), conn.LocalAddr())
		go handle(conn)
	}
}

// LoadTLSCertificate loads a TLS certificate chain from file
func loadTLSCertificate(certFile string) (*tls.Certificate, error) {
	var (
		cert         tls.Certificate
		err          error
		certPEMBlock []byte
		certDERBlock *pem.Block
	)

	if certPEMBlock, err = ioutil.ReadFile(certFile); err != nil {
		return nil, err
	}

	for {
		certDERBlock, certPEMBlock = pem.Decode(certPEMBlock)
		if certDERBlock == nil {
			break
		}

		if certDERBlock.Type == "CERTIFICATE" {
			cert.Certificate = append(cert.Certificate, certDERBlock.Bytes)
		}
	}

	if len(cert.Certificate) == 0 {
		return nil, errors.New("crypto/tls: failed to parse certificate PEM data")
	}

	return &cert, nil
}

func handle(conn net.Conn) {
	reader := bufio.NewReader(conn)

	for {
		line, _, e := reader.ReadLine()
		if e != nil {
			fmt.Println("readline: ", e)
			break
		}

		fmt.Println("select cert: ", string(line))

		enc := gob.NewEncoder(conn)
		cert, ok := certs[string(line)]
		if !ok {
			cert = &tls.Certificate{}
		}
		if e := enc.Encode(cert); e != nil {
			fmt.Println("gob:", e)
			break
		}

	}

	conn.Close()

	return
}
