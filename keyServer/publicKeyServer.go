package main

import (
	"bufio"
	"crypto/tls"
	"encoding/gob"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"
)

var certs map[string]*tls.Certificate

func publicKeyServer() {
	certs = make(map[string]*tls.Certificate, len(conf.Hosts))

	// 加载所有已配置证书
	for k, v := range conf.Hosts {
		cert, e := loadTLSCertificate(v)
		if e != nil {
			panic(e)
		}
		certs[k] = cert
		log.Println("loadTLSCertificate: %s\n", k)
	}

	// 启动tls监听
	cert, err := tls.LoadX509KeyPair(conf.Cert, conf.Key)
	if err != nil {
		panic(err)
	}
	l, err := tls.Listen("tcp", conf.CertAddr, &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		panic(err)
	}
	defer l.Close()

	log.Printf("publicKeyServer: %s\n", conf.CertAddr)

	for {
		conn, e := l.Accept()
		if e != nil {
			log.Println("accept ERR: ", e)
			continue
		}

		if 0 > strings.Index(conf.WhiteIp, strings.Split(conn.RemoteAddr().String(), ":")[0]) {
			log.Println("403: ", conn.RemoteAddr().String())
			conn.Close()
			continue
		}

		log.Println("request: ", conn.RemoteAddr(), conn.LocalAddr())
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	reader := bufio.NewReader(conn)

	for {
		line, _, e := reader.ReadLine()
		if e != nil {
			fmt.Println("readline: ", e)
			break
		}

		enc := gob.NewEncoder(conn)
		cert, ok := certs[string(line)]
		if !ok {
			cert = &tls.Certificate{}
		}

		if e := enc.Encode(cert); e != nil {
			log.Println("gob:", e)
			break
		}

		fmt.Println("get cert: ", string(line), cert)
	}

	conn.Close()

	return
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
