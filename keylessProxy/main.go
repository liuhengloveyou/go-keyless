package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/gob"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"time"

	"github.com/cloudflare/gokeyless/client"
	gocommon "github.com/liuhengloveyou/go-common"
)

type HostConfig struct {
	KeyServerAddr string `json:"keyServerAddr"`
	keyServerCA   string `json: "keyServerCA"`
}

type Config struct {
	Addr             string   `json:"addr"`
	Resolvers        []string `json:"resolvers"`
	ProxyCert        string   `json:"proxyCert"`
	ProxyKey         string   `json:"proxyKey"`
	ProxyCA          string   `json:"proxyCA"`
	TargetAddr       string   `json:"targetAddr"`
	PubKeyServer     []string `json:"pubKeyServer"`
	SessionTicketKey string   `json:"sessionTicketKey"`

	Hosts map[string]*HostConfig `json:"hosts"`
}

var (
	confile = flag.String("conf", "./app.conf", "配置文件路径.")
	conf    Config
	certs   map[string]*tls.Certificate

	keylessClient *client.Client
	conn          []*tls.Conn
)

func init() {
	// 加载配置
	if e := gocommon.LoadJsonConfig(*confile, &conf); e != nil {
		panic(e)
	}

	certs = make(map[string]*tls.Certificate, len(conf.Hosts))
	conn = make([]*tls.Conn, len(conf.PubKeyServer))
}

func main() {
	runtime.GOMAXPROCS(16)
	flag.Parse()

	gob.Register(rsa.PublicKey{})

	var e error

	if keylessClient, e = client.NewClientFromFile(conf.ProxyCert, conf.ProxyKey, conf.ProxyCA); e != nil {
		panic(e)
	}

	keylessClient.Dialer.Timeout = 1 * time.Second
	keylessClient.Resolvers = conf.Resolvers
	keylessClient.Config.ClientSessionCache = NewGlobalSession()

	serverConfig := &tls.Config{
		InsecureSkipVerify:     true,
		Certificates:           nil,
		GetCertificate:         getCertificate,
		ServerName:             "keyless.vfcc.com",
		SessionTicketsDisabled: false,
		SessionTicketKey:       sha256.Sum256([]byte(conf.SessionTicketKey)),
	}

	l, e := tls.Listen("tcp", conf.Addr, serverConfig)
	if e != nil {
		panic(e)
	}

	fmt.Println("keylessProxy: ", conf.Addr)
	for {
		conn, e := l.Accept()
		if e != nil {
			fmt.Println("accept: ", e)
			continue
		}

		fmt.Println("request: ", conn.RemoteAddr(), conn.LocalAddr())
		go handle(conn)
	}
}

func handle(sconn net.Conn) {
	defer sconn.Close()

	addrs := strings.Fields(conf.TargetAddr)
	dconn, e := net.Dial(addrs[0], addrs[1])
	if e != nil {
		fmt.Println("dial: ", conf.TargetAddr, e)
		return
	}
	defer dconn.Close()

	ExitChan := make(chan bool, 1)
	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		var b [65535]byte
		for {
			n, e := sconn.Read(b[0:])
			if e != nil {
				fmt.Println("read sconn: ", e)
				break
			}
			if _, e = dconn.Write(b[:n]); e != nil {
				fmt.Println("write dconn: ", e)
				break
			}
		}

		ExitChan <- true
	}(sconn, dconn, ExitChan)

	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		var b [65535]byte
		for {
			n, e := dconn.Read(b[0:])
			if e != nil {
				fmt.Println("read dconn: ", e)
				break
			}

			if _, e = sconn.Write(b[:n]); e != nil {
				fmt.Println("write sconn: ", e)
				break
			}
		}

		ExitChan <- true
	}(sconn, dconn, ExitChan)

	<-ExitChan
	fmt.Println("requst over: ", sconn.RemoteAddr().String())

	return
}

func getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("GetCertificate: %#v\n", clientHello) // SNI

	if clientHello.ServerName == "" {
		return nil, fmt.Errorf("client must have SNI.")
	}

	if _, ok := conf.Hosts[clientHello.ServerName]; false == ok {
		log.Println("403: ", clientHello.ServerName)
		return nil, nil
	}

	if cert, ok := certs[clientHello.ServerName]; ok {
		fmt.Println("get cert from local: ", clientHello.ServerName)
		return cert, nil
	}

	fmt.Println("get cert from server: ", clientHello.ServerName)
	cert, e := getCertificateFromServer(conf.Hosts[clientHello.ServerName].KeyServerAddr, clientHello)
	if e != nil {
		fmt.Println("get cert from server ERR: ", e)
		return nil, e
	}

	certs[clientHello.ServerName] = cert

	return cert, nil
}

func getCertificateFromServer(priserver string, clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var e error
	var i int
	var cert tls.Certificate

BEGIN:
	for ; i < len(conn); i++ {
		if conn[i] == nil {
			if conn[i], e = tls.Dial("tcp", conf.PubKeyServer[i], &tls.Config{InsecureSkipVerify: true}); e == nil {
				break
			}
		} else {
			e = nil
			break
		}
	}
	if e != nil {
		return nil, e
	}

	if _, e = fmt.Fprintf(conn[i], "%s\n", clientHello.ServerName); e != nil {
		fmt.Println("write ERR: ", i, e)
		conn[i].Close()
		conn[i] = nil
		goto BEGIN
	}

	if e := gob.NewDecoder(conn[i]).Decode(&cert); e != nil && e != io.EOF {
		fmt.Println("read ERR: ", i, e)
		conn[i].Close()
		conn[i] = nil
		goto BEGIN
	}

	if 0 >= len(cert.Certificate) {
		return nil, fmt.Errorf("no certificate for %s", clientHello.ServerName)
	}

	// privatekey
	if cert.Leaf, e = x509.ParseCertificate(cert.Certificate[0]); e != nil {
		return nil, e
	}
	if cert.PrivateKey, e = keylessClient.NewRemoteSignerByCert(priserver, cert.Leaf); e != nil {
		return nil, e
	}

	return &cert, nil
}
