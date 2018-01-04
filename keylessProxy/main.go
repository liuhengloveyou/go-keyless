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
	PriKeyServer string `json:"priKeyServer"`
	KeyServerCA  string `json: "keyServerCA"`
}

type Config struct {
	Addr         string   `json:"addr"`
	TargetAddr   string   `json:"target"`
	PubKeyServer []string `json:"pubKeyServer"`
	Resolvers    []string `json:"resolvers"`

	Cert             string `json:"cert"`
	Key              string `json:"key"`
	CA               string `json:"ca"`
	SessionTicketKey string `json:"sessionTicketKey"`

	// 只有配置的域名才能连接成功
	Hosts map[string]*HostConfig `json:"hosts"`
}

var (
	confile = flag.String("conf", "./app.conf", "配置文件路径")
	conf    Config

	// 所有已配置的域名
	certs map[string]*tls.Certificate

	// 用来从keyServer取私钥的客户端
	keylessClient *client.Client

	// 用来从keyServer取证书的客户端
	pubKeyClient []*tls.Conn
)

func init() {
	// 加载配置
	if e := gocommon.LoadJsonConfig(*confile, &conf); e != nil {
		panic(e)
	}

	certs = make(map[string]*tls.Certificate, len(conf.Hosts))
	pubKeyClient = make([]*tls.Conn, len(conf.PubKeyServer))

	gob.Register(rsa.PublicKey{})

	ncpu := 8
	if runtime.NumCPU() > ncpu {
		ncpu = runtime.NumCPU()
	}
	runtime.GOMAXPROCS(ncpu)
}

func main() {
	flag.Parse()

	var e error

	fmt.Println(">>>", conf)

	if keylessClient, e = client.NewClientFromFile(conf.Cert, conf.Key, conf.CA); e != nil {
		panic(e)
	}

	keylessClient.Dialer.Timeout = 1 * time.Second
	//keylessClient.Resolvers = conf.Resolvers
	keylessClient.Config.InsecureSkipVerify = true
	//keylessClient.Config.ClientSessionCache = NewGlobalSession()

	serverConfig := &tls.Config{
		InsecureSkipVerify:     true,
		Certificates:           nil,
		GetCertificate:         getCertificate,
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
	addrs := strings.Fields(conf.TargetAddr)
	dconn, e := net.Dial(addrs[0], addrs[1])
	if e != nil {
		log.Println("dial: ", conf.TargetAddr, e)
		return
	}

	defer dconn.Close()
	defer sconn.Close()
	ExitChan := make(chan bool, 1)

	go func(sconn net.Conn, dconn net.Conn, Exit chan bool) {
		var b [65535]byte
		for {
			n, e := sconn.Read(b[0:])
			if e != nil {
				log.Println("read client: ", e)
				break
			}
			if _, e = dconn.Write(b[:n]); e != nil {
				fmt.Println("write server: ", e)
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
				fmt.Println("read server: ", e)
				break
			}

			if _, e = sconn.Write(b[:n]); e != nil {
				fmt.Println("write client: ", e)
				break
			}
		}

		ExitChan <- true
	}(sconn, dconn, ExitChan)

	<-ExitChan
	fmt.Println("over: ", sconn.RemoteAddr().String())

	return
}

func getCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fmt.Printf("GetCertificate: %#v\n", clientHello.ServerName)

	if clientHello.ServerName == "" {
		return nil, fmt.Errorf("MUST support SNI.")
	}

	if _, ok := conf.Hosts[clientHello.ServerName]; false == ok {
		log.Println("403: ", clientHello.ServerName)
		return nil, nil
	}

	if cert, ok := certs[clientHello.ServerName]; ok {
		fmt.Println("get cert from local cache: ", clientHello.ServerName)
		return cert, nil
	}

	fmt.Println("get cert from keyServer: ", clientHello.ServerName)
	cert, e := getCertificateFromServer(conf.Hosts[clientHello.ServerName].PriKeyServer, clientHello)
	if e != nil {
		fmt.Println("get cert from server ERR: ", e)
		return nil, e
	}

	certs[clientHello.ServerName] = cert

	return cert, nil
}

func getCertificateFromServer(priserver string, clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	var (
		e    error
		i    int
		cert tls.Certificate
	)

BEGIN:
	for ; i < len(pubKeyClient); i++ {
		if pubKeyClient[i] == nil {
			if pubKeyClient[i], e = tls.Dial("tcp", conf.PubKeyServer[i], &tls.Config{InsecureSkipVerify: true}); e == nil {
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

	if _, e = fmt.Fprintf(pubKeyClient[i], "%s\n", clientHello.ServerName); e != nil {
		fmt.Println("write ERR: ", i, e)
		pubKeyClient[i].Close()
		pubKeyClient[i] = nil
		goto BEGIN
	}

	if e := gob.NewDecoder(pubKeyClient[i]).Decode(&cert); e != nil && e != io.EOF {
		fmt.Println("read ERR: ", i, e)
		pubKeyClient[i].Close()
		pubKeyClient[i] = nil
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
