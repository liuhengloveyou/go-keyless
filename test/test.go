package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
)

func main() {
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			SessionTicketsDisabled: true,
		},
		DisableCompression: true,
	}}

	resp, err := client.Get("https://www.demo.com:1443/lua")
	if err != nil {
		panic(err)
	}

	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))
	fmt.Println(resp.Status)
}
