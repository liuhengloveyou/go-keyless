package main

import (
	"crypto/tls"
	"fmt"
)

type GlobalSession struct {
	session map[string]*tls.ClientSessionState
}

func NewGlobalSession() *GlobalSession {
	return &GlobalSession{
		session: make(map[string]*tls.ClientSessionState, 10000),
	}
}

func (p *GlobalSession) Get(sessionKey string) (session *tls.ClientSessionState, ok bool) {
	fmt.Println("GlobalSession get: ", sessionKey)

	session, ok = p.session[sessionKey]

	return
}

// Put adds the ClientSessionState to the cache with the given key.
func (p *GlobalSession) Put(sessionKey string, cs *tls.ClientSessionState) {
	fmt.Printf("GlobalSession put: %s\n%#v", sessionKey, cs)

	p.session[sessionKey] = cs
}
