package main

import (
	"crypto/tls"
	"fmt"
)

type GlobalSession struct {
	session map[string]*tls.SessionState
}

func NewGlobalSession() *GlobalSession {
	return &GlobalSession{
		session: make(map[string]*tls.SessionState, 10000),
	}
}

func (p *GlobalSession) Get(sessionKey []byte) (session *tls.SessionState, ok bool) {
	fmt.Println("GlobalSession get: ", string(sessionKey))

	session, ok = p.session[string(sessionKey)]

	return
}

// Put adds the ClientSessionState to the cache with the given key.
func (p *GlobalSession) Put(sessionKey []byte, sess *tls.SessionState) {
	fmt.Printf("GlobalSession put: '%v'\n%#v", string(sessionKey), sess)

	p.session[string(sessionKey)] = sess
}
