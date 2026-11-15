// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"crypto/sha256"
	"hash"
	"net"

	dtlscookie "github.com/pion/dtls/v4/internal/cookie"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

func remoteAddr(conn dtlsflight.Conn) net.Addr {
	if conn == nil {
		return nil
	}

	return conn.RemoteAddr()
}

func clientHelloCookie(clientHello *handshake.MessageClientHello) ([]byte, bool) {
	for _, value := range clientHello.Extensions {
		if cookie, ok := value.(*extension13.Cookie); ok {
			return cookie.Cookie, true
		}
	}

	return nil, false
}

// cookieGenerator returns the configured stateless cookie generator. Unit
// tests construct handshake configs directly without one, so fall back to an
// ephemeral generator rather than failing the handshake.
func cookieGenerator(flightCtx *handshakeContext) (*dtlscookie.Generator, error) {
	if flightCtx.cfg.DTLS13CookieGenerator != nil {
		return flightCtx.cfg.DTLS13CookieGenerator, nil
	}

	generator, err := dtlscookie.NewDefaultGenerator()
	if err != nil {
		return nil, err
	}
	flightCtx.cfg.DTLS13CookieGenerator = generator

	return generator, nil
}

// initialClientHelloDigest hashes the exact initial ClientHello body with the
// negotiated cipher suite hash.
func initialClientHelloDigest(flightCtx *handshakeContext) []byte {
	var hash hash.Hash
	if flightCtx.state.CipherSuite != nil {
		hash = flightCtx.state.CipherSuite.HashFunc()()
	} else {
		hash = sha256.New()
	}
	hash.Write(flightCtx.state.RemoteClientHelloSnapshots.Initial().Body())

	return hash.Sum(nil)
}

// generateStatelessCookie binds the HelloRetryRequest cookie to the peer
// address and the initial ClientHello so the server can verify it without
// retaining per-connection state.
func generateStatelessCookie(flightCtx *handshakeContext, addr net.Addr) ([]byte, error) {
	generator, err := cookieGenerator(flightCtx)
	if err != nil {
		return nil, err
	}

	return generator.Generate(addr, initialClientHelloDigest(flightCtx))
}

// validateStatelessCookie accepts only an unexpired cookie that authenticates
// the peer address and the initial ClientHello.
func validateStatelessCookie(flightCtx *handshakeContext, addr net.Addr, value []byte) error {
	generator, err := cookieGenerator(flightCtx)
	if err != nil {
		return err
	}
	if err := generator.Validate(addr, initialClientHelloDigest(flightCtx), value); err != nil {
		return dtlserrors.ErrCookieMismatch
	}

	return nil
}
