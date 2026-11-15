// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package cookie builds and validates the stateless HelloRetryRequest
// cookies used by the DTLS 1.3 server.
//
// A cookie is an authenticated, self-contained token bound to the peer
// transport address, the initial ClientHello, and an expiry time. The server
// therefore needs no per-connection state to validate a cookie echoed in a
// retry ClientHello.
package cookie

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"net"
	"time"
)

const (
	// minKeyLength is the smallest accepted cookie MAC key.
	minKeyLength = 16
	// maxKeyLength bounds key material to keep the per-cookie MAC cost fixed.
	maxKeyLength = 64
	// maxKeys limits the key identifiers that fit in one byte.
	maxKeys = 256

	version byte = 1

	versionLength = 1
	keyIDLength   = 1
	expiryLength  = 8
	// TagLength is the HMAC-SHA256 tag carried by every cookie.
	TagLength = sha256.Size

	// Length is the fixed wire size of a cookie.
	Length = versionLength + keyIDLength + expiryLength + TagLength
)

var (
	// ErrInvalidKey is returned when cookie key material is empty or outside
	// the accepted length range.
	ErrInvalidKey = errors.New("cookie key must be between 16 and 64 bytes")
	// ErrNoKeys is returned when no key material is configured.
	ErrNoKeys = errors.New("cookie generator requires at least one key")
	// ErrExpired is returned when the cookie expiry is in the past.
	ErrExpired = errors.New("cookie has expired")
	// ErrInvalid is returned for malformed or unauthenticated cookies.
	ErrInvalid = errors.New("invalid cookie")
)

// DefaultTTL matches the path validation window used for DTLS handshakes.
const DefaultTTL = 30 * time.Second

// Generator issues and validates stateless cookies. The first key signs new
// cookies while every key remains valid for verification, which supports key
// rotation without dropping in-flight handshakes. The zero value is not
// usable; construct one with NewGenerator.
type Generator struct {
	keys [][]byte
	now  func() time.Time
	ttl  time.Duration
}

// Option customizes a Generator.
type Option func(*Generator)

// WithClock overrides the time source. It is intended for tests that need
// deterministic expiry and rotation behavior.
func WithClock(now func() time.Time) Option {
	return func(generator *Generator) {
		if now != nil {
			generator.now = now
		}
	}
}

// WithTTL overrides the default cookie lifetime.
func WithTTL(ttl time.Duration) Option {
	return func(generator *Generator) {
		if ttl > 0 {
			generator.ttl = ttl
		}
	}
}

// NewGenerator creates a Generator whose first key is the active signing key.
// Additional keys are accepted only for verification and enable rotation:
// install a new key first, wait for the previous TTL to elapse, then remove
// the old key.
func NewGenerator(keys [][]byte, opts ...Option) (*Generator, error) {
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	if len(keys) > maxKeys {
		return nil, ErrInvalidKey
	}
	generator := &Generator{now: time.Now, ttl: DefaultTTL}
	for _, key := range keys {
		if len(key) < minKeyLength || len(key) > maxKeyLength {
			return nil, ErrInvalidKey
		}
		generator.keys = append(generator.keys, append([]byte(nil), key...))
	}
	for _, opt := range opts {
		opt(generator)
	}

	return generator, nil
}

// NewRandomKey returns fresh key material suitable for NewGenerator.
func NewRandomKey() ([]byte, error) {
	key := make([]byte, minKeyLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}

	return key, nil
}

// NewDefaultGenerator builds a Generator with one random key.
func NewDefaultGenerator() (*Generator, error) {
	key, err := NewRandomKey()
	if err != nil {
		return nil, err
	}

	return NewGenerator([][]byte{key})
}

// Generate binds a cookie to the peer address and the initial ClientHello
// digest. The digest is the handshake hash of the ClientHello body, computed
// by the caller with the negotiated cipher suite hash.
func (g *Generator) Generate(addr net.Addr, clientHelloDigest []byte) ([]byte, error) {
	if g == nil || len(g.keys) == 0 {
		return nil, ErrNoKeys
	}
	expiry := g.now().Add(g.ttl).UnixMilli()

	return g.build(0, expiry, addr, clientHelloDigest), nil
}

// IssueWithKey signs a cookie with a specific configured key index instead
// of the active key. It exists so tests can reproduce a cookie issued before a
// rotation.
func (g *Generator) IssueWithKey(keyID int, addr net.Addr, clientHelloDigest []byte) ([]byte, error) {
	if g == nil || keyID < 0 || keyID >= len(g.keys) {
		return nil, ErrInvalidKey
	}
	expiry := g.now().Add(g.ttl).UnixMilli()

	return g.build(keyID, expiry, addr, clientHelloDigest), nil
}

// Validate accepts a cookie only when it is well formed, unexpired, and
// authenticates the given address and ClientHello digest with one of the
// configured keys.
func (g *Generator) Validate(addr net.Addr, clientHelloDigest, value []byte) error {
	if g == nil || len(g.keys) == 0 {
		return ErrNoKeys
	}
	if len(value) != Length || value[0] != version {
		return ErrInvalid
	}
	keyID := int(value[1])
	if keyID >= len(g.keys) {
		return ErrInvalid
	}
	expiryMillis := int64(binary.BigEndian.Uint64(value[versionLength+keyIDLength:]))
	if g.now().UnixMilli() >= expiryMillis {
		return ErrExpired
	}
	expiry := make([]byte, expiryLength)
	binary.BigEndian.PutUint64(expiry, uint64(expiryMillis)) //nolint:gosec // UnixMilli stays within uint64.
	expected := g.mac(g.keys[keyID], addr, clientHelloDigest, expiry)
	if !hmac.Equal(expected, value[Length-TagLength:]) {
		return ErrInvalid
	}

	return nil
}

func (g *Generator) build(keyID int, expiryMillis int64, addr net.Addr, clientHelloDigest []byte) []byte {
	cookie := make([]byte, 0, Length)
	cookie = append(cookie, version, byte(keyID)) //nolint:gosec // keyID is bounded by maxKeys.
	expiry := make([]byte, expiryLength)
	binary.BigEndian.PutUint64(expiry, uint64(expiryMillis)) //nolint:gosec // UnixMilli stays within uint64.
	cookie = append(cookie, expiry...)
	cookie = append(cookie, g.mac(g.keys[keyID], addr, clientHelloDigest, expiry)...)

	return cookie
}

func (g *Generator) mac(key []byte, addr net.Addr, clientHelloDigest, expiry []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte{version})
	if addr != nil {
		mac.Write([]byte(addr.Network()))
		mac.Write([]byte{0})
		mac.Write([]byte(addr.String()))
		mac.Write([]byte{0})
	}
	mac.Write(expiry)
	mac.Write(clientHelloDigest)

	return mac.Sum(nil)
}
