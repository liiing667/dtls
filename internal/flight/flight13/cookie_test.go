// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"net"
	"testing"
	"time"

	"github.com/pion/dtls/v4/internal/ciphersuite"
	dtlsconfig "github.com/pion/dtls/v4/internal/config"
	dtlscookie "github.com/pion/dtls/v4/internal/cookie"
	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	cryptosuite "github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/crypto/signaturehash"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cookieTestTime = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

func newCookieGenerator(t *testing.T, keys ...[]byte) *dtlscookie.Generator {
	t.Helper()
	if len(keys) == 0 {
		keys = [][]byte{bytesRepeat(0x42, 16)}
	}
	now := cookieTestTime
	generator, err := dtlscookie.NewGenerator(keys, dtlscookie.WithClock(func() time.Time { return now }))
	require.NoError(t, err)

	return generator
}

func bytesRepeat(value byte, length int) []byte {
	out := make([]byte, length)
	for index := range out {
		out[index] = value
	}

	return out
}

func cookieTestContext(t *testing.T, generator *dtlscookie.Generator) (*handshakeContext, net.Addr) {
	t.Helper()
	suite := ciphersuite.ForID(cryptosuite.TLS_AES_128_GCM_SHA256)
	state := dtlsstate.NewState13(false)
	state.CipherSuite = suite
	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{uint16(cryptosuite.TLS_AES_128_GCM_SHA256)},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Extensions: []extension.Value{
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(signaturehash.Algorithms())},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{},
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
		},
	}
	_, snapshot, err := negotiation.FinalizeClientHello(clientHello, nil)
	require.NoError(t, err)
	require.NoError(t, state.RemoteClientHelloSnapshots.Record(snapshot))

	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}

	return &handshakeContext{
		state:      &state,
		cfg:        &dtlsconfig.HandshakeConfig{LocalCipherSuites: []dtlsconfig.CipherSuite{suite}, DTLS13CookieGenerator: generator},
		remoteAddr: addr,
	}, addr
}

func TestStatelessCookieRoundTrip(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, addr := cookieTestContext(t, generator)

	value, err := generateStatelessCookie(flightCtx, addr)
	require.NoError(t, err)
	assert.Len(t, value, dtlscookie.Length)
	require.NoError(t, validateStatelessCookie(flightCtx, addr, value))
}

func TestStatelessCookieBindsAddress(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, addr := cookieTestContext(t, generator)

	value, err := generateStatelessCookie(flightCtx, addr)
	require.NoError(t, err)

	otherAddr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5000}
	err = validateStatelessCookie(flightCtx, otherAddr, value)
	assert.ErrorIs(t, err, dtlserrors.ErrCookieMismatch)
}

func TestStatelessCookieBindsClientHello(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, addr := cookieTestContext(t, generator)

	value, err := generateStatelessCookie(flightCtx, addr)
	require.NoError(t, err)

	clientHello := &handshake.MessageClientHello{
		Version:            protocol.Version1_2,
		CipherSuiteIDs:     []uint16{uint16(cryptosuite.TLS_AES_128_GCM_SHA256)},
		CompressionMethods: dtlsflight.DefaultCompressionMethods(),
		Random:             handshake.Random{RandomBytes: [handshake.RandomBytesLength]byte{0x01}},
		Extensions: []extension.Value{
			&extension.SignatureAlgorithms{Schemes: dtlsflight.SignatureSchemeIDs(signaturehash.Algorithms())},
			&extension.SupportedGroups{Groups: []elliptic.Curve{elliptic.X25519}},
			&extension13.ClientKeyShare{},
			&extension13.OfferedVersions{Versions: []protocol.Version{protocol.Version1_3}},
			&extension.ServerNameOffer{ServerName: "different.example"},
		},
	}
	_, changedSnapshot, err := negotiation.FinalizeClientHello(clientHello, nil)
	require.NoError(t, err)
	flightCtx.state.RemoteClientHelloSnapshots.Reset()
	require.NoError(t, flightCtx.state.RemoteClientHelloSnapshots.Record(changedSnapshot))

	assert.ErrorIs(t, validateStatelessCookie(flightCtx, addr, value), dtlserrors.ErrCookieMismatch)
}

func TestStatelessCookieRejectsExpiredValue(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, addr := cookieTestContext(t, generator)

	value, err := generateStatelessCookie(flightCtx, addr)
	require.NoError(t, err)

	expired := cookieTestTime.Add(dtlscookie.DefaultTTL)
	expiredGenerator, err := dtlscookie.NewGenerator(
		[][]byte{bytesRepeat(0x42, 16)},
		dtlscookie.WithClock(func() time.Time { return expired }),
	)
	require.NoError(t, err)
	flightCtx.cfg.DTLS13CookieGenerator = expiredGenerator

	assert.ErrorIs(t, validateStatelessCookie(flightCtx, addr, value), dtlserrors.ErrCookieMismatch)
}

func TestStatelessCookieKeyRotation(t *testing.T) {
	rotated := newCookieGenerator(t, bytesRepeat(0x07, 16), bytesRepeat(0x42, 16))
	flightCtx, addr := cookieTestContext(t, rotated)
	digest := initialClientHelloDigest(flightCtx)

	// A cookie issued before rotation keeps the old key identifier (1),
	// while new cookies use the active key (0).
	oldCookie, err := rotated.IssueWithKey(1, addr, digest)
	require.NoError(t, err)
	assert.Equal(t, byte(1), oldCookie[1])

	flightCtx.cfg.DTLS13CookieGenerator = rotated
	newCookie, err := generateStatelessCookie(flightCtx, addr)
	require.NoError(t, err)
	assert.Zero(t, newCookie[1])
	require.NoError(t, validateStatelessCookie(flightCtx, addr, newCookie))
	require.NoError(t, validateStatelessCookie(flightCtx, addr, oldCookie))

	// After retiring the old key, cookies issued under it are rejected.
	retired := newCookieGenerator(t, bytesRepeat(0x07, 16))
	flightCtx.cfg.DTLS13CookieGenerator = retired
	assert.ErrorIs(t, validateStatelessCookie(flightCtx, addr, oldCookie), dtlserrors.ErrCookieMismatch)
	assert.NoError(t, validateStatelessCookie(flightCtx, addr, newCookie))
}

func TestClientHelloCookieReadsExtension(t *testing.T) {
	clientHello := &handshake.MessageClientHello{
		Extensions: []extension.Value{
			&extension13.Cookie{Cookie: []byte{0x01, 0x02}},
		},
	}

	value, present := clientHelloCookie(clientHello)
	require.True(t, present)
	assert.Equal(t, []byte{0x01, 0x02}, value)

	_, present = clientHelloCookie(&handshake.MessageClientHello{})
	assert.False(t, present)
}
