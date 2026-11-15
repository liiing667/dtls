// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package flight13

import (
	"context"
	"testing"

	dtlsflight "github.com/pion/dtls/v4/internal/flight"
	"github.com/pion/dtls/v4/internal/negotiation"
	"github.com/pion/dtls/v4/pkg/crypto/elliptic"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/extension"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlight2InsecureSkipHelloVerifyOmitsCookie(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, _ := cookieTestContext(t, generator)
	flightCtx.cfg.InsecureSkipHelloVerify = true
	flightCtx.state.HelloRetryRequest = negotiation.RetryRequest{}
	flightCtx.state.SelectedGroup = elliptic.X25519

	packets, dtlsAlert, err := flight2Generate(nil, flightCtx)
	require.NoError(t, err)
	require.Nil(t, dtlsAlert)
	require.Len(t, packets, 1)
	assert.Nil(t, flightCtx.state.Cookie)

	handshakeMessage, ok := packets[0].Content.(*handshake.Handshake)
	require.True(t, ok)
	serverHello, ok := handshakeMessage.Message.(*handshake.MessageServerHello)
	require.True(t, ok)
	for _, value := range serverHello.Extensions {
		assert.NotEqual(t, extension.TypeCookie, value.ExtensionType())
	}
}

func TestFlight2InsecureSkipHelloVerifySkipsCookieValidation(t *testing.T) {
	generator := newCookieGenerator(t)
	flightCtx, _ := cookieTestContext(t, generator)
	flightCtx.cfg.InsecureSkipHelloVerify = true

	id := uint16(flightCtx.cfg.LocalCipherSuites[0].ID())
	// A cookie-bearing HRR authorizes the retry; the parse path must not
	// independently validate the echoed cookie in skip mode.
	request, err := negotiation.ValidateHelloRetryRequest(
		flightCtx.state.RemoteClientHelloSnapshots.Initial(),
		&handshake.MessageServerHello{
			CipherSuiteID: &id,
			Extensions: []extension.Value{
				&extension13.SelectedVersion{Version: protocol.Version1_3},
				&extension13.Cookie{Cookie: []byte("not a stateless cookie")},
			},
		},
	)
	require.NoError(t, err)
	retryClientHello, err := negotiation.BuildClientHelloRetry(
		flightCtx.state.RemoteClientHelloSnapshots.Initial(), request, nil,
	)
	require.NoError(t, err)

	cache := dtlsflight.NewCache()
	raw, err := (&handshake.Handshake{Header: handshake.Header{MessageSequence: 1}, Message: retryClientHello}).Marshal()
	require.NoError(t, err)
	cache.Push(raw, 0, 1, handshake.TypeClientHello, true)
	flightCtx.cache = cache
	flightCtx.state.HandshakeRecvSequence = 1
	flightCtx.state.HelloRetryRequest = request
	flightCtx.state.SelectedGroup = 0
	flightCtx.state.PSKOnly = true

	nextFlight, dtlsAlert, parseErr := flight2Parse(context.Background(), nil, flightCtx)
	require.NoError(t, parseErr)
	require.Nil(t, dtlsAlert)
	assert.Equal(t, Flight4, nextFlight)
}
