// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtlshandshake

import (
	"crypto"
	"testing"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/dtls/v4/pkg/protocol/alert"
	extension13 "github.com/pion/dtls/v4/pkg/protocol/extension/dtls13"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
	"github.com/stretchr/testify/require"
)

func pskSelectionHello(t *testing.T, psks []dtlsstate.PSK) (*handshake.MessageClientHello, []byte) {
	t.Helper()
	cfg := testHandshakeConfig13(t)
	base := &handshake.MessageClientHello{
		Version: protocol.Version1_2, CipherSuiteIDs: []uint16{0x1301, 0x1302},
		CompressionMethods: []*protocol.CompressionMethod{{ID: 0}},
	}
	hello, _, err := FinalizeClientHelloWithPSKs(base, cfg, psks, NewTranscript())
	require.NoError(t, err)

	return hello, rawHandshakeMessage13(t, 0, hello)
}

func pskSelectionContext(t *testing.T) *handshakeContext {
	t.Helper()
	cfg := testHandshakeConfig13(t)
	state := newTestState13(t, false)
	state.CipherSuite = cfg.LocalCipherSuites[0]

	return &handshakeContext{state: state, cfg: cfg, transcript: NewTranscript()}
}

func TestSelectPSKOfferKeepsIdentityAndBinderTogether(t *testing.T) {
	psks := []dtlsstate.PSK{
		{Identity: []byte("first"), Secret: []byte("secret-first"), Hash: crypto.SHA256, External: true},
		{Identity: []byte("second"), Secret: []byte("secret-second"), Hash: crypto.SHA256, External: true},
	}
	for _, test := range []struct {
		name    string
		index   int
		wantErr error
	}{
		{name: "first identity", index: 0},
		{name: "second identity", index: 1},
		{name: "negative index", index: -1, wantErr: dtlserrors.ErrPSKIdentity},
		{name: "index past offer", index: 7, wantErr: dtlserrors.ErrPSKIdentity},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello, raw := pskSelectionHello(t, psks)
			c := pskSelectionContext(t)
			c.cfg.SelectPSK = func([][]byte) (int, []byte, crypto.Hash, error) {
				if test.index < 0 || test.index >= len(psks) {
					return test.index, psks[0].Secret, crypto.SHA256, nil
				}

				return test.index, psks[test.index].Secret, crypto.SHA256, nil
			}
			err := c.selectPSK(hello, raw)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)
				require.Empty(t, c.state.PSK)

				return
			}
			require.NoError(t, err)
			require.Equal(t, psks[test.index].Secret, c.state.PSK)
			require.Equal(t, uint16(test.index), c.state.PSKIdentity)
			require.Equal(t, psks[test.index].Identity, c.state.IdentityHint)
		})
	}
}

func TestSelectPSKRejectsDuplicateIdentity(t *testing.T) {
	psks := []dtlsstate.PSK{
		{Identity: []byte("dup"), Secret: []byte("secret-a"), Hash: crypto.SHA256, External: true},
		{Identity: []byte("dup"), Secret: []byte("secret-b"), Hash: crypto.SHA256, External: true},
	}
	hello, raw := pskSelectionHello(t, psks)
	c := pskSelectionContext(t)
	calls := 0
	c.cfg.SelectPSK = func([][]byte) (int, []byte, crypto.Hash, error) {
		calls++

		return 1, []byte("secret-b"), crypto.SHA256, nil
	}
	err := c.selectPSK(hello, raw)
	require.ErrorIs(t, err, dtlserrors.ErrPSKIdentity)
	var gotAlert *alert.Alert
	require.ErrorAs(t, err, &gotAlert)
	require.Equal(t, alert.IllegalParameter, gotAlert.Description)
	require.Zero(t, calls)
	require.Empty(t, c.state.PSK)
}

func TestSelectPSKRejectsUnsupportedHash(t *testing.T) {
	psks := []dtlsstate.PSK{
		{Identity: []byte("a"), Secret: []byte("secret-a"), Hash: crypto.SHA256, External: true},
	}
	for _, test := range []struct {
		name   string
		hashID crypto.Hash
	}{
		{name: "sha512", hashID: crypto.SHA512},
		{name: "zero hash", hashID: crypto.Hash(0)},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello, raw := pskSelectionHello(t, psks)
			c := pskSelectionContext(t)
			c.cfg.SelectPSK = func([][]byte) (int, []byte, crypto.Hash, error) {
				return 0, []byte("secret-a"), test.hashID, nil
			}
			require.NotPanics(t, func() {
				err := c.selectPSK(hello, raw)
				require.ErrorIs(t, err, dtlserrors.ErrPSKHash)
				require.Empty(t, c.state.PSK)
			})
		})
	}
}

func TestSelectPSKRejectsBinderHashMismatch(t *testing.T) {
	psks := []dtlsstate.PSK{
		{Identity: []byte("a"), Secret: []byte("secret-a"), Hash: crypto.SHA256, External: true},
	}
	for _, test := range []struct {
		name       string
		binderSize int
		wantErr    error
	}{
		{name: "selected hash does not match binder", binderSize: crypto.SHA384.Size(), wantErr: dtlserrors.ErrPreSharedKeyFormat},
		{name: "binder is not a transcript hash", binderSize: 40, wantErr: dtlserrors.ErrPSKHash},
	} {
		t.Run(test.name, func(t *testing.T) {
			hello, raw := pskSelectionHello(t, psks)
			offer := hello.Extensions[len(hello.Extensions)-1].(*extension13.OfferedPSKs)
			offer.Binders[0] = make([]byte, test.binderSize)
			raw = rawHandshakeMessage13(t, 0, hello)
			c := pskSelectionContext(t)
			c.cfg.SelectPSK = func([][]byte) (int, []byte, crypto.Hash, error) {
				return 0, []byte("secret-a"), crypto.SHA256, nil
			}
			err := c.selectPSK(hello, raw)
			require.ErrorIs(t, err, test.wantErr)
			require.Empty(t, c.state.PSK)
		})
	}
}
