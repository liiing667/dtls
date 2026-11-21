// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"bytes"
	"crypto"
	"crypto/tls"
	"sync"
	"testing"
	"time"

	dtlsstate "github.com/pion/dtls/v4/internal/state"
	"github.com/pion/dtls/v4/pkg/crypto/ciphersuite"
	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sessionAuditStore is an in-memory SessionStore. In fixed mode Get returns
// the pinned session for every key, simulating a store shared across hosts.
type sessionAuditStore struct {
	mu       sync.Mutex
	sessions map[string]Session
	fixed    *Session
}

func newSessionAuditStore() *sessionAuditStore {
	return &sessionAuditStore{sessions: map[string]Session{}}
}

func (s *sessionAuditStore) Set(key []byte, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[string(key)] = session

	return nil
}

func (s *sessionAuditStore) Get(key []byte) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fixed != nil {
		return *s.fixed, nil
	}

	return s.sessions[string(key)], nil
}

func (s *sessionAuditStore) Del(key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, string(key))

	return nil
}

func (s *sessionAuditStore) ticketSession() (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, session := range s.sessions {
		if session.Ticket != nil {
			return session, true
		}
	}

	return Session{}, false
}

func auditTicketSession(isClient bool, cert tls.Certificate, secret []byte) Session {
	return Session{
		Version: 1, IsClient: isClient,
		ID:     bytes.Repeat([]byte{0x11}, 32),
		Secret: secret,
		Ticket: &SessionTicket{
			CipherSuite: ciphersuite.TLS_AES_128_GCM_SHA256, Lifetime: 3600,
			AgeAdd: 12345, Nonce: []byte{1}, CreatedAt: time.Now(),
			PeerCertificates: cert.Certificate,
		},
	}
}

func TestTicketPSKValidation(t *testing.T) {
	now := time.Now()
	valid := Session{
		Version: 1, IsClient: true,
		ID: []byte("ticket-identity"), Secret: bytes.Repeat([]byte{0x42}, 32),
		IdentityHint: []byte("hint"),
		Ticket: &SessionTicket{
			CipherSuite: ciphersuite.TLS_AES_128_GCM_SHA256, Lifetime: 3600,
			AgeAdd: 7, CreatedAt: now.Add(-time.Second), ServerName: "example.com",
			NegotiatedProtocol: "proto", MaxEarlyDataSize: 128,
			PeerCertificates: [][]byte{{1, 2, 3}},
		},
	}

	t.Run("valid", func(t *testing.T) {
		psk := valid.ticketPSK("example.com", now)
		require.NotNil(t, psk)
		assert.Equal(t, valid.ID, psk.Identity)
		assert.Equal(t, valid.Secret, psk.Secret)
		assert.Equal(t, crypto.SHA256, psk.Hash)
		assert.Equal(t, valid.IdentityHint, psk.IdentityHint)
		assert.Equal(t, valid.Ticket.PeerCertificates, psk.PeerCertificates)
		assert.Equal(t, uint32(1000)+7, psk.ObfuscatedTicketAge)
		require.NotNil(t, psk.Ticket)
		assert.Equal(t, valid.Ticket.CipherSuite, psk.Ticket.CipherSuite)
		assert.Equal(t, valid.Ticket.Lifetime, psk.Ticket.Lifetime)
		assert.Equal(t, valid.Ticket.NegotiatedProtocol, psk.Ticket.NegotiatedProtocol)
		assert.Equal(t, valid.Ticket.MaxEarlyDataSize, psk.Ticket.MaxEarlyDataSize)
	})

	t.Run("sha384 suite", func(t *testing.T) {
		session := valid
		ticket := *valid.Ticket
		ticket.CipherSuite = ciphersuite.TLS_AES_256_GCM_SHA384
		session.Ticket = &ticket
		session.Secret = bytes.Repeat([]byte{0x42}, 48)
		psk := session.ticketPSK("example.com", now)
		require.NotNil(t, psk)
		assert.Equal(t, crypto.SHA384, psk.Hash)
	})

	rejected := []struct {
		name   string
		mutate func(*Session)
		name0  string
	}{
		{"nil ticket", func(s *Session) { s.Ticket = nil }, "example.com"},
		{"other host", func(*Session) {}, "other.example.com"},
		{"empty identity", func(s *Session) { s.ID = nil }, "example.com"},
		{"expired", func(s *Session) { s.Ticket.CreatedAt = now.Add(-2 * time.Hour) }, "example.com"},
		{"future ticket", func(s *Session) { s.Ticket.CreatedAt = now.Add(time.Minute) }, "example.com"},
		{"zero lifetime", func(s *Session) { s.Ticket.Lifetime = 0 }, "example.com"},
		{"lifetime over seven days", func(s *Session) { s.Ticket.Lifetime = 8 * 24 * 60 * 60 }, "example.com"},
		{"short secret", func(s *Session) { s.Secret = s.Secret[:31] }, "example.com"},
		{"unknown suite", func(s *Session) { s.Ticket.CipherSuite = 0xffff }, "example.com"},
		{"dtls12 only suite", func(s *Session) { s.Ticket.CipherSuite = ciphersuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 }, "example.com"},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			session := valid
			ticket := *valid.Ticket
			session.Ticket = &ticket
			tc.mutate(&session)
			assert.Nil(t, session.ticketPSK(tc.name0, now))
		})
	}
}

func auditClientOpts(store SessionStore, extra ...ClientOption) []ClientOption {
	opts := []ClientOption{
		WithInsecureSkipVerify(true),
		WithSessionStore(store),
		WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3),
		WithFlightInterval(10 * time.Millisecond),
	}

	return append(opts, extra...)
}

func auditServerOpts(store SessionStore, cert tls.Certificate) []ServerOption {
	return []ServerOption{
		WithCertificates(cert),
		WithSessionStore(store),
		WithMinVersion(protocol.Version1_3), WithMaxVersion(protocol.Version1_3),
		WithFlightInterval(10 * time.Millisecond),
	}
}

func resumedPSK(t *testing.T, conn *Conn) []byte {
	t.Helper()
	state, ok := conn.state.(*dtlsstate.State13)
	require.True(t, ok, "expected DTLS 1.3 connection state")

	return state.PSK
}

func requireHandshakeOK(t *testing.T, client, server handshakeResult) {
	t.Helper()
	require.NoError(t, client.configErr)
	require.NoError(t, client.handshakeError)
	require.NoError(t, server.configErr)
	require.NoError(t, server.handshakeError)
}

// TestSessionTicketLifecycle runs a full DTLS 1.3 handshake that issues a
// ticket, then verifies a second connection resumes with the stored PSK.
func TestSessionTicketLifecycle(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientStore, serverStore := newSessionAuditStore(), newSessionAuditStore()

	client, server := handshakePair(t, auditClientOpts(clientStore), auditServerOpts(serverStore, cert))
	requireHandshakeOK(t, client, server)
	require.Empty(t, resumedPSK(t, client.conn), "first handshake must not resume")
	require.Empty(t, resumedPSK(t, server.conn), "first handshake must not resume")

	var clientTicket, serverTicket Session
	require.Eventually(t, func() bool {
		var okClient, okServer bool
		clientTicket, okClient = clientStore.ticketSession()
		serverTicket, okServer = serverStore.ticketSession()

		return okClient && okServer
	}, 5*time.Second, 10*time.Millisecond, "server must issue and store a session ticket")
	require.Equal(t, clientTicket.ID, serverTicket.ID)
	require.Equal(t, clientTicket.Secret, serverTicket.Secret)

	// Pin the issued sessions so the second lookup cannot miss on a changed key.
	resumeClientStore, resumeServerStore := newSessionAuditStore(), newSessionAuditStore()
	resumeClientStore.fixed = &clientTicket
	resumeServerStore.fixed = &serverTicket
	client, server = handshakePair(t, auditClientOpts(resumeClientStore), auditServerOpts(resumeServerStore, cert))
	requireHandshakeOK(t, client, server)
	require.NotEmpty(t, resumedPSK(t, client.conn), "second handshake must resume")
	require.NotEmpty(t, resumedPSK(t, server.conn), "second handshake must resume")
	assert.Equal(t, resumedPSK(t, client.conn), resumedPSK(t, server.conn))
	assert.Equal(t, clientTicket.Secret, resumedPSK(t, server.conn))
}

// TestSessionTicketResumeScenarios seeds client and server stores directly and
// checks that ticket, host identity, expiry, and secret are validated together:
// a mismatch anywhere must fall back to a full handshake (or fail), never
// resume with a stale or foreign PSK.
func TestSessionTicketResumeScenarios(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	secret := bytes.Repeat([]byte{0x42}, 32)

	freshStores := func() (*sessionAuditStore, *sessionAuditStore) {
		clientStore, serverStore := newSessionAuditStore(), newSessionAuditStore()
		clientSession := auditTicketSession(true, cert, secret)
		serverSession := auditTicketSession(false, cert, secret)
		clientStore.fixed = &clientSession
		serverStore.fixed = &serverSession

		return clientStore, serverStore
	}

	run := func(t *testing.T, clientStore, serverStore *sessionAuditStore, extra ...ClientOption) (handshakeResult, handshakeResult) {
		t.Helper()

		return handshakePair(t, auditClientOpts(clientStore, extra...), auditServerOpts(serverStore, cert))
	}

	t.Run("resume", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.NotEmpty(t, resumedPSK(t, client.conn))
		assert.Equal(t, secret, resumedPSK(t, server.conn))
	})

	t.Run("duplicate ticket reuse", func(t *testing.T) {
		// Ordinary resumption may reuse a ticket until it expires; early-data
		// replay is blocked separately by EarlyDataSessionStore.Claim.
		clientStore, serverStore := freshStores()
		for range 2 {
			client, server := run(t, clientStore, serverStore)
			requireHandshakeOK(t, client, server)
			assert.Equal(t, secret, resumedPSK(t, server.conn))
		}
	})

	t.Run("expired client ticket", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		clientStore.fixed.Ticket.CreatedAt = time.Now().Add(-2 * time.Hour)
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, server.conn), "expired ticket must not resume")
	})

	t.Run("expired server ticket", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		serverStore.fixed.Ticket.CreatedAt = time.Now().Add(-2 * time.Hour)
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, server.conn), "server must ignore an expired ticket")
	})

	t.Run("cross host", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		client, server := run(t, clientStore, serverStore, WithServerName("other.example.com"))
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, client.conn), "ticket must not resume under another server name")
		assert.Empty(t, resumedPSK(t, server.conn), "ticket must not resume under another server name")
	})

	t.Run("wrong server secret", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		serverStore.fixed.Secret = bytes.Repeat([]byte{0x24}, 32)
		client, server := run(t, clientStore, serverStore)
		require.Error(t, server.handshakeError, "binder mismatch must fail the handshake")
		require.Error(t, client.handshakeError)
	})

	t.Run("empty ticket kept as cache miss", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		clientStore.fixed = &Session{Version: 1, IsClient: true, ID: []byte("legacy"), Secret: bytes.Repeat([]byte{7}, 48)}
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, server.conn), "ticketless entries require a full handshake")
	})

	t.Run("legacy entry without metadata", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		clientStore.fixed.Version = 0
		serverStore.fixed.Version = 0
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, server.conn), "legacy entries require a full handshake")
	})

	t.Run("role mismatch", func(t *testing.T) {
		clientStore, serverStore := freshStores()
		clientStore.fixed.IsClient = false
		client, server := run(t, clientStore, serverStore)
		requireHandshakeOK(t, client, server)
		assert.Empty(t, resumedPSK(t, server.conn), "another role's ticket must not resume")
	})
}

// TestSessionTicketNotUsableForDTLS12 keeps the DTLS 1.2 session cache and the
// DTLS 1.3 ticket cache isolated: a ticket entry must never be resumed as a
// 1.2 session, and the ordinary 1.2 cache keeps working.
func TestSessionTicketNotUsableForDTLS12(t *testing.T) {
	cert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)
	clientOpts := func(store SessionStore) []ClientOption {
		return []ClientOption{
			WithInsecureSkipVerify(true), WithSessionStore(store),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
			WithFlightInterval(10 * time.Millisecond),
		}
	}
	serverOpts := func(store SessionStore) []ServerOption {
		return []ServerOption{
			WithCertificates(cert), WithSessionStore(store),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
			WithFlightInterval(10 * time.Millisecond),
		}
	}
	serverSessionID := func(conn *Conn) []byte {
		return dtlsstate.CommonState(conn.state).SessionID
	}

	t.Run("ordinary cache resumes", func(t *testing.T) {
		clientStore, serverStore := newSessionAuditStore(), newSessionAuditStore()
		client, server := handshakePair(t, clientOpts(clientStore), serverOpts(serverStore))
		requireHandshakeOK(t, client, server)
		storedID := serverSessionID(server.conn)
		require.NotEmpty(t, storedID)

		// Pin the cached client session so the lookup cannot miss on a changed key.
		clientSession, ok := clientStore.ticketSession()
		require.False(t, ok, "1.2 entries must not carry a ticket")
		require.Len(t, clientStore.sessions, 1)
		for _, session := range clientStore.sessions {
			clientSession = session
		}
		require.Nil(t, clientSession.Ticket)
		require.Len(t, clientSession.Secret, 48)
		pinned := newSessionAuditStore()
		pinned.fixed = &clientSession

		client, server = handshakePair(t, clientOpts(pinned), serverOpts(serverStore))
		requireHandshakeOK(t, client, server)
		assert.Equal(t, storedID, serverSessionID(server.conn), "server must echo the cached session ID")
	})

	t.Run("ticket entry is not a 1.2 session", func(t *testing.T) {
		ticket := auditTicketSession(true, cert, bytes.Repeat([]byte{0x42}, 48))
		serverTicket := auditTicketSession(false, cert, bytes.Repeat([]byte{0x42}, 48))
		clientStore, serverStore := newSessionAuditStore(), newSessionAuditStore()
		clientStore.fixed = &ticket
		serverStore.fixed = &serverTicket
		client, server := handshakePair(t, clientOpts(clientStore), serverOpts(serverStore))
		requireHandshakeOK(t, client, server)
		require.NotEmpty(t, serverSessionID(server.conn))
		assert.NotEqual(t, ticket.ID, serverSessionID(server.conn),
			"a ticket entry must never be resumed as a DTLS 1.2 session")
	})
}
