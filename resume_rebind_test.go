// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/pion/dtls/v4/pkg/crypto/selfsign"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rebindSessionStore struct {
	mu      sync.Mutex
	session Session
	has     bool
	gets    int
}

func (s *rebindSessionStore) Set(_ []byte, session Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session = session
	s.has = true

	return nil
}

func (s *rebindSessionStore) Get(_ []byte) (Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if !s.has {
		return Session{}, nil
	}

	return s.session, nil
}

func (s *rebindSessionStore) Del(_ []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.has = false

	return nil
}

func (s *rebindSessionStore) getCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.gets
}

func (s *rebindSessionStore) snapshot() (Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.session, s.has
}

func (s *rebindSessionStore) replace(session Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.session = session
	s.has = true
}

func newRebindCA(t *testing.T, name string, notAfter time.Time) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              notAfter,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

func newRebindCert(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	name string,
	clientAuth bool,
	notBefore, notAfter time.Time,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	usage := x509.ExtKeyUsageServerAuth
	if clientAuth {
		usage = x509.ExtKeyUsageClientAuth
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     []string{name},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func rebindPool(certs ...*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool
}

func rebindClientOpts(version protocol.Version, store *rebindSessionStore, pool *x509.CertPool) []ClientOption {
	return []ClientOption{
		WithServerName("test.server"),
		WithRootCAs(pool),
		WithSessionStore(store),
		WithMinVersion(version),
		WithMaxVersion(version),
	}
}

func rebindServerOpts(version protocol.Version, store *rebindSessionStore, cert tls.Certificate) []ServerOption {
	return []ServerOption{
		WithCertificates(cert),
		WithSessionStore(store),
		WithMinVersion(version),
		WithMaxVersion(version),
	}
}

var errRebindTestRejected = errors.New("rejected by test policy")

// A resumed connection must re-bind to the peer certificate chain under the
// current RootCAs, name, and signature policy instead of reusing the chain
// cached in the session.
func TestResumeRebindsServerCertificate(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		name := "1.2"
		if version == protocol.Version1_3 {
			name = "1.3"
		}
		t.Run(name, func(t *testing.T) {
			notAfter := time.Now().Add(time.Hour)
			ca1, ca1Key := newRebindCA(t, "ca1", notAfter)
			ca2, ca2Key := newRebindCA(t, "ca2", notAfter)
			serverCert1 := newRebindCert(t, ca1, ca1Key, "test.server", false, time.Now().Add(-time.Hour), notAfter)
			serverCert2 := newRebindCert(t, ca2, ca2Key, "test.server", false, time.Now().Add(-time.Hour), notAfter)

			awaitTicket := func(store *rebindSessionStore) {
				t.Helper()
				if version != protocol.Version1_3 {
					return
				}
				deadline := time.Now().Add(5 * time.Second)
				for time.Now().Before(deadline) {
					if _, ok := store.snapshot(); ok {
						return
					}
					time.Sleep(10 * time.Millisecond)
				}
				t.Fatal("server did not issue a session ticket")
			}

			t.Run("valid session resumes", func(t *testing.T) {
				clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
				client, server := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				awaitTicket(clientStore)
				_ = client.conn.Close()
				_ = server.conn.Close()

				client2, server2 := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client2.handshakeError)
				require.NoError(t, server2.handshakeError)
				assert.Positive(t, serverStore.getCount(), "client should offer the stored session")
				state, ok := client2.conn.ConnectionState()
				require.True(t, ok)
				require.NotEmpty(t, state.PeerCertificates)
				assert.Equal(t, serverCert1.Certificate[0], state.PeerCertificates[0])
			})

			t.Run("CA rotation falls back to full handshake", func(t *testing.T) {
				clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
				client, server := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				awaitTicket(clientStore)
				_ = client.conn.Close()
				_ = server.conn.Close()

				// The server rotated to a certificate from a new CA and the
				// client now trusts only that CA.
				client2, server2 := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca2)),
					rebindServerOpts(version, serverStore, serverCert2))
				require.NoError(t, client2.handshakeError)
				require.NoError(t, server2.handshakeError)
				state, ok := client2.conn.ConnectionState()
				require.True(t, ok)
				require.NotEmpty(t, state.PeerCertificates)
				assert.Equal(t, serverCert2.Certificate[0], state.PeerCertificates[0],
					"resumed connection must bind the chain valid under current policy")
			})

			t.Run("untrusted chain is not resumed", func(t *testing.T) {
				clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
				client, server := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				awaitTicket(clientStore)
				_ = client.conn.Close()
				_ = server.conn.Close()

				// The client no longer trusts the CA that issued the cached chain.
				client2, _ := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca2)),
					rebindServerOpts(version, serverStore, serverCert1))
				assert.Error(t, client2.handshakeError,
					"resumption must not resurrect a chain the current policy rejects")
			})

			t.Run("expired chain is not resumed", func(t *testing.T) {
				clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
				client, server := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				awaitTicket(clientStore)
				_ = client.conn.Close()
				_ = server.conn.Close()

				// The cached chain has since expired; the server still presents
				// a valid one, so a full handshake must replace the session.
				expired := newRebindCert(t, ca1, ca1Key, "test.server", false,
					time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour))
				session, ok := clientStore.snapshot()
				require.True(t, ok)
				session.PeerCertificates = expired.Certificate
				if session.Ticket != nil {
					session.Ticket.PeerCertificates = expired.Certificate
				}
				clientStore.replace(session)

				client2, server2 := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client2.handshakeError)
				require.NoError(t, server2.handshakeError)
				state, ok := client2.conn.ConnectionState()
				require.True(t, ok)
				require.NotEmpty(t, state.PeerCertificates)
				assert.Equal(t, serverCert1.Certificate[0], state.PeerCertificates[0],
					"an expired cached chain must not be bound to the resumed connection")
			})

			t.Run("verify callbacks run on resumption", func(t *testing.T) {
				clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
				client, server := handshakePair(t,
					rebindClientOpts(version, clientStore, rebindPool(ca1)),
					rebindServerOpts(version, serverStore, serverCert1))
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				awaitTicket(clientStore)
				_ = client.conn.Close()
				_ = server.conn.Close()

				peerCalled := false
				opts := append(rebindClientOpts(version, clientStore, rebindPool(ca1)),
					WithVerifyPeerCertificate(func(_ [][]byte, _ [][]*x509.Certificate) error {
						peerCalled = true

						return errRebindTestRejected
					}))
				client2, _ := handshakePair(t, opts, rebindServerOpts(version, serverStore, serverCert1))
				assert.Error(t, client2.handshakeError)
				assert.True(t, peerCalled, "VerifyPeerCertificate must run for a resumed connection")
			})
		})
	}
}

// A server that requires client certificates must not resume a session when
// the current ClientCAs or signature policy changed; the client certificate
// must be re-selected and re-verified under current policy.
func TestResumeRebindsClientCertificate(t *testing.T) {
	notAfter := time.Now().Add(time.Hour)
	ca1, ca1Key := newRebindCA(t, "client-ca1", notAfter)
	ca2, ca2Key := newRebindCA(t, "client-ca2", notAfter)
	clientCert1 := newRebindCert(t, ca1, ca1Key, "client.one", true, time.Now().Add(-time.Hour), notAfter)
	clientCert2 := newRebindCert(t, ca2, ca2Key, "client.two", true, time.Now().Add(-time.Hour), notAfter)
	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	serverOpts := func(store *rebindSessionStore, pool *x509.CertPool) []ServerOption {
		return []ServerOption{
			WithCertificates(serverCert),
			WithClientAuth(RequireAndVerifyClientCert),
			WithClientCAs(pool),
			WithSessionStore(store),
			WithMinVersion(protocol.Version1_2),
			WithMaxVersion(protocol.Version1_2),
		}
	}
	clientOpts := func(store *rebindSessionStore, cert tls.Certificate) []ClientOption {
		return []ClientOption{
			WithCertificates(cert),
			WithInsecureSkipVerify(true),
			WithSessionStore(store),
			WithMinVersion(protocol.Version1_2),
			WithMaxVersion(protocol.Version1_2),
		}
	}

	t.Run("client CA rotation re-selects certificate", func(t *testing.T) {
		clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
		client, server := handshakePair(t, clientOpts(clientStore, clientCert1), serverOpts(serverStore, rebindPool(ca1)))
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
		_ = client.conn.Close()
		_ = server.conn.Close()

		client2, server2 := handshakePair(t, clientOpts(clientStore, clientCert2), serverOpts(serverStore, rebindPool(ca2)))
		require.NoError(t, client2.handshakeError)
		require.NoError(t, server2.handshakeError)
		state, ok := server2.conn.ConnectionState()
		require.True(t, ok)
		require.NotEmpty(t, state.PeerCertificates)
		assert.Equal(t, clientCert2.Certificate[0], state.PeerCertificates[0],
			"the server must bind the client certificate selected under current policy")
	})

	t.Run("untrusted client chain is not resumed", func(t *testing.T) {
		clientStore, serverStore := &rebindSessionStore{}, &rebindSessionStore{}
		client, server := handshakePair(t, clientOpts(clientStore, clientCert1), serverOpts(serverStore, rebindPool(ca1)))
		require.NoError(t, client.handshakeError)
		require.NoError(t, server.handshakeError)
		_ = client.conn.Close()
		_ = server.conn.Close()

		// The server no longer trusts the CA that issued the client certificate.
		client2, _ := handshakePair(t, clientOpts(clientStore, clientCert1), serverOpts(serverStore, rebindPool(ca2)))
		assert.Error(t, client2.handshakeError,
			"resumption must not bypass current client certificate policy")
	})
}

// A connection resumed from exported state must re-bind to the peer
// certificate chain under the current RootCAs, ClientCAs, name, and signature
// policy, and must run the explicit verification callbacks.
func TestResumeExportedStateRebindsPolicy(t *testing.T) {
	for _, version := range []protocol.Version{protocol.Version1_2, protocol.Version1_3} {
		name := "1.2"
		if version == protocol.Version1_3 {
			name = "1.3"
		}
		t.Run(name, func(t *testing.T) {
			notAfter := time.Now().Add(time.Hour)
			ca1, ca1Key := newRebindCA(t, "ca1", notAfter)
			ca2, _ := newRebindCA(t, "ca2", notAfter)
			serverCert1 := newRebindCert(t, ca1, ca1Key, "test.server", false, time.Now().Add(-time.Hour), notAfter)

			export := func(t *testing.T, clientOpts []ClientOption, serverOpts []ServerOption) (*State, *State) {
				t.Helper()
				client, server := handshakePair(t, clientOpts, serverOpts)
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				clientState, err := client.conn.ExportState()
				require.NoError(t, err)
				serverState, err := server.conn.ExportState()
				require.NoError(t, err)
				_ = client.conn.Close()
				_ = server.conn.Close()

				return &clientState, &serverState
			}
			resumePair := func(t *testing.T, clientState, serverState *State, clientOpts, serverOpts []Option) (*Conn, *Conn, error, error) {
				t.Helper()
				ca, cb := packetPipe()
				t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
				resumedClient, clientErr := Resume(clientState, ca, ca.RemoteAddr(), clientOpts...)
				resumedServer, serverErr := Resume(serverState, cb, cb.RemoteAddr(), serverOpts...)
				if clientErr == nil {
					t.Cleanup(func() { _ = resumedClient.Close() })
				}
				if serverErr == nil {
					t.Cleanup(func() { _ = resumedServer.Close() })
				}

				return resumedClient, resumedServer, clientErr, serverErr
			}
			clientOpts := func(pool *x509.CertPool) []ClientOption {
				return []ClientOption{
					WithServerName("test.server"), WithRootCAs(pool),
					WithMinVersion(version), WithMaxVersion(version),
				}
			}
			serverOpts := func() []ServerOption {
				return []ServerOption{
					WithCertificates(serverCert1),
					WithMinVersion(version), WithMaxVersion(version),
				}
			}
			resumeClientOpts := func(pool *x509.CertPool) []Option {
				return []Option{
					WithServerName("test.server"), WithRootCAs(pool),
					WithMinVersion(version), WithMaxVersion(version),
				}
			}
			resumeServerOpts := func() []Option {
				return []Option{
					WithCertificates(serverCert1),
					WithMinVersion(version), WithMaxVersion(version),
				}
			}

			t.Run("valid state resumes", func(t *testing.T) {
				clientState, serverState := export(t, clientOpts(rebindPool(ca1)), serverOpts())
				resumedClient, resumedServer, clientErr, serverErr := resumePair(t,
					clientState, serverState, resumeClientOpts(rebindPool(ca1)), resumeServerOpts())
				require.NoError(t, clientErr)
				require.NoError(t, serverErr)
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				require.NoError(t, resumedClient.HandshakeContext(ctx))
				require.NoError(t, resumedServer.HandshakeContext(ctx))
				exchangeResumeData(t, resumedClient, resumedServer)
			})

			t.Run("untrusted chain is not resumed", func(t *testing.T) {
				clientState, serverState := export(t, clientOpts(rebindPool(ca1)), serverOpts())
				// The client no longer trusts the CA that issued the peer chain.
				_, _, clientErr, _ := resumePair(t,
					clientState, serverState, resumeClientOpts(rebindPool(ca2)), resumeServerOpts())
				assert.Error(t, clientErr,
					"Resume must not restore a chain the current policy rejects")
			})

			t.Run("expired chain is not resumed", func(t *testing.T) {
				short := time.Now().Add(2 * time.Second)
				shortCA, shortCAKey := newRebindCA(t, "short-ca", short)
				shortCert := newRebindCert(t, shortCA, shortCAKey, "test.server", false, time.Now().Add(-time.Hour), short)
				client, server := handshakePair(t,
					[]ClientOption{
						WithServerName("test.server"), WithRootCAs(rebindPool(shortCA)),
						WithMinVersion(version), WithMaxVersion(version),
					},
					[]ServerOption{
						WithCertificates(shortCert),
						WithMinVersion(version), WithMaxVersion(version),
					})
				require.NoError(t, client.handshakeError)
				require.NoError(t, server.handshakeError)
				clientState, err := client.conn.ExportState()
				require.NoError(t, err)
				_ = client.conn.Close()
				_ = server.conn.Close()

				time.Sleep(time.Until(short.Add(time.Second)))
				ca, cb := packetPipe()
				t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
				_, err = Resume(&clientState, ca, ca.RemoteAddr(),
					WithServerName("test.server"), WithRootCAs(rebindPool(shortCA)),
					WithMinVersion(version), WithMaxVersion(version))
				assert.Error(t, err, "Resume must not restore an expired peer chain")
			})

			t.Run("verify callbacks run on resume", func(t *testing.T) {
				clientState, serverState := export(t, clientOpts(rebindPool(ca1)), serverOpts())
				peerCalled := false
				_, _, clientErr, _ := resumePair(t,
					clientState, serverState,
					append(resumeClientOpts(rebindPool(ca1)),
						WithVerifyPeerCertificate(func(_ [][]byte, _ [][]*x509.Certificate) error {
							peerCalled = true

							return errRebindTestRejected
						})),
					resumeServerOpts())
				assert.Error(t, clientErr)
				assert.True(t, peerCalled, "VerifyPeerCertificate must run for a resumed connection")
			})

			t.Run("verify connection runs on resume", func(t *testing.T) {
				clientState, serverState := export(t, clientOpts(rebindPool(ca1)), serverOpts())
				connCalled := false
				_, _, clientErr, _ := resumePair(t,
					clientState, serverState,
					append(resumeClientOpts(rebindPool(ca1)),
						WithVerifyConnection(func(_ *State) error {
							connCalled = true

							return errRebindTestRejected
						})),
					resumeServerOpts())
				assert.Error(t, clientErr)
				assert.True(t, connCalled, "VerifyConnection must run for a resumed connection")
			})
		})
	}
}

// A server resuming exported state must re-verify the client certificate
// chain against the current ClientCAs.
func TestResumeExportedStateRebindsClientCertificate(t *testing.T) {
	notAfter := time.Now().Add(time.Hour)
	ca1, ca1Key := newRebindCA(t, "client-ca1", notAfter)
	ca2, _ := newRebindCA(t, "client-ca2", notAfter)
	clientCert1 := newRebindCert(t, ca1, ca1Key, "client.one", true, time.Now().Add(-time.Hour), notAfter)
	serverCert, err := selfsign.GenerateSelfSigned()
	require.NoError(t, err)

	client, server := handshakePair(t,
		[]ClientOption{
			WithCertificates(clientCert1), WithInsecureSkipVerify(true),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
		},
		[]ServerOption{
			WithCertificates(serverCert),
			WithClientAuth(RequireAndVerifyClientCert), WithClientCAs(rebindPool(ca1)),
			WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2),
		})
	require.NoError(t, client.handshakeError)
	require.NoError(t, server.handshakeError)
	serverState, err := server.conn.ExportState()
	require.NoError(t, err)
	_ = client.conn.Close()
	_ = server.conn.Close()

	// The server no longer trusts the CA that issued the client certificate.
	ca, cb := packetPipe()
	t.Cleanup(func() { _ = ca.Close(); _ = cb.Close() })
	_, err = Resume(&serverState, cb, cb.RemoteAddr(),
		WithCertificates(serverCert),
		WithClientAuth(RequireAndVerifyClientCert), WithClientCAs(rebindPool(ca2)),
		WithMinVersion(protocol.Version1_2), WithMaxVersion(protocol.Version1_2))
	assert.Error(t, err, "Resume must not restore a client chain the current policy rejects")
}
