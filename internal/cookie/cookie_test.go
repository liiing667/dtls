// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package cookie

import (
	"bytes"
	"crypto/sha256"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	primaryKey   = bytes.Repeat([]byte{0x42}, minKeyLength)
	secondaryKey = bytes.Repeat([]byte{0x07}, minKeyLength)
	digest       = bytes.Repeat([]byte{0xab}, sha256.Size)
)

func newTestGenerator(t *testing.T, now time.Time, keys ...[]byte) *Generator {
	t.Helper()
	clock := now
	generator, err := NewGenerator(keys, WithClock(func() time.Time { return clock }), WithTTL(time.Minute))
	require.NoError(t, err)

	return generator
}

func TestNewGeneratorRejectsKeyMaterial(t *testing.T) {
	_, err := NewGenerator(nil)
	assert.ErrorIs(t, err, ErrNoKeys)

	_, err = NewGenerator([][]byte{make([]byte, minKeyLength-1)})
	assert.ErrorIs(t, err, ErrInvalidKey)

	_, err = NewGenerator([][]byte{make([]byte, maxKeyLength+1)})
	assert.ErrorIs(t, err, ErrInvalidKey)

	tooMany := make([][]byte, maxKeys+1)
	for index := range tooMany {
		tooMany[index] = make([]byte, minKeyLength)
	}
	_, err = NewGenerator(tooMany)
	assert.ErrorIs(t, err, ErrInvalidKey)
}

func TestGenerateValidateRoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, now, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}

	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)
	assert.Len(t, value, Length)
	assert.Equal(t, version, value[0])
	assert.Zero(t, value[1])
	require.NoError(t, generator.Validate(addr, digest, value))
}

func TestValidateRejectsAddressMismatch(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, now, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)

	otherPort := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5001}
	assert.ErrorIs(t, generator.Validate(otherPort, digest, value), ErrInvalid)

	otherIP := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 5000}
	assert.ErrorIs(t, generator.Validate(otherIP, digest, value), ErrInvalid)

	assert.ErrorIs(t, generator.Validate(nil, digest, value), ErrInvalid)
}

func TestValidateRejectsDigestMismatch(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, now, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)

	otherDigest := bytes.Repeat([]byte{0xcd}, sha256.Size)
	assert.ErrorIs(t, generator.Validate(addr, otherDigest, value), ErrInvalid)
}

func TestValidateRejectsExpiredCookie(t *testing.T) {
	issuedAt := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, issuedAt, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)

	later := issuedAt.Add(time.Minute)
	expired := later
	expiredGenerator, err := NewGenerator([][]byte{primaryKey}, WithClock(func() time.Time { return expired }), WithTTL(time.Minute))
	require.NoError(t, err)
	assert.ErrorIs(t, expiredGenerator.Validate(addr, digest, value), ErrExpired)

	// One millisecond before expiry remains valid.
	withinWindow := issuedAt.Add(time.Minute - time.Millisecond)
	validGenerator, err := NewGenerator([][]byte{primaryKey}, WithClock(func() time.Time { return withinWindow }), WithTTL(time.Minute))
	require.NoError(t, err)
	assert.NoError(t, validGenerator.Validate(addr, digest, value))
}

func TestValidateRejectsMalformedCookie(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, now, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}

	assert.ErrorIs(t, generator.Validate(addr, digest, nil), ErrInvalid)
	assert.ErrorIs(t, generator.Validate(addr, digest, make([]byte, Length-1)), ErrInvalid)

	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)
	unknownKeyID := bytes.Clone(value)
	unknownKeyID[1] = 7
	assert.ErrorIs(t, generator.Validate(addr, digest, unknownKeyID), ErrInvalid)

	wrongVersion := bytes.Clone(value)
	wrongVersion[0] = version + 1
	assert.ErrorIs(t, generator.Validate(addr, digest, wrongVersion), ErrInvalid)

	tamperedTag := bytes.Clone(value)
	tamperedTag[Length-1] ^= 0xff
	assert.ErrorIs(t, generator.Validate(addr, digest, tamperedTag), ErrInvalid)
}

func TestKeyRotationAcceptsOldAndNewCookies(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := now

	// During rotation the new key is active while the old key remains
	// installed for verification of in-flight handshakes.
	rotated, err := NewGenerator([][]byte{secondaryKey, primaryKey}, WithClock(func() time.Time { return clock }), WithTTL(time.Minute))
	require.NoError(t, err)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}

	// A cookie issued before rotation carries the old key identifier.
	oldCookie := buildCookieWithKey(t, rotated, 1, addr, digest, clock.Add(time.Minute).UnixMilli())

	newCookie, err := rotated.Generate(addr, digest)
	require.NoError(t, err)
	assert.Zero(t, newCookie[1], "new cookies use the active (first) key")
	assert.Equal(t, byte(1), oldCookie[1], "old cookies keep their original key identifier")

	require.NoError(t, rotated.Validate(addr, digest, newCookie))
	require.NoError(t, rotated.Validate(addr, digest, oldCookie))

	// After retiring the old key, old cookies stop validating while new ones
	// continue to work.
	retired, err := NewGenerator([][]byte{secondaryKey}, WithClock(func() time.Time { return clock }), WithTTL(time.Minute))
	require.NoError(t, err)
	assert.ErrorIs(t, retired.Validate(addr, digest, oldCookie), ErrInvalid)
	assert.NoError(t, retired.Validate(addr, digest, newCookie))
}

func TestGenerateIsDeterministicWithFixedClock(t *testing.T) {
	now := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	generator := newTestGenerator(t, now, primaryKey)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}

	first, err := generator.Generate(addr, digest)
	require.NoError(t, err)
	second, err := generator.Generate(addr, digest)
	require.NoError(t, err)
	assert.True(t, bytes.Equal(first, second))
}

func TestNewRandomKeyProducesUsableMaterial(t *testing.T) {
	key, err := NewRandomKey()
	require.NoError(t, err)
	assert.Len(t, key, minKeyLength)

	generator, err := NewGenerator([][]byte{key})
	require.NoError(t, err)
	addr := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 5000}
	value, err := generator.Generate(addr, digest)
	require.NoError(t, err)
	assert.NoError(t, generator.Validate(addr, digest, value))
}

func buildCookieWithKey(t *testing.T, generator *Generator, keyID int, addr net.Addr, clientHelloDigest []byte, expiryMillis int64) []byte {
	t.Helper()
	require.Less(t, keyID, len(generator.keys))

	return generator.build(keyID, expiryMillis, addr, clientHelloDigest)
}
