// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package state

import (
	"math"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckReplaySequenceOutOfOrderWindow(t *testing.T) {
	common := &Common{}

	commit, ok := common.CheckReplaySequence(1, 10, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())

	// An earlier record inside the window is still accepted, out of order.
	commit, ok = common.CheckReplaySequence(1, 7, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.False(t, commit(), "out-of-order records are not the latest")

	highest, seen := common.HighestRemoteSequenceNumber(1)
	assert.True(t, seen)
	assert.Equal(t, uint64(10), highest)
}

func TestCheckReplaySequenceDuplicate(t *testing.T) {
	common := &Common{}

	commit, ok := common.CheckReplaySequence(1, 5, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())

	_, ok = common.CheckReplaySequence(1, 5, 64, math.MaxUint64, true, true)
	assert.False(t, ok, "committed records must fail the replay check")

	// The check does not mutate the window: a record discarded before its
	// commit does not consume the sequence number.
	_, ok = common.CheckReplaySequence(1, 6, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	commit, ok = common.CheckReplaySequence(1, 6, 64, math.MaxUint64, true, true)
	require.True(t, ok, "an uncommitted check must not consume the sequence number")
	assert.True(t, commit())
}

func TestCheckReplaySequenceOldEpoch(t *testing.T) {
	common := &Common{}

	commit, ok := common.CheckReplaySequence(2, 0, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
	assert.Equal(t, uint64(2), common.HighestRemoteEpoch())

	// A gated record from an older epoch is still marked in its own window
	// but no longer counts as the latest.
	commit, ok = common.CheckReplaySequence(1, 0, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.False(t, commit())
	_, ok = common.CheckReplaySequence(1, 0, 64, math.MaxUint64, true, true)
	assert.False(t, ok, "the old epoch window must still consume the record")

	// Ungated epochs (DTLS 1.2 protected epochs) ignore the highest epoch.
	commit, ok = common.CheckReplaySequence(1, 1, 64, math.MaxUint64, true, false)
	require.True(t, ok)
	assert.True(t, commit())

	// The newest epoch is unaffected.
	commit, ok = common.CheckReplaySequence(2, 1, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
}

func TestCheckReplaySequenceExtremeSequenceNumbers(t *testing.T) {
	common := &Common{}

	// Sequence zero as the very first record is the latest.
	commit, ok := common.CheckReplaySequence(1, 0, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
	_, ok = common.CheckReplaySequence(1, 0, 64, math.MaxUint64, true, true)
	assert.False(t, ok)

	// Records beyond the epoch's sequence number limit are rejected.
	_, ok = common.CheckReplaySequence(2, 101, 64, 100, true, true)
	assert.False(t, ok)
	commit, ok = common.CheckReplaySequence(2, 100, 64, 100, true, true)
	require.True(t, ok)
	assert.True(t, commit())

	// The largest representable sequence number commits without wrapping.
	commit, ok = common.CheckReplaySequence(3, math.MaxUint64, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
	highest, seen := common.HighestRemoteSequenceNumber(3)
	assert.True(t, seen)
	assert.Equal(t, uint64(math.MaxUint64), highest)

	// Window edge: the record exactly windowSize behind the head is too old.
	commit, ok = common.CheckReplaySequence(4, 10, 4, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
	_, ok = common.CheckReplaySequence(4, 6, 4, math.MaxUint64, true, true)
	assert.False(t, ok)
	commit, ok = common.CheckReplaySequence(4, 7, 4, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.False(t, commit())
}

func TestCheckReplaySequenceCommitUpdatesIdentity(t *testing.T) {
	common := &Common{}

	// Without updateSequence the commit only touches the window.
	commit, ok := common.CheckReplaySequence(0, 3, 64, math.MaxUint64, false, true)
	require.True(t, ok)
	assert.True(t, commit())
	_, seen := common.HighestRemoteSequenceNumber(0)
	assert.False(t, seen)
	assert.Equal(t, uint64(0), common.HighestRemoteEpoch())

	// With updateSequence the commit closes record identity and window
	// state together.
	commit, ok = common.CheckReplaySequence(1, 9, 64, math.MaxUint64, true, true)
	require.True(t, ok)
	assert.True(t, commit())
	highest, seen := common.HighestRemoteSequenceNumber(1)
	assert.True(t, seen)
	assert.Equal(t, uint64(9), highest)
	assert.Equal(t, uint64(1), common.HighestRemoteEpoch())
	_, ok = common.CheckReplaySequence(1, 9, 64, math.MaxUint64, true, true)
	assert.False(t, ok)
}

func TestCheckReplaySequenceConcurrent(t *testing.T) {
	common := &Common{}
	const goroutines = 8
	const records = 64
	const window = goroutines * records

	var wg sync.WaitGroup
	for g := range goroutines {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range records {
				seq := uint64(g*records + i) //nolint:gosec // G115 test counters stay small.
				commit, ok := common.CheckReplaySequence(1, seq, window, math.MaxUint64, true, true)
				if assert.True(t, ok) {
					commit()
				}
			}
		}()
	}
	wg.Wait()

	for seq := range uint64(goroutines * records) {
		_, ok := common.CheckReplaySequence(1, seq, window, math.MaxUint64, true, true)
		assert.False(t, ok, "sequence %d must be consumed exactly once", seq)
	}
	highest, seen := common.HighestRemoteSequenceNumber(1)
	assert.True(t, seen)
	assert.Equal(t, uint64(goroutines*records-1), highest)
}

func TestPruneReplayState(t *testing.T) {
	common := &Common{}
	keys := &TrafficKeyState{}
	keys.Install(&TrafficGeneration{Epoch: 3}, &TrafficGeneration{Epoch: 3})

	for _, epoch := range []uint64{0, 2, 3} {
		commit, ok := common.CheckReplaySequence(epoch, 1, 64, math.MaxUint64, true, true)
		require.True(t, ok)
		commit()
	}
	common.LocalSequenceNumber = map[uint64]uint64{0: 1, 2: 1, 3: 1}

	common.PruneReplayState(keys)

	assert.Contains(t, common.ReplayDetector, uint64(0), "epoch zero carries the plaintext handshake")
	assert.NotContains(t, common.ReplayDetector, uint64(2))
	assert.Contains(t, common.ReplayDetector, uint64(3))
	assert.Contains(t, common.LocalSequenceNumber, uint64(0))
	assert.NotContains(t, common.LocalSequenceNumber, uint64(2))
	assert.Contains(t, common.LocalSequenceNumber, uint64(3))
	assert.NotContains(t, common.RemoteSequenceNumber, uint64(2))
	assert.Contains(t, common.RemoteSequenceNumber, uint64(3))
}
