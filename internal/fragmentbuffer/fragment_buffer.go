// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package fragmentbuffer reassembles fragmented DTLS handshake messages.
package fragmentbuffer

import (
	"bytes"
	"math"
	"slices"

	dtlserrors "github.com/pion/dtls/v4/internal/errors"
	"github.com/pion/dtls/v4/pkg/protocol/handshake"
)

const (
	// 2 megabytes.
	fragmentBufferMaxSize  = 2000000
	fragmentBufferMaxCount = 1000
	// canonicalMessageLimit bounds retained reassembled messages independently
	// of how often each one is retransmitted.
	canonicalMessageLimit = 1000
)

type fragment struct {
	handshakeHeader handshake.Header
	data            []byte
}

type fragmentKey struct {
	messageSequence uint16
	fragmentOffset  uint32
}

type parsedFragment struct {
	header handshake.Header
	data   []byte
}

type fragments struct {
	fragmentByOffset map[uint32]*fragment
	offsets          []uint32
	fragmentsLength  uint32
	handshakeLength  uint32
	handshakeType    handshake.Type
	epoch            uint64
}

// canonicalMessage is the single verified, reassembled message accepted for
// a message sequence. Retransmissions must reproduce it byte for byte even
// when their fragmentation differs.
type canonicalMessage struct {
	epoch uint64
	typ   handshake.Type
	data  []byte
}

// FragmentBuffer stores and reassembles fragmented DTLS handshake messages.
type FragmentBuffer struct {
	// map of MessageSequenceNumbers that hold slices of fragments
	cache map[uint16]*fragments

	// canonical retains the reassembled message of every completed sequence.
	// It keeps retransmission validation independent of the reassembly cache,
	// which drops a sequence as soon as the message is popped.
	canonical map[uint16]canonicalMessage

	currentMessageSequenceNumber uint16
	sequenceExhausted            bool

	totalBufferSize    int
	totalFragmentCount int
}

// New creates an empty FragmentBuffer.
func New() *FragmentBuffer {
	return &FragmentBuffer{cache: map[uint16]*fragments{}, canonical: map[uint16]canonicalMessage{}}
}

// current total size of buffer.
func (f *FragmentBuffer) size() int {
	return f.totalBufferSize
}

// AdvanceTo discards fragments for message sequences before messageSequence.
func (f *FragmentBuffer) AdvanceTo(messageSequence uint16) {
	if f.sequenceExhausted || messageSequence <= f.currentMessageSequenceNumber {
		return
	}

	for cachedSequence, cachedFragments := range f.cache {
		if cachedSequence >= messageSequence {
			continue
		}
		f.totalBufferSize -= int(cachedFragments.fragmentsLength)
		f.totalFragmentCount -= len(cachedFragments.fragmentByOffset)
		delete(f.cache, cachedSequence)
	}
	for canonicalSequence := range f.canonical {
		if canonicalSequence < messageSequence {
			delete(f.canonical, canonicalSequence)
		}
	}

	f.currentMessageSequenceNumber = messageSequence
}

// PushResult identifies retransmitted messages among the received fragments.
type PushResult struct {
	IsRetransmit bool
	// IsRetransmitStart reports an old message's offset-zero fragment.
	IsRetransmitStart bool
}

// Push validates and adds handshake fragments from content to the buffer.
// content starts with a handshake header.
func (f *FragmentBuffer) Push(epoch uint64, content []byte) (PushResult, error) {
	parsed, err := parseFragments(content)
	if err != nil {
		return PushResult{}, err
	}
	if err = f.validateFragments(epoch, parsed); err != nil {
		return PushResult{}, err
	}

	result, newFragmentCount, newBufferSize := f.prospectiveResourceUsage(parsed)
	if f.size()+newBufferSize >= fragmentBufferMaxSize ||
		f.totalFragmentCount+newFragmentCount > fragmentBufferMaxCount {
		return PushResult{}, dtlserrors.ErrFragmentBufferOverflow
	}

	f.commitFragments(epoch, parsed)

	return result, nil
}

func parseFragments(content []byte) ([]parsedFragment, error) {
	parsed := make([]parsedFragment, 0)
	for remaining := content; len(remaining) != 0; {
		var header handshake.Header
		if err := header.Unmarshal(remaining); err != nil {
			return nil, err
		}

		end := handshake.HeaderLength + int(header.FragmentLength)
		if end > len(remaining) {
			return nil, dtlserrors.ErrBufferTooSmall
		}
		parsed = append(parsed, parsedFragment{
			header: header,
			data:   remaining[handshake.HeaderLength:end],
		})
		remaining = remaining[end:]
	}

	return parsed, nil
}

func (f *FragmentBuffer) validateFragments(epoch uint64, parsed []parsedFragment) error {
	slices.SortFunc(parsed, func(a, b parsedFragment) int {
		if a.header.MessageSequence != b.header.MessageSequence {
			return int(a.header.MessageSequence) - int(b.header.MessageSequence)
		}

		return int(a.header.FragmentOffset) - int(b.header.FragmentOffset)
	})
	for i, candidate := range parsed {
		if err := validateFragmentBounds(candidate.header); err != nil {
			return err
		}
		if err := f.validateCanonicalFragment(epoch, candidate); err != nil {
			return err
		}
		if err := f.validateCachedFragment(epoch, candidate); err != nil {
			return err
		}
		if i == 0 || parsed[i-1].header.MessageSequence != candidate.header.MessageSequence {
			continue
		}
		previous := parsed[i-1]
		if previous.header.Type != candidate.header.Type || previous.header.Length != candidate.header.Length {
			return dtlserrors.ErrInvalidPacket
		}
		if err := validateFragmentPair(previous.header, previous.data, candidate.header, candidate.data); err != nil {
			return err
		}
	}

	return nil
}

// validateCanonicalFragment enforces the single-message rule of RFC 6347
// Section 4.1.1.1: a retransmitted record must carry the same handshake
// message with the same message_seq, regardless of how it is fragmented.
// Legal retransmissions with new fragmentation boundaries are accepted; a
// changed message body or mismatched metadata is rejected.
func (f *FragmentBuffer) validateCanonicalFragment(epoch uint64, candidate parsedFragment) error {
	canonical, ok := f.canonical[candidate.header.MessageSequence]
	if !ok {
		return nil
	}
	if canonical.epoch != epoch || canonical.typ != candidate.header.Type ||
		candidate.header.Length != uint32(len(canonical.data)) {
		return dtlserrors.ErrInvalidPacket
	}
	end := candidate.header.FragmentOffset + candidate.header.FragmentLength
	if end > uint32(len(canonical.data)) ||
		!bytes.Equal(canonical.data[candidate.header.FragmentOffset:end], candidate.data) {
		return dtlserrors.ErrInvalidPacket
	}

	return nil
}

func (f *FragmentBuffer) validateCachedFragment(epoch uint64, candidate parsedFragment) error {
	header := candidate.header
	cached := f.cache[header.MessageSequence]
	if cached == nil {
		return nil
	}
	if cached.epoch != epoch || cached.handshakeType != header.Type || cached.handshakeLength != header.Length {
		return dtlserrors.ErrInvalidPacket
	}
	if existing := cached.fragmentByOffset[header.FragmentOffset]; existing != nil {
		return validateFragmentPair(existing.handshakeHeader, existing.data, header, candidate.data)
	}
	index, _ := slices.BinarySearch(cached.offsets, header.FragmentOffset)
	for _, offset := range cached.offsets[max(0, index-1):min(len(cached.offsets), index+1)] {
		existing := cached.fragmentByOffset[offset]
		if err := validateFragmentPair(existing.handshakeHeader, existing.data, header, candidate.data); err != nil {
			return err
		}
	}

	return nil
}

func validateFragmentBounds(header handshake.Header) error {
	if header.FragmentOffset > header.Length ||
		header.FragmentLength > header.Length-header.FragmentOffset {
		return dtlserrors.ErrInvalidPacket
	}

	return nil
}

func validateFragmentPair(existingHeader handshake.Header, existingData []byte, candidateHeader handshake.Header, candidateData []byte) error {
	if existingHeader.FragmentOffset == candidateHeader.FragmentOffset {
		if existingHeader != candidateHeader || !bytes.Equal(existingData, candidateData) {
			return dtlserrors.ErrInvalidPacket
		}

		return nil
	}

	existingEnd := existingHeader.FragmentOffset + existingHeader.FragmentLength
	candidateEnd := candidateHeader.FragmentOffset + candidateHeader.FragmentLength
	if existingHeader.FragmentOffset < candidateEnd && candidateHeader.FragmentOffset < existingEnd {
		return dtlserrors.ErrInvalidPacket
	}

	return nil
}

func (f *FragmentBuffer) prospectiveResourceUsage(parsed []parsedFragment) (result PushResult, newFragmentCount int, newBufferSize int) {
	newFragments := map[fragmentKey]struct{}{}
	for _, candidate := range parsed {
		header := candidate.header
		if f.sequenceExhausted || header.MessageSequence < f.currentMessageSequenceNumber || f.isCanonicalRetransmit(header.MessageSequence) {
			result.IsRetransmit = true
			result.IsRetransmitStart = result.IsRetransmitStart || header.FragmentOffset == 0

			continue
		}

		if messageFragments, ok := f.cache[header.MessageSequence]; ok {
			if _, ok = messageFragments.fragmentByOffset[header.FragmentOffset]; ok {
				continue
			}
		}

		key := fragmentKey{
			messageSequence: header.MessageSequence,
			fragmentOffset:  header.FragmentOffset,
		}
		if _, ok := newFragments[key]; !ok {
			newFragments[key] = struct{}{}
			newFragmentCount++
			newBufferSize += int(header.FragmentLength)
		}
	}

	return result, newFragmentCount, newBufferSize
}

func (f *FragmentBuffer) isCanonicalRetransmit(sequence uint16) bool {
	_, ok := f.canonical[sequence]

	return ok
}

func (f *FragmentBuffer) commitFragments(epoch uint64, parsed []parsedFragment) {
	added := map[uint16][]uint32{}
	for _, candidate := range parsed {
		header := candidate.header
		if f.sequenceExhausted || header.MessageSequence < f.currentMessageSequenceNumber || f.isCanonicalRetransmit(header.MessageSequence) {
			continue
		}

		messageFragments, ok := f.cache[header.MessageSequence]
		if !ok {
			messageFragments = &fragments{fragmentByOffset: map[uint32]*fragment{}, handshakeLength: header.Length, handshakeType: header.Type, epoch: epoch}
			f.cache[header.MessageSequence] = messageFragments
		}
		if _, ok = messageFragments.fragmentByOffset[header.FragmentOffset]; !ok {
			added[header.MessageSequence] = append(added[header.MessageSequence], header.FragmentOffset)
			messageFragments.fragmentByOffset[header.FragmentOffset] = &fragment{handshakeHeader: header, data: bytes.Clone(candidate.data)}
			messageFragments.fragmentsLength += header.FragmentLength
			f.totalBufferSize += int(header.FragmentLength)
			f.totalFragmentCount++
		}
	}
	for sequence, offsets := range added {
		message := f.cache[sequence]
		message.offsets = mergeOffsets(message.offsets, offsets)
	}
}

func mergeOffsets(existing, added []uint32) []uint32 {
	merged := slices.Grow(existing, len(added))[:len(existing)+len(added)]
	for i, j, k := len(existing)-1, len(added)-1, len(merged)-1; j >= 0; k-- {
		if i >= 0 && merged[i] > added[j] {
			merged[k] = merged[i]
			i--
		} else {
			merged[k] = added[j]
			j--
		}
	}

	return merged
}

// Pop returns the next complete handshake message and its record epoch.
func (f *FragmentBuffer) Pop() (content []byte, epoch uint64) {
	if f.sequenceExhausted {
		return nil, 0
	}

	frags, ok := f.cache[f.currentMessageSequenceNumber]
	if !ok {
		return nil, 0
	}

	if frags.fragmentsLength != frags.handshakeLength {
		return nil, 0
	}

	var rawMessage []byte
	targetOffset := uint32(0)
	for i := 0; i < len(frags.fragmentByOffset) && targetOffset < frags.handshakeLength; i++ {
		if frag, ok := frags.fragmentByOffset[targetOffset]; ok {
			rawMessage = append(rawMessage, frag.data...)
			targetOffset = frag.handshakeHeader.FragmentOffset + frag.handshakeHeader.FragmentLength
		} else {
			return nil, 0
		}
	}

	if int(frags.handshakeLength) != len(rawMessage) {
		return nil, 0
	}

	firstHeader := frags.fragmentByOffset[0].handshakeHeader
	firstHeader.FragmentOffset = 0
	firstHeader.FragmentLength = firstHeader.Length

	rawHeader, _ := firstHeader.Marshal()

	messageEpoch := frags.epoch

	f.totalBufferSize -= int(frags.fragmentsLength)
	f.totalFragmentCount -= len(frags.fragmentByOffset)

	sequence := f.currentMessageSequenceNumber
	delete(f.cache, sequence)
	// Deliver the final sequence once, then treat all further input as old.
	// Wrapping would let new content reuse an authenticated message sequence.
	if f.currentMessageSequenceNumber == math.MaxUint16 {
		f.sequenceExhausted = true
	} else {
		f.currentMessageSequenceNumber++
	}
	// Retain the canonical message so a retransmit is validated against the
	// exact bytes that entered the handshake transcript.
	if !f.sequenceExhausted {
		f.evictCanonical()
		f.canonical[sequence] = canonicalMessage{
			epoch: messageEpoch,
			typ:   firstHeader.Type,
			data:  bytes.Clone(rawMessage),
		}
	}

	return append(rawHeader, rawMessage...), messageEpoch
}

// evictCanonical keeps the canonical message table bounded. Sequences are
// produced in ascending order, so the smallest retained sequence is the one
// least likely to be retransmitted next.
func (f *FragmentBuffer) evictCanonical() {
	if len(f.canonical) < canonicalMessageLimit {
		return
	}
	var oldest uint16
	first := true
	for sequence := range f.canonical {
		if first || sequence < oldest {
			oldest = sequence
			first = false
		}
	}
	delete(f.canonical, oldest)
}
