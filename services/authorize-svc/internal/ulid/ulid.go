// Package ulid generates ULIDs (Universally Unique Lexicographically Sortable
// Identifiers) for decision ids.
//
// A ULID is a 128-bit value — a 48-bit big-endian millisecond timestamp followed
// by 80 bits of entropy — rendered as 26 Crockford base32 characters. The textual
// form is lexicographically sortable by creation time, which is exactly what the
// audit read path wants (TRD §12). The character set excludes I, L, O, and U, so
// the output matches the frozen contract's ULID pattern
// (^[0-9A-HJKMNP-TV-Z]{26}$ — see contracts/schemas/common.schema.json).
package ulid

import (
	"crypto/rand"
	"time"
)

// crockford is the Crockford base32 alphabet (no I, L, O, U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// New returns a new ULID string using the current wall clock for the timestamp
// component and crypto/rand for the entropy component.
//
// Note: this uses the wall clock intentionally and only for id generation — it is
// NOT a policy predicate input. Determinism of the *decision* comes from the
// orchestrator-injected evaluated_at/counter_snapshot, never from here.
func New() string {
	var b [16]byte

	ms := uint64(time.Now().UTC().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)

	// 80 bits of entropy. rand.Read never returns an error with the crypto reader.
	_, _ = rand.Read(b[6:])

	return encode(b)
}

// encode renders 16 bytes as 26 Crockford base32 characters (the canonical ULID
// bit layout: 5 bits per character, high bits first, top 2 bits of the first
// character are always zero).
func encode(b [16]byte) string {
	d := make([]byte, 26)
	d[0] = crockford[(b[0]&224)>>5]
	d[1] = crockford[b[0]&31]
	d[2] = crockford[(b[1]&248)>>3]
	d[3] = crockford[((b[1]&7)<<2)|((b[2]&192)>>6)]
	d[4] = crockford[(b[2]&62)>>1]
	d[5] = crockford[((b[2]&1)<<4)|((b[3]&240)>>4)]
	d[6] = crockford[((b[3]&15)<<1)|((b[4]&128)>>7)]
	d[7] = crockford[(b[4]&124)>>2]
	d[8] = crockford[((b[4]&3)<<3)|((b[5]&224)>>5)]
	d[9] = crockford[b[5]&31]
	d[10] = crockford[(b[6]&248)>>3]
	d[11] = crockford[((b[6]&7)<<2)|((b[7]&192)>>6)]
	d[12] = crockford[(b[7]&62)>>1]
	d[13] = crockford[((b[7]&1)<<4)|((b[8]&240)>>4)]
	d[14] = crockford[((b[8]&15)<<1)|((b[9]&128)>>7)]
	d[15] = crockford[(b[9]&124)>>2]
	d[16] = crockford[((b[9]&3)<<3)|((b[10]&224)>>5)]
	d[17] = crockford[b[10]&31]
	d[18] = crockford[(b[11]&248)>>3]
	d[19] = crockford[((b[11]&7)<<2)|((b[12]&192)>>6)]
	d[20] = crockford[(b[12]&62)>>1]
	d[21] = crockford[((b[12]&1)<<4)|((b[13]&240)>>4)]
	d[22] = crockford[((b[13]&15)<<1)|((b[14]&128)>>7)]
	d[23] = crockford[(b[14]&124)>>2]
	d[24] = crockford[((b[14]&3)<<3)|((b[15]&224)>>5)]
	d[25] = crockford[b[15]&31]
	return string(d)
}
