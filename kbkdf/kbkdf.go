// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package kbkdf implements the Key-Based Key Derivation Function (HKDF) as
// defined in NIST SP800-108.
//
// SP800-108 specifies that the fixed input data fields may be omitted unless
// required for certain purposes. This implementation does not omit any of the
// fields and orders them as specified in SP800-108.
package kbkdf // import "golang.org/x/crypto/kbkdf"

import (
	"encoding/binary"
	"hash"
	"math"
)

// Counter generates keyLen bytes of key material using the given PRF (i.e.,
// HMAC or CMAC) with the counter-mode KBKDF.
func Counter(prf func() hash.Hash, keyLen int, label, context []byte) []byte {
	if keyLen < 0 {
		panic("kbkdf: negative amount of key data requested")
	}
	if keyLen > (math.MaxUint32 / 8) {
		panic("kbkdf: 2^32 or more bits of key data requested")
	}
	result := make([]byte, 0, keyLen)
	hashLen := prf().Size()
	iterations := (keyLen + hashLen - 1) / hashLen
	for ctr := uint32(1); ctr <= uint32(iterations); ctr++ {
		ki := prf()
		binary.Write(ki, binary.BigEndian, ctr)
		ki.Write(label)
		ki.Write([]byte{0x00})
		ki.Write(context)
		binary.Write(ki, binary.BigEndian, uint32(keyLen*8))
		result = ki.Sum(result)
	}
	return result[:keyLen]
}
