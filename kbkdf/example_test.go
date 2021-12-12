// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package kbkdf_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"hash"

	"golang.org/x/crypto/kbkdf"
)

// Usage example that expands one primary secret into three other
// cryptographically secure keys.
func Example_usage() {
	// Underlying hash function for HMAC.
	h := sha256.New

	// Cryptographically secure primary secret.
	secret := []byte{0x00, 0x01, 0x02, 0x03} // i.e. NOT this.

	// Keyed pseudorandom function for the KDF, in this case HMAC.
	hmac := func() hash.Hash { return hmac.New(h, secret) }

	// Non-secret context info, optional (can be nil).
	context := []byte("kbkdf example")

	// Generate three 128-bit derived keys.
	for i := 0; i < 3; i++ {
		// Non-secret label, optional (can be nil).
		// Recommended: hash-length random value.
		label := make([]byte, h().Size())
		if _, err := rand.Read(label); err != nil {
			panic(err)
		}
		key := kbkdf.Counter(hmac, 16, label, context)
		fmt.Printf("Key #%d: %v\n", i+1, !bytes.Equal(key, make([]byte, 16)))
	}

	// Output:
	// Key #1: true
	// Key #2: true
	// Key #3: true
}
