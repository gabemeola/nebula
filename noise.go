package nebula

import (
	"crypto/cipher"
	"encoding/binary"
	"unsafe"

	"github.com/flynn/noise"
)

var noiseEndianness binary.ByteOrder = binary.BigEndian

type NebulaCipherState struct {
	c cipher.AEAD
	//k [32]byte
	//n uint64
}

func NewNebulaCipherState(s *noise.CipherState) NebulaCipherState {
	return NebulaCipherState{c: s.Cipher().(cipher.AEAD)}

}

// EncryptDanger encrypts and authenticates a given payload.
//
// out is a destination slice to hold the output of the EncryptDanger operation.
//   - ad is additional data, which will be authenticated and appended to out, but not encrypted.
//   - plaintext is encrypted, authenticated and appended to out.
//   - n is a nonce value which must never be re-used with this key.
//   - nb is a buffer used for temporary storage in the implementation of this call, which should
//     be re-used by callers to minimize garbage collection.
func (s NebulaCipherState) EncryptDanger(out, ad, plaintext []byte, n uint64, nb []byte) ([]byte, error) {
	// perf: early bounds check
	_ = nb[11:]

	// TODO: Is this okay now that we have made messageCounter atomic?
	// Alternative may be to split the counter space into ranges
	//if n <= s.n {
	//	return nil, errors.New("CRITICAL: a duplicate counter value was used")
	//}
	//s.n = n

	// Zero out first 4 bytes in one operation
	*(*uint32)(unsafe.Pointer(&nb[0])) = 0
	noiseEndianness.PutUint64(nb[4:], n)

	//l.Debugf("Encryption: outlen: %d, nonce: %d, ad: %s, plainlen %d", len(out), n, ad, len(plaintext))
	return s.c.Seal(out, nb, plaintext, ad), nil
}

func (s NebulaCipherState) DecryptDanger(out, ad, ciphertext []byte, n uint64, nb []byte) ([]byte, error) {
	// perf: early bounds check
	_ = nb[11:]

	// Zero out first 4 bytes in one operation
	*(*uint32)(unsafe.Pointer(&nb[0])) = 0
	noiseEndianness.PutUint64(nb[4:], n)

	// TODO: This interface casting can't be performant in the hot path
	return s.c.Open(out, nb, ciphertext, ad)
}

func (s NebulaCipherState) Overhead() int {
	return s.c.Overhead()
}
