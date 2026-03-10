package hash

import (
	"encoding/hex"
	"errors"
)

var ErrInvalidDigestLength = errors.New("invalid digest length")

type Digest [32]byte

type Hasher interface {
	Name() string
	HashLeaf(data []byte) (Digest, error)
	HashNode(left Digest, right Digest) (Digest, error)
}

func (d Digest) Bytes() []byte {
	buf := make([]byte, len(d))
	copy(buf, d[:])
	return buf
}

func (d Digest) String() string {
	return hex.EncodeToString(d[:])
}

func DigestFromBytes(data []byte) (Digest, error) {
	var digest Digest
	if len(data) != len(digest) {
		return Digest{}, ErrInvalidDigestLength
	}
	copy(digest[:], data)
	return digest, nil
}

func MustDigestFromBytes(data []byte) Digest {
	digest, err := DigestFromBytes(data)
	if err != nil {
		panic(err)
	}
	return digest
}

func DigestFromHex(encoded string) (Digest, error) {
	bytes, err := hex.DecodeString(encoded)
	if err != nil {
		return Digest{}, err
	}
	return DigestFromBytes(bytes)
}
