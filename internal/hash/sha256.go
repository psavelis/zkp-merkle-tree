package hash

import "crypto/sha256"

type SHA256Hasher struct{}

func NewSHA256Hasher() SHA256Hasher {
	return SHA256Hasher{}
}

func (SHA256Hasher) Name() string {
	return "sha256"
}

func (SHA256Hasher) HashLeaf(data []byte) (Digest, error) {
	payload := make([]byte, 1+len(data))
	payload[0] = 0x00
	copy(payload[1:], data)
	sum := sha256.Sum256(payload)
	return Digest(sum), nil
}

func (SHA256Hasher) HashNode(left Digest, right Digest) (Digest, error) {
	payload := make([]byte, 1+len(left)+len(right))
	payload[0] = 0x01
	copy(payload[1:], left[:])
	copy(payload[1+len(left):], right[:])
	sum := sha256.Sum256(payload)
	return Digest(sum), nil
}
