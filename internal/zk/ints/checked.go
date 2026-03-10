package ints

import (
	"errors"
)

var ErrOverflow = errors.New("integer overflow")

func CheckedAdd(left int, right int) (int, error) {
	maxInt := int(^uint(0) >> 1)
	if right > 0 && left > maxInt-right {
		return 0, ErrOverflow
	}
	return left + right, nil
}
