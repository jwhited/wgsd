package wgsd

import (
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type encoder interface {
	EncodeToString([]byte) string
}

func getEncoder(e string) (encoder, error) {
	parts := strings.Split(e, ":")
	if len(parts) > 2 {
		return nil, errors.New("failed to parse encoder")
	}
	name := parts[0]
	if len(parts) == 1 {
		return buildEncoder(name, 0)
	}
	trunc, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, err
	}
	if trunc < 0 {
		return nil, errors.New("truncation value is < 0")
	}
	return buildEncoder(name, trunc)
}

func buildEncoder(name string, trunc int) (encoder, error) {
	switch name {
	case "b32":
		if trunc != 0 {
			return nil, fmt.Errorf("%s doesn't support truncation", name)
		}
		return base32.StdEncoding, nil
	case "sha1":
		return &shaOne{trunc: trunc}, nil
	case "hex":
		return &hexa{trunc: trunc}, nil
	default:
		return nil, errors.New("invalid encoder")
	}
}

type shaOne struct {
	trunc int
}

func (e *shaOne) EncodeToString(b []byte) string {
	h := sha1.New()
	_, _ = h.Write(b)
	sum := h.Sum(nil)
	r := hex.EncodeToString(sum)
	if e.trunc == 0 || len(r) < e.trunc {
		return r
	}
	return r[:e.trunc]
}

type hexa struct {
	trunc int
}

func (e *hexa) EncodeToString(b []byte) string {
	r := hex.EncodeToString(b)
	if e.trunc == 0 || len(r) < e.trunc {
		return r
	}
	return r[:e.trunc]
}
