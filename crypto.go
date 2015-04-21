package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"hash"
	//"crypto/sha256"
	//"crypto/sha512"
)

const MaxUint64 = ^uint64(0)
const MinUint64 = uint64(0)

const PrimeStride = uint64(7) // Some prime uint64

const MaxInt64 = int64(MaxUint64 >> 1)

func RandomInt32() (ret int32) {
	b, _ := RandomBytes(4)
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.LittleEndian, &ret)
	return
}

func RandomInt64() (ret int64) {
	b, _ := RandomBytes(8)
	buf := bytes.NewBuffer(b)
	binary.Read(buf, binary.LittleEndian, &ret)
	return
}

func RandomBytes(c int) ([]byte, error) {
	b := make([]byte, c, c)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func RandomString(c int) (string, error) {
	if b, err := RandomBytes(c); err != nil {
		return "", err
	} else {
		return base64.URLEncoding.EncodeToString(b), nil
	}
}

type Encoder func([]byte) ([]byte, error)
type Checker func([]byte) error

func HMAC_Encoder(h func() hash.Hash, secret []byte) Encoder {
	return func(v []byte) (r []byte, err error) {
		mac := hmac.New(h, secret)
		_, err = mac.Write(v)
		if err != nil {
			return
		}
		copy(r, mac.Sum(nil))
		mac.Reset()
		return
	}
}
