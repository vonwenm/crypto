package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"hash/fnv"
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

type Signer func([]byte) ([]byte, error)
type Verifier func(v, mac []byte) bool

func HMAC_Signer(h func() hash.Hash, secret []byte) Signer {
	return func(v []byte) (r []byte, err error) {
		f := hmac.New(h, secret)
		if _, err = f.Write(v); err != nil {
			return
		}
		r = f.Sum(nil)
		f.Reset()
		return
	}
}

func HMAC_Verifier(h func() hash.Hash, secret []byte) Verifier {
	return func(v, mac []byte) bool {
		f := hmac.New(h, secret)
		if _, err := f.Write(v); err != nil {
			return false
		}
		r := f.Sum(nil)
		f.Reset()
		return hmac.Equal(r, mac)
	}
}

func CrcHash32(v []byte) int32 {
	return int32(crc32.Checksum(v, crc32.MakeTable(crc32.Castagnoli)))
}

func CrcHash64(v []byte) int64 {
	return int64(crc64.Checksum(v, crc64.MakeTable(crc64.ISO)))
}

func New32a(v []byte) int32 {
	h := fnv.New32a()
	h.Write([]byte(v))
	return int32(h.Sum32())
}

func New64a(v []byte) int64 {
	h := fnv.New64a()
	h.Write(v)
	return int64(h.Sum64())
}

func MakePasswordHash(username, password string) string {
	u := []byte(username)
	p := []byte(password)
	h := hmac.New(sha256.New, p) // Use the password as the secret
	h.Write(u)                   // Hash the username with the password
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func CheckPasswordHash(password_hash, snonce, cnonce, server_hash string) bool {
	s := []byte(server_hash)
	n := []byte(snonce + cnonce)
	h := hmac.New(sha256.New, n) // Use the nonce combo as the secret
	h.Write(s)                   // Hash the server's stored password hash
	t := base64.StdEncoding.EncodeToString(h.Sum(nil))
	r := t == password_hash
	return r
}
