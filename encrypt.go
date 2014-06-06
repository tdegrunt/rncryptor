package rncryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"hash"
)

func Encrypt(data, password []byte, v int) string {

	version := byte(3)
	options := byte(1)
	encryptionSalt, err := RandomBytes(8)
	hmacSalt, err := RandomBytes(8)
	iv, err := RandomBytes(16)
	cipherText := Pad(data)

	hmacKey := Key(password, hmacSalt, 10000, 32, sha1.New)
	cipherKey := Key(password, encryptionSalt, 10000, 32, sha1.New)

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		panic(err)
	}

	cbc := cipher.NewCBCEncrypter(block, iv)
	cbc.CryptBlocks(cipherText, cipherText)

	buf := bytes.NewBuffer([]byte{version, options})
	buf.Write(encryptionSalt)
	buf.Write(hmacSalt)
	buf.Write(iv)
	buf.Write(cipherText)

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(buf.Bytes())
	expectedMAC := mac.Sum(nil)

	buf.Write(expectedMAC)

	result := base64.StdEncoding.EncodeToString(buf.Bytes())

	return result
}

// Pad applies the PKCS #7 padding scheme on the buffer.
func Pad(in []byte) []byte {
	padding := 16 - (len(in) % 16)
	if padding == 0 {
		padding = 16
	}
	for i := 0; i < padding; i++ {
		in = append(in, byte(padding))
	}
	return in
}

func RandomBytes(length int) ([]byte, error) {
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	U := make([]byte, hashLen)
	for block := 1; block <= numBlocks; block++ {
		// N.B.: || means concatenation, ^ means XOR
		// for each block T_i = U_1 ^ U_2 ^ ... ^ U_iter
		// U_1 = PRF(password, salt || uint(i))
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(U, T)

		// U_n = PRF(password, U_(n-1))
		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = U[:0]
			U = prf.Sum(U)
			for x := range U {
				T[x] ^= U[x]
			}
		}
	}
	return dk[:keyLen]
}
