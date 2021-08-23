package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
)

const (
	KeySize   = 32
	SaltSize  = 16
	NonceSize = 24

	Overhead = NonceSize + secretbox.Overhead
)

const (
	ScryptIters   = 1 << 20
	ScryptMemCost = 8
	ScryptCPUCost = 1
)

var (
	ErrCiphertextTooShort = errors.New("relay: ciphertext too short")
	ErrDecryptFailed      = errors.New("relay: decryption failed")
)

type encryptingReader struct {
	key       [KeySize]byte
	chunkSize int
	r         io.Reader
	chunk     []byte
	idx       int
}

func NewEncryptingReader(r io.Reader, chunkSize int, key [KeySize]byte) io.Reader {
	return &encryptingReader{
		key:       key,
		chunkSize: chunkSize,
		r:         r,
		idx:       0,
	}
}

func (er *encryptingReader) Read(b []byte) (n int, err error) {
	l := len(b)

	// generate the first encrypted chunk if necessary
	if er.chunk == nil {
		err = er.readNextChunk()
		if err != nil {
			return 0, err
		}
	}

	var copied int
	for n < l {
		copied = copy(b[n:], er.chunk[er.idx:])
		er.idx += copied
		n += copied

		if er.idx >= len(er.chunk) {
			if err = er.readNextChunk(); err != nil {
				return
			}
		}
	}
	return
}

func (er *encryptingReader) readNextChunk() error {
	data := make([]byte, er.chunkSize)
	n, err := er.r.Read(data)
	if n == 0 {
		return io.EOF
	}
	if err != nil && err != io.EOF {
		return err
	}

	ciphertext, err := EncryptChunk(er.key, data[:n])
	if err != nil {
		return err
	}

	er.chunk = ciphertext
	er.idx = 0
	return nil
}

type decryptingReader struct {
	key       [KeySize]byte
	chunkSize int
	r         io.Reader
	chunk     []byte
	idx       int
}

func NewDecryptingReader(r io.Reader, chunkSize int, key [KeySize]byte) io.Reader {
	return &decryptingReader{
		key:       key,
		chunkSize: chunkSize,
		r:         r,
		idx:       0,
	}
}

func (dr *decryptingReader) Read(b []byte) (n int, err error) {
	l := len(b)

	// generate the first decrypted chunk if necessary
	if dr.chunk == nil {
		err = dr.readNextChunk()
		if err != nil {
			return 0, err
		}
	}

	var copied int
	for n < l {
		copied = copy(b[n:], dr.chunk[dr.idx:])
		dr.idx += copied
		n += copied

		if dr.idx >= len(dr.chunk) {
			if err = dr.readNextChunk(); err != nil {
				return
			}
		}
	}
	return
}

func (dr *decryptingReader) readNextChunk() error {
	data := make([]byte, dr.chunkSize)
	n, err := dr.r.Read(data)
	if n == 0 {
		return io.EOF
	}
	if err != nil && err != io.EOF {
		return err
	}

	plaintext, err := DecryptChunk(dr.key, data[:n], nil)
	if err != nil {
		return err
	}

	dr.chunk = plaintext
	dr.idx = 0
	return nil
}

func HashFile(path string) ([]byte, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()

	return HashData(handle)
}

func HashData(r io.Reader) ([]byte, error) {
	hasher := sha256.New()

	if _, err := io.Copy(hasher, r); err != nil {
		return nil, err
	}

	return hasher.Sum(nil), nil
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func GenerateKey(password []byte, salt *[SaltSize]byte) (*[KeySize]byte, *[SaltSize]byte, error) {
	// generate a new salt if necessary
	if salt == nil {
		salt = new([SaltSize]byte)
		_, err := rand.Read(salt[:])
		if err != nil {
			return nil, nil, err
		}
	}

	key := new([KeySize]byte)
	keySlice, err := scrypt.Key(password, salt[:], ScryptIters, ScryptMemCost, ScryptCPUCost, KeySize)
	if err != nil {
		return nil, nil, err
	}
	copy(key[:], keySlice)
	Zero(keySlice)

	return key, salt, nil
}

func EncryptChunk(key [KeySize]byte, chunk []byte) ([]byte, error) {
	nonce := new([NonceSize]byte)
	_, err := rand.Read(nonce[:])
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(nonce))
	copy(ciphertext, nonce[:])
	ciphertext = secretbox.Seal(ciphertext, chunk, nonce, &key)
	return ciphertext, nil
}

func DecryptChunk(key [KeySize]byte, ciphertext []byte, out []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize+secretbox.Overhead {
		return nil, ErrCiphertextTooShort
	}
	nonce := new([NonceSize]byte)
	copy(nonce[:], ciphertext)

	out, ok := secretbox.Open(out, ciphertext[NonceSize:], nonce, &key)
	if !ok {
		return nil, ErrDecryptFailed
	}
	return out, nil
}
