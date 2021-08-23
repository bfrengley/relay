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

type chunkReader struct {
	r       io.Reader
	chunkFn func([KeySize]byte, []byte) ([]byte, error)

	key       [KeySize]byte
	chunkSize int

	chunk []byte
	idx   int
}

func NewEncryptingReader(r io.Reader, chunkSize int, key [KeySize]byte) io.Reader {
	return &chunkReader{
		r:         r,
		chunkFn:   EncryptChunk,
		key:       key,
		chunkSize: chunkSize,
		idx:       0,
	}
}

func NewDecryptingReader(r io.Reader, chunkSize int, key [KeySize]byte) io.Reader {
	return &chunkReader{
		r: r,
		chunkFn: func(key_ [KeySize]byte, data []byte) ([]byte, error) {
			return DecryptChunk(key_, data, nil)
		},
		key:       key,
		chunkSize: chunkSize,
		idx:       0,
	}
}

func (er *chunkReader) Read(b []byte) (n int, err error) {
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

func (er *chunkReader) readNextChunk() error {
	data := make([]byte, er.chunkSize)
	n, err := er.r.Read(data)
	if n == 0 {
		return io.EOF
	}
	if err != nil && err != io.EOF {
		return err
	}

	nextChunk, err := er.chunkFn(er.key, data[:n])
	if err != nil {
		return err
	}

	er.chunk = nextChunk
	er.idx = 0
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
	if len(ciphertext) < Overhead {
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
