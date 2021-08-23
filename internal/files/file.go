package files

import (
	"bytes"
	"time"

	"github.com/bfrengley/relay/internal/crypto"
	"github.com/google/uuid"
)

type FileMetadata struct {
	FileID
	Name      string    `json:"name"`
	Size      uint64    `json:"size"`
	Salt      []byte    `json:"salt"`
	Hash      []byte    `json:"hash"`
	Challenge []byte    `json:"challenge"`
	Uploaded  time.Time `json:"uploaded,omitempty"`
	Downloads uint      `json:"downloads,omitempty"`
}

type FileID struct {
	ID string `json:"id,omitempty"`
}

type File struct {
	FileMetadata
	Data [][]byte
}

func NewFile(id uuid.UUID) File {
	return File{}
}

func (file *FileMetadata) CheckChallenge(key [crypto.KeySize]byte) bool {
	b, err := crypto.DecryptChunk(key, file.Challenge, nil)
	if err != nil {
		return false
	}
	return bytes.Equal(b, file.Hash)
}
