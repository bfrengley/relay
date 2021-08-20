package relay

import (
	"crypto/sha256"
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"
)

type FileMetadata struct {
	Name      string    `json:"name"`
	Size      uint      `json:"size"`
	Hash      []byte    `json:"hash"`
	Challenge []byte    `json:"challenge"`
	Uploaded  time.Time `json:"uploaded"`
}

type FileID struct {
	ID string `json:"id"`
}

type file struct {
	FileMetadata
	data []byte
}

type RelayServer struct {
	fileLock sync.Mutex
	files    map[string]file
}

func (rs *RelayServer) CreateFile(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var meta FileMetadata
	err := decoder.Decode(&meta)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if meta.Name == "" {
		http.Error(w, "Name cannot be empty", http.StatusBadRequest)
		return
	}
	if meta.Size == 0 {
		http.Error(w, "File must be >0 bytes", http.StatusBadRequest)
		return
	}
	if len(meta.Hash) != sha256.Size {
		http.Error(w, "Hash must be valid SHA-256 hash", http.StatusBadRequest)
		return
	}
	if len(meta.Challenge) != 32 { // is this right?
		http.Error(w, "Challenge must be 32 bytes", http.StatusBadRequest)
		return
	}
	if !meta.Uploaded.IsZero() {
		http.Error(w, `Unexpected field "uploaded" found`, http.StatusBadRequest)
		return
	}

	id := string(meta.Hash)
	idJson, err := json.Marshal(FileID{id})
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	f := file{meta, make([]byte, meta.Size)}

	rs.fileLock.Lock()
	rs.files[id] = f
	rs.fileLock.Unlock()

	w.Header().Add("Content-Type", "application/json")
	w.Write(idJson)
}
