package relay

import (
	"crypto/sha256"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/bfrengley/relay/internal/crypto"
	"github.com/bfrengley/relay/internal/files"
	"github.com/google/uuid"
	"github.com/julienschmidt/httprouter"
)

func prettyPrint(i interface{}) string {
	s, _ := json.MarshalIndent(i, "", "\t")
	return string(s)
}

type RelayServer struct {
	readyFiles   files.FileSet
	pendingFiles files.FileSet
}

func (rs *RelayServer) CreateFile(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var meta files.FileMetadata
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
	if len(meta.Salt) != crypto.SaltSize {
		http.Error(w, "Salt must be 16 bytes", http.StatusBadRequest)
		return
	}
	if len(meta.Challenge) != sha256.Size+crypto.Overhead { // is this right?
		http.Error(w, "Invalid challenge size", http.StatusBadRequest)
		return
	}
	if !meta.Uploaded.IsZero() {
		http.Error(w, `Unexpected field "uploaded" found`, http.StatusBadRequest)
		return
	}
	if meta.ID != "" {
		http.Error(w, `Unexpected field "id" found`, http.StatusBadRequest)
		return
	}
	if meta.Downloads != 0 {
		http.Error(w, `Unexpected field "downloads" found`, http.StatusBadRequest)
	}

	id := uuid.New()
	idBytes, err := json.Marshal(files.FileID{ID: id.String()})
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	meta.ID = id.String()
	meta.Uploaded = time.Now().UTC()
	f := files.File{FileMetadata: meta, Data: make([][]byte, 0)}
	rs.pendingFiles.Set(id, f)
	log.Println("INFO: created new file", prettyPrint(meta))

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(idBytes)
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (rs *RelayServer) UploadFile(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	idStr := p.ByName("id")
	if idStr == "" {
		http.Error(w, "Missing file ID", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idStr)
	f, ok := rs.pendingFiles.Remove(id)

	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}

	log.Println("INFO: beginning upload for file", idStr)
	var fileBytes, totalBytes uint64
	for {
		select {
		case <-r.Context().Done():
			log.Println("INFO: upload for file", idStr, "cancelled")
			return
		default: // request not cancelled - read next chunk
		}

		chunk := make([]byte, ChunkSize)
		n, err := r.Body.Read(chunk)
		if n > 0 {
			if n < crypto.Overhead {
				http.Error(w, "Invalid chunk", http.StatusBadRequest)
				return
			}

			fileBytes += uint64(n - crypto.Overhead)
			totalBytes += uint64(n)
			if fileBytes > f.Size {
				http.Error(w, "Data exceeded expected file size", http.StatusBadRequest)
				return
			}

			f.Data = append(f.Data, chunk[:n])
		}

		if err == io.EOF {
			break // we've read the whole body
		} else if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return // ?
		}
	}

	if fileBytes < f.Size {
		log.Println("INFO: received", fileBytes, "bytes but expected", f.Size)
		http.Error(w, "Data smaller than expected file size", http.StatusBadRequest)
		return
	}

	log.Println("INFO: received", totalBytes, "bytes of data for file", idStr)
	rs.readyFiles.Set(id, f)
	w.Write([]byte(""))
}

func (rs *RelayServer) GetFileContents(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	idStr := p.ByName("id")
	if idStr == "" {
		http.Error(w, "Missing file ID", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idStr)
	f, ok := rs.readyFiles.Get(id)

	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}

	flusher := w.(http.Flusher)
	w.Header().Add("X-Content-Type-Options", "nosniff")

	for i := range f.Data {
		_, err := w.Write(f.Data[i])
		if err != nil {
			log.Println("ERR:", err)
			return
		}
		flusher.Flush()
	}

	rs.readyFiles.Lock()
	f.Downloads += 1
	rs.readyFiles.Unlock()
}

func (rs *RelayServer) GetFileMetadata(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	idStr := p.ByName("id")
	if idStr == "" {
		http.Error(w, "Missing file ID", http.StatusBadRequest)
		return
	}

	id, err := uuid.Parse(idStr)
	f, ok := rs.readyFiles.Get(id)

	if !ok || err != nil {
		http.NotFound(w, r)
		return
	}

	metaBytes, err := json.Marshal(f.FileMetadata)
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")

	_, err = w.Write(metaBytes)
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (rs *RelayServer) GetFileList(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	files := make([]files.FileMetadata, 0)
	rs.readyFiles.Lock()
	for _, f := range rs.readyFiles.Files {
		files = append(files, f.FileMetadata)
	}
	rs.readyFiles.Unlock()

	filesBytes, err := json.Marshal(files)
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Add("Content-Type", "application/json")

	_, err = w.Write(filesBytes)
	if err != nil {
		log.Printf("ERR: %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func ListenAndServe(port string) error {
	rs := RelayServer{files.NewSet(), files.NewSet()}
	router := httprouter.New()

	router.GET("/files", rs.GetFileList)
	router.POST("/files", rs.CreateFile)
	router.PUT("/files/:id", rs.UploadFile)
	router.GET("/files/:id/metadata", rs.GetFileMetadata)
	router.GET("/files/:id", rs.GetFileContents)

	log.Println("INFO: listening on port", port)
	return http.ListenAndServe(":"+port, router)
}
