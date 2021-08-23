package relay

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/schollz/progressbar/v3"

	"github.com/bfrengley/relay/internal/crypto"
	"github.com/bfrengley/relay/internal/files"
)

const (
	ChunkSize    = 32 * 1024
	RawChunkSize = ChunkSize - crypto.Overhead
)

type RelayClient struct {
	Server string
	c      http.Client
}

func NewClient(server string) RelayClient {
	return RelayClient{server, http.Client{}}
}

func (rc *RelayClient) UploadFile(filepath, pass string) error {
	f, err := os.Open(filepath)
	if err != nil {
		return err
	}

	info, err := f.Stat()
	if err != nil {
		return err
	}

	if info.IsDir() {
		return errors.New("cannot upload a directory")
	}

	log.Println("INFO: hashing the file")
	hash, err := crypto.HashData(f)
	if err != nil {
		return err
	}
	log.Println("INFO: file hash", hex.EncodeToString(hash))

	log.Println("INFO: generating a key")
	key, salt, err := crypto.GenerateKey([]byte(pass), nil)
	log.Println("INFO: generated a key with salt", hex.EncodeToString(salt[:]))
	if err != nil {
		return err
	}

	log.Println("INFO: creating decryption challenge")
	challenge, err := crypto.EncryptChunk(*key, hash)
	if err != nil {
		return err
	}

	fileData := files.FileMetadata{
		Name:      info.Name(),
		Size:      uint64(info.Size()),
		Salt:      salt[:],
		Hash:      hash,
		Challenge: challenge,
	}

	log.Println("INFO: validating challenge...", fileData.CheckChallenge(*key))

	resBody, err := json.Marshal(fileData)
	if err != nil {
		return err
	}

	log.Println("INFO: creating remote file")
	res, err := rc.c.Post(rc.Server+"/files", "application/json", bytes.NewReader(resBody))
	defer func(r *http.Response) {
		if r != nil {
			r.Body.Close()
		}
	}(res)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var id files.FileID
	if err = json.Unmarshal(body, &id); err != nil {
		return err
	}
	log.Println("INFO: created remote file with id", id.ID)

	_, err = f.Seek(0, 0)
	if err != nil {
		return err
	}

	encryptedBytes, chunks := encryptedSize(fileData.Size)
	log.Println("INFO: uploading", encryptedBytes, "bytes in", chunks, "chunks")

	pb := progressbar.NewOptions64(
		int64(encryptedBytes),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription("Uploading"),
		progressbar.OptionSetRenderBlankState(true),
	)

	enc := crypto.NewEncryptingReader(f, RawChunkSize, *key)

	put, err := http.NewRequest(
		http.MethodPut,
		rc.Server+"/files/"+id.ID,
		io.TeeReader(enc, pb),
	)
	if err != nil {
		return err
	}
	put.Header.Add("X-Content-Type-Options", "nosniff")

	res, err = rc.c.Do(put)
	defer func(r *http.Response) {
		if r != nil {
			r.Body.Close()
		}
	}(res)
	if err != nil {
		return err
	}

	// progressbar doesn't print a newline when it finishes; do it ourselves
	println()

	if res.StatusCode == http.StatusOK {
		log.Println("INFO: successfully uploaded", encryptedBytes, "bytes in", chunks, "chunks")
	} else {
		body, _ = ioutil.ReadAll(res.Body)
		return fmt.Errorf(
			"upload failed with status code %d and body \"%s\"",
			res.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	return nil
}

func (rc *RelayClient) DownloadFile(id, pass string) ([]byte, error) {
	log.Println("INFO: getting metadata for file", id)
	res, err := rc.c.Get(rc.Server + "/files/" + id + "/metadata")
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"download failed with status code %d and body \"%s\"",
			res.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var meta files.FileMetadata
	err = json.Unmarshal(body, &meta)
	if err != nil {
		return nil, err
	}

	log.Println("INFO: got file metadata", prettyPrint(meta))

	log.Println("INFO: deriving key")
	key, _, err := crypto.GenerateKey([]byte(pass), (*[16]byte)(meta.Salt))
	if err != nil {
		return nil, err
	}

	log.Println("INFO: validating challenge...")
	if meta.CheckChallenge(*key) {
		log.Println("INFO: successfully validated challenge")
	} else {
		return nil, errors.New("failed to validate challenge; incorrect password for decryption")
	}

	log.Println("INFO: downloading and decrypting file")

	res, err = rc.c.Get(rc.Server + "/files/" + id)
	if err != nil {
		return nil, err
	}

	if res.StatusCode != http.StatusOK {
		body, _ = ioutil.ReadAll(res.Body)
		return nil, fmt.Errorf(
			"download failed with status code %d and body \"%s\"",
			res.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	pb := progressbar.NewOptions64(
		int64(meta.Size),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionSetDescription("Downloading"),
		progressbar.OptionSetRenderBlankState(true),
	)

	dec := crypto.NewDecryptingReader(res.Body, ChunkSize, *key)
	file, err := io.ReadAll(io.TeeReader(dec, pb))
	if err != nil {
		return nil, err
	}

	// progressbar doesn't print a newline when it finishes; do it ourselves
	println()
	log.Println("INFO: file downloaded and decrypted")
	log.Println("INFO: checking decrypted file hash")
	log.Println("INFO: expecting:", hex.EncodeToString(meta.Hash))

	hash, err := crypto.HashData(bytes.NewReader(file))
	if err != nil {
		return nil, err
	}

	log.Println("INFO:   hash is:", hex.EncodeToString(hash))
	if !bytes.Equal(hash, meta.Hash) {
		return nil, errors.New("hashes do not match")
	}

	log.Println("INFO: hashes match; file download and decryption successful")
	return file, nil
}

func encryptedSize(size uint64) (bytes uint64, chunks uint64) {
	chunks, extra := size/RawChunkSize, size%RawChunkSize > 0
	if extra {
		chunks += 1
	}
	bytes = size + chunks*crypto.Overhead
	return bytes, chunks
}
