package files

import (
	"sync"

	"github.com/google/uuid"
)

type FileSet struct {
	sync.Mutex
	Files map[uuid.UUID]File
}

func (fs *FileSet) Set(id uuid.UUID, f File) {
	fs.Lock()
	fs.Files[id] = f
	fs.Unlock()
}

func (fs *FileSet) Remove(id uuid.UUID) (File, bool) {
	fs.Lock()
	defer fs.Unlock()

	f, ok := fs.Files[id]
	if ok {
		delete(fs.Files, id)
	}
	return f, ok
}

func (fs *FileSet) Get(id uuid.UUID) (File, bool) {
	fs.Lock()
	f, ok := fs.Files[id]
	fs.Unlock()
	return f, ok
}

func NewSet() FileSet {
	return FileSet{sync.Mutex{}, make(map[uuid.UUID]File)}
}
