package bootstrap

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"platform.4so.io/factory/internal/durablefile"
)

type Journal struct {
	dir  string
	path string
}

func NewJournal(dir string) *Journal {
	return &Journal{dir: dir, path: filepath.Join(dir, "bootstrap-state.json")}
}

func (j *Journal) Load() (*Run, error) {
	raw, err := os.ReadFile(j.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read bootstrap journal: %w", err)
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	var run Run
	if err = dec.Decode(&run); err != nil {
		return nil, fmt.Errorf("decode bootstrap journal: %w", err)
	}
	var extra any
	if err = dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("bootstrap journal has trailing data")
	}
	return &run, nil
}

func (j *Journal) Save(run Run) error {
	raw, err := json.MarshalIndent(run, "", "  ")
	if err != nil {
		return fmt.Errorf("encode bootstrap journal: %w", err)
	}
	raw = append(raw, '\n')
	if err = durablefile.Replace(j.path, raw, 0o700, 0o600); err != nil {
		return fmt.Errorf("persist bootstrap journal: %w", err)
	}
	return nil
}

// bytesReader keeps the journal package dependency-free and explicit.
type byteReader struct {
	data   []byte
	offset int
}

func bytesReader(data []byte) *byteReader { return &byteReader{data: data} }
func (r *byteReader) Read(p []byte) (int, error) {
	if r.offset >= len(r.data) {
		return 0, io.EOF
	}
	n := copy(p, r.data[r.offset:])
	r.offset += n
	return n, nil
}
