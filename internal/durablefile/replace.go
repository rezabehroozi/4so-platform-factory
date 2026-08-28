package durablefile

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Replace atomically replaces path and does not report success until both the
// file contents and the parent-directory rename are durably synchronized.
func Replace(path string, data []byte, dirMode, fileMode fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return fmt.Errorf("create durable file directory: %w", err)
	}
	temp, err := os.CreateTemp(dir, ".durable-*")
	if err != nil {
		return fmt.Errorf("create durable temp file: %w", err)
	}
	name := temp.Name()
	keep := false
	defer func() {
		_ = temp.Close()
		if !keep {
			_ = os.Remove(name)
		}
	}()
	if err = temp.Chmod(fileMode); err != nil {
		return fmt.Errorf("set durable temp mode: %w", err)
	}
	if _, err = temp.Write(data); err != nil {
		return fmt.Errorf("write durable temp file: %w", err)
	}
	if err = temp.Sync(); err != nil {
		return fmt.Errorf("sync durable temp file: %w", err)
	}
	if err = temp.Close(); err != nil {
		return fmt.Errorf("close durable temp file: %w", err)
	}
	if err = os.Rename(name, path); err != nil {
		return fmt.Errorf("replace durable file: %w", err)
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open durable parent directory: %w", err)
	}
	if err = dirHandle.Sync(); err != nil {
		_ = dirHandle.Close()
		return fmt.Errorf("sync durable parent directory: %w", err)
	}
	if err = dirHandle.Close(); err != nil {
		return fmt.Errorf("close durable parent directory: %w", err)
	}
	keep = true
	return nil
}
