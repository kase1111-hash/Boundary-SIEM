package app

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// seededMarker records in the rules directory that the shipped rules were
// copied, so rules deleted through the API are not restored on restart.
// LoadCustomRules ignores hidden files.
const seededMarker = ".seeded"

// isRuleFile reports whether name is a rule file LoadCustomRules reads.
func isRuleFile(name string) bool {
	if strings.HasPrefix(name, ".") {
		return false
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml", ".json":
		return true
	}
	return false
}

// seedRules copies the rule files of seedDir (the shipped rules/ directory)
// into rulesDir, the API-writable directory the rule handler loads, once.
// Existing files are never overwritten. It returns the number of files
// copied. Delete rulesDir/.seeded to copy missing shipped rules again.
func seedRules(rulesDir, seedDir string) (int, error) {
	if rulesDir == "" || seedDir == "" {
		return 0, nil
	}
	if same, err := sameDir(rulesDir, seedDir); err != nil || same {
		return 0, err
	}
	if _, err := os.Stat(filepath.Join(rulesDir, seededMarker)); err == nil {
		return 0, nil
	}

	src, err := os.OpenRoot(seedDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil // nothing shipped next to the binary
		}
		return 0, err
	}
	defer func() { _ = src.Close() }()

	if err := os.MkdirAll(rulesDir, 0o750); err != nil {
		return 0, err
	}
	dst, err := os.OpenRoot(rulesDir)
	if err != nil {
		return 0, err
	}
	defer func() { _ = dst.Close() }()

	entries, err := fs.ReadDir(src.FS(), ".")
	if err != nil {
		return 0, err
	}
	copied := 0
	for _, entry := range entries {
		name := entry.Name()
		if !entry.Type().IsRegular() || !isRuleFile(name) {
			continue
		}
		if _, err := dst.Stat(name); err == nil {
			continue // never overwrite a rule file
		}
		data, err := src.ReadFile(name)
		if err != nil {
			return copied, fmt.Errorf("read %s: %w", name, err)
		}
		if err := dst.WriteFile(name, data, 0o600); err != nil {
			return copied, fmt.Errorf("write %s: %w", name, err)
		}
		copied++
	}

	marker := fmt.Sprintf("shipped rules from %s copied at %s\n", seedDir, time.Now().UTC().Format(time.RFC3339))
	if err := dst.WriteFile(seededMarker, []byte(marker), 0o600); err != nil {
		return copied, err
	}
	return copied, nil
}

// sameDir reports whether a and b name the same directory.
func sameDir(a, b string) (bool, error) {
	absA, err := filepath.Abs(a)
	if err != nil {
		return false, err
	}
	absB, err := filepath.Abs(b)
	if err != nil {
		return false, err
	}
	return absA == absB, nil
}
