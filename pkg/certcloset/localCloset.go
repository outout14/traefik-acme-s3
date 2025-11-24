package certcloset

import (
	"encoding/json"
	"fmt"
	"os"
)

type LocalCertCloset struct {
	index *CertificateList
	path  string
}

// NewLocalCertCloset constructs a LocalCertCloset pointing to the
// provided filesystem `path`. It ensures the certificate index file
// exists (creating it if necessary) and loads the index into memory.
func NewLocalCertCloset(config Config, path string) (*LocalCertCloset, error) {
	cg := LocalCertCloset{
		path: path,
	}

	if _, err := os.Stat(path + "/" + CerticateIndexFile); os.IsNotExist(err) {
		if err := cg.SaveIndex(); err != nil {
			return nil, fmt.Errorf("unable to create new index file: %w", err)
		}
	}

	if err := cg.retrieveIdx(); err != nil {
		return nil, err
	}

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("local closet path does not exist: %w", err)
	}

	return &cg, nil
}

// CheckIntegrity inspects the local certificate files and returns a
// slice of CertificateEntry for which the corresponding filesystem
// entries are missing (failed integrity checks).
func (c *LocalCertCloset) CheckIntegrity() []*CertificateEntry {
	// Returns the failed integrity check
	var failed []*CertificateEntry

	for _, cert := range c.index.CertIndex {
		if _, err := os.Stat(c.path + "/" + cert.Domain); os.IsNotExist(err) {
			failed = append(failed, &cert)
		}
	}

	return failed
}

// retrieveIdx reads the index file from disk and unmarshals it into
// the LocalCertCloset.index field.
func (c *LocalCertCloset) retrieveIdx() error {
	fPath := c.path + "/" + CerticateIndexFile
	idx, err := os.ReadFile(fPath)
	if err != nil {
		return fmt.Errorf("unable to read index from disk: %w", err)
	}

	err = json.Unmarshal(idx, &c.index)
	if err != nil {
		return fmt.Errorf("unable to unmarshal index: %w", err)
	}
	return nil
}

// GetIndex returns the in-memory CertificateList pointer held by the
// LocalCertCloset.
func (c *LocalCertCloset) GetIndex() *CertificateList {
	return c.index
}

// SetIndex replaces the LocalCertCloset's in-memory index with the
// provided CertificateList pointer.
func (c *LocalCertCloset) SetIndex(idx *CertificateList) {
	c.index = idx
}

// SaveIndex marshals the in-memory index and writes it to disk at the
// configured path as the certificate index file.
func (c *LocalCertCloset) SaveIndex() error {
	fPath := c.path + "/" + CerticateIndexFile

	idx, err := json.Marshal(c.index)
	if err != nil {
		return err
	}

	err = os.WriteFile(fPath, []byte(idx), 0644)
	if err != nil {
		return fmt.Errorf("unable to write index on disk: %w", err)
	}
	return nil
}
