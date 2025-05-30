package certcloset

import (
	"encoding/json"
	"fmt"
	"os"
)

type LocalCertCloset struct {
	index CertificateList
	path  string
}

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

func (c *LocalCertCloset) GetIndex() CertificateList {
	return c.index
}

func (c *LocalCertCloset) SetIndex(idx CertificateList) {
	c.index = idx
}

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
