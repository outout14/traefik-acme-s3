package certcloset

import (
	"encoding/json"
	"fmt"
	"os"
)

func (c *CertCloset) WriteIdxOnDisk(path string) error {
	// Store on disk (locally) the index
	fPath := path + "/" + CerticateIndexFile

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
