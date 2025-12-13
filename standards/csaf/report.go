package csaf

import (
	"encoding/json"
	"os"
)

func (doc CSAF) WriteFileJSON(filename string, perm os.FileMode) error {
	if b, err := json.Marshal(doc); err != nil {
		return err
	} else {
		return os.WriteFile(filename, b, perm)
	}
}
