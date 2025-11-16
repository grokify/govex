package govex

import (
	"encoding/json"
	"os"
	"path/filepath"
)

type FilepathStats struct {
	CountsByFilepath map[string]int   `json:"countsByFilepath"`
	FilepathsByCount map[int][]string `json:"filepathsByCount"`
}

func NewFilepathStats() FilepathStats {
	return FilepathStats{
		CountsByFilepath: map[string]int{},
		FilepathsByCount: map[int][]string{},
	}
}

func ReadFileFilepathStats(filename string) (FilepathStats, error) {
	set := NewFilepathStats()
	b, err := os.ReadFile(filename)
	if err != nil {
		return set, err
	}
	return set, json.Unmarshal(b, &set)
}

func (stats FilepathStats) FileInfoSet() FileInfoSet {
	set := NewFileInfoset()
	for fp, fcount := range stats.CountsByFilepath {
		dir, filename := filepath.Split(fp)
		set.Add(dir, filename, fcount)
	}
	return set
}

func (stats FilepathStats) WriteJSON(filename string) error {
	if b, err := json.MarshalIndent(stats, "", "  "); err != nil {
		return err
	} else {
		return os.WriteFile(filename, b, 0600)
	}
}
