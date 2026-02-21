package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/grokify/govex/feeds/cisakev"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/type/maputil"
)

type CKEV struct {
	Vulnerabilities maputil.MapStringAnys `json:"vulnerabilities"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("must supply JSON filename, exiting...")
		os.Exit(1)
	}
	b, err := os.ReadFile(filepath.Clean(os.Args[1])) // #nosec G703 -- CLI dev tool intentionally reads user-specified files
	if err != nil {
		slog.Error("failed to read file", "error", err)
		os.Exit(2)
	}
	ckev := CKEV{}
	err = json.Unmarshal(b, &ckev)
	if err != nil {
		slog.Error("failed to unmarshal JSON", "error", err)
		os.Exit(3)
	}
	keys := ckev.Vulnerabilities.UniqueKeys()
	fmtutil.MustPrintJSON(keys)

	cat, err := cisakev.ReadFile(filepath.Clean(os.Args[1]))
	if err != nil {
		slog.Error("failed to read CISA KEV file", "error", err)
		os.Exit(4)
	}
	_, m := cat.Vulnerabilities.CVEIDs()
	fmtutil.MustPrintJSON(m)

	fmt.Println("DONE")
	os.Exit(0)
}
