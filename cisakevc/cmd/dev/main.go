package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/grokify/govex/cisakevc"
	"github.com/grokify/mogo/fmt/fmtutil"
	"github.com/grokify/mogo/type/maputil"
)

type CKEV struct {
	Vulnerabilities maputil.MapStringAnys `json:"vulnerabilities"`
}

func main() {
	fmtutil.PrintJSON(os.Args)
	if len(os.Args) < 2 {
		fmt.Println("must supply JSON filename, exiting...")
		os.Exit(1)
	}
	b, err := os.ReadFile(os.Args[1])
	if err != nil {
		slog.Error(err.Error())
		os.Exit(2)
	}
	ckev := CKEV{}
	err = json.Unmarshal(b, &ckev)
	if err != nil {
		slog.Error(err.Error())
		os.Exit(3)
	}
	keys := ckev.Vulnerabilities.UniqueKeys()
	fmtutil.PrintJSON(keys)

	cat, err := cisakevc.ReadFile(os.Args[1])
	if err != nil {
		slog.Error(err.Error())
		os.Exit(4)
	}
	_, m := cat.Vulnerabilities.CVEIDs()
	fmtutil.MustPrintJSON(m)

	fmt.Println("DONE")
	os.Exit(0)
}
