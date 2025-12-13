package sitewriter

import (
	"fmt"
	"io"
	"strings"
)

func writeReportMkdnShields(w io.Writer, shieldsMkdn string) error {
	out := ""
	if strings.TrimSpace(shieldsMkdn) != "" {
		out = `
<div align="center">

` + shieldsMkdn + `

</div>

	`
	}

	if out != "" {
		if _, err := fmt.Fprintln(w, out); err != nil {
			return err
		} else {
			return nil
		}
	} else {
		return nil
	}
}

/*
func writeReportMkdnTime(w io.Writer, dt *time.Time) (bool, error) {
	if dt != nil && !dt.IsZero() {
		if _, err := fmt.Fprintf(w, "* Report Time: %s\n\n", dt.Format(time.RFC1123)); err != nil {
			return false, err
		} else {
			return true, nil
		}
	} else {
		return false, nil
	}
}
*/
