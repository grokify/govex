package govex

import (
	"fmt"
	"io"
	"time"
)

func writeReportTime(w io.Writer, dt *time.Time) (bool, error) {
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
