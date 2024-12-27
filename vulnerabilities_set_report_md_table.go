package govex

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/grokify/gocharts/v2/data/table"

	"github.com/grokify/govex/severity"
)

func (vs *VulnerabilitiesSet) WriteReportMarkdownTableToFile(filename string, perm os.FileMode, colDefs table.ColumnDefinitionSet, addColLineNum bool, opts *ValueOpts) error {
	if file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm); err != nil {
		return err
	} else {
		defer file.Close()
		return vs.WriteReportMarkdownTable(file, colDefs, addColLineNum, opts)
	}
}

func (vs *VulnerabilitiesSet) WriteReportMarkdownTable(w io.Writer, colDefs table.ColumnDefinitionSet, addColLineNum bool, opts *ValueOpts) error {
	if vs.Name != "" {
		if _, err := fmt.Fprintln(w, fmt.Sprintf("# %s\n\n", vs.Name)); err != nil {
			return err
		}
	}
	if vs.DateTime != nil && !vs.DateTime.IsZero() {
		if _, err := fmt.Fprintln(w, fmt.Sprintf("* Report Time: %s\n\n", vs.DateTime.Format(time.RFC1123))); err != nil {
			return err
		}
	}
	h := vs.Vulnerabilities.SeverityHistogram()
	sevs := severity.SeveritiesAll()

	if _, err := fmt.Fprintln(w, fmt.Sprintf("\n## %s Counts\n", "Severity")); err != nil {
		return err
	}
	for _, sev := range sevs {
		count := h.GetOrDefault(sev, 0)
		if _, err := fmt.Fprintln(w, fmt.Sprintf("* %s: %d", sev, count)); err != nil {
			return err
		}
	}

	for _, sev := range sevs {
		count := h.GetOrDefault(sev, 0)
		if _, err := fmt.Fprintln(w, fmt.Sprintf("\n## %s (%d)\n\n", sev, count)); err != nil {
			return err
		} else if count <= 0 {
			continue
		} else if vsSev, err := vs.Vulnerabilities.FilterSeverities([]string{sev}); err != nil {
			return err
		} else if tblSev, err := vsSev.Table(colDefs, opts); err != nil {
			return err
		} else {
			if addColLineNum {
				tblSev.AddColumnLineNumber("Number", 1)
			}
			if _, err := fmt.Fprintln(w, tblSev.Markdown("\n", true)); err != nil {
				return err
			}
		}
	}
	return nil
}
