package govex

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/table"

	"github.com/grokify/govex/severity"
)

func (vs *VulnerabilitiesSet) WriteReportMarkdownTablesToFile(filename string, perm os.FileMode, shieldsMkdn string, colDefs table.ColumnDefinitionSet, addColLineNum bool, opts *ValueOptions) error {
	if file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm); err != nil {
		return err
	} else {
		defer file.Close()
		return vs.WriteReportMarkdownTables(file, shieldsMkdn, colDefs, addColLineNum, opts)
	}
}

func (vs *VulnerabilitiesSet) WriteReportMarkdownTables(w io.Writer, shieldsMkdn string, colDefs table.ColumnDefinitionSet, addColLineNum bool, opts *ValueOptions) error {
	name := vs.Name
	if name == "" {
		name = ReportName
	}
	if _, err := fmt.Fprintf(w, "# %s\n\n", name); err != nil {
		return err
	}

	if shieldsMkdn != "" {
		if _, err := fmt.Fprintf(w, "%s\n\n", shieldsMkdn); err != nil {
			return err
		}
	}

	haveBullets := false
	vs.RepoPath = strings.TrimSpace(vs.RepoPath)
	vs.RepoURL = strings.TrimSpace(vs.RepoURL)

	if vs.RepoPath != "" {
		if vs.RepoURL != "" {
			if _, err := fmt.Fprintf(w, "* Repo Path: [%s](%s)\n", vs.RepoPath, vs.RepoURL); err != nil {
				return err
			} else {
				haveBullets = true
			}
		} else {
			if _, err := fmt.Fprintf(w, "* Repo Path: %s\n", vs.RepoPath); err != nil {
				return err
			} else {
				haveBullets = true
			}
		}
	}

	if wrote, err := WriteReportMkdnTime(w, vs.DateTime); err != nil {
		return err
	} else if wrote {
		haveBullets = true
	}

	if haveBullets {
		if _, err := fmt.Fprintln(w, ""); err != nil {
			return err
		}
	}

	h := vs.Vulnerabilities.SeverityHistogram()
	sevs := severity.SeveritiesAll()

	if 1 == 0 {
		if _, err := fmt.Fprintf(w, "\n## %s Summary Counts\n\n", "Severity"); err != nil {
			return err
		}
		for _, sev := range sevs {
			count := h.GetOrDefault(sev, 0)
			if _, err := fmt.Fprintf(w, "* %s: %d\n", sev, count); err != nil {
				return err
			}
		}
	}

	for _, sev := range sevs {
		count := h.GetOrDefault(sev, 0)
		if count < 0 {
			panic("severity count should not be negative")
		} else if _, err := fmt.Fprintf(w, "\n## %s (%d)\n\n", sev, count); err != nil {
			return err
		} else if count == 0 {
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

func WriteReportMkdnTime(w io.Writer, dt *time.Time) (bool, error) {
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
