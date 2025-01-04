package govex

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/errors/errorsutil"
	"github.com/grokify/mogo/os/fileext"
	"github.com/grokify/mogo/os/osutil"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/strconv/strconvutil"
	"github.com/grokify/mogo/text/markdown"
	"github.com/grokify/mogo/time/timeutil"
	"github.com/grokify/mogo/type/maputil"
	"github.com/grokify/mogo/type/slicesutil"

	"github.com/grokify/govex/severity"
)

const (
	FilenameIndexMd   = "index.md"
	FilenameReadmeMd  = "README.md"
	FilenameVulnsJSON = "vulns.json"
	FilenameVulnsXLSX = "vulns.json"
	FilenameMetaJSON  = "meta.json"
	ReportsRepoTitle  = "AppSec Reports"
)

var (
	ErrFieldDateTimeCannotBeNil        = errors.New("field DateTime cannot be nil")
	ErrFieldIndexFileCannotBeUndefined = errors.New("field IndexFilename cannot be undefined")
	ErrFieldRepoPathCannotBeUndefined  = errors.New("field RootFilePath cannot be undefined")
	ErrVulnerabilitySetCannotBeNil     = errors.New("vulnerability set canot be nil")
)

// SiteWriter is designed to write files that are read from a git repo web UI.
type SiteWriter struct {
	IndexFilename              string
	RootFilePath               string
	FilesPerm                  os.FileMode
	SeverityCutoff             string
	RootIndexFileTable         bool
	RootIndexName              string
	ShieldsWrite               bool
	ShieldFontSize             int
	MetaWrite                  bool
	MkdnWriteFileVulns         bool
	MkdnWriteFileVulnsAsIndex  bool
	MkdnColDefsSet             table.ColumnDefinitionSet
	MkdnAddColLinNum           bool
	JSONWriteFileVulns         bool
	JSONWriteFileVulnsAsLatest bool
	JSONPrefix                 string
	JSONIndent                 string
	XLSXWriteFileVulns         bool
	XLSXSheetName1             string
	XLSXSheetName2             string
	XLSXColDefsSet             table.ColumnDefinitionSet
}

// DefaultSiteWriter returns a `SiteWriter{}`. Typically, `RootFilePath` still
// needs to be set.
func DefaultSiteWriter() SiteWriter {
	return SiteWriter{
		IndexFilename:              FilenameReadmeMd,
		RootFilePath:               ".",
		SeverityCutoff:             severity.SeverityHigh,
		FilesPerm:                  0600,
		RootIndexFileTable:         true,
		RootIndexName:              ReportsRepoTitle,
		ShieldsWrite:               true,
		ShieldFontSize:             12,
		MetaWrite:                  true,
		MkdnWriteFileVulns:         true,
		MkdnWriteFileVulnsAsIndex:  true,
		MkdnColDefsSet:             TableColumnDefinitionSetSASTSCA(),
		MkdnAddColLinNum:           true,
		JSONWriteFileVulns:         true,
		JSONWriteFileVulnsAsLatest: true,
		JSONPrefix:                 "",
		JSONIndent:                 "  ",
		XLSXWriteFileVulns:         true,
		XLSXSheetName1:             P1DoNow,
		XLSXSheetName2:             P2DoNext,
		XLSXColDefsSet:             TableColumnDefinitionSetSASTSCA(),
	}
}

func WriteFilesSiteForRepo(rootFilePath string, vs *VulnerabilitiesSet) error {
	if vs == nil {
		return ErrVulnerabilitySetCannotBeNil
	}
	meta := vs.Meta()
	missingFields := meta.MissingFields()
	if len(missingFields) > 0 {
		return fmt.Errorf("missing meta fields: [%s]", strings.Join(missingFields, ", "))
	}
	sw := DefaultSiteWriter()
	sw.RootFilePath = rootFilePath
	return sw.WriteFiles(vs)
}

func (sw SiteWriter) WriteFiles(vs *VulnerabilitiesSet) error {
	if err := sw.writeFilesVulns(vs); err != nil {
		return err
	}
	dirsWithIndexes, err := sw.getRepoDirsWithIndexes("", []string{})
	if err != nil {
		return errorsutil.NewErrorWithLocation(err.Error())
	}
	if sw.RootIndexFileTable {
		if err := sw.writeRootIndexWithTableFile(sw.RootIndexName, dirsWithIndexes); err != nil {
			return errorsutil.NewErrorWithLocation(err.Error())
		}
	} else if err := sw.writeRootIndexFile(sw.RootIndexName, dirsWithIndexes); err != nil {
		return errorsutil.NewErrorWithLocation(err.Error())
	}
	return nil
}

func (sw SiteWriter) writeFilesVulns(vs *VulnerabilitiesSet) error {
	if vs == nil {
		return ErrVulnerabilitySetCannotBeNil
	} else if vs.RepoPath == "" {
		return ErrFieldRepoPathCannotBeUndefined
	}
	if vs.DateTime == nil {
		return ErrFieldDateTimeCannotBeNil
	}
	dt := vs.DateTime.UTC()
	filenameBase := fmt.Sprintf("vulns_%s.", dt.Format(timeutil.ISO8601CompactZ))
	repoDir := sw.buildVulnsRepoDir(sw.RootFilePath, vs.RepoPath)
	if err := os.MkdirAll(repoDir, osutil.ModeDir0755); err != nil {
		return err
	}
	shieldsMkdn := ""
	if sw.ShieldsWrite {
		shieldsMkdn = `
![](latest-critical.svg)
![](latest-high.svg)
![](latest-medium.svg)
![](latest-low.svg)
![](latest-informational.svg)
![](latest-none.svg)
![](latest-unknown.svg)
	`
	}

	// Markdown Historical
	if sw.MkdnWriteFileVulns {
		if err := vs.WriteReportMarkdownTablesToFile(
			filepath.Join(repoDir, filenameBase+fileext.ExtMarkdown),
			sw.FilesPerm, shieldsMkdn, sw.MkdnColDefsSet, sw.MkdnAddColLinNum, vs.VulnValueOpts); err != nil {
			return errorsutil.NewErrorWithLocation(err.Error())
		}
	}
	// Markdown Index
	if sw.MkdnWriteFileVulnsAsIndex {
		if err := vs.WriteReportMarkdownTablesToFile(
			filepath.Join(repoDir, sw.IndexFilename),
			sw.FilesPerm, shieldsMkdn, sw.MkdnColDefsSet, sw.MkdnAddColLinNum, vs.VulnValueOpts); err != nil {
			return err
		}
	}
	// JSON Historical
	if sw.JSONWriteFileVulns {
		if err := vs.WriteFileJSON(
			filepath.Join(repoDir, filenameBase+fileext.ExtJSON),
			sw.JSONPrefix, sw.JSONIndent, sw.FilesPerm); err != nil {
			return err
		}
	}
	// JSON Latest
	if sw.JSONWriteFileVulnsAsLatest {
		if err := vs.WriteFileJSON(
			filepath.Join(repoDir, FilenameVulnsJSON),
			sw.JSONPrefix, sw.JSONIndent, sw.FilesPerm); err != nil {
			return err
		}
	}
	// XLSX
	if sw.XLSXWriteFileVulns {
		if sw.SeverityCutoff == "" {
			if err := vs.Vulnerabilities.WriteFileXLSX(
				filepath.Join(repoDir, filenameBase+fileext.ExtXLSX),
				sw.XLSXSheetName1, sw.XLSXColDefsSet, vs.VulnValueOpts); err != nil {
				return err
			}
		} else if _, _, err := vs.Vulnerabilities.WriteFileXLSXSplitSeverity(
			filepath.Join(repoDir, filenameBase+fileext.ExtXLSX),
			sw.XLSXColDefsSet, sw.SeverityCutoff,
			sw.XLSXSheetName1, sw.XLSXSheetName2, vs.VulnValueOpts); err != nil {
			return err
		}
	}
	if sw.ShieldsWrite {
		if err := sw.writeSeverityShieldsSVG(repoDir,
			pointer.Pointer(vs.Vulnerabilities.SeverityHistogram()),
		); err != nil {
			return err
		}
	}
	if sw.MetaWrite {
		if err := vs.WriteFileMeta(filepath.Join(repoDir, FilenameMetaJSON), 0600); err != nil {
			return err
		}
	}
	return nil
}

func (sw SiteWriter) buildVulnsRepoDir(rootFilePath, repoFilePath string) string {
	var dirParts []string
	if rootFilePath != "" {
		dirParts = append(dirParts, rootFilePath)
	}
	if repoFilePath != "" {
		dirParts = append(dirParts, repoFilePath)
	}
	if len(dirParts) == 0 {
		dirParts = append(dirParts, ".")
	}
	return strings.Join(dirParts, string(filepath.Separator))
}

func (sw SiteWriter) writeRootIndexFile(rootIndexName string, dirsWithIndexes []string) error {
	if strings.TrimSpace(sw.IndexFilename) == "" {
		return errorsutil.NewErrorWithLocation(ErrFieldIndexFileCannotBeUndefined.Error())
	}
	fp := filepath.Join(sw.RootFilePath, sw.IndexFilename)
	if file, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, sw.FilesPerm); err != nil {
		return errorsutil.NewErrorWithLocation(err.Error())
	} else {
		if err := sw.writeRootIndex(file, rootIndexName, dirsWithIndexes); err != nil {
			err2 := file.Close()
			if err2 != nil {
				return errorsutil.Wrap(err, err2.Error())
			} else {
				return err
			}
		} else {
			return file.Close()
		}
	}
}

func (sw SiteWriter) writeRootIndex(w io.Writer, rootIndexName string, dirsWithIndexes []string) error {
	if _, err := fmt.Fprintf(w, "# %s\n\n", rootIndexName); err != nil {
		return err
	}
	sort.Strings(dirsWithIndexes)
	for _, sdir := range dirsWithIndexes {
		sdirWithIndex := filepath.Join(sdir, sw.IndexFilename)
		if _, err := fmt.Fprintf(w, "1. [%s](%s)\n", sdir, sdirWithIndex); err != nil {
			return err
		}
	}
	return nil
}

func (sw SiteWriter) writeRootIndexWithTableFile(rootIndexName string, dirsWithIndexes []string) error {
	if strings.TrimSpace(sw.IndexFilename) == "" {
		return errorsutil.NewErrorWithLocation(ErrFieldIndexFileCannotBeUndefined.Error())
	}
	fp := filepath.Join(sw.RootFilePath, sw.IndexFilename)
	if file, err := os.OpenFile(fp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, sw.FilesPerm); err != nil {
		return errorsutil.NewErrorWithLocation(err.Error())
	} else {
		if err := sw.writeRootIndexWithTable(file, rootIndexName, dirsWithIndexes); err != nil {
			err2 := file.Close()
			if err2 != nil {
				return errorsutil.Wrap(err, err2.Error())
			} else {
				return err
			}
		} else {
			return file.Close()
		}
	}
}

func (sw SiteWriter) writeRootIndexWithTable(w io.Writer, rootIndexName string, dirsWithIndexes []string) error {
	if _, err := fmt.Fprintf(w, "# %s\n\n", rootIndexName); err != nil {
		return err
	}

	sort.Strings(dirsWithIndexes)
	tbl := sw.reposListTableSeverities(dirsWithIndexes)

	_, err := fmt.Fprint(w, tbl.Markdown("\n", true))
	return err
}

func (sw SiteWriter) reposListTableSeverities(dirsWithIndex []string) *table.Table {
	tbl := table.NewTable("Repo Severities")
	sevs := severity.SeveritiesAll()
	tbl.Columns = []string{"Repo", "Last Updated"}
	tbl.Columns = append(tbl.Columns, sevs...)
	tbl.FormatMap = map[int]string{
		-1: table.FormatInt,
		0:  table.FormatURL,
		1:  table.FormatDate}
	sort.Strings(dirsWithIndex)
	for _, dir := range dirsWithIndex {
		row := []string{
			markdown.Linkify(filepath.Join(dir, sw.IndexFilename), dir),
		}
		fpMeta := sw.buildFilePath(dir, FilenameMetaJSON)
		if meta, err := ReadFileVulnerabilitiesSetMeta(fpMeta); err != nil {
			row = append(row, "")
			counts := slicesutil.MakeRepeatingElement(len(sevs), "?")
			row = append(row, counts...)
		} else {
			if meta.DateTime == nil || meta.DateTime.IsZero() {
				row = append(row, "")
			} else {
				row = append(row, meta.DateTime.Format(timeutil.RFC3339FullDate))
			}
			counts := strconvutil.SliceItoa(maputil.ValuesByKeys(meta.SeverityCounts, sevs, 0))
			row = append(row, counts...)
		}
		tbl.Rows = append(tbl.Rows, row)
	}
	return &tbl
}

func (sw SiteWriter) getRepoDirsWithIndexes(subDir string, dirsWithIndex []string) ([]string, error) {
	rootDir := sw.RootFilePath
	if rootDir == "" {
		rootDir = "."
	}
	if subDir != "" && subDir != "." {
		checkIndexPath := filepath.Join(rootDir, subDir, sw.IndexFilename)
		ok, err := osutil.Exists(checkIndexPath)
		if err == nil && ok {
			dirsWithIndex = append(dirsWithIndex, subDir)
		}
	}
	procDir := filepath.Join(rootDir, subDir)
	sdirs, err := osutil.ReadDirMore(procDir, nil, true, false, false)
	if err != nil {
		err2 := errorsutil.Wrapf(err, "procDir  (%s)", procDir)
		return dirsWithIndex, errorsutil.NewErrorWithLocation(err2.Error())
	}
	for _, sdir := range sdirs {
		dirsWithIndex, err = sw.getRepoDirsWithIndexes(filepath.Join(subDir, sdir.Name()), dirsWithIndex)
		if err != nil {
			return dirsWithIndex, errorsutil.NewErrorWithLocation(err.Error())
		}
	}
	return dirsWithIndex, nil
}

func (sw SiteWriter) writeSeverityShieldsSVG(dir string, h *histogram.Histogram) error {
	if h == nil {
		return errors.New("param histogram cannot be nil")
	}
	if dir == "" {
		dir = "."
	}
	sc := severity.SeverityCountsSet{Histogram: h}

	fnFilepath := func(sev string) (string, error) {
		sev2, _, err := severity.ParseSeverity(sev)
		if err != nil {
			return "", err
		}
		fn := fmt.Sprintf("latest-%s.svg", strings.ToLower(sev2))
		return filepath.Join(dir, fn), nil
	}

	return sc.WriteShields(
		severity.SeveritiesAll(),
		sw.ShieldFontSize,
		sw.SeverityCutoff,
		fnFilepath,
		severity.FuncShieldNameSeverity(),
		0644,
	)
}

func (sw SiteWriter) buildFilePath(sparts ...string) string {
	rootDir := sw.RootFilePath
	if rootDir == "" {
		rootDir = "."
	}
	if len(sparts) == 0 {
		return rootDir
	}
	parts := []string{rootDir}
	parts = append(parts, sparts...)
	return filepath.Join(parts...)
}
