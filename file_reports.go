package govex

import (
	"strconv"

	"github.com/grokify/gocharts/v2/data/table"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/text/markdown"
)

type FileInfoSetReports struct {
	Set *FileInfoSet
}

func NewFileInfoSetReports(set *FileInfoSet) FileInfoSetReports {
	return FileInfoSetReports{Set: set}
}

func (rpts *FileInfoSetReports) TableSet() (*table.TableSet, error) {
	tbl1 := rpts.FindingCountFileDistribution("Distribution")
	tbl2 := rpts.TableFilepathCounts("Files")
	ts := table.NewTableSet("Vex File Info")
	err := ts.Add(tbl1, tbl2)
	return ts, err
}

func (rpts *FileInfoSetReports) FindingCountFileDistribution(name string) *table.Table {
	tbl := table.NewTable(name)
	tbl.Columns = []string{"Finding Count", "File Count"}
	tbl.FormatMap = map[int]string{-1: table.FormatInt}
	if rpts.Set != nil {
		m := rpts.Set.FilepathCountByFindingCount()
		for findingCount, filepathCount := range m {
			tbl.Rows = append(tbl.Rows, []string{
				strconv.Itoa(findingCount),
				strconv.Itoa(filepathCount)})
		}
	}
	return &tbl
}

func (rpts *FileInfoSetReports) TableFilepathCounts(name string) *table.Table {
	tbl := table.NewTable(name)
	tbl.Columns = []string{
		"Filepath",
		"Directory",
		"Filename",
		"Finding Count",
		"Work Item ID"}
	tbl.FormatMap = map[int]string{
		3: table.FormatInt,
		4: table.FormatURL}
	if rpts.Set != nil {
		for _, fi := range rpts.Set.Items {
			row := []string{
				fi.Filepath(),
				pointer.Dereference(fi.Directory),
				pointer.Dereference(fi.Filename),
				strconv.Itoa(pointer.Dereference(fi.FindingCount)),
				markdown.Linkify(pointer.Dereference(fi.WorkItemURL), pointer.Dereference(fi.WorkItemID)),
			}
			tbl.Rows = append(tbl.Rows, row)
		}
	}
	return &tbl
}

func (rpts *FileInfoSetReports) WriteXLSX(filename string) error {
	if ts, err := rpts.TableSet(); err != nil {
		return err
	} else {
		return ts.WriteXLSX(filename)
	}
}
