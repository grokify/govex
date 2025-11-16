package govex

import (
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/grokify/gocharts/v2/charts/text/progressbarchart"
	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/mogo/pointer"
	"github.com/grokify/mogo/strconv/strconvutil"
	"github.com/grokify/mogo/type/slicesutil"
)

type FileInfoSet struct {
	Items map[string]FileInfo `json:"items,omitempty"` // key is full filepath (directory + filename)
}

func NewFileInfoset() FileInfoSet {
	return FileInfoSet{Items: map[string]FileInfo{}}
}

func NewFileInfosetFromFilepathStats(filename string) (FileInfoSet, error) {
	if stats, err := ReadFileFilepathStats(filename); err != nil {
		return NewFileInfoset(), err
	} else {
		return stats.FileInfoSet(), nil
	}
}

func (set *FileInfoSet) Add(dir, filename string, fcount int) {
	fp := joinFilepath([]string{dir, filename}, false)
	fi, ok := set.Items[fp]
	if !ok {
		fi = FileInfo{}
		if dir != "" {
			fi.Directory = pointer.Pointer(dir)
		}
		if filename != "" {
			fi.Filename = pointer.Pointer(filename)
		}
	}
	fcount += pointer.Dereference(fi.FindingCount)
	fi.FindingCount = pointer.Pointer(fcount)
	set.Items[fp] = fi
}

func (set *FileInfoSet) FindingCountsByPath() map[string]int {
	out := map[string]int{}
	for _, fi := range set.Items {
		fp := fi.Filepath()
		if fi.FindingCount != nil {
			out[fp] += pointer.Dereference(fi.FindingCount)
		}
	}
	return out
}

func (set *FileInfoSet) Filenames(dedupe bool) []string {
	var out []string
	for _, fi := range set.Items {
		if fi.Filename != nil {
			out = append(out, pointer.Dereference(fi.Filename))
		}
	}
	if dedupe {
		out = slicesutil.Dedupe(out)
	}
	return out
}

func (set *FileInfoSet) FilepathsByFindingCount() map[int][]string {
	out := map[int][]string{}
	src := set.FindingCountsByPath()
	for fp, fcount := range src {
		if _, ok := out[fcount]; !ok {
			out[fcount] = []string{}
		}
		out[fcount] = append(out[fcount], fp)
	}
	return out
}

func (set *FileInfoSet) FilepathsByFilename() map[string][]string {
	out := map[string][]string{}
	for _, fi := range set.Items {
		fp := fi.Filepath()
		fn := pointer.Dereference(fi.Filename)
		if _, ok := out[fn]; !ok {
			out[fn] = []string{}
		}
		out[fn] = append(out[fn], fp)
	}
	for fn, fps := range out {
		fps = slicesutil.Dedupe(fps)
		out[fn] = fps
	}
	return out
}

func (set *FileInfoSet) FilepathsForFilename(filename string) []string {
	filepaths := set.FilepathsByFilename()
	if fps, ok := filepaths[filename]; ok {
		return fps
	} else {
		return []string{}
	}
}

func (set *FileInfoSet) FilepathCountByFindingCount() map[int]int {
	out := map[int]int{}
	src := set.FilepathsByFindingCount()
	for k, vs := range src {
		out[k] = len(vs)
	}
	return out
}

func (set *FileInfoSet) FilepathCountByFindingCountChart() string {
	counts := set.FilepathsByFindingCount()

	h := histogram.NewHistogram("")
	buckets := []int{}
	for fCount, filePaths := range counts {
		buckets = append(buckets, fCount)
		plural := ""
		if fCount != 1 {
			plural = "s"
		}
		flawCountStr := strconv.Itoa(fCount) + " finding" + plural
		h.Add(flawCountStr, len(filePaths))
	}
	sort.Ints(buckets)
	fCountStrs := strconvutil.SliceItoa(buckets)
	for i, fCountStr := range fCountStrs {
		plural := ""
		if fCountStr != "1" {
			plural = "s"
		}
		fCountStrs[i] += " finding" + plural
	}
	h.Order = fCountStrs

	cht := progressbarchart.NewTasksFromHistogram(h)
	return cht.ProgressBarChartText()
}

func (set *FileInfoSet) FilepathStats() FilepathStats {
	stats := NewFilepathStats()
	for _, fi := range set.Items {
		fp := fi.Filepath()
		fc := pointer.Dereference(fi.FindingCount)
		stats.CountsByFilepath[fp] += fc
	}
	for fp, fc := range stats.CountsByFilepath {
		if _, ok := stats.FilepathsByCount[fc]; !ok {
			stats.FilepathsByCount[fc] = []string{}
		}
		if !slices.Contains(stats.FilepathsByCount[fc], fp) {
			stats.FilepathsByCount[fc] = append(stats.FilepathsByCount[fc], fp)
		}
	}
	for k, vs := range stats.FilepathsByCount {
		vs = slicesutil.Dedupe(vs)
		stats.FilepathsByCount[k] = vs
	}
	return stats
}

func (set *FileInfoSet) FindingCountForFilename(filename string) (*int, error) {
	fi, err := set.FileInfoForFilename(filename)
	if err != nil {
		return nil, err
	} else if fi == nil || fi.FindingCount == nil {
		return nil, nil
	} else {
		return pointer.Pointer(pointer.Dereference(fi.FindingCount)), nil
	}
}

func (set *FileInfoSet) FileInfoForFilename(filename string) (*FileInfo, error) {
	fps := set.FilepathsForFilename(filename)
	if len(fps) == 0 {
		return nil, nil
	} else if len(fps) == 1 {
		if fi, ok := set.Items[fps[0]]; ok {
			return &fi, nil
		} else {
			return nil, fmt.Errorf("internal error: filepath not found: filename (%s) filepath (%s)", filename, fps[0])
		}
	} else {
		return nil, fmt.Errorf("found multiple filepaths for filename: filename (%s) filepaths (%s)", filename, strings.Join(fps, ","))
	}
}

func (set *FileInfoSet) FindingCountsStats() map[string]int {
	out := map[string]int{}
	for _, v := range set.Items {
		if v.FindingCount == nil {
			out["nil"]++
		}
		fc := pointer.Dereference(v.FindingCount)
		if fc > 0 {
			out["positive"]++
		} else if fc < 0 {
			out["negative"]++
		} else {
			out["zero"]++
		}
	}
	return out
}

func (set *FileInfoSet) FindingCountsSum() int {
	sum := 0
	for _, v := range set.Items {
		if v.FindingCount != nil {
			sum += pointer.Dereference(v.FindingCount)
		}
	}
	return sum
}

func (set *FileInfoSet) WorkItemIDs(dedupe bool) []string {
	var out []string
	for _, v := range set.Items {
		if v.WorkItemID != nil {
			out = append(out, pointer.Dereference(v.WorkItemID))
		}
	}
	if dedupe {
		out = slicesutil.Dedupe(out)
	}
	sort.Strings(out)
	return out
}

func (fs *FileInfoSet) WorkItemIDToFindingCount(inclZeroCounts bool) map[string]int {
	out := map[string]int{}
	for _, v := range fs.Items {
		if v.FindingCount == nil || v.WorkItemID == nil {
			continue
		}
		fcount := pointer.Dereference(v.FindingCount)
		if fcount == 0 && !inclZeroCounts {
			continue
		}
		out[pointer.Dereference(v.WorkItemID)] = fcount
	}
	return out
}

type FileInfo struct {
	Directory    *string `json:"directory,omitempty"`
	Filename     *string `json:"filename,omitempty"`
	FindingCount *int    `json:"findingCount"`
	WorkItemID   *string `json:"workItemID,omitempty"`
}

func (fi FileInfo) Filepath() string {
	return joinFilepath([]string{
		pointer.Dereference(fi.Directory),
		pointer.Dereference(fi.Filename),
	}, false)
}

func joinFilepath(parts []string, inclEmpty bool) string {
	var out []string
	for _, p := range parts {
		if !inclEmpty && len(p) == 0 {
			continue
		}
		out = append(out, p)
	}
	return filepath.Join(out...)
}
