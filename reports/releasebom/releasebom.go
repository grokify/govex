package releasebom

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/grokify/gocharts/v2/data/table"
	yaml "gopkg.in/yaml.v3"
)

type ReleaseBOM struct {
	Name             string    `yaml:"name,omitempty"`
	Version          string    `yaml:"version,omitempty"`
	ContainerImages  Artifacts `yaml:"containerImages,omitempty"`
	Documents        Artifacts `yaml:"documents,omitempty"`
	HelmCharts       Artifacts `yaml:"helmCharts,omitempty"`
	TerraformScripts Artifacts `yaml:"terraformScripts,omitempty"`
}

func (bom *ReleaseBOM) AddImage(art Artifact) {
	if len(bom.ContainerImages) == 0 {
		bom.ContainerImages = append(bom.ContainerImages, art)
		return
	}
	for _, a := range bom.ContainerImages {
		if a.Equal(art) {
			return
		}
	}
	bom.ContainerImages = append(bom.ContainerImages, art)
}

const pdfMarkdownHeader = `---
header-includes:
 \usepackage{geometry}

documentclass: extarticle
fontsize: 10pt
geometry: margin=2cm
mainfont: Arial
sansfont: Arial
table-width: 100%
table-column-widths: [20%, 80%]

output:
  pdf_document
---`

func (bom *ReleaseBOM) Sort() {
	bom.ContainerImages.Sort()
	bom.Documents.Sort()
	bom.HelmCharts.Sort()
	bom.TerraformScripts.Sort()
}

func (bom *ReleaseBOM) ReleaseManifestDocMarkdown() (string, error) {
	bom.Sort()
	sb := strings.Builder{}
	if _, err := sb.WriteString(pdfMarkdownHeader + "\n\n"); err != nil {
		return "", err
	}
	reportName := bom.Name
	if strings.TrimSpace(reportName) == "" {
		reportName = "Bill of Materials"
	}

	if _, err := sb.WriteString(fmt.Sprintf("# %s\n\n", reportName)); err != nil {
		return "", err
	}

	if ver := strings.TrimSpace(bom.Version); ver != "" {
		if _, err := sb.WriteString(fmt.Sprintf("Version: %s\n\n",
			ver)); err != nil {
			return "", err
		}
	}

	printArtifacts := func(sb *strings.Builder, sectionName string, arts Artifacts) error {
		if len(arts) > 0 {
			mk, err := arts.Markdown()
			if err != nil {
				return err
			}
			if mk != "" {
				if _, err := fmt.Fprintf(sb, "## %s\n\n%s\n\n", sectionName, mk); err != nil {
					return err
				}
			}
		}
		return nil
	}

	if err := printArtifacts(&sb, "Documents", bom.Documents); err != nil {
		return "", err
	}

	if err := printArtifacts(&sb, "Container Images", bom.ContainerImages); err != nil {
		return "", err
	}

	return sb.String(), nil
}

func (bom *ReleaseBOM) ReleaseManifestDocYAML() ([]byte, error) {
	return yaml.Marshal(bom)
}

func (bom *ReleaseBOM) WriteFileReleaseManifestDocMarkdown(filename string) error {
	if mk, err := bom.ReleaseManifestDocMarkdown(); err != nil {
		return err
	} else {
		return os.WriteFile(filename, []byte(mk), 0600)
	}
}

func (bom *ReleaseBOM) WriteFileReleaseManifestDocYAML(filename string) error {
	if yml, err := bom.ReleaseManifestDocYAML(); err != nil {
		return err
	} else {
		return os.WriteFile(filename, yml, 0600)
	}
}

type Artifacts []Artifact

func (arts *Artifacts) HaveImageTag(imageName, tag string) bool {
	for _, art := range *arts {
		if art.Name == imageName && art.Tag == tag {
			return true
		}
	}
	return false
}

func (arts *Artifacts) Markdown() (string, error) {
	sb := strings.Builder{}
	for _, art := range *arts {
		name := art.NameDesc()
		if name != "" {
			if _, err := fmt.Fprintf(&sb, "1. %s\n\n", name); err != nil {
				return "", err
			}
		} else {
			continue
		}
		printed := 0
		if tag := strings.TrimSpace(art.Tag); tag != "" {
			if _, err := fmt.Fprintf(&sb, "    * Tag: %s\n", tag); err != nil {
				return "", err
			}
			printed++
		}
		if dig := strings.TrimSpace(art.Digest); dig != "" {
			if _, err := fmt.Fprintf(&sb, "    * Digest: %s\n", "`"+dig+"`"); err != nil {
				return "", err
			}
			printed++
		}
		if printed > 0 {
			if _, err := sb.WriteString("\n"); err != nil {
				return "", err
			}
		}
	}
	return sb.String(), nil
}

func (arts *Artifacts) Sort() {
	sort.Slice(*arts, func(i, j int) bool {
		return (*arts)[i].NameDesc() < (*arts)[j].NameDesc()
	})
}

func (arts *Artifacts) Table2Col(colNameItem string) *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{
		colNameItem,
		"Tag / Hash",
	}
	for _, art := range *arts {
		name := art.NameDesc()
		digest := strings.TrimSpace(art.Digest)
		if digest != "" {
			digest = "`" + digest + "`"
		}

		tbl.Rows = append(tbl.Rows, []string{
			name, art.Tag})
		if digest != "" {
			tbl.Rows = append(tbl.Rows, []string{
				"", digest})
		}
	}
	return &tbl
}

func (arts *Artifacts) Table3Col(colNameItem string) *table.Table {
	tbl := table.NewTable("")
	tbl.Columns = []string{
		colNameItem,
		"Tag",
		"Hash",
	}
	for _, art := range *arts {
		name := art.NameDesc()
		digest := strings.TrimSpace(art.Digest)
		if digest != "" {
			digest = "`" + digest + "`"
		}
		tbl.Rows = append(tbl.Rows, []string{
			name,
			art.Tag,
			digest,
		})
	}
	return &tbl
}

type Artifact struct {
	Name        string     `yaml:"name,omitempty"`
	Description string     `yaml:"description,omitempty"`
	Tag         string     `yaml:"tag,omitempty"`
	Digest      string     `yaml:"digest,omitempty"`
	GitSHA      string     `yaml:"gitSHA,omitempty"`
	BuiltAt     *time.Time `yaml:"builtAt,omitempty"`
}

func (art *Artifact) Equal(a Artifact) bool {
	if (art.BuiltAt == nil && a.BuiltAt != nil) ||
		(art.BuiltAt != nil && a.BuiltAt == nil) {
		return false
	} else if art.Name == a.Name &&
		art.Description == a.Description &&
		art.Tag == a.Tag &&
		art.Digest == a.Digest &&
		art.GitSHA == a.Description &&
		(art.BuiltAt == nil && a.BuiltAt == nil ||
			(art.BuiltAt.Equal(*a.BuiltAt))) {
		return true
	} else {
		return false
	}
}

func (art *Artifact) NameDesc() string {
	nameParts := []string{art.Name}
	if d := strings.TrimSpace(art.Description); d != "" {
		nameParts = append(nameParts, "("+d+")")
	}
	name := strings.Join(nameParts, " ")
	return name
}
