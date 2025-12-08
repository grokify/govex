package spotbugs

import (
	"encoding/xml"
	"os"
)

// BugCollection represents the root element of a SpotBugs XML report
type BugCollection struct {
	XMLName   xml.Name `xml:"BugCollection"`
	Version   string   `xml:"version,attr"`
	Threshold string   `xml:"threshold,attr"`
	Effort    string   `xml:"effort,attr"`
	Files     []File   `xml:"file"`
	Error     *Error   `xml:"Error"`
	Project   *Project `xml:"Project"`
}

func (bc *BugCollection) BugInstanceCountAllFiles() int {
	sum := 0
	for _, f := range bc.Files {
		sum += len(f.BugInstances)
	}
	return sum
}

// File represents a file containing bug instances
type File struct {
	XMLName      xml.Name      `xml:"file"`
	ClassName    string        `xml:"classname,attr"`
	BugInstances []BugInstance `xml:"BugInstance"`
}

// BugInstance represents a single bug instance found by SpotBugs
type BugInstance struct {
	XMLName    xml.Name `xml:"BugInstance"`
	Type       string   `xml:"type,attr"`
	Priority   string   `xml:"priority,attr"`
	Category   string   `xml:"category,attr"`
	Message    string   `xml:"message,attr"`
	LineNumber int      `xml:"lineNumber,attr,omitempty"`
}

// Error represents the Error element in the report
type Error struct {
	XMLName xml.Name `xml:"Error"`
}

// Project represents the Project element containing source directories
type Project struct {
	XMLName xml.Name `xml:"Project"`
	SrcDirs []SrcDir `xml:"SrcDir"`
}

// SrcDir represents a source directory path
type SrcDir struct {
	XMLName xml.Name `xml:"SrcDir"`
	Path    string   `xml:",chardata"`
}

// ParseBugCollectionFromFile parses a SpotBugs XML file and returns a BugCollection
func ParseBugCollectionFromFile(filePath string) (*BugCollection, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var bugCollection BugCollection
	if err := xml.Unmarshal(data, &bugCollection); err != nil {
		return nil, err
	}

	return &bugCollection, nil
}

// ParseBugCollectionFromBytes parses SpotBugs XML data from bytes and returns a BugCollection
func ParseBugCollectionFromBytes(data []byte) (*BugCollection, error) {
	var bugCollection BugCollection
	if err := xml.Unmarshal(data, &bugCollection); err != nil {
		return nil, err
	}

	return &bugCollection, nil
}
