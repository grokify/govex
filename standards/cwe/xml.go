package cwe

import (
	_ "embed"
	"encoding/xml"

	"github.com/grokify/mogo/encoding/xmlutil"
)

type XML struct {
	XMLName           xml.Name      `xml:"Weakness_Catalog"`
	Date              string        `xml:"Date,attr" json:"date"`
	Name              string        `xml:"Name,attr" json:"name"`
	Version           string        `xml:"Version,attr" json:"version"`
	XMLNameSpace      string        `xml:"xmlns,attr"`
	XMLSchemaInstance string        `xml:"xmlns xsi,attr"`
	XMLSchemaLocation string        `xml:"xsi schemaLocation,attr"`
	XHTML             string        `xml:"xmlns xhtml,attr"`
	Weaknesses        WeaknessesXML `xml:"Weaknesses"`
}

func ReadFileXML(name string) (XML, error) {
	x := XML{}
	if err := xmlutil.UnmarshalFile(name, &x); err != nil {
		return x, err
	} else {
		return x, nil
	}
}
