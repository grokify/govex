package cwe

import (
	"strings"

	"github.com/grokify/mogo/type/stringsutil"
)

type WeaknessesXML struct {
	Weakness []Weakness `xml:"Weakness"`
}

func (w WeaknessesXML) Set() *WeaknessSet {
	out := NewWeaknessSet()
	for _, w := range w.Weakness {
		w.Inflate()
		out.Data[w.ID] = w
	}
	return out
}

type Weakness struct {
	ID                  uint   `xml:"ID,attr"`
	Name                string `xml:"Name,attr"`
	Abstraction         string `xml:"Abstraction,attr"`
	Structure           string `xml:"Structure,attr"`
	Status              string `xml:"Status,attr"`
	Description         string `xml:"Description"`
	ExtendedDescription string `xml:"Extended_Description"`
}

func (w *Weakness) Inflate() {
	w.CondenseSpace()
}

func (w *Weakness) CondenseSpace() {
	w.Name = stringsutil.CondenseSpace(w.Name)
	w.Description = stringsutil.CondenseSpace(w.Description)
	w.ExtendedDescription = stringsutil.CondenseSpace(w.ExtendedDescription)
}

func CondenseSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

type WeaknessSet struct {
	Data map[uint]Weakness `json:"data"`
}

func NewWeaknessSet() *WeaknessSet {
	return &WeaknessSet{Data: map[uint]Weakness{}}
}

func ReadWeaknessSet(filename string) (*WeaknessSet, error) {
	if x, err := ReadFileXML(filename); err != nil {
		return nil, err
	} else {
		return x.Weaknesses.Set(), nil
	}
}

func GetWeaknessSet() *WeaknessSet {
	if x, err := ReadFileXML(""); err != nil {
		panic(err)
	} else {
		return x.Weaknesses.Set()
	}
}

func (set *WeaknessSet) Add(w ...Weakness) {
	for _, wi := range w {
		set.Data[wi.ID] = wi
	}
}

func (set *WeaknessSet) Len() int {
	return len(set.Data)
}

func (set *WeaknessSet) GetByID(id uint) *Weakness {
	if w, ok := set.Data[id]; ok {
		return &w
	} else {
		return nil
	}
}

func (set *WeaknessSet) GetByName(name string) []Weakness {
	var out []Weakness
	for _, w := range set.Data {
		if w.Name == name {
			out = append(out, w)
		}
	}
	return out
}
