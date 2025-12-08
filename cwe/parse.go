package cwe

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/grokify/mogo/sort/sortutil"
)

var rxCWE = regexp.MustCompile(`^(CWE-[0-9]+)`)

func ParseCWEAsPrefix(s string) (string, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	m := rxCWE.FindStringSubmatch(s)
	if len(m) > 0 {
		return m[1], nil
	} else {
		return "", fmt.Errorf("cannot parse CWE (%s)", s)
	}
}

func ParsesCWEsAsPrefix(s []string) ([]string, error) {
	var out []string
	for _, si := range s {
		if c, err := ParseCWEAsPrefix(si); err != nil {
			return nil, err
		} else {
			out = append(out, c)
		}
	}
	return sortutil.IntegerSuffix(out), nil
}
