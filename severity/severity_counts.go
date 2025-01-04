package severity

import (
	"errors"
	"os"
	"strconv"
	"strings"

	badge "github.com/essentialkaos/go-badge"
	"github.com/grokify/gocharts/v2/data/histogram"
	"github.com/grokify/google-fonts/roboto"
	"github.com/grokify/mogo/image/colors"
)

type SeverityCountsSet struct {
	Histogram *histogram.Histogram
}

func FuncShieldNameSeverity() func(sev string) (string, error) {
	return func(sev string) (string, error) {
		sev2, _, err := ParseSeverity(sev)
		if err != nil {
			return sev2, nil
		}
		return sev2 + " Vulns", nil
	}
}

func (sc SeverityCountsSet) WriteShields(sevs []string,
	fontSize int,
	sevCutoff string,
	fnFilepath func(sev string) (string, error),
	fnShieldName func(sev string) (string, error),
	perm os.FileMode,
) error {
	if sc.Histogram == nil {
		return errors.New("field SeverityCounts.Histogram cannot be nil")
	}
	g, err := badge.NewGeneratorFromBytes(roboto.RobotoRegular(), fontSize)
	if err != nil {
		return err
	}

	for _, sev := range sevs {
		fp, err := fnFilepath(sev)
		if err != nil {
			return err
		}
		sevShieldName, err := fnShieldName(sev)
		if err != nil {
			return err
		}
		clr, err := SeverityCountColorHex(sev, sevCutoff, sc.Histogram.BinValueOrDefault(sev, 0))
		if err != nil {
			return err
		}
		b := g.GeneratePlastic(
			sevShieldName,
			strconv.Itoa(sc.Histogram.BinValueOrDefault(sev, 0)),
			"#"+clr)
		if err = os.WriteFile(fp, b, perm); err != nil {
			return err
		}
	}

	return nil
}

func SeverityCountColorHex(sev, sevCutoffIncl string, count int) (string, error) {
	if count <= 0 {
		return colors.ShieldBrightGreenHex, nil
	}
	_, sevInt, err := ParseSeverity(sev)
	if err != nil {
		return "", err
	}
	sevCutoffIncl = strings.TrimSpace(sevCutoffIncl)
	if sevCutoffIncl == "" {
		return colors.ShieldRedHex, nil
	} else if _, sevCutoffInclInt, err := ParseSeverity(sevCutoffIncl); err != nil {
		return "", err
	} else if sevInt <= sevCutoffInclInt {
		return colors.ShieldRedHex, nil
	} else {
		return colors.ShieldYellowHex, nil
	}
}
