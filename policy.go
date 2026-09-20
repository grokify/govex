package govex

import (
	"time"

	"github.com/grokify/govex/severity"
)

type Policy struct {
	SLA       severity.SLAMap
	SLAAtTime *time.Time
}
