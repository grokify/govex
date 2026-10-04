module github.com/grokify/govex

go 1.26.4

require (
	github.com/essentialkaos/go-badge v1.4.3
	github.com/grokify/gocharts/v2 v2.27.1
	github.com/grokify/google-fonts v0.1.9
	github.com/grokify/mogo v0.75.0
	github.com/grokify/sogo v0.15.0
	github.com/invopop/jsonschema v0.14.0
	github.com/jessevdk/go-flags v1.6.1
	github.com/johnfercher/maroto/v2 v2.4.3
	github.com/pandatix/go-cvss v0.6.4
	github.com/plexusone/findingspec v0.1.0
	github.com/quay/claircore/toolkit v1.7.0
	github.com/relvacode/iso8601 v1.8.1
	github.com/shopspring/decimal v1.4.0
	github.com/spf13/cobra v1.10.2
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/boombuler/barcode v1.1.0 // indirect
	github.com/buger/jsonparser v1.6.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/clipperhouse/displaywidth v0.11.0 // indirect
	github.com/clipperhouse/uax29/v2 v2.7.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/goccy/go-json v0.11.2 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/grokify/base36 v1.0.5 // indirect
	github.com/grokify/priority-frameworks v0.4.0 // indirect
	github.com/hhrutter/tiff v1.0.7 // indirect
	github.com/huandu/xstrings v1.6.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/johnfercher/go-tree v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mattn/go-runewidth v0.0.30 // indirect
	github.com/olekukonko/cat v0.0.0-20250911104152-50322a0618f6 // indirect
	github.com/olekukonko/errors v1.3.0 // indirect
	github.com/olekukonko/ll v0.1.8 // indirect
	github.com/olekukonko/tablewriter v1.1.5 // indirect
	github.com/package-url/packageurl-go v0.1.7 // indirect
	github.com/pb33f/go-yaml v0.1.1 // indirect
	github.com/pb33f/ordered-map/v2 v2.3.2 // indirect
	github.com/pdfcpu/pdfcpu v0.15.0 // indirect
	github.com/phpdave11/gofpdf v1.4.3 // indirect
	github.com/richardlehane/mscfb v1.0.9 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tiendc/go-deepcopy v1.7.2 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/quicktemplate v1.8.0 // indirect
	github.com/xuri/efp v0.0.2 // indirect
	github.com/xuri/excelize/v2 v2.11.0 // indirect
	github.com/xuri/nfp v0.0.2-0.20250530014748-2ddeb826f9a9 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/image v0.46.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
)

// pdfcpu v0.16.x changed the api.LoadConfiguration / api.MergeRaw signatures
// (added context.Context / ConfigurationOptions), which breaks the PDF merge
// package in github.com/johnfercher/maroto/v2 used by the vulnreport and
// pentest reports. Exclude these versions until maroto supports the new API.
exclude (
	github.com/pdfcpu/pdfcpu v0.16.0
	github.com/pdfcpu/pdfcpu v0.16.1
)
