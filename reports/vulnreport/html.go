package vulnreport

import (
	"html/template"
	"os"
	"strings"
)

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<style>
body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 64rem; padding: 0 1rem; color: #1f2328; }
h1 { border-bottom: 1px solid #d1d9e0; padding-bottom: 0.3rem; }
h2 { margin-top: 2rem; }
.classification { text-align: center; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; border: 1px solid #1f2328; padding: 0.3rem; margin-bottom: 1.5rem; }
.subtitle { color: #59636e; font-size: 1.1rem; margin-top: -0.5rem; }
dl.meta { display: grid; grid-template-columns: max-content 1fr; gap: 0.25rem 1rem; }
dl.meta dt { font-weight: 600; }
dl.meta dd { margin: 0; }
table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
th, td { border: 1px solid #d1d9e0; padding: 0.4rem 0.6rem; text-align: left; }
th { background: #f6f8fa; }
section.finding { border-top: 1px solid #d1d9e0; padding-top: 0.5rem; margin-top: 1.5rem; }
section.finding h3 { margin-bottom: 0.5rem; }
section.finding h4 { margin: 0.75rem 0 0.25rem; }
</style>
</head>
<body>
{{if .Classification}}<div class="classification">{{.Classification}}</div>{{end}}
<h1>{{.Title}}</h1>
{{if .Subtitle}}<p class="subtitle">{{.Subtitle}}</p>{{end}}
{{if .MetaFields}}<dl class="meta">{{range .MetaFields}}<dt>{{.Label}}</dt><dd>{{.Value}}</dd>{{end}}</dl>{{end}}
{{if .Summary}}<h2>Executive Summary</h2>
{{range .SummaryParagraphs}}<p>{{.}}</p>
{{end}}{{end}}
<h2>Severity Summary</h2>
{{.SeverityTableHTML}}
<h2>Findings</h2>
{{if .HaveFindings}}{{.FindingsTableHTML}}{{else}}<p>No findings.</p>{{end}}
{{if .FindingDetails}}<h2>Finding Details</h2>
{{range .FindingDetails}}<section class="finding">
<h3>{{.Name}}</h3>
<dl class="meta">
{{if .ID}}<dt>ID</dt><dd>{{.ID}}</dd>{{end}}
{{if .Severity}}<dt>Severity</dt><dd>{{.Severity}}</dd>{{end}}
{{if .RiskInherent}}<dt>Inherent Risk</dt><dd>{{.RiskInherent}}</dd>{{end}}
{{if .SeverityResidual}}<dt>Residual Severity</dt><dd>{{.SeverityResidual}}</dd>{{end}}
{{if .RiskResidual}}<dt>Residual Risk</dt><dd>{{.RiskResidual}}</dd>{{end}}
</dl>
{{if .Description}}<p>{{.Description}}</p>{{end}}
{{if .Controls}}<h4>Compensating Controls</h4>
<ul>
{{range .Controls}}<li><strong>{{.Name}}</strong>{{if .Description}}: {{.Description}}{{end}}{{if .Verified}} <em>(verified)</em>{{end}}</li>
{{end}}</ul>
{{end}}</section>
{{end}}{{end}}
</body>
</html>
`

type htmlData struct {
	Title             string
	Subtitle          string
	Classification    string
	MetaFields        []metaField
	Summary           string
	SummaryParagraphs []string
	SeverityTableHTML template.HTML
	HaveFindings      bool
	FindingsTableHTML template.HTML
	FindingDetails    []findingDetail
}

// HTML renders the report as a standalone HTML document. Table cell values
// and metadata are HTML-escaped.
func (r *Report) HTML() (string, error) {
	findings, err := r.FindingsTable()
	if err != nil {
		return "", err
	}

	data := htmlData{
		Title:             r.Title,
		Subtitle:          r.Subtitle,
		Classification:    r.Classification,
		MetaFields:        r.metaFields(),
		Summary:           r.Summary,
		SeverityTableHTML: template.HTML(r.SeverityTable().ToHTML(true)), // #nosec G203 -- cell values escaped by ToHTML(true)
		HaveFindings:      len(findings.Rows) > 0,
		FindingsTableHTML: template.HTML(findings.ToHTML(true)), // #nosec G203 -- cell values escaped by ToHTML(true)
		FindingDetails:    r.findingDetails(),
	}
	for _, para := range strings.Split(r.Summary, "\n\n") {
		if para = strings.TrimSpace(para); para != "" {
			data.SummaryParagraphs = append(data.SummaryParagraphs, para)
		}
	}

	tmpl, err := template.New("vulnreport").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	if err := tmpl.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

// WriteHTMLFile writes the report as an HTML file.
func (r *Report) WriteHTMLFile(filename string, perm os.FileMode) error {
	h, err := r.HTML()
	if err != nil {
		return err
	}
	return os.WriteFile(filename, []byte(h), perm)
}
