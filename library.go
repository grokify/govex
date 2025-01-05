package govex

type Library struct {
	Name         string `json:"name"`
	Description  string `json:"description"`
	Type         string `json:"type"` // corresponds with Grype.
	Version      string `json:"version"`
	VersionFixed string `json:"versionFixed"`
}
